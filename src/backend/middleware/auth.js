/**
 * ═══════════════════════════════════════════════════════════════════
 * Auth Middleware - OIDC/Keycloak mit Rollenverwaltung
 * ═══════════════════════════════════════════════════════════════════
 */

const { Issuer, generators } = require("openid-client");
const { getDb, audit } = require("../db");

let oidcClient = null;

async function getClient() {
  if (oidcClient) return oidcClient;
  if (!process.env.OIDC_ISSUER) {
    if (process.env.NODE_ENV === "production") {
      console.error("FATAL: OIDC_ISSUER nicht gesetzt bei NODE_ENV=production");
      process.exit(1);
    }
    console.warn("⚠️  OIDC nicht konfiguriert — Dev-Modus aktiv (nur development!)");
    return null;
  }
  const issuer = await Issuer.discover(process.env.OIDC_ISSUER);
  oidcClient = new issuer.Client({
    client_id: process.env.OIDC_CLIENT_ID,
    client_secret: process.env.OIDC_CLIENT_SECRET,
    redirect_uris: [process.env.OIDC_REDIRECT_URI],
    response_types: ["code"],
  });
  console.log("✅ OIDC Client initialisiert:", process.env.OIDC_ISSUER);
  return oidcClient;
}

// ── Rolle aus Keycloak Claims bestimmen ──────────────────────────
// BRK.id MemberShip-IDs → Bereitschaft-Code + Rolle
const GROUP_MAP = {
  "GRP_Kreisbereitschaftsleitung": { code: "KBL",   rolle: "admin" },
  "GRP_Bereitschaft_ND":           { code: "BND",   rolle: "bl"    },
  "GRP_Bereitschaft_SOB":          { code: "BSOB",  rolle: "bl"    },
  "GRP_Bereitschaft_BGH":          { code: "BBGH",  rolle: "bl"    },
  "GRP_Bereitschaft_KaHu":         { code: "BKAHU", rolle: "bl"    },
  "GRP_Bereitschaft_KarKo":        { code: "BKK",   rolle: "bl"    },
  "GRP_Bereitschaft_WEIlG":        { code: "BWEIG", rolle: "bl"    },
};

function extractRole(userinfo) {
  const groups = userinfo.groups || [];
  // KBL hat immer Vorrang → admin
  if (groups.includes("GRP_Kreisbereitschaftsleitung")) return "admin";
  for (const g of groups) {
    if (GROUP_MAP[g]) return GROUP_MAP[g].rolle;
  }
  return "helfer";
}

function extractBereitschaft(userinfo) {
  const groups = userinfo.groups || [];
  // KBL → eigene Bereitschaft behalten aber Rolle=admin
  // Spezifische Bereitschaft als Code, auch wenn Admin
  const specific = groups.find(g => GROUP_MAP[g] && GROUP_MAP[g].code !== "KBL");
  if (specific) return GROUP_MAP[specific].code;
  if (groups.includes("GRP_Kreisbereitschaftsleitung")) return "KBL";
  return null;
}



// ── User in DB aktualisieren ─────────────────────────────────────
function syncUser(sessionUser) {
  const db = getDb();
  db.prepare(`
    INSERT INTO users (sub, name, email, rolle, bereitschaft_code, last_login)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(sub) DO UPDATE SET
      name = excluded.name,
      email = CASE WHEN users.email != '' AND users.email IS NOT NULL THEN users.email ELSE excluded.email END,
      rolle = excluded.rolle,
      bereitschaft_code = excluded.bereitschaft_code,
      last_login = datetime('now')
  `).run(
    sessionUser.sub,
    sessionUser.name,
    sessionUser.email,
    sessionUser.rolle,
    sessionUser.bereitschaftCode
  );
}

// ── Express Router ───────────────────────────────────────────────
const express = require("express");
const router = express.Router();

// Login
router.get("/login", async (req, res) => {
  // DEV_AUTH: Eigene Login-Seite für Entwicklung
  if (process.env.DEV_AUTH === "true") {
    const db = getDb();
    const bcs = db.prepare("SELECT code, name, short FROM bereitschaften ORDER BY name").all();
    const bcOptions = bcs.map(b => `<option value="${b.code}">${b.name} (${b.short})</option>`).join("");
    return res.send(`<!DOCTYPE html><html lang="de"><head><meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>SanWD v8 – Dev Login</title>
      <style>
        body{font-family:Arial,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f0f2f5}
        .box{background:#fff;padding:32px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.1);max-width:400px;width:100%}
        h2{margin:0 0 4px;color:#1a237e;font-size:20px}
        .sub{font-size:12px;color:#666;margin-bottom:20px}
        .warn{display:inline-block;background:#fff3e0;color:#e65100;padding:4px 10px;border-radius:4px;font-size:11px;font-weight:600;margin-bottom:16px}
        label{display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:#333}
        input,select{width:100%;padding:9px 12px;border:1px solid #ddd;border-radius:6px;font-size:13px;box-sizing:border-box;margin-bottom:14px}
        .row{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}
        button{width:100%;padding:11px;background:#1a237e;color:#fff;border:none;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer}
        button:hover{background:#283593}
      </style></head><body>
      <div class="box">
        <h2>SanWD v8</h2>
        <div class="sub">Entwicklungs-Login</div>
        <div class="warn">⚠ DEV_AUTH – Nicht für Produktion!</div>
        <form method="POST" action="/auth/dev-login">
          <div class="row">
            <div><label>Name</label><input name="name" value="Dev Admin" required></div>
            <div><label>E-Mail</label><input name="email" value="dev@sanwd.local" required></div>
          </div>
          <label>Rolle</label>
          <select name="rolle">
            <option value="admin">Admin</option>
            <option value="bl">Bereitschaftsleiter (BL)</option>
            <option value="kbl">Kreisbereitschaftsleitung (KBL)</option>
            <option value="se">Servicestelle Ehrenamt (SE)</option>
            <option value="helfer">Helfer</option>
          </select>
          <label>Bereitschaft</label>
          <select name="bereitschaftCode">${bcOptions || '<option value="SETUP">Keine vorhanden</option>'}</select>
          <button type="submit">Dev-Login</button>
        </form>
      </div></body></html>`);
  }

  const client = await getClient();
  if (!client) {
    if (process.env.NODE_ENV === "production") {
      return res.status(503).send("OIDC nicht verfügbar. Bitte Admin kontaktieren.");
    }
    return res.status(503).send("Weder DEV_AUTH noch OIDC konfiguriert.");
  }

  const nonce = generators.nonce();
  const state = generators.state();
  req.session.oidcNonce = nonce;
  req.session.oidcState = state;

  res.redirect(client.authorizationUrl({
    scope: "openid profile email groups",
    nonce, state,
  }));
});

// Callback
router.get("/callback", async (req, res) => {
  try {
    const client = await getClient();
    if (!client) return res.redirect("/");

    const params = client.callbackParams(req);
    // Session verloren? → Neu einloggen statt Fehler
    if (!req.session.oidcState || !req.session.oidcNonce) {
      console.warn("OIDC Callback: State/Nonce fehlt in Session – leite zu Login um");
      return res.redirect("/auth/login");
    }
    const tokenSet = await client.callback(
      process.env.OIDC_REDIRECT_URI, params,
      { nonce: req.session.oidcNonce, state: req.session.oidcState }
    );
    const userinfo = await client.userinfo(tokenSet.access_token);

    // DEBUG: Alle Claims loggen
    console.log("OIDC userinfo claims:", JSON.stringify({
      sub: userinfo.sub,
      groups: userinfo.groups,
      memberOf: userinfo.memberOf,
      membership: userinfo.membership,
      roles: userinfo.realm_access?.roles,
      clientRoles: userinfo.resource_access?.[process.env.OIDC_CLIENT_ID]?.roles,
      allKeys: Object.keys(userinfo)
    }, null, 2));

    const rolle = extractRole(userinfo);
    let bereitschaftCode = extractBereitschaft(userinfo);

    if (!bereitschaftCode || bereitschaftCode === "ADMIN") {
      if (rolle === "admin") {
        bereitschaftCode = "ADMIN";
      } else {
        return res.status(403).send("Keine Bereitschaft zugewiesen. Bitte beim Admin melden.");
      }
    }

    // Prüfe ob Bereitschaft existiert (bei Setup-Modus erlauben)
    const db = getDb();
    const bcCount = db.prepare("SELECT COUNT(*) as c FROM bereitschaften").get().c;
    if (bcCount > 0) {
      const bc = db.prepare("SELECT code FROM bereitschaften WHERE code = ?").get(bereitschaftCode);
      if (!bc && bereitschaftCode !== "ADMIN" && bereitschaftCode !== "SETUP") {
        return res.status(403).send(`Bereitschaft "${bereitschaftCode}" nicht in der Datenbank. Admin kontaktieren.`);
      }
    }

    req.session.user = {
      sub: userinfo.sub,
      name: userinfo.name || userinfo.preferred_username,
      email: userinfo.email,
      rolle,
      bereitschaftCode,
    };

    // Token-Infos fuer Session-Validierung
    // Token-Expiry: Großzügig setzen, Refresh-Token übernimmt die Verlängerung
    // Access-Token läuft nach 5 Min ab, aber Refresh-Token hält die Session am Leben
    req.session.tokenExpiry = Date.now() + 3600000; // 1h initial, wird per Refresh verlängert
    req.session.refreshToken = tokenSet.refresh_token || "";
    req.session.accessToken = tokenSet.access_token || "";
    req.session.tokenEndpoint = client.issuer?.metadata?.token_endpoint || "";
    syncUser(req.session.user);
    audit(req.session.user, "login", "user", req.session.user.sub, `Rolle: ${rolle}`);

    delete req.session.oidcNonce;
    delete req.session.oidcState;
    res.redirect(process.env.APP_URL || "/");
  } catch (err) {
    console.error("OIDC Callback Fehler:", err);
    res.status(500).send("Authentifizierung fehlgeschlagen: " + err.message);
  }
});

// Logout
router.get("/logout", (req, res) => {
  if (req.session.user) {
    audit(req.session.user, "logout", "user", req.session.user.sub);
  }
  req.session.destroy(() => res.redirect("/"));
});

// Status
router.get("/status", (req, res) => {
  if (!req.session?.user) return res.json({ authenticated: false });
  const db = getDb();
  const bc = db.prepare("SELECT code, name, short FROM bereitschaften WHERE code = ?")
    .get(req.session.user.bereitschaftCode);
  res.json({
    authenticated: true,
    user: { ...req.session.user, bereitschaft: bc },
  });
});


// ── Dev Login GET → Redirect zu /auth/login ─────────────────────
router.get("/dev-login", (req, res) => {
  res.redirect("/auth/login");
});

// ── Dev Login POST (nur bei DEV_AUTH=true) ───────────────────────
router.post("/dev-login", (req, res) => {
  if (process.env.DEV_AUTH !== "true") return res.status(403).send("Nicht verfügbar");
  const { name, email, rolle, bereitschaftCode } = req.body || {};
  req.session.user = {
    sub: "dev-" + (rolle || "admin"),
    name: name || "Dev User",
    email: email || "dev@sanwd.local",
    rolle: rolle || "admin",
    bereitschaftCode: bereitschaftCode || "",
  };
  syncUser(req.session.user);
  audit(req.session.user, "login", "user", req.session.user.sub, "Dev-Login (" + rolle + ")");
  return res.redirect(process.env.APP_URL || "/");
});


// ── Emergency Login (Hidden Admin-Zugang) ────────────────────────
router.get("/emergency", (req, res) => {
  const db = getDb();
  const bcs = db.prepare("SELECT code, name, short FROM bereitschaften ORDER BY name").all();
  const bcOpts = bcs.map(b => '<option value="' + b.code + '">' + b.name + '</option>').join("");
  res.send(`<!DOCTYPE html><html lang="de"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Notfall-Zugang</title>
    <style>
      body{font-family:Arial,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5}
      .box{background:#fff;padding:32px;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.15);max-width:360px;width:100%}
      h2{margin:0 0 8px;color:#c62828;font-size:18px}
      .sub{font-size:12px;color:#666;margin-bottom:20px}
      label{display:block;font-size:13px;font-weight:600;margin-bottom:4px;color:#333}
      input{width:100%;padding:8px 10px;border:1px solid #ccc;border-radius:4px;font-size:14px;box-sizing:border-box;margin-bottom:12px}
      select{width:100%;padding:8px 10px;border:1px solid #ccc;border-radius:4px;font-size:14px;box-sizing:border-box;margin-bottom:16px}
      button{width:100%;padding:10px;background:#c62828;color:#fff;border:none;border-radius:4px;font-size:14px;font-weight:600;cursor:pointer}
      button:hover{background:#a01a1a}
      .warn{font-size:11px;color:#c62828;margin-top:12px;text-align:center}
    </style>
  </head><body>
    <div class="box">
      <h2>\u26a0\ufe0f Notfall-Zugang</h2>
      <div class="sub">Nur bei Keycloak-Ausfall verwenden</div>
      <form method="POST" action="/auth/emergency-login">
        <label>Passwort</label>
        <input type="password" name="password" required autofocus>
        <label>Bereitschaft</label>
        <select name="bereitschaftCode">${bcOpts}</select>
        <button type="submit">Notfall-Login</button>
      </form>
      <div class="warn">Zugriff wird protokolliert</div>
    </div>
  </body></html>`);
});

router.post("/emergency-login", (req, res) => {
  const crypto = require("crypto");
  const { password, bereitschaftCode } = req.body || {};
  const hash = crypto.createHash("sha256").update(password || "").digest("hex");
  const expectedHash = process.env.EMERGENCY_PASSWORD_HASH;

  if (!expectedHash) {
    return res.status(503).send("Emergency-Login nicht konfiguriert");
  }
  if (hash !== expectedHash) {
    console.warn("Emergency-Login: Falsches Passwort von", req.ip);
    return res.status(401).send("Falsches Passwort");
  }

  const bc = bereitschaftCode || "BSOB";
  req.session.user = {
    sub: "emergency-admin",
    name: "Notfall-Administrator",
    email: "emergency@sanwd.local",
    rolle: "admin",
    bereitschaftCode: bc,
  };

  const { getDb, audit } = require("../db");
  const db = getDb();
  db.prepare(`
    INSERT INTO users (sub, name, email, rolle, bereitschaft_code, last_login)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(sub) DO UPDATE SET
      rolle = excluded.rolle,
      bereitschaft_code = excluded.bereitschaft_code,
      last_login = datetime('now')
  `).run("emergency-admin", "Notfall-Administrator", "emergency@sanwd.local", "admin", bc);

  audit(req.session.user, "emergency-login", "user", "emergency-admin", "Notfall-Login von " + req.ip);
  console.warn("Emergency-Login aktiviert von", req.ip, "BC:", bc);
  res.redirect(process.env.APP_URL || "/");
});

module.exports = router;

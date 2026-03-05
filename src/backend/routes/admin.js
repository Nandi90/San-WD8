const express = require("express");
const router = express.Router();
const { getDb, audit } = require("../db");
const { requireAdmin } = require("../middleware/rbac");

router.use(requireAdmin);

// ── Benutzer-Übersicht ───────────────────────────────────────────
router.get("/users", (req, res) => {
  const rows = getDb().prepare(`
    SELECT u.sub, u.name, u.email, u.rolle, u.bereitschaft_code, u.last_login,
           b.name as bereitschaft_name
    FROM users u LEFT JOIN bereitschaften b ON u.bereitschaft_code = b.code
    ORDER BY u.last_login DESC
  `).all();
  res.json(rows);
});

// ── Benutzer-Rolle ändern ────────────────────────────────────────
router.put("/users/:sub/rolle", (req, res) => {
  const { rolle } = req.body;
  if (!["admin", "bl", "helfer"].includes(rolle)) {
    return res.status(400).json({ error: "Ungültige Rolle" });
  }
  getDb().prepare("UPDATE users SET rolle = ? WHERE sub = ?").run(rolle, req.params.sub);
  audit(req.session.user, "change_role", "user", req.params.sub, `Neue Rolle: ${rolle}`);
  res.json({ success: true });
});

// ── Benutzer Bereitschaft zuweisen ───────────────────────────────
router.put("/users/:sub/bereitschaft", (req, res) => {
  const { bereitschaft_code } = req.body;
  getDb().prepare("UPDATE users SET bereitschaft_code = ? WHERE sub = ?")
    .run(bereitschaft_code, req.params.sub);
  audit(req.session.user, "change_bereitschaft", "user", req.params.sub, bereitschaft_code);
  res.json({ success: true });
});

// ── Bereitschaft hinzufügen ──────────────────────────────────────
router.post("/bereitschaften", (req, res) => {
  const { code, name, short } = req.body;
  if (!code || !name || !short) return res.status(400).json({ error: "Code, Name und Short erforderlich" });

  getDb().prepare("INSERT OR IGNORE INTO bereitschaften (code, name, short) VALUES (?,?,?)").run(code, name, short);
  getDb().prepare("INSERT OR IGNORE INTO kostensaetze (bereitschaft_code) VALUES (?)").run(code);

  audit(req.session.user, "create", "bereitschaft", code, name);
  res.json({ success: true });
});

// ── Audit Log ────────────────────────────────────────────────────
router.get("/audit", (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  const rows = getDb().prepare(
    "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?"
  ).all(limit);
  res.json(rows);
});

// ── Dashboard Stats ──────────────────────────────────────────────
router.get("/stats", (req, res) => {
  const db = getDb();
  res.json({
    vorgaenge: db.prepare("SELECT COUNT(*) as c FROM vorgaenge").get().c,
    vorgaengeThisYear: db.prepare("SELECT COUNT(*) as c FROM vorgaenge WHERE year = ?").get(new Date().getFullYear()).c,
    kunden: db.prepare("SELECT COUNT(*) as c FROM kunden").get().c,
    users: db.prepare("SELECT COUNT(*) as c FROM users").get().c,
    bereitschaften: db.prepare("SELECT COUNT(*) as c FROM bereitschaften").get().c,
    templates: db.prepare("SELECT COUNT(*) as c FROM pdf_templates").get().c,
    lastSync: db.prepare("SELECT MAX(synced_at) as t FROM vorgaenge").get().t,
  });
});

// ── App-Konfiguration ─────────────────────────────────────────────
router.post("/config", (req, res) => {
  const { key, value } = req.body || {};
  if (!key) return res.status(400).json({ error: "key fehlt" });
  const { setConfig } = require("../db");
  setConfig(key, String(value ?? ""));
  res.json({ ok: true });
});

router.get("/config/:key", (req, res) => {
  const { getConfig } = require("../db");
  res.json({ key: req.params.key, value: getConfig(req.params.key, null) });
});

// ── BRK.id Gruppen-Verwaltung ─────────────────────────────────────

// Alle BRK.id Funktionsgruppen auflisten
router.get("/brk-id-groups", (req, res) => {
  const db = getDb();
  const groups = db.prepare("SELECT * FROM brk_id_groups ORDER BY rolle DESC, group_code ASC").all();
  res.json(groups);
});

// Einzelne Gruppe anlegen oder aktualisieren
router.put("/brk-id-groups/:code", (req, res) => {
  const db = getDb();
  const code = decodeURIComponent(req.params.code);
  const { type, rolle, bereitschaft_code, description, active } = req.body;
  const validRollen = ["admin", "kbl", "bl", "se", "helfer"];
  if (!validRollen.includes(rolle)) return res.status(400).json({ error: "Ungültige Rolle" });
  db.prepare(`
    INSERT INTO brk_id_groups (group_code, type, rolle, bereitschaft_code, description, active)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(group_code) DO UPDATE SET
      type=excluded.type, rolle=excluded.rolle,
      bereitschaft_code=excluded.bereitschaft_code,
      description=excluded.description, active=excluded.active
  `).run(code, type || "rolle", rolle, bereitschaft_code || null, description || "", active ?? 1);
  res.json({ ok: true });
});

// Gruppe löschen
router.delete("/brk-id-groups/:code", (req, res) => {
  const db = getDb();
  db.prepare("DELETE FROM brk_id_groups WHERE group_code=?").run(decodeURIComponent(req.params.code));
  res.json({ ok: true });
});

// brk_id_group auf einer Bereitschaft setzen
router.put("/bereitschaften/:code/brk-id-group", (req, res) => {
  const db = getDb();
  const { brk_id_group } = req.body;
  db.prepare("UPDATE bereitschaften SET brk_id_group=? WHERE code=?")
    .run(brk_id_group || "", req.params.code);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
// LOKALE BENUTZERVERWALTUNG (Lokaler Auth-Modus)
// ══════════════════════════════════════════════════════════════
const bcrypt = require("bcryptjs");

// Liste aller lokalen Benutzer
router.get("/local-users", (req, res) => {
  const rows = getDb().prepare(`
    SELECT lu.id, lu.username, lu.name, lu.email, lu.rolle,
           lu.bereitschaft_code, lu.active, lu.created_at, lu.updated_at,
           b.name as bereitschaft_name, b.short as bereitschaft_short
    FROM local_users lu
    LEFT JOIN bereitschaften b ON lu.bereitschaft_code = b.code
    ORDER BY lu.name ASC
  `).all();
  res.json(rows);
});

// Benutzer anlegen
router.post("/local-users", async (req, res) => {
  const { username, name, email, password, rolle, bereitschaft_code } = req.body || {};
  if (!username || !name || !password) return res.status(400).json({ error: "Username, Name und Passwort erforderlich" });
  const validRollen = ["admin", "kbl", "bl", "se", "helfer"];
  if (rolle && !validRollen.includes(rolle)) return res.status(400).json({ error: "Ungültige Rolle" });
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = getDb().prepare(
      "INSERT INTO local_users (username, name, email, password_hash, rolle, bereitschaft_code) VALUES (?,?,?,?,?,?)"
    ).run(username.trim(), name.trim(), email || "", hash, rolle || "helfer", bereitschaft_code || null);
    audit(req.session.user, "create", "local_user", String(result.lastInsertRowid), username);
    res.json({ ok: true, id: result.lastInsertRowid });
  } catch(e) {
    if (e.message?.includes("UNIQUE")) return res.status(409).json({ error: "Benutzername bereits vergeben" });
    res.status(500).json({ error: e.message });
  }
});

// Benutzer bearbeiten (ohne Passwort)
router.put("/local-users/:id", (req, res) => {
  const { name, email, rolle, bereitschaft_code, active } = req.body || {};
  const validRollen = ["admin", "kbl", "bl", "se", "helfer"];
  if (rolle && !validRollen.includes(rolle)) return res.status(400).json({ error: "Ungültige Rolle" });
  getDb().prepare(`
    UPDATE local_users SET name=?, email=?, rolle=?, bereitschaft_code=?, active=?,
    updated_at=datetime('now') WHERE id=?
  `).run(name, email || "", rolle || "helfer", bereitschaft_code || null, active ?? 1, req.params.id);
  audit(req.session.user, "update", "local_user", req.params.id, `Rolle: ${rolle}`);
  res.json({ ok: true });
});

// Passwort zurücksetzen
router.put("/local-users/:id/password", async (req, res) => {
  const { password } = req.body || {};
  if (!password || password.length < 6) return res.status(400).json({ error: "Passwort mind. 6 Zeichen" });
  const hash = await bcrypt.hash(password, 10);
  getDb().prepare("UPDATE local_users SET password_hash=?, updated_at=datetime('now') WHERE id=?").run(hash, req.params.id);
  audit(req.session.user, "password_reset", "local_user", req.params.id, "");
  res.json({ ok: true });
});

// Benutzer löschen
router.delete("/local-users/:id", (req, res) => {
  getDb().prepare("DELETE FROM local_users WHERE id=?").run(req.params.id);
  audit(req.session.user, "delete", "local_user", req.params.id, "");
  res.json({ ok: true });
});

module.exports = router;

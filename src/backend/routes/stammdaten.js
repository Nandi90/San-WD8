const express = require("express");
const multer = require("multer");
const router = express.Router();
const { getDb, audit } = require("../db");
const { requireAuth, requireBL, requireAdmin, getBereitschaftCode } = require("../middleware/rbac");

const upload = multer({
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ["image/png", "image/jpeg", "image/svg+xml", "image/webp"];
    if (allowed.includes(file.mimetype)) { cb(null, true); }
    else { cb(new Error("Nur Bilder erlaubt (PNG, JPEG, SVG, WebP)"), false); }
  }
});
router.use(requireAuth);

// ── Eigene Bereitschaft laden ────────────────────────────────────
router.get("/me", (req, res) => {
  const bc = getBereitschaftCode(req);
  const bereitschaft = getDb().prepare("SELECT * FROM bereitschaften WHERE code = ?").get(bc);
  const kosten = getDb().prepare("SELECT * FROM kostensaetze WHERE bereitschaft_code = ?").get(bc);
  if (!bereitschaft) return res.status(404).json({ error: "Bereitschaft nicht gefunden" });
  res.json({
    ...bereitschaft,
    logo: bereitschaft.logo ? `/api/stammdaten/logo` : null,
    kostensaetze: kosten,
  });
});

// ── Alle Bereitschaften (Admin) ──────────────────────────────────
router.get("/bereitschaften", (req, res) => {
  const rows = getDb().prepare("SELECT code, name, short FROM bereitschaften ORDER BY name").all();
  res.json(rows);
});

// ── Alle Bereitschaften mit vollen Details (Admin) ───────────────
router.get("/bereitschaften/details", requireAdmin, (req, res) => {
  const rows = getDb().prepare("SELECT code, name, short, leiter_name, leiter_title, telefon, fax, mobil, email, funkgruppe, kv_name, kgf, kv_adresse, kv_plz_ort FROM bereitschaften ORDER BY name").all();
  res.json(rows);
});

// ── Einzelne Bereitschaft aktualisieren (Admin) ──────────────────
router.put("/bereitschaften/:code", requireAdmin, (req, res) => {
  const { code } = req.params;
  const { leiter_name, leiter_title, telefon, fax, mobil, email, funkgruppe } = req.body;
  getDb().prepare(`
    UPDATE bereitschaften SET
      leiter_name=?, leiter_title=?, telefon=?, fax=?, mobil=?, email=?, funkgruppe=?,
      updated_at=datetime('now')
    WHERE code = ?
  `).run(leiter_name||"", leiter_title||"", telefon||"", fax||"", mobil||"", email||"", funkgruppe||"", code);
  audit(req.session.user, "update", "bereitschaft", code, JSON.stringify({ email }));
  res.json({ success: true });
});

router.get("/alle", requireAdmin, (req, res) => {
  const rows = getDb().prepare("SELECT code, name, short FROM bereitschaften ORDER BY name").all();
  res.json(rows);
});

// ── Bereitschaft aktualisieren ───────────────────────────────────
router.put("/", requireAdmin, (req, res) => {
  const bc = getBereitschaftCode(req);
  const { leiter_name, leiter_title, telefon, fax, mobil, email, funkgruppe,
          kv_name, kgf, kv_adresse, kv_plz_ort } = req.body;

  getDb().prepare(`
    UPDATE bereitschaften SET
      leiter_name=?, leiter_title=?, telefon=?, fax=?, mobil=?, email=?, funkgruppe=?,
      kv_name=?, kgf=?, kv_adresse=?, kv_plz_ort=?, updated_at=datetime('now')
    WHERE code = ?
  `).run(leiter_name, leiter_title, telefon, fax, mobil, email, funkgruppe,
         kv_name, kgf, kv_adresse, kv_plz_ort, bc);

  audit(req.session.user, "update", "bereitschaft", bc, req.body);
  res.json({ success: true });
});

// ── Kostensätze aktualisieren ────────────────────────────────────
router.put("/kostensaetze", requireAdmin, (req, res) => {
  const bc = getBereitschaftCode(req);
  const k = req.body;

  getDb().prepare(`
    UPDATE kostensaetze SET
      helfer=?, ktw=?, rtw=?, gktw=?, einsatzleiter=?, einsatzleiter_kfz=?,
      seg_lkw=?, mtw=?, zelt=?, km_ktw=?, km_rtw=?, km_gktw=?,
      km_el_kfz=?, km_seg_lkw=?, km_mtw=?, verpflegung=?, updated_at=datetime('now')
    WHERE bereitschaft_code = ?
  `).run(k.helfer, k.ktw, k.rtw, k.gktw, k.einsatzleiter, k.einsatzleiter_kfz,
         k.seg_lkw, k.mtw, k.zelt, k.km_ktw, k.km_rtw, k.km_gktw,
         k.km_el_kfz, k.km_seg_lkw, k.km_mtw, k.verpflegung, bc);

  audit(req.session.user, "update", "kostensaetze", bc);
  res.json({ success: true });
});

// ── Logo Upload ──────────────────────────────────────────────────
router.post("/logo", requireAdmin, upload.single("logo"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Keine Datei" });
  const bc = getBereitschaftCode(req);
  getDb().prepare("UPDATE bereitschaften SET logo = ?, updated_at = datetime('now') WHERE code = ?")
    .run(req.file.buffer, bc);
  audit(req.session.user, "upload", "logo", bc);
  res.json({ success: true, logo: `/api/stammdaten/logo` });
});

router.delete("/logo", requireAdmin, (req, res) => {
  const bc = getBereitschaftCode(req);
  getDb().prepare("UPDATE bereitschaften SET logo = NULL, updated_at = datetime('now') WHERE code = ?").run(bc);
  res.json({ success: true });
});


// ── Logo ausliefern ─────────────────────────────────────────────────
// BL darf nur Bereitschaftsleiter-Daten ändern
router.put("/bereitschaftsleiter", requireBL, (req, res) => {
  const bc = getBereitschaftCode(req);
  const { leiter_name, leiter_title, telefon, fax, mobil, email, funkgruppe } = req.body;
  getDb().prepare(`
    UPDATE bereitschaften SET
      leiter_name=?, leiter_title=?, telefon=?, fax=?, mobil=?, email=?, funkgruppe=?,
      updated_at=datetime('now')
    WHERE code = ?
  `).run(leiter_name||"", leiter_title||"", telefon||"", fax||"", mobil||"", email||"", funkgruppe||"", bc);
  res.json({ success: true });
});

router.get("/logo", (req, res) => {
  const bc = getBereitschaftCode(req);
  const row = getDb().prepare("SELECT logo FROM bereitschaften WHERE code = ?").get(bc);
  if (!row || !row.logo) return res.status(404).send("Kein Logo vorhanden");
  res.set("Content-Type", "image/png");
  res.set("Cache-Control", "private, max-age=3600");
  res.send(row.logo);
});

// ── Counter (Laufende Nummern) ───────────────────────────────────
router.get("/counter/:year", (req, res) => {
  const bc = getBereitschaftCode(req);
  const row = getDb().prepare("SELECT next_nr FROM counter WHERE bereitschaft_code = ? AND year = ?")
    .get(bc, parseInt(req.params.year));
  res.json({ nextNr: row ? row.next_nr : 1 });
});

router.post("/counter/:year/increment", requireBL, (req, res) => {
  const bc = getBereitschaftCode(req);
  const year = parseInt(req.params.year);
  getDb().prepare(`
    INSERT INTO counter (bereitschaft_code, year, next_nr) VALUES (?, ?, 2)
    ON CONFLICT(bereitschaft_code, year) DO UPDATE SET next_nr = next_nr + 1
  `).run(bc, year);
  res.json({ success: true });
});

module.exports = router;

// ═══════════════════════════════════════════════════════════════════
// Setup Wizard (v8)
// ═══════════════════════════════════════════════════════════════════

// Setup-Status (kein requireAdmin – alle dürfen prüfen)
router.get("/setup/status", (req, res) => {
  const { getConfig } = require("../db");
  const complete = getConfig("setup_complete", "false") === "true";
  const hasBCs = getDb().prepare("SELECT COUNT(*) as c FROM bereitschaften").get().c > 0;
  res.json({ setupComplete: complete, hasBereitschaften: hasBCs });
});

// Setup abschließen
router.post("/setup/complete", requireAdmin, (req, res) => {
  const { setConfig } = require("../db");
  setConfig("setup_complete", "true");
  audit(req.session.user, "setup", "system", "setup_complete", "Ersteinrichtung abgeschlossen");
  res.json({ success: true });
});

// Organisation speichern (für Wizard – aktualisiert ALLE Bereitschaften gleichzeitig)
router.put("/setup/organisation", requireAdmin, (req, res) => {
  const { kv_name, kgf, kv_adresse, kv_plz_ort } = req.body;
  // Organisationsdaten auf alle Bereitschaften schreiben
  getDb().prepare("UPDATE bereitschaften SET kv_name=?, kgf=?, kv_adresse=?, kv_plz_ort=?, updated_at=datetime('now')").run(
    kv_name || "", kgf || "", kv_adresse || "", kv_plz_ort || ""
  );
  audit(req.session.user, "setup", "organisation", "all", JSON.stringify({ kv_name }));
  res.json({ success: true });
});

// ── Bereitschaft anlegen (CRUD) ──────────────────────────────────
router.post("/bereitschaften", requireAdmin, (req, res) => {
  const { code, name, short } = req.body;
  if (!code || !name) return res.status(400).json({ error: "Code und Name erforderlich" });
  
  // Prüfe ob Code bereits existiert
  const existing = getDb().prepare("SELECT code FROM bereitschaften WHERE code=?").get(code);
  if (existing) return res.status(409).json({ error: `Bereitschaft ${code} existiert bereits` });
  
  getDb().prepare("INSERT INTO bereitschaften (code, name, short) VALUES (?,?,?)").run(code, name, short || code);
  getDb().prepare("INSERT OR IGNORE INTO kostensaetze (bereitschaft_code) VALUES (?)").run(code);
  audit(req.session.user, "create", "bereitschaft", code, name);
  res.json({ success: true, code });
});

// ── Bereitschaft löschen ─────────────────────────────────────────
router.delete("/bereitschaften/:code", requireAdmin, (req, res) => {
  const { code } = req.params;
  // Prüfe ob Vorgänge existieren
  const vorgaenge = getDb().prepare("SELECT COUNT(*) as c FROM vorgaenge WHERE bereitschaft_code=?").get(code);
  if (vorgaenge.c > 0) return res.status(409).json({ error: `${vorgaenge.c} Vorgänge zugewiesen – Bereitschaft kann nicht gelöscht werden` });
  
  getDb().prepare("DELETE FROM kostensaetze WHERE bereitschaft_code=?").run(code);
  getDb().prepare("DELETE FROM bereitschaften WHERE code=?").run(code);
  audit(req.session.user, "delete", "bereitschaft", code);
  res.json({ success: true });
});

// ── Kostensätze für Setup speichern (beliebiger BC-Code) ─────────
router.put("/setup/kostensaetze/:code", requireAdmin, (req, res) => {
  const { code } = req.params;
  const k = req.body;
  getDb().prepare(`UPDATE kostensaetze SET 
    helfer=?, ktw=?, rtw=?, gktw=?, einsatzleiter=?, einsatzleiter_kfz=?,
    seg_lkw=?, mtw=?, zelt=?, km_ktw=?, km_rtw=?, km_gktw=?,
    km_el_kfz=?, km_seg_lkw=?, km_mtw=?, verpflegung=?, updated_at=datetime('now')
    WHERE bereitschaft_code=?`).run(
    k.helfer||0, k.ktw||0, k.rtw||0, k.gktw||0, k.einsatzleiter||0, k.einsatzleiter_kfz||0,
    k.seg_lkw||0, k.mtw||0, k.zelt||0, k.km_ktw||0, k.km_rtw||0, k.km_gktw||0,
    k.km_el_kfz||0, k.km_seg_lkw||0, k.km_mtw||0, k.verpflegung||0, code
  );
  res.json({ success: true });
});

// Kostensätze auf alle BCs kopieren
router.post("/setup/kostensaetze-apply-all", requireAdmin, (req, res) => {
  const k = req.body;
  getDb().prepare(`UPDATE kostensaetze SET 
    helfer=?, ktw=?, rtw=?, gktw=?, einsatzleiter=?, einsatzleiter_kfz=?,
    seg_lkw=?, mtw=?, zelt=?, km_ktw=?, km_rtw=?, km_gktw=?,
    km_el_kfz=?, km_seg_lkw=?, km_mtw=?, verpflegung=?, updated_at=datetime('now')`).run(
    k.helfer||0, k.ktw||0, k.rtw||0, k.gktw||0, k.einsatzleiter||0, k.einsatzleiter_kfz||0,
    k.seg_lkw||0, k.mtw||0, k.zelt||0, k.km_ktw||0, k.km_rtw||0, k.km_gktw||0,
    k.km_el_kfz||0, k.km_seg_lkw||0, k.km_mtw||0, k.verpflegung||0
  );
  audit(req.session.user, "setup", "kostensaetze", "all", "Standardkostensätze angewendet");
  res.json({ success: true });
});

const express = require("express");
const crypto = require("crypto");
const db = require("./db");
const app = express();

app.use(express.json({ limit: "12mb" }));
app.use(express.static("public"));

db.exec(`CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`);

function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(pw, salt, 64).toString("hex");
  return salt + ":" + hash;
}

function checkPassword(pw, stored) {
  const [salt, hash] = stored.split(":");
  const test = crypto.scryptSync(pw, salt, 64);
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), test);
}

function newSession(user) {
  const token = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO sessions (token, user_id, name, role) VALUES (?, ?, ?, ?)")
    .run(token, user.id, user.name, user.role);
  return token;
}

function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  const row = db.prepare("SELECT user_id, name, role FROM sessions WHERE token = ?").get(token);
  if (!row) return res.status(401).json({ error: "Not logged in." });
  req.user = { id: row.user_id, name: row.name, role: row.role };
  next();
}

app.get("/api/health", (req, res) => res.json({ status: "ok" }));

app.get("/api/db-test", (req, res) => {
  const row = db.prepare("SELECT COUNT(*) AS n FROM users").get();
  res.json({ users: row.n });
});

app.post("/api/signup", (req, res) => {
  const { name, role, identifier, password } = req.body || {};
  if (!name || !role || !identifier || !password)
    return res.status(400).json({ error: "Fill in all fields." });
  if (password.length < 6)
    return res.status(400).json({ error: "Password needs 6+ characters." });
  const exists = db.prepare("SELECT id FROM users WHERE identifier = ?").get(identifier);
  if (exists) return res.status(409).json({ error: "Account already exists. Log in." });
  const r = db
    .prepare("INSERT INTO users (name, role, identifier, password_hash) VALUES (?, ?, ?, ?)")
    .run(name, role, identifier, hashPassword(password));
  const user = { id: Number(r.lastInsertRowid), name, role };
  res.json({ token: newSession(user), user });
});

app.post("/api/login", (req, res) => {
  const { identifier, password } = req.body || {};
  if (!identifier || !password)
    return res.status(400).json({ error: "Fill in all fields." });
  const row = db.prepare("SELECT * FROM users WHERE identifier = ?").get(identifier);
  if (!row) return res.status(404).json({ error: "No account found. Sign up first." });
  if (!checkPassword(password, row.password_hash))
    return res.status(401).json({ error: "Wrong password." });
  const user = { id: row.id, name: row.name, role: row.role };
  res.json({ token: newSession(user), user });
});

app.get("/api/me", auth, (req, res) => res.json({ user: req.user }));

app.post("/api/attendance", auth, (req, res) => {
  const { day, meal, planned, served } = req.body || {};
  if (!day || !meal || !Number.isInteger(planned) || !Number.isInteger(served))
    return res.status(400).json({ error: "Need day, meal, planned and served." });
  db.prepare("INSERT INTO attendance (user_id, day, meal, planned, served) VALUES (?, ?, ?, ?, ?)")
    .run(req.user.id, day, meal, planned, served);
  res.json({ saved: true });
});

app.get("/api/attendance", auth, (req, res) => {
  const rows = db
    .prepare("SELECT day, meal, planned, served FROM attendance WHERE user_id = ? ORDER BY id DESC LIMIT 30")
    .all(req.user.id);
  res.json({ rows });
});

app.post("/api/leftovers", auth, (req, res) => {
  const { day, dishes } = req.body || {};
  if (!day || !Array.isArray(dishes) || !dishes.length)
    return res.status(400).json({ error: "Need day and a list of dishes." });
  const ins = db.prepare("INSERT INTO leftovers (user_id, day, dish, returned_pct) VALUES (?, ?, ?, ?)");
  for (const d of dishes) {
    if (!d.dish || !Number.isInteger(d.returned_pct))
      return res.status(400).json({ error: "Each dish needs a name and returned_pct." });
    ins.run(req.user.id, day, d.dish, d.returned_pct);
  }
  res.json({ saved: dishes.length });
});

app.get("/api/leftovers", auth, (req, res) => {
  const rows = db
    .prepare("SELECT day, dish, returned_pct FROM leftovers WHERE user_id = ? ORDER BY id DESC LIMIT 50")
    .all(req.user.id);
  res.json({ rows });
});

app.get("/api/summary", auth, (req, res) => {
  const s = db
    .prepare("SELECT COUNT(*) AS services, COALESCE(SUM(planned - served), 0) AS plates_saved FROM attendance WHERE user_id = ?")
    .get(req.user.id);
  const top = db
    .prepare("SELECT dish, ROUND(AVG(returned_pct)) AS avg FROM leftovers WHERE user_id = ? GROUP BY dish ORDER BY AVG(returned_pct) DESC LIMIT 1")
    .get(req.user.id);
  res.json({ services: s.services, plates_saved: s.plates_saved, top_dish: top || null });
});

app.listen(3000, () => console.log("Running on http://localhost:3000"));
app.get("/api/forecast", auth, (req, res) => {
  const hc = Number(req.query.hc) || 600;
  const lv = Number(req.query.lv) || 0;
  const dw = Number(req.query.dw) || 1;
  const ho = req.query.ho === "1" ? 0.85 : 1;
  const rn = req.query.rn === "1" ? 1.05 : 1;
  const h = db
    .prepare("SELECT COUNT(*) AS n, AVG(served) AS avg_served, AVG(planned) AS avg_planned FROM (SELECT served, planned FROM attendance WHERE user_id = ? ORDER BY id DESC LIMIT 10)")
    .get(req.user.id);
  const useHistory = h.n >= 3;
  let plates;
  if (useHistory) {
    plates = Math.round(h.avg_served * ((1 - lv / 100) / 0.82) * dw * ho * rn);
  } else {
    plates = Math.round(hc * (1 - lv / 100) * dw * ho * rn * 0.88);
  }
  const usual = useHistory ? Math.round(h.avg_planned) : Math.round(hc * 0.9 * 1.2);
  res.json({
    plates,
    rice_kg: +(plates * 0.06).toFixed(1),
    dal_kg: +(plates * 0.035).toFixed(1),
    veg_kg: +(plates * 0.1).toFixed(1),
    usual_rice_kg: +(usual * 0.06).toFixed(1),
    saved_rs: Math.max(0, (usual - plates) * 28),
    based_on: useHistory ? "history" : "formula",
    services_used: h.n,
  });
});
db.exec(`CREATE TABLE IF NOT EXISTS donations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  cert_id TEXT NOT NULL UNIQUE,
  food TEXT NOT NULL,
  kg REAL NOT NULL,
  receiver TEXT NOT NULL,
  cooked_min_ago INTEGER NOT NULL,
  safe_by TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`);

app.post("/api/donations", auth, (req, res) => {
  const { food, kg, receiver, cooked_min_ago, safe_by } = req.body || {};
  if (!food || typeof kg !== "number" || !receiver || !Number.isInteger(cooked_min_ago) || !safe_by)
    return res.status(400).json({ error: "Need food, kg, receiver, cooked_min_ago and safe_by." });
  const cert_id = "TZ-" + new Date().getFullYear() + "-" + crypto.randomBytes(3).toString("hex").toUpperCase();
  db.prepare("INSERT INTO donations (user_id, cert_id, food, kg, receiver, cooked_min_ago, safe_by) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .run(req.user.id, cert_id, food, kg, receiver, cooked_min_ago, safe_by);
  res.json({ cert_id });
});

app.get("/api/donations", auth, (req, res) => {
  const rows = db
    .prepare("SELECT cert_id, food, kg, receiver, created_at FROM donations WHERE user_id = ? ORDER BY id DESC LIMIT 20")
    .all(req.user.id);
  const t = db.prepare("SELECT COALESCE(SUM(kg), 0) AS total_kg FROM donations WHERE user_id = ?").get(req.user.id);
  res.json({ rows, total_kg: t.total_kg });
});
const fs = require("fs");
const path = require("path");
const UP = path.join(__dirname, "uploads");
fs.mkdirSync(UP, { recursive: true });

db.exec(`CREATE TABLE IF NOT EXISTS photos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  file TEXT NOT NULL,
  day TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`);

app.post("/api/photos", auth, (req, res) => {
  const { image, day } = req.body || {};
  const m = /^data:image\/(jpeg|png|webp);base64,(.+)$/.exec(image || "");
  if (!m || !day) return res.status(400).json({ error: "Send a JPEG, PNG or WebP image and a day." });
  const buf = Buffer.from(m[2], "base64");
  if (buf.length > 8 * 1024 * 1024) return res.status(413).json({ error: "Image too large." });
  const file = crypto.randomBytes(16).toString("hex") + "." + (m[1] === "jpeg" ? "jpg" : m[1]);
  fs.writeFileSync(path.join(UP, file), buf);
  const r = db.prepare("INSERT INTO photos (user_id, file, day) VALUES (?, ?, ?)").run(req.user.id, file, day);
  res.json({ id: Number(r.lastInsertRowid) });
});

app.get("/api/photos", auth, (req, res) => {
  const rows = db
    .prepare("SELECT id, day, created_at FROM photos WHERE user_id = ? ORDER BY id DESC LIMIT 24")
    .all(req.user.id);
  res.json({ rows });
});

app.get("/api/photos/:id/file", auth, (req, res) => {
  const row = db
    .prepare("SELECT file FROM photos WHERE id = ? AND user_id = ?")
    .get(Number(req.params.id), req.user.id);
  if (!row) return res.status(404).json({ error: "Not found." });
  res.sendFile(path.join(UP, row.file));
});

app.delete("/api/photos/:id", auth, (req, res) => {
  const row = db
    .prepare("SELECT file FROM photos WHERE id = ? AND user_id = ?")
    .get(Number(req.params.id), req.user.id);
  if (!row) return res.status(404).json({ error: "Not found." });
  fs.rmSync(path.join(UP, row.file), { force: true });
  db.prepare("DELETE FROM photos WHERE id = ?").run(Number(req.params.id));
  res.json({ deleted: true });
});
db.exec(`CREATE TABLE IF NOT EXISTS places (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  lat REAL NOT NULL,
  lng REAL NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`);

app.get("/api/places", auth, (req, res) => {
  const rows = db
    .prepare("SELECT id, name, kind, lat, lng FROM places WHERE user_id = ? ORDER BY id")
    .all(req.user.id);
  res.json({ rows });
});

app.post("/api/places", auth, (req, res) => {
  const { name, kind, lat, lng } = req.body || {};
  if (!["kitchen", "ngo", "volunteer"].includes(kind) || !name ||
      typeof lat !== "number" || typeof lng !== "number" ||
      Math.abs(lat) > 90 || Math.abs(lng) > 180)
    return res.status(400).json({ error: "Need a name, a kind and valid lat/lng." });
  if (kind === "kitchen")
    db.prepare("DELETE FROM places WHERE user_id = ? AND kind = 'kitchen'").run(req.user.id);
  const r = db
    .prepare("INSERT INTO places (user_id, name, kind, lat, lng) VALUES (?, ?, ?, ?, ?)")
    .run(req.user.id, String(name).slice(0, 80), kind, lat, lng);
  res.json({ id: Number(r.lastInsertRowid) });
});

app.delete("/api/places/:id", auth, (req, res) => {
  db.prepare("DELETE FROM places WHERE id = ? AND user_id = ?").run(Number(req.params.id), req.user.id);
  res.json({ deleted: true });
});
const { DatabaseSync } = require("node:sqlite");

const db = new DatabaseSync("thaali.db");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    identifier TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    day TEXT NOT NULL,
    meal TEXT NOT NULL,
    planned INTEGER NOT NULL,
    served INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS leftovers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    day TEXT NOT NULL,
    dish TEXT NOT NULL,
    returned_pct INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

module.exports = db;
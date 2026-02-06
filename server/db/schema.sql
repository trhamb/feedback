PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY,
    event_name TEXT NOT NULL,
    rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    ip_hash TEXT
);

-- Staff accounts for dashboard access (create accounts via server/scripts/create-staff.js)
CREATE TABLE IF NOT EXISTS staff (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Settings (hub PIN editable from dashboard)
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY,
    event_name TEXT NOT NULL,
    rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    ip_hash TEXT
);

-- Staff accounts: role is 'volunteer' | 'staff' | 'admin' (create via server/scripts/create-staff.js)
CREATE TABLE IF NOT EXISTS staff (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'staff' CHECK (role IN ('volunteer', 'staff', 'admin')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Settings (optional key/value for app configuration)
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
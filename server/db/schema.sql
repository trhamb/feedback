PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY,
    event_name TEXT NOT NULL,
    rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    ip_hash TEXT
);
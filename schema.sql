-- cloud-serv schema (reference copy).
-- CloudDB creates these tables at startup if missing; this file documents them
-- and can seed a fresh DB manually:  sqlite3 data/cloud.db < schema.sql
--
-- WARNING: no DROP statements here. Use a separate migration to reset.

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT UNIQUE NOT NULL,
    display_name  TEXT NOT NULL,
    password_hash TEXT NOT NULL,              -- pbkdf2$<iters>$<salt>$<hash>
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    encrypt_files INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    token_hash  TEXT UNIQUE NOT NULL,         -- sha256 of the token given to the client
    client_ip   TEXT DEFAULT '',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at  INTEGER NOT NULL,             -- unix epoch seconds
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_session_hash ON sessions(token_hash);

CREATE TABLE IF NOT EXISTS api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL,
    name         TEXT DEFAULT '',
    prefix       TEXT NOT NULL,               -- e.g. csk_ab12cd34 (safe to display)
    key_hash     TEXT UNIQUE NOT NULL,        -- sha256 of the full key
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_apikey_hash ON api_keys(key_hash);

CREATE TABLE IF NOT EXISTS files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    name        TEXT NOT NULL,                -- original filename shown to the user
    mime        TEXT DEFAULT 'application/octet-stream',
    size        INTEGER DEFAULT 0,
    storage_key TEXT NOT NULL,                -- opaque blob name under STORAGE_DIR/<user_id>/
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_files_user ON files(user_id);

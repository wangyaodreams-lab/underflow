-- Underflow initial schema (SQLite).
-- Timestamps are stored as unix nanoseconds (INTEGER) for driver portability.
-- All ciphertext columns are BLOB and opaque to the server.

CREATE TABLE IF NOT EXISTS users (
    id          TEXT    PRIMARY KEY,
    email       TEXT    NOT NULL UNIQUE,
    kdf_id      INTEGER NOT NULL,
    kdf_m       INTEGER NOT NULL,
    kdf_t       INTEGER NOT NULL,
    kdf_p       INTEGER NOT NULL,
    kdf_salt    BLOB    NOT NULL,
    verifier    BLOB    NOT NULL,
    created_at  INTEGER NOT NULL,
    disabled    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vaults (
    id                  TEXT    PRIMARY KEY,
    owner_id            TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name_enc            BLOB    NOT NULL,
    protected_vault_key BLOB    NOT NULL,
    alg                 INTEGER NOT NULL,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL,
    revision            INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_vaults_owner ON vaults(owner_id);

CREATE TABLE IF NOT EXISTS items (
    id          TEXT    PRIMARY KEY,
    vault_id    TEXT    NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    revision    INTEGER NOT NULL,
    blob        BLOB,
    deleted     INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_items_vault_revision ON items(vault_id, revision);

CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT    PRIMARY KEY,
    user_id      TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   BLOB    NOT NULL UNIQUE,
    device_label TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id       TEXT    PRIMARY KEY,
    user_id  TEXT,
    action   TEXT    NOT NULL,
    ip       TEXT    NOT NULL DEFAULT '',
    ua       TEXT    NOT NULL DEFAULT '',
    at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user_at ON audit_log(user_id, at);

-- Global monotonic revision counter used for incremental sync.
CREATE TABLE IF NOT EXISTS sync_counter (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    value INTEGER NOT NULL
);
INSERT OR IGNORE INTO sync_counter(id, value) VALUES (1, 0);

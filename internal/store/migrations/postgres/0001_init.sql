-- Underflow initial schema (PostgreSQL).
-- Timestamps are stored as unix nanoseconds (BIGINT) for driver portability.
-- All ciphertext columns are BYTEA and opaque to the server.

CREATE TABLE IF NOT EXISTS users (
    id          TEXT     PRIMARY KEY,
    email       TEXT     NOT NULL UNIQUE,
    kdf_id      SMALLINT NOT NULL,
    kdf_m       BIGINT   NOT NULL,
    kdf_t       BIGINT   NOT NULL,
    kdf_p       SMALLINT NOT NULL,
    kdf_salt    BYTEA    NOT NULL,
    verifier    BYTEA    NOT NULL,
    created_at  BIGINT   NOT NULL,
    disabled    BOOLEAN  NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS vaults (
    id                  TEXT     PRIMARY KEY,
    owner_id            TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name_enc            BYTEA    NOT NULL,
    protected_vault_key BYTEA    NOT NULL,
    alg                 SMALLINT NOT NULL,
    created_at          BIGINT   NOT NULL,
    updated_at          BIGINT   NOT NULL,
    revision            BIGINT   NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_vaults_owner ON vaults(owner_id);

CREATE TABLE IF NOT EXISTS items (
    id          TEXT     PRIMARY KEY,
    vault_id    TEXT     NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    revision    BIGINT   NOT NULL,
    blob        BYTEA,
    deleted     BOOLEAN  NOT NULL DEFAULT FALSE,
    updated_at  BIGINT   NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_items_vault_revision ON items(vault_id, revision);

CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT   PRIMARY KEY,
    user_id      TEXT   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   BYTEA  NOT NULL UNIQUE,
    device_label TEXT   NOT NULL DEFAULT '',
    created_at   BIGINT NOT NULL,
    expires_at   BIGINT NOT NULL,
    last_seen_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id       TEXT   PRIMARY KEY,
    user_id  TEXT,
    action   TEXT   NOT NULL,
    ip       TEXT   NOT NULL DEFAULT '',
    ua       TEXT   NOT NULL DEFAULT '',
    at       BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user_at ON audit_log(user_id, at);

-- Global monotonic revision counter used for incremental sync.
CREATE TABLE IF NOT EXISTS sync_counter (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    value BIGINT  NOT NULL
);
INSERT INTO sync_counter(id, value) VALUES (1, 0) ON CONFLICT (id) DO NOTHING;

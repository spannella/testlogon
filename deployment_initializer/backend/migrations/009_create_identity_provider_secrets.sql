CREATE TABLE IF NOT EXISTS identity_provider_secrets (
    secret_ref TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    secret_value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identity_provider_secrets_provider
    ON identity_provider_secrets(provider_id);

CREATE TABLE IF NOT EXISTS identity_provider_secret_audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id TEXT NOT NULL,
    secret_ref TEXT NOT NULL,
    action TEXT NOT NULL,
    actor_email TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identity_provider_secret_audit_events_provider
    ON identity_provider_secret_audit_events(provider_id);

CREATE INDEX IF NOT EXISTS idx_identity_provider_secret_audit_events_secret_ref
    ON identity_provider_secret_audit_events(secret_ref);

-- Rollback strategy (execute manually):
-- DROP INDEX IF EXISTS idx_identity_provider_secret_audit_events_secret_ref;
-- DROP INDEX IF EXISTS idx_identity_provider_secret_audit_events_provider;
-- DROP TABLE IF EXISTS identity_provider_secret_audit_events;
-- DROP INDEX IF EXISTS idx_identity_provider_secrets_provider;
-- DROP TABLE IF EXISTS identity_provider_secrets;

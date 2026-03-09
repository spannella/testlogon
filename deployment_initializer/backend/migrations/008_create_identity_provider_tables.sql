CREATE TABLE IF NOT EXISTS identity_providers (
    provider_id TEXT PRIMARY KEY,
    provider_type TEXT NOT NULL,
    issuer TEXT NOT NULL,
    metadata_url TEXT,
    client_id TEXT NOT NULL,
    secret_ref TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_provider_role_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id TEXT NOT NULL,
    external_group_or_claim TEXT NOT NULL,
    internal_role TEXT NOT NULL,
    priority INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(provider_id) REFERENCES identity_providers(provider_id) ON DELETE CASCADE,
    UNIQUE(provider_id, external_group_or_claim, internal_role)
);

CREATE TABLE IF NOT EXISTS external_identities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    external_subject TEXT NOT NULL,
    external_tenant TEXT NOT NULL,
    last_login_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(provider_id) REFERENCES identity_providers(provider_id) ON DELETE CASCADE,
    UNIQUE(provider_id, external_subject, external_tenant)
);

CREATE INDEX IF NOT EXISTS idx_identity_provider_role_mappings_provider
    ON identity_provider_role_mappings(provider_id);

CREATE INDEX IF NOT EXISTS idx_external_identities_provider_subject_tenant
    ON external_identities(provider_id, external_subject, external_tenant);

-- Rollback strategy (execute manually in reverse dependency order):
-- DROP INDEX IF EXISTS idx_external_identities_provider_subject_tenant;
-- DROP INDEX IF EXISTS idx_identity_provider_role_mappings_provider;
-- DROP TABLE IF EXISTS external_identities;
-- DROP TABLE IF EXISTS identity_provider_role_mappings;
-- DROP TABLE IF EXISTS identity_providers;

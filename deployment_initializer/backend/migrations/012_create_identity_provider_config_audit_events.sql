CREATE TABLE IF NOT EXISTS identity_provider_config_audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor_email TEXT NOT NULL,
    details TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(provider_id) REFERENCES identity_providers(provider_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_identity_provider_config_audit_provider
    ON identity_provider_config_audit_events(provider_id);

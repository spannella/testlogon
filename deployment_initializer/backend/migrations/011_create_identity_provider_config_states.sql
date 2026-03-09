CREATE TABLE IF NOT EXISTS identity_provider_config_states (
    provider_id TEXT PRIMARY KEY,
    config_status TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(provider_id) REFERENCES identity_providers(provider_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_identity_provider_config_states_status
    ON identity_provider_config_states(config_status);

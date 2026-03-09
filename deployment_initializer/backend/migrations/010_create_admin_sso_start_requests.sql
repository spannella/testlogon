CREATE TABLE IF NOT EXISTS admin_sso_start_requests (
    state_signature TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(provider_id) REFERENCES identity_providers(provider_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_admin_sso_start_requests_provider
    ON admin_sso_start_requests(provider_id);

CREATE INDEX IF NOT EXISTS idx_admin_sso_start_requests_expires
    ON admin_sso_start_requests(expires_at);

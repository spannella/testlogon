CREATE TABLE IF NOT EXISTS admin_sso_auth_audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id TEXT,
    auth_method TEXT NOT NULL,
    outcome TEXT NOT NULL,
    actor_email TEXT,
    external_subject TEXT,
    external_tenant TEXT,
    mapped_role TEXT,
    failure_reason TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(provider_id) REFERENCES identity_providers(provider_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_sso_auth_audit_provider
    ON admin_sso_auth_audit_events(provider_id);
CREATE INDEX IF NOT EXISTS idx_admin_sso_auth_audit_outcome
    ON admin_sso_auth_audit_events(outcome);
CREATE INDEX IF NOT EXISTS idx_admin_sso_auth_audit_created_at
    ON admin_sso_auth_audit_events(created_at);

CREATE TABLE IF NOT EXISTS session_audit_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    actor_email TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    action TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES deployment_sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_session_audit_entries_session ON session_audit_entries(session_id);

CREATE TABLE IF NOT EXISTS deploy_approval_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    actor_email TEXT NOT NULL,
    decision TEXT NOT NULL,
    comment TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES deployment_sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_deploy_approval_records_session ON deploy_approval_records(session_id);

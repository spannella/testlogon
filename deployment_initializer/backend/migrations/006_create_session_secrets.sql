CREATE TABLE IF NOT EXISTS session_secrets (
    session_id TEXT PRIMARY KEY,
    secrets_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES deployment_sessions(session_id)
);

CREATE TABLE IF NOT EXISTS deployment_sessions (
    session_id TEXT PRIMARY KEY,
    env TEXT NOT NULL,
    region TEXT NOT NULL,
    created_by TEXT NOT NULL,
    config_json TEXT NOT NULL,
    status TEXT NOT NULL,
    execution_mode TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_deployment_sessions_env ON deployment_sessions(env);
CREATE INDEX IF NOT EXISTS idx_deployment_sessions_status ON deployment_sessions(status);

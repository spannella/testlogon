CREATE TABLE IF NOT EXISTS deploy_idempotency_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES deployment_sessions(session_id),
    UNIQUE(session_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_deploy_idempotency_session ON deploy_idempotency_records(session_id);

CREATE TABLE IF NOT EXISTS deploy_environment_locks (
    env TEXT NOT NULL,
    region TEXT NOT NULL,
    session_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    locked_at TEXT NOT NULL,
    PRIMARY KEY (env, region)
);

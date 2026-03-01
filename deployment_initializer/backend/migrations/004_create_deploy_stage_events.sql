CREATE TABLE IF NOT EXISTS deploy_stage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES deployment_sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_deploy_stage_events_session ON deploy_stage_events(session_id);
CREATE INDEX IF NOT EXISTS idx_deploy_stage_events_run ON deploy_stage_events(run_id);

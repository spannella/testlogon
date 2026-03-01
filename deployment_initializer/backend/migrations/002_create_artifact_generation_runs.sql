CREATE TABLE IF NOT EXISTS artifact_generation_runs (
    run_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    artifacts_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES deployment_sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_artifact_generation_runs_session ON artifact_generation_runs(session_id);
CREATE INDEX IF NOT EXISTS idx_artifact_generation_runs_created_at ON artifact_generation_runs(created_at);

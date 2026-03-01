CREATE TABLE IF NOT EXISTS artifact_objects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    hash TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES deployment_sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_artifact_objects_session ON artifact_objects(session_id);
CREATE INDEX IF NOT EXISTS idx_artifact_objects_run ON artifact_objects(run_id);

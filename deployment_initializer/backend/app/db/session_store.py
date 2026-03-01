from __future__ import annotations

import os
from functools import lru_cache

from app.services.sessions import SqliteSessionStore


@lru_cache(maxsize=1)
def get_session_store() -> SqliteSessionStore:
    db_path = os.getenv('DEPLOYMENT_SESSIONS_DB_PATH', 'deployment_initializer/backend/deployment_initializer.db')
    store = SqliteSessionStore(db_path=db_path)
    store.migrate()
    return store

from __future__ import annotations

import json
import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime, timezone


class SecretStore(ABC):
    @abstractmethod
    def put_session_secrets(self, session_id: str, secrets: dict[str, str]) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_session_secrets(self, session_id: str) -> dict[str, str]:
        raise NotImplementedError


class SqliteSecretStore(SecretStore):
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def put_session_secrets(self, session_id: str, secrets: dict[str, str]) -> None:
        with self._connect() as conn:
            conn.execute(
                '''
                INSERT OR REPLACE INTO session_secrets (
                    session_id, secrets_json, updated_at
                ) VALUES (?, ?, ?)
                ''',
                (session_id, json.dumps(secrets, sort_keys=True), datetime.now(tz=timezone.utc).isoformat()),
            )

    def get_session_secrets(self, session_id: str) -> dict[str, str]:
        with self._connect() as conn:
            row = conn.execute(
                '''
                SELECT secrets_json
                FROM session_secrets
                WHERE session_id = ?
                LIMIT 1
                ''',
                (session_id,),
            ).fetchone()
        if row is None:
            return {}
        return json.loads(row['secrets_json'])

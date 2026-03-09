from __future__ import annotations

import json
import re
import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime, timezone


SECRET_REF_PATTERN = re.compile(r'^secret://[a-zA-Z0-9._/-]+$')


class SecretStore(ABC):
    @abstractmethod
    def put_session_secrets(self, session_id: str, secrets: dict[str, str]) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_session_secrets(self, session_id: str) -> dict[str, str]:
        raise NotImplementedError

    @abstractmethod
    def put_identity_provider_secret(
        self,
        provider_id: str,
        secret_ref: str,
        secret_value: str,
        actor_email: str,
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def rotate_identity_provider_secret(
        self,
        provider_id: str,
        secret_ref: str,
        secret_value: str,
        actor_email: str,
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_identity_provider_secret(self, provider_id: str, secret_ref: str, actor_email: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def validate_identity_provider_secret_ref(self, secret_ref: str, require_exists: bool = True) -> None:
        raise NotImplementedError


class SqliteSecretStore(SecretStore):
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON;')
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

    def put_identity_provider_secret(
        self,
        provider_id: str,
        secret_ref: str,
        secret_value: str,
        actor_email: str,
    ) -> None:
        self._write_identity_provider_secret(
            provider_id=provider_id,
            secret_ref=secret_ref,
            secret_value=secret_value,
            actor_email=actor_email,
            action='write',
        )

    def rotate_identity_provider_secret(
        self,
        provider_id: str,
        secret_ref: str,
        secret_value: str,
        actor_email: str,
    ) -> None:
        self._write_identity_provider_secret(
            provider_id=provider_id,
            secret_ref=secret_ref,
            secret_value=secret_value,
            actor_email=actor_email,
            action='rotate',
        )

    def _write_identity_provider_secret(
        self,
        provider_id: str,
        secret_ref: str,
        secret_value: str,
        actor_email: str,
        action: str,
    ) -> None:
        if not secret_value:
            raise ValueError('idp_secret_value_required')
        self.validate_identity_provider_secret_ref(secret_ref, require_exists=False)

        now = datetime.now(tz=timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                '''
                INSERT INTO identity_provider_secrets (
                    provider_id, secret_ref, secret_value, updated_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(secret_ref)
                DO UPDATE SET
                    provider_id = excluded.provider_id,
                    secret_value = excluded.secret_value,
                    updated_at = excluded.updated_at
                ''',
                (provider_id, secret_ref, secret_value, now),
            )
            conn.execute(
                '''
                INSERT INTO identity_provider_secret_audit_events (
                    provider_id, secret_ref, action, actor_email, created_at
                ) VALUES (?, ?, ?, ?, ?)
                ''',
                (provider_id, secret_ref, action, actor_email, now),
            )

    def get_identity_provider_secret(self, provider_id: str, secret_ref: str, actor_email: str) -> str:
        self.validate_identity_provider_secret_ref(secret_ref, require_exists=True)
        with self._connect() as conn:
            row = conn.execute(
                '''
                SELECT secret_value
                FROM identity_provider_secrets
                WHERE provider_id = ? AND secret_ref = ?
                LIMIT 1
                ''',
                (provider_id, secret_ref),
            ).fetchone()
            if row is None:
                raise ValueError('secret_ref_not_found')

            conn.execute(
                '''
                INSERT INTO identity_provider_secret_audit_events (
                    provider_id, secret_ref, action, actor_email, created_at
                ) VALUES (?, ?, ?, ?, ?)
                ''',
                (provider_id, secret_ref, 'read', actor_email, datetime.now(tz=timezone.utc).isoformat()),
            )
        return str(row['secret_value'])

    def validate_identity_provider_secret_ref(self, secret_ref: str, require_exists: bool = True) -> None:
        if not secret_ref or not SECRET_REF_PATTERN.match(secret_ref):
            raise ValueError('invalid_secret_ref_format')

        if not require_exists:
            return

        with self._connect() as conn:
            row = conn.execute(
                '''
                SELECT 1
                FROM identity_provider_secrets
                WHERE secret_ref = ?
                LIMIT 1
                ''',
                (secret_ref,),
            ).fetchone()
        if row is None:
            raise ValueError('secret_ref_not_found')

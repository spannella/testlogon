from __future__ import annotations

import json
import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException
from app.services.secret_store import SecretStore, SqliteSecretStore

from app.models import (
    ApprovalDecision,
    ApprovalRecord,
    AuditEntry,
    DeployEvent,
    DeployResponse,
    ExternalIdentity,
    DeploymentSession,
    DeploymentSessionCreate,
    DeploymentSessionUpdate,
    ExecutionMode,
    IdentityProvider,
    IdentityProviderRoleMapping,
    ArtifactRecord,
    GeneratedArtifact,
    SessionEvent,
    SessionMetadata,
    SessionStatus,
)


ALLOWED_STATUS_TRANSITIONS: dict[SessionStatus, set[SessionStatus]] = {
    SessionStatus.DRAFT: {SessionStatus.VALIDATED, SessionStatus.FAILED},
    SessionStatus.VALIDATED: {SessionStatus.READY, SessionStatus.FAILED},
    SessionStatus.READY: {SessionStatus.DEPLOYING, SessionStatus.FAILED},
    SessionStatus.DEPLOYING: {SessionStatus.DEPLOYED, SessionStatus.FAILED},
    SessionStatus.DEPLOYED: set(),
    SessionStatus.FAILED: {SessionStatus.DRAFT, SessionStatus.VALIDATED},
}


class SessionStore(ABC):
    @abstractmethod
    def create(self, payload: DeploymentSessionCreate) -> DeploymentSession:
        raise NotImplementedError

    @abstractmethod
    def get(self, session_id: str) -> DeploymentSession:
        raise NotImplementedError

    @abstractmethod
    def update(self, session_id: str, payload: DeploymentSessionUpdate) -> DeploymentSession:
        raise NotImplementedError

    @abstractmethod
    def save_generation_run(self, session_id: str, run_id: str, artifacts: list[GeneratedArtifact]) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_latest_generation_run(self, session_id: str) -> list[GeneratedArtifact]:
        raise NotImplementedError

    @abstractmethod
    def save_artifact_records(self, records: list[ArtifactRecord]) -> None:
        raise NotImplementedError

    @abstractmethod
    def list_artifact_records(self, session_id: str) -> list[ArtifactRecord]:
        raise NotImplementedError

    @abstractmethod
    def get_artifact_record(self, session_id: str, run_id: str, artifact_name: str) -> ArtifactRecord:
        raise NotImplementedError

    @abstractmethod
    def save_deploy_events(self, session_id: str, run_id: str, events: list[DeployEvent]) -> None:
        raise NotImplementedError

    @abstractmethod
    def list_deploy_events(self, session_id: str, run_id: str) -> list[DeployEvent]:
        raise NotImplementedError

    @abstractmethod
    def list_all_deploy_events(self, session_id: str) -> list[DeployEvent]:
        raise NotImplementedError

    @abstractmethod
    def get_deploy_response_by_idempotency(self, session_id: str, idempotency_key: str) -> DeployResponse | None:
        raise NotImplementedError

    @abstractmethod
    def save_deploy_response_idempotency(self, session_id: str, idempotency_key: str, response: DeployResponse) -> None:
        raise NotImplementedError

    @abstractmethod
    def acquire_environment_lock(self, env: str, region: str, session_id: str, run_id: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def release_environment_lock(self, env: str, region: str, session_id: str, run_id: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def save_session_secrets(self, session_id: str, secrets: dict[str, str]) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_session_secrets(self, session_id: str) -> dict[str, str]:
        raise NotImplementedError

    @abstractmethod
    def add_audit_entry(
        self,
        session_id: str,
        actor_email: str,
        actor_role: str,
        action: str,
        details: dict[str, str] | None = None,
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def list_audit_entries(self, session_id: str) -> list[AuditEntry]:
        raise NotImplementedError

    @abstractmethod
    def add_approval_record(
        self,
        session_id: str,
        actor_email: str,
        decision: ApprovalDecision,
        comment: str | None = None,
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def list_approval_records(self, session_id: str) -> list[ApprovalRecord]:
        raise NotImplementedError

    @abstractmethod
    def list_session_events(self, session_id: str) -> list[SessionEvent]:
        raise NotImplementedError

    @abstractmethod
    def create_identity_provider(
        self,
        provider_id: str,
        provider_type: str,
        issuer: str,
        metadata_url: str | None,
        client_id: str,
        secret_ref: str,
        created_by: str,
        enabled: bool = False,
    ) -> IdentityProvider:
        raise NotImplementedError

    @abstractmethod
    def list_identity_providers(self) -> list[IdentityProvider]:
        raise NotImplementedError

    @abstractmethod
    def add_identity_provider_role_mapping(
        self,
        provider_id: str,
        external_group_or_claim: str,
        internal_role: str,
        priority: int,
    ) -> IdentityProviderRoleMapping:
        raise NotImplementedError

    @abstractmethod
    def list_identity_provider_role_mappings(self, provider_id: str) -> list[IdentityProviderRoleMapping]:
        raise NotImplementedError

    @abstractmethod
    def upsert_external_identity(
        self,
        user_id: str,
        provider_id: str,
        external_subject: str,
        external_tenant: str,
    ) -> ExternalIdentity:
        raise NotImplementedError

    @abstractmethod
    def get_identity_provider(self, provider_id: str) -> IdentityProvider:
        raise NotImplementedError

    @abstractmethod
    def create_admin_sso_start_request(
        self,
        provider_id: str,
        state_signature: str,
        nonce: str,
        expires_at: datetime,
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def consume_admin_sso_start_request(self, state_signature: str, now: datetime | None = None) -> dict[str, str]:
        raise NotImplementedError

    @abstractmethod
    def get_identity_provider_client_secret(self, provider_id: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def update_identity_provider(
        self,
        provider_id: str,
        provider_type: str,
        issuer: str,
        metadata_url: str | None,
        client_id: str,
        secret_ref: str,
        updated_by: str,
    ) -> IdentityProvider:
        raise NotImplementedError

    @abstractmethod
    def delete_identity_provider(self, provider_id: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_identity_provider_config_status(self, provider_id: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def set_identity_provider_config_status(self, provider_id: str, status: str, updated_by: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def delete_identity_provider_role_mapping(self, provider_id: str, mapping_id: int) -> None:
        raise NotImplementedError

    @abstractmethod
    def add_identity_provider_config_audit_event(
        self,
        provider_id: str,
        action: str,
        actor_email: str,
        details: str,
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def rollback_identity_provider_configs(self, actor_email: str) -> int:
        raise NotImplementedError

    @abstractmethod
    def add_admin_sso_auth_audit_event(
        self,
        auth_method: str,
        outcome: str,
        actor_email: str | None,
        provider_id: str | None = None,
        external_subject: str | None = None,
        external_tenant: str | None = None,
        mapped_role: str | None = None,
        failure_reason: str | None = None,
    ) -> None:
        raise NotImplementedError


class SqliteSessionStore(SessionStore):
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._secret_store: SecretStore = SqliteSecretStore(db_path=db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON;')
        return conn

    def migrate(self) -> None:
        migrations_dir = Path(__file__).resolve().parents[2] / 'migrations'
        migration_files = sorted(migrations_dir.glob('*.sql'))
        with self._connect() as conn:
            for migration_file in migration_files:
                conn.executescript(migration_file.read_text())

    def create(self, payload: DeploymentSessionCreate) -> DeploymentSession:
        now = datetime.now(tz=timezone.utc).isoformat()
        session_id = _new_session_id()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO deployment_sessions (
                    session_id, env, region, created_by, config_json, status, execution_mode, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    payload.metadata.env,
                    payload.metadata.region,
                    payload.metadata.created_by,
                    json.dumps(payload.config.model_dump(mode='json')),
                    SessionStatus.DRAFT.value,
                    payload.execution_mode.value,
                    now,
                    now,
                ),
            )
        self.save_session_secrets(session_id, payload.config.required_secrets.model_dump(mode='json'))
        return self.get(session_id)

    def get(self, session_id: str) -> DeploymentSession:
        with self._connect() as conn:
            row = conn.execute(
                'SELECT * FROM deployment_sessions WHERE session_id = ?',
                (session_id,),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='session_not_found')
        return _row_to_session(row)

    def update(self, session_id: str, payload: DeploymentSessionUpdate) -> DeploymentSession:
        current = self.get(session_id)

        next_status = payload.status or current.status
        if payload.status is not None and payload.status != current.status:
            allowed = ALLOWED_STATUS_TRANSITIONS[current.status]
            if payload.status not in allowed:
                raise HTTPException(
                    status_code=400,
                    detail=f'invalid_status_transition:{current.status.value}->{payload.status.value}',
                )

        metadata = payload.metadata or current.metadata
        config = payload.config if payload.config is not None else current.config
        execution_mode = payload.execution_mode or current.execution_mode
        now = datetime.now(tz=timezone.utc).isoformat()

        with self._connect() as conn:
            conn.execute(
                """
                UPDATE deployment_sessions
                SET env = ?, region = ?, created_by = ?, config_json = ?, status = ?, execution_mode = ?, updated_at = ?
                WHERE session_id = ?
                """,
                (
                    metadata.env,
                    metadata.region,
                    metadata.created_by,
                    json.dumps(config.model_dump(mode='json')),
                    next_status.value,
                    execution_mode.value,
                    now,
                    session_id,
                ),
            )

        if payload.config is not None:
            self.save_session_secrets(session_id, payload.config.required_secrets.model_dump(mode='json'))

        return self.get(session_id)

    def save_generation_run(self, session_id: str, run_id: str, artifacts: list[GeneratedArtifact]) -> None:
        created_at = datetime.now(tz=timezone.utc).isoformat()
        artifacts_json = json.dumps([a.model_dump(mode='json') for a in artifacts], sort_keys=True)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO artifact_generation_runs (run_id, session_id, artifacts_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (run_id, session_id, artifacts_json, created_at),
            )

    def get_latest_generation_run(self, session_id: str) -> list[GeneratedArtifact]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT artifacts_json
                FROM artifact_generation_runs
                WHERE session_id = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (session_id,),
            ).fetchone()

        if row is None:
            return []

        payload = json.loads(row['artifacts_json'])
        return [GeneratedArtifact.model_validate(item) for item in payload]


    def save_artifact_records(self, records: list[ArtifactRecord]) -> None:
        created_at = datetime.now(tz=timezone.utc).isoformat()
        with self._connect() as conn:
            for record in records:
                conn.execute(
                    """
                    INSERT INTO artifact_objects (
                        run_id, session_id, name, version, hash, generated_at, storage_key, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.run_id,
                        record.session_id,
                        record.name,
                        record.version,
                        record.hash,
                        record.generated_at.isoformat(),
                        record.storage_key,
                        created_at,
                    ),
                )

    def list_artifact_records(self, session_id: str) -> list[ArtifactRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT run_id, session_id, name, version, hash, generated_at, storage_key
                FROM artifact_objects
                WHERE session_id = ?
                ORDER BY generated_at DESC, name ASC
                """,
                (session_id,),
            ).fetchall()

        return [
            ArtifactRecord(
                run_id=row['run_id'],
                session_id=row['session_id'],
                name=row['name'],
                version=row['version'],
                hash=row['hash'],
                generated_at=datetime.fromisoformat(row['generated_at']),
                storage_key=row['storage_key'],
            )
            for row in rows
        ]

    def get_artifact_record(self, session_id: str, run_id: str, artifact_name: str) -> ArtifactRecord:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT run_id, session_id, name, version, hash, generated_at, storage_key
                FROM artifact_objects
                WHERE session_id = ? AND run_id = ? AND name = ?
                LIMIT 1
                """,
                (session_id, run_id, artifact_name),
            ).fetchone()

        if row is None:
            raise HTTPException(status_code=404, detail='artifact_not_found')

        return ArtifactRecord(
            run_id=row['run_id'],
            session_id=row['session_id'],
            name=row['name'],
            version=row['version'],
            hash=row['hash'],
            generated_at=datetime.fromisoformat(row['generated_at']),
            storage_key=row['storage_key'],
        )

    def save_deploy_events(self, session_id: str, run_id: str, events: list[DeployEvent]) -> None:
        with self._connect() as conn:
            for event in events:
                conn.execute(
                    """
                    INSERT INTO deploy_stage_events (
                        session_id, run_id, stage, status, message, details_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        run_id,
                        event.stage,
                        event.status,
                        event.message,
                        json.dumps(event.details or {}, sort_keys=True),
                        event.created_at.isoformat(),
                    ),
                )

    def list_deploy_events(self, session_id: str, run_id: str) -> list[DeployEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT stage, status, message, details_json, created_at
                FROM deploy_stage_events
                WHERE session_id = ? AND run_id = ?
                ORDER BY id ASC
                """,
                (session_id, run_id),
            ).fetchall()

        return [
            DeployEvent(
                stage=row['stage'],
                status=row['status'],
                message=row['message'],
                details=json.loads(row['details_json']) or None,
                created_at=datetime.fromisoformat(row['created_at']),
            )
            for row in rows
        ]

    def list_all_deploy_events(self, session_id: str) -> list[DeployEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT stage, status, message, details_json, created_at
                FROM deploy_stage_events
                WHERE session_id = ?
                ORDER BY created_at ASC, id ASC
                """,
                (session_id,),
            ).fetchall()

        return [
            DeployEvent(
                stage=row['stage'],
                status=row['status'],
                message=row['message'],
                details=json.loads(row['details_json']) or None,
                created_at=datetime.fromisoformat(row['created_at']),
            )
            for row in rows
        ]

    def get_deploy_response_by_idempotency(self, session_id: str, idempotency_key: str) -> DeployResponse | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT response_json
                FROM deploy_idempotency_records
                WHERE session_id = ? AND idempotency_key = ?
                LIMIT 1
                """,
                (session_id, idempotency_key),
            ).fetchone()

        if row is None:
            return None
        return DeployResponse.model_validate(json.loads(row['response_json']))

    def save_deploy_response_idempotency(self, session_id: str, idempotency_key: str, response: DeployResponse) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO deploy_idempotency_records (
                    session_id, idempotency_key, response_json, created_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    session_id,
                    idempotency_key,
                    json.dumps(response.model_dump(mode='json'), sort_keys=True),
                    datetime.now(tz=timezone.utc).isoformat(),
                ),
            )

    def acquire_environment_lock(self, env: str, region: str, session_id: str, run_id: str) -> bool:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO deploy_environment_locks (
                        env, region, session_id, run_id, locked_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (env, region, session_id, run_id, datetime.now(tz=timezone.utc).isoformat()),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def release_environment_lock(self, env: str, region: str, session_id: str, run_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                DELETE FROM deploy_environment_locks
                WHERE env = ? AND region = ? AND session_id = ? AND run_id = ?
                """,
                (env, region, session_id, run_id),
            )

    def save_session_secrets(self, session_id: str, secrets: dict[str, str]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO session_secrets (
                    session_id, secrets_json, updated_at
                ) VALUES (?, ?, ?)
                """,
                (session_id, json.dumps(secrets, sort_keys=True), datetime.now(tz=timezone.utc).isoformat()),
            )

    def get_session_secrets(self, session_id: str) -> dict[str, str]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT secrets_json
                FROM session_secrets
                WHERE session_id = ?
                LIMIT 1
                """,
                (session_id,),
            ).fetchone()

        if row is None:
            return {}
        return json.loads(row['secrets_json'])

    def add_audit_entry(
        self,
        session_id: str,
        actor_email: str,
        actor_role: str,
        action: str,
        details: dict[str, str] | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO session_audit_entries (
                    session_id, actor_email, actor_role, action, details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    actor_email,
                    actor_role,
                    action,
                    json.dumps(details or {}, sort_keys=True),
                    datetime.now(tz=timezone.utc).isoformat(),
                ),
            )

    def list_audit_entries(self, session_id: str) -> list[AuditEntry]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT session_id, actor_email, actor_role, action, details_json, created_at
                FROM session_audit_entries
                WHERE session_id = ?
                ORDER BY id ASC
                """,
                (session_id,),
            ).fetchall()

        return [
            AuditEntry(
                session_id=row['session_id'],
                actor_email=row['actor_email'],
                actor_role=row['actor_role'],
                action=row['action'],
                details=json.loads(row['details_json']) or None,
                created_at=datetime.fromisoformat(row['created_at']),
            )
            for row in rows
        ]

    def add_approval_record(
        self,
        session_id: str,
        actor_email: str,
        decision: ApprovalDecision,
        comment: str | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO deploy_approval_records (
                    session_id, actor_email, decision, comment, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    actor_email,
                    decision.value,
                    comment,
                    datetime.now(tz=timezone.utc).isoformat(),
                ),
            )

    def list_approval_records(self, session_id: str) -> list[ApprovalRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT session_id, actor_email, decision, comment, created_at
                FROM deploy_approval_records
                WHERE session_id = ?
                ORDER BY id ASC
                """,
                (session_id,),
            ).fetchall()

        return [
            ApprovalRecord(
                session_id=row['session_id'],
                actor_email=row['actor_email'],
                decision=ApprovalDecision(row['decision']),
                comment=row['comment'],
                created_at=datetime.fromisoformat(row['created_at']),
            )
            for row in rows
        ]

    def list_session_events(self, session_id: str) -> list[SessionEvent]:
        audit_events = [
            SessionEvent(
                event_type='audit',
                created_at=entry.created_at,
                actor_email=entry.actor_email,
                message=entry.action,
                details=entry.details,
            )
            for entry in self.list_audit_entries(session_id)
        ]
        deploy_events = [
            SessionEvent(
                event_type='deploy_stage',
                created_at=entry.created_at,
                status=entry.status,
                message=entry.message,
                details=entry.details,
            )
            for entry in self.list_all_deploy_events(session_id)
        ]
        merged = audit_events + deploy_events
        merged.sort(key=lambda event: event.created_at)
        return merged

    def create_identity_provider(
        self,
        provider_id: str,
        provider_type: str,
        issuer: str,
        metadata_url: str | None,
        client_id: str,
        secret_ref: str,
        created_by: str,
        enabled: bool = False,
    ) -> IdentityProvider:
        try:
            self._secret_store.validate_identity_provider_secret_ref(secret_ref=secret_ref, require_exists=True)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        now = datetime.now(tz=timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO identity_providers (
                    provider_id, provider_type, issuer, metadata_url, client_id, secret_ref,
                    enabled, created_by, updated_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    provider_id,
                    provider_type,
                    issuer,
                    metadata_url,
                    client_id,
                    secret_ref,
                    1 if enabled else 0,
                    created_by,
                    created_by,
                    now,
                    now,
                ),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO identity_provider_config_states (
                    provider_id, config_status, updated_by, updated_at
                ) VALUES (?, 'draft', ?, ?)
                """,
                (provider_id, created_by, now),
            )
            row = conn.execute(
                """
                SELECT provider_id, provider_type, issuer, metadata_url, client_id, secret_ref,
                       enabled, created_by, updated_by, created_at, updated_at
                FROM identity_providers
                WHERE provider_id = ?
                """,
                (provider_id,),
            ).fetchone()

        if row is None:
            raise HTTPException(status_code=500, detail='identity_provider_create_failed')
        return _row_to_identity_provider(row)

    def list_identity_providers(self) -> list[IdentityProvider]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT provider_id, provider_type, issuer, metadata_url, client_id, secret_ref,
                       enabled, created_by, updated_by, created_at, updated_at
                FROM identity_providers
                ORDER BY provider_id ASC
                """
            ).fetchall()
        return [_row_to_identity_provider(row) for row in rows]

    def get_identity_provider(self, provider_id: str) -> IdentityProvider:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT provider_id, provider_type, issuer, metadata_url, client_id, secret_ref,
                       enabled, created_by, updated_by, created_at, updated_at
                FROM identity_providers
                WHERE provider_id = ?
                LIMIT 1
                """,
                (provider_id,),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='identity_provider_not_found')
        return _row_to_identity_provider(row)

    def add_identity_provider_role_mapping(
        self,
        provider_id: str,
        external_group_or_claim: str,
        internal_role: str,
        priority: int,
    ) -> IdentityProviderRoleMapping:
        created_at = datetime.now(tz=timezone.utc).isoformat()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO identity_provider_role_mappings (
                    provider_id, external_group_or_claim, internal_role, priority, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (provider_id, external_group_or_claim, internal_role, priority, created_at),
            )
            mapping_id = cursor.lastrowid
            row = conn.execute(
                """
                SELECT id, provider_id, external_group_or_claim, internal_role, priority, created_at
                FROM identity_provider_role_mappings
                WHERE id = ?
                """,
                (mapping_id,),
            ).fetchone()

        if row is None:
            raise HTTPException(status_code=500, detail='identity_provider_role_mapping_create_failed')
        return _row_to_identity_provider_role_mapping(row)

    def list_identity_provider_role_mappings(self, provider_id: str) -> list[IdentityProviderRoleMapping]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, provider_id, external_group_or_claim, internal_role, priority, created_at
                FROM identity_provider_role_mappings
                WHERE provider_id = ?
                ORDER BY priority ASC, id ASC
                """,
                (provider_id,),
            ).fetchall()
        return [_row_to_identity_provider_role_mapping(row) for row in rows]

    def upsert_external_identity(
        self,
        user_id: str,
        provider_id: str,
        external_subject: str,
        external_tenant: str,
    ) -> ExternalIdentity:
        now = datetime.now(tz=timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO external_identities (
                    user_id, provider_id, external_subject, external_tenant, last_login_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider_id, external_subject, external_tenant)
                DO UPDATE SET
                    user_id = excluded.user_id,
                    last_login_at = excluded.last_login_at,
                    updated_at = excluded.updated_at
                """,
                (user_id, provider_id, external_subject, external_tenant, now, now, now),
            )
            row = conn.execute(
                """
                SELECT id, user_id, provider_id, external_subject, external_tenant, last_login_at, created_at, updated_at
                FROM external_identities
                WHERE provider_id = ? AND external_subject = ? AND external_tenant = ?
                """,
                (provider_id, external_subject, external_tenant),
            ).fetchone()

        if row is None:
            raise HTTPException(status_code=500, detail='external_identity_upsert_failed')
        return _row_to_external_identity(row)

    def create_admin_sso_start_request(
        self,
        provider_id: str,
        state_signature: str,
        nonce: str,
        expires_at: datetime,
    ) -> None:
        now = datetime.now(tz=timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO admin_sso_start_requests (
                    state_signature, provider_id, nonce, expires_at, used_at, created_at
                ) VALUES (?, ?, ?, ?, NULL, ?)
                """,
                (state_signature, provider_id, nonce, expires_at.isoformat(), now),
            )

    def consume_admin_sso_start_request(self, state_signature: str, now: datetime | None = None) -> dict[str, str]:
        now_dt = now or datetime.now(tz=timezone.utc)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT state_signature, provider_id, nonce, expires_at, used_at
                FROM admin_sso_start_requests
                WHERE state_signature = ?
                LIMIT 1
                """,
                (state_signature,),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail='sso_state_not_found')

            if row['used_at'] is not None:
                raise HTTPException(status_code=400, detail='sso_state_already_used')

            if datetime.fromisoformat(row['expires_at']) < now_dt:
                raise HTTPException(status_code=400, detail='sso_state_expired')

            conn.execute(
                """
                UPDATE admin_sso_start_requests
                SET used_at = ?
                WHERE state_signature = ?
                """,
                (now_dt.isoformat(), state_signature),
            )

        return {
            'state_signature': row['state_signature'],
            'provider_id': row['provider_id'],
            'nonce': row['nonce'],
            'expires_at': row['expires_at'],
        }

    def get_identity_provider_client_secret(self, provider_id: str) -> str:
        provider = self.get_identity_provider(provider_id)
        try:
            return self._secret_store.get_identity_provider_secret(
                provider_id=provider_id,
                secret_ref=provider.secret_ref,
                actor_email='system:admin_sso_callback',
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    def update_identity_provider(
        self,
        provider_id: str,
        provider_type: str,
        issuer: str,
        metadata_url: str | None,
        client_id: str,
        secret_ref: str,
        updated_by: str,
    ) -> IdentityProvider:
        now = datetime.now(tz=timezone.utc).isoformat()
        with self._connect() as conn:
            updated = conn.execute(
                """
                UPDATE identity_providers
                SET provider_type = ?, issuer = ?, metadata_url = ?, client_id = ?, secret_ref = ?,
                    updated_by = ?, updated_at = ?
                WHERE provider_id = ?
                """,
                (provider_type, issuer, metadata_url, client_id, secret_ref, updated_by, now, provider_id),
            )
            if updated.rowcount == 0:
                raise HTTPException(status_code=404, detail='identity_provider_not_found')
        return self.get_identity_provider(provider_id)

    def delete_identity_provider(self, provider_id: str) -> None:
        with self._connect() as conn:
            deleted = conn.execute(
                "DELETE FROM identity_providers WHERE provider_id = ?",
                (provider_id,),
            )
            if deleted.rowcount == 0:
                raise HTTPException(status_code=404, detail='identity_provider_not_found')

    def get_identity_provider_config_status(self, provider_id: str) -> str:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT config_status
                FROM identity_provider_config_states
                WHERE provider_id = ?
                LIMIT 1
                """,
                (provider_id,),
            ).fetchone()
        if row is None:
            return 'draft'
        return str(row['config_status'])

    def set_identity_provider_config_status(self, provider_id: str, status: str, updated_by: str) -> None:
        now = datetime.now(tz=timezone.utc).isoformat()
        with self._connect() as conn:
            provider_row = conn.execute(
                "SELECT provider_id FROM identity_providers WHERE provider_id = ? LIMIT 1",
                (provider_id,),
            ).fetchone()
            if provider_row is None:
                raise HTTPException(status_code=404, detail='identity_provider_not_found')

            conn.execute(
                """
                INSERT OR REPLACE INTO identity_provider_config_states (
                    provider_id, config_status, updated_by, updated_at
                ) VALUES (?, ?, ?, ?)
                """,
                (provider_id, status, updated_by, now),
            )

            conn.execute(
                """
                UPDATE identity_providers
                SET enabled = ?, updated_by = ?, updated_at = ?
                WHERE provider_id = ?
                """,
                (1 if status == 'active' else 0, updated_by, now, provider_id),
            )

    def delete_identity_provider_role_mapping(self, provider_id: str, mapping_id: int) -> None:
        with self._connect() as conn:
            deleted = conn.execute(
                """
                DELETE FROM identity_provider_role_mappings
                WHERE provider_id = ? AND id = ?
                """,
                (provider_id, mapping_id),
            )
            if deleted.rowcount == 0:
                raise HTTPException(status_code=404, detail='identity_provider_role_mapping_not_found')

    def add_identity_provider_config_audit_event(
        self,
        provider_id: str,
        action: str,
        actor_email: str,
        details: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO identity_provider_config_audit_events (
                    provider_id, action, actor_email, details, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (provider_id, action, actor_email, details, datetime.now(tz=timezone.utc).isoformat()),
            )

    def add_admin_sso_auth_audit_event(
        self,
        auth_method: str,
        outcome: str,
        actor_email: str | None,
        provider_id: str | None = None,
        external_subject: str | None = None,
        external_tenant: str | None = None,
        mapped_role: str | None = None,
        failure_reason: str | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO admin_sso_auth_audit_events (
                    provider_id, auth_method, outcome, actor_email, external_subject, external_tenant,
                    mapped_role, failure_reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    provider_id,
                    auth_method,
                    outcome,
                    actor_email,
                    external_subject,
                    external_tenant,
                    mapped_role,
                    failure_reason,
                    datetime.now(tz=timezone.utc).isoformat(),
                ),
            )

    def rollback_identity_provider_configs(self, actor_email: str) -> int:
        now = datetime.now(tz=timezone.utc).isoformat()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT provider_id FROM identity_providers"
            ).fetchall()
            provider_ids = [str(row['provider_id']) for row in rows]

            conn.execute(
                "UPDATE identity_providers SET enabled = 0, updated_by = ?, updated_at = ?",
                (actor_email, now),
            )
            for provider_id in provider_ids:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO identity_provider_config_states (
                        provider_id, config_status, updated_by, updated_at
                    ) VALUES (?, 'draft', ?, ?)
                    """,
                    (provider_id, actor_email, now),
                )
                conn.execute(
                    """
                    INSERT INTO identity_provider_config_audit_events (
                        provider_id, action, actor_email, details, created_at
                    ) VALUES (?, 'rollback', ?, ?, ?)
                    """,
                    (provider_id, actor_email, 'sso_disabled_restore_local_only', now),
                )

        return len(provider_ids)


def _new_session_id() -> str:
    from uuid import uuid4

    return str(uuid4())


def _row_to_session(row: sqlite3.Row) -> DeploymentSession:
    return DeploymentSession(
        session_id=row['session_id'],
        metadata=SessionMetadata(
            env=row['env'],
            region=row['region'],
            created_by=row['created_by'],
        ),
        config=json.loads(row['config_json']),
        status=SessionStatus(row['status']),
        execution_mode=ExecutionMode(row['execution_mode']),
        created_at=datetime.fromisoformat(row['created_at']),
        updated_at=datetime.fromisoformat(row['updated_at']),
    )


def _row_to_identity_provider(row: sqlite3.Row) -> IdentityProvider:
    return IdentityProvider(
        provider_id=row['provider_id'],
        provider_type=row['provider_type'],
        issuer=row['issuer'],
        metadata_url=row['metadata_url'],
        client_id=row['client_id'],
        secret_ref=row['secret_ref'],
        enabled=bool(row['enabled']),
        created_by=row['created_by'],
        updated_by=row['updated_by'],
        created_at=datetime.fromisoformat(row['created_at']),
        updated_at=datetime.fromisoformat(row['updated_at']),
    )


def _row_to_identity_provider_role_mapping(row: sqlite3.Row) -> IdentityProviderRoleMapping:
    return IdentityProviderRoleMapping(
        mapping_id=row['id'],
        provider_id=row['provider_id'],
        external_group_or_claim=row['external_group_or_claim'],
        internal_role=row['internal_role'],
        priority=row['priority'],
        created_at=datetime.fromisoformat(row['created_at']),
    )


def _row_to_external_identity(row: sqlite3.Row) -> ExternalIdentity:
    return ExternalIdentity(
        identity_id=row['id'],
        user_id=row['user_id'],
        provider_id=row['provider_id'],
        external_subject=row['external_subject'],
        external_tenant=row['external_tenant'],
        last_login_at=datetime.fromisoformat(row['last_login_at']) if row['last_login_at'] else None,
        created_at=datetime.fromisoformat(row['created_at']),
        updated_at=datetime.fromisoformat(row['updated_at']),
    )

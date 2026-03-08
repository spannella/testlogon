from __future__ import annotations

import sqlite3
from pathlib import Path
import sys

import pytest
from fastapi import HTTPException

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.services.sessions import SqliteSessionStore
from app.services.secret_store import SqliteSecretStore


@pytest.fixture()
def store(tmp_path: Path) -> SqliteSessionStore:
    db_path = tmp_path / 'identity_providers.db'
    session_store = SqliteSessionStore(db_path=str(db_path))
    session_store.migrate()
    return session_store


def _put_idp_secret(store: SqliteSessionStore, provider_id: str, secret_ref: str) -> None:
    secret_store = SqliteSecretStore(db_path=store._db_path)  # noqa: SLF001 - helper for store-level integration tests
    secret_store.put_identity_provider_secret(
        provider_id=provider_id,
        secret_ref=secret_ref,
        secret_value='super-sensitive-secret-value',
        actor_email='root@example.com',
    )


def test_migration_creates_identity_provider_tables_and_indexes(store: SqliteSessionStore) -> None:
    with store._connect() as conn:  # noqa: SLF001 - migration structure verification
        tables = {
            row['name']
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        indexes = {
            row['name']
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            ).fetchall()
        }

    assert 'identity_providers' in tables
    assert 'identity_provider_role_mappings' in tables
    assert 'external_identities' in tables
    assert 'idx_identity_provider_role_mappings_provider' in indexes
    assert 'idx_external_identities_provider_subject_tenant' in indexes


def test_data_access_methods_create_mapping_and_upsert_external_identity(store: SqliteSessionStore) -> None:
    _put_idp_secret(store, provider_id='entra-primary', secret_ref='secret://identity/entra-primary')

    provider = store.create_identity_provider(
        provider_id='entra-primary',
        provider_type='oidc',
        issuer='https://login.microsoftonline.com/tenant/v2.0',
        metadata_url='https://login.microsoftonline.com/tenant/.well-known/openid-configuration',
        client_id='client-id-123',
        secret_ref='secret://identity/entra-primary',
        created_by='root@example.com',
        enabled=True,
    )

    assert provider.provider_id == 'entra-primary'
    assert provider.enabled is True

    mapping = store.add_identity_provider_role_mapping(
        provider_id='entra-primary',
        external_group_or_claim='group:directory-admins',
        internal_role='admin',
        priority=10,
    )
    assert mapping.provider_id == 'entra-primary'
    assert mapping.internal_role == 'admin'

    identity = store.upsert_external_identity(
        user_id='u-001',
        provider_id='entra-primary',
        external_subject='subject-abc',
        external_tenant='tenant-001',
    )
    assert identity.user_id == 'u-001'

    updated = store.upsert_external_identity(
        user_id='u-002',
        provider_id='entra-primary',
        external_subject='subject-abc',
        external_tenant='tenant-001',
    )
    assert updated.identity_id == identity.identity_id
    assert updated.user_id == 'u-002'


def test_uniqueness_and_foreign_keys_are_enforced(store: SqliteSessionStore) -> None:
    _put_idp_secret(store, provider_id='entra-primary', secret_ref='secret://identity/entra-primary')

    store.create_identity_provider(
        provider_id='entra-primary',
        provider_type='oidc',
        issuer='https://login.microsoftonline.com/tenant/v2.0',
        metadata_url=None,
        client_id='client-id-123',
        secret_ref='secret://identity/entra-primary',
        created_by='root@example.com',
    )

    with pytest.raises(sqlite3.IntegrityError):
        with store._connect() as conn:  # noqa: SLF001 - direct constraint verification
            conn.execute(
                """
                INSERT INTO external_identities (
                    user_id, provider_id, external_subject, external_tenant, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                ('u-001', 'missing-provider', 'subject-1', 'tenant-1', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'),
            )

    with store._connect() as conn:  # noqa: SLF001 - direct constraint verification
        conn.execute(
            """
            INSERT INTO external_identities (
                user_id, provider_id, external_subject, external_tenant, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            ('u-001', 'entra-primary', 'subject-1', 'tenant-1', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'),
        )

    with pytest.raises(sqlite3.IntegrityError):
        with store._connect() as conn:  # noqa: SLF001 - direct constraint verification
            conn.execute(
                """
                INSERT INTO external_identities (
                    user_id, provider_id, external_subject, external_tenant, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                ('u-002', 'entra-primary', 'subject-1', 'tenant-1', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'),
            )


def test_create_identity_provider_rejects_missing_or_invalid_secret_ref(store: SqliteSessionStore) -> None:
    with pytest.raises(HTTPException) as missing_exc:
        store.create_identity_provider(
            provider_id='entra-missing-ref',
            provider_type='oidc',
            issuer='https://login.microsoftonline.com/tenant/v2.0',
            metadata_url=None,
            client_id='client-id-123',
            secret_ref='secret://identity/not-provisioned',
            created_by='root@example.com',
        )
    assert 'secret_ref_not_found' in str(missing_exc.value)

    with pytest.raises(HTTPException) as invalid_exc:
        store.create_identity_provider(
            provider_id='entra-invalid-ref',
            provider_type='oidc',
            issuer='https://login.microsoftonline.com/tenant/v2.0',
            metadata_url=None,
            client_id='client-id-123',
            secret_ref='not-a-secret-ref',
            created_by='root@example.com',
        )
    assert 'invalid_secret_ref_format' in str(invalid_exc.value)


def test_idp_secret_value_not_persisted_in_identity_providers_table(store: SqliteSessionStore) -> None:
    secret_ref = 'secret://identity/entra-primary'
    _put_idp_secret(store, provider_id='entra-primary', secret_ref=secret_ref)

    store.create_identity_provider(
        provider_id='entra-primary',
        provider_type='oidc',
        issuer='https://login.microsoftonline.com/tenant/v2.0',
        metadata_url=None,
        client_id='client-id-123',
        secret_ref=secret_ref,
        created_by='root@example.com',
    )

    with store._connect() as conn:  # noqa: SLF001 - direct persistence verification
        row = conn.execute(
            "SELECT secret_ref, client_id, issuer FROM identity_providers WHERE provider_id = ?",
            ('entra-primary',),
        ).fetchone()

    assert row is not None
    assert row['secret_ref'] == secret_ref
    assert 'super-sensitive-secret-value' not in f"{row['secret_ref']} {row['client_id']} {row['issuer']}"


def test_secret_store_emits_audit_events_for_write_read_rotate(store: SqliteSessionStore) -> None:
    secret_store = SqliteSecretStore(db_path=store._db_path)  # noqa: SLF001 - integration verification
    ref = 'secret://identity/audit-provider'

    secret_store.put_identity_provider_secret(
        provider_id='audit-provider',
        secret_ref=ref,
        secret_value='first-secret',
        actor_email='root@example.com',
    )
    secret = secret_store.get_identity_provider_secret(
        provider_id='audit-provider',
        secret_ref=ref,
        actor_email='security@example.com',
    )
    assert secret == 'first-secret'

    secret_store.rotate_identity_provider_secret(
        provider_id='audit-provider',
        secret_ref=ref,
        secret_value='second-secret',
        actor_email='root@example.com',
    )

    with store._connect() as conn:  # noqa: SLF001 - audit verification
        actions = [
            row['action']
            for row in conn.execute(
                """
                SELECT action
                FROM identity_provider_secret_audit_events
                WHERE secret_ref = ?
                ORDER BY id ASC
                """,
                (ref,),
            ).fetchall()
        ]

    assert actions == ['write', 'read', 'rotate']


def test_manual_rollback_strategy_drops_identity_provider_tables(store: SqliteSessionStore) -> None:
    with store._connect() as conn:  # noqa: SLF001 - rollback verification
        conn.executescript(
            """
            DROP INDEX IF EXISTS idx_external_identities_provider_subject_tenant;
            DROP INDEX IF EXISTS idx_identity_provider_role_mappings_provider;
            DROP TABLE IF EXISTS external_identities;
            DROP TABLE IF EXISTS identity_provider_role_mappings;
            DROP TABLE IF EXISTS identity_providers;
            """
        )
        remaining = {
            row['name']
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }

    assert 'identity_providers' not in remaining
    assert 'identity_provider_role_mappings' not in remaining
    assert 'external_identities' not in remaining

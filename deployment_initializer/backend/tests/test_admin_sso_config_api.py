from __future__ import annotations

import os
from pathlib import Path
import sys

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

DB_PATH = '/tmp/deployment_initializer_admin_sso_config_api_test.db'
os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH
os.environ['ADMIN_SSO_ENFORCE_FOR_ADMINS'] = 'false'

from app.db.session_store import get_session_store
from app.main import app
from app.services.auth import issue_root_session_token
from app.services.secret_store import SqliteSecretStore


ROOT_HEADERS = {'Authorization': f'Bearer {issue_root_session_token("root@example.com")}' }
ADMIN_HEADERS = {'X-SSO-Email': 'admin@example.com', 'X-SSO-Role': 'admin'}


def _client(headers: dict[str, str]) -> TestClient:
    os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH
    get_session_store.cache_clear()
    db_path = Path(DB_PATH)
    if db_path.exists():
        db_path.unlink()
    return TestClient(app, headers=headers)


def _seed_secret(provider_id: str, secret_ref: str) -> None:
    store = get_session_store()
    store.migrate()
    secret_store = SqliteSecretStore(db_path=DB_PATH)
    secret_store.put_identity_provider_secret(
        provider_id=provider_id,
        secret_ref=secret_ref,
        secret_value='secret-value-1',
        actor_email='root@example.com',
    )


def test_non_root_cannot_create_provider_config() -> None:
    client = _client(headers=ADMIN_HEADERS)
    response = client.post(
        '/auth/admin/sso/providers',
        json={
            'provider_id': 'entra-1',
            'provider_type': 'oidc',
            'issuer': 'https://issuer.example.com',
            'client_id': 'client-1',
            'secret_ref': 'secret://identity/entra-1',
        },
    )
    assert response.status_code == 403


def test_root_can_crud_and_activate_validated_provider() -> None:
    client = _client(headers=ROOT_HEADERS)
    _seed_secret('entra-1', 'secret://identity/entra-1')

    created = client.post(
        '/auth/admin/sso/providers',
        json={
            'provider_id': 'entra-1',
            'provider_type': 'oidc',
            'issuer': 'https://issuer.example.com',
            'client_id': 'client-1',
            'secret_ref': 'secret://identity/entra-1',
        },
    )
    assert created.status_code == 200
    assert created.json()['config_status'] == 'draft'

    test_cfg = client.post('/auth/admin/sso/providers/entra-1/test-config')
    assert test_cfg.status_code == 200
    assert test_cfg.json()['status'] == 'ok'

    validated = client.post('/auth/admin/sso/providers/entra-1/validate')
    assert validated.status_code == 200
    assert validated.json()['config_status'] == 'validated'

    activated = client.post('/auth/admin/sso/providers/entra-1/activate')
    assert activated.status_code == 200
    assert activated.json()['config_status'] == 'active'
    assert activated.json()['provider']['enabled'] is True


def test_invalid_protocol_config_cannot_activate() -> None:
    client = _client(headers=ROOT_HEADERS)
    _seed_secret('saml-1', 'secret://identity/saml-1')

    created = client.post(
        '/auth/admin/sso/providers',
        json={
            'provider_id': 'saml-1',
            'provider_type': 'saml',
            'issuer': 'https://saml-idp.example.com',
            'client_id': 'unused-client',
            'secret_ref': 'secret://identity/saml-1',
        },
    )
    assert created.status_code == 200

    activate = client.post('/auth/admin/sso/providers/saml-1/activate')
    assert activate.status_code == 400
    assert activate.json()['detail'] == 'invalid_provider_metadata_url_required'


def test_activate_requires_prior_validate_even_when_config_is_valid() -> None:
    client = _client(headers=ROOT_HEADERS)
    _seed_secret('entra-3', 'secret://identity/entra-3')

    create_resp = client.post(
        '/auth/admin/sso/providers',
        json={
            'provider_id': 'entra-3',
            'provider_type': 'oidc',
            'issuer': 'https://issuer.example.com',
            'client_id': 'client-3',
            'secret_ref': 'secret://identity/entra-3',
        },
    )
    assert create_resp.status_code == 200

    activate_without_validate = client.post('/auth/admin/sso/providers/entra-3/activate')
    assert activate_without_validate.status_code == 400
    assert activate_without_validate.json()['detail'] == 'identity_provider_not_validated'


def test_role_mapping_crud_is_root_only() -> None:
    root_client = _client(headers=ROOT_HEADERS)
    _seed_secret('entra-2', 'secret://identity/entra-2')
    root_client.post(
        '/auth/admin/sso/providers',
        json={
            'provider_id': 'entra-2',
            'provider_type': 'oidc',
            'issuer': 'https://issuer.example.com',
            'client_id': 'client-2',
            'secret_ref': 'secret://identity/entra-2',
        },
    )

    added = root_client.post(
        '/auth/admin/sso/providers/entra-2/role-mappings',
        params={'external_group_or_claim': 'group-admins', 'internal_role': 'admin', 'priority': 10},
    )
    assert added.status_code == 200
    mapping_id = added.json()['mapping_id']

    admin_client = TestClient(app, headers=ADMIN_HEADERS)
    denied = admin_client.delete(f'/auth/admin/sso/providers/entra-2/role-mappings/{mapping_id}')
    assert denied.status_code == 403

    deleted = root_client.delete(f'/auth/admin/sso/providers/entra-2/role-mappings/{mapping_id}')
    assert deleted.status_code == 200


def test_rollback_disables_sso_and_is_auditable() -> None:
    client = _client(headers=ROOT_HEADERS)
    _seed_secret('entra-rb', 'secret://identity/entra-rb')

    created = client.post(
        '/auth/admin/sso/providers',
        json={
            'provider_id': 'entra-rb',
            'provider_type': 'oidc',
            'issuer': 'https://issuer.example.com',
            'client_id': 'client-rb',
            'secret_ref': 'secret://identity/entra-rb',
        },
    )
    assert created.status_code == 200
    assert created.json()['provider']['enabled'] is False

    assert client.post('/auth/admin/sso/providers/entra-rb/validate').status_code == 200
    activated = client.post('/auth/admin/sso/providers/entra-rb/activate')
    assert activated.status_code == 200
    assert activated.json()['provider']['enabled'] is True

    os.environ['ADMIN_SSO_ENFORCE_FOR_ADMINS'] = 'true'
    rollback = client.post('/auth/admin/sso/rollback')
    assert rollback.status_code == 200
    assert rollback.json()['status'] == 'rolled_back'

    provider_after = client.get('/auth/admin/sso/providers/entra-rb')
    assert provider_after.status_code == 200
    assert provider_after.json()['provider']['enabled'] is False
    assert provider_after.json()['config_status'] == 'draft'
    assert os.environ['ADMIN_SSO_ENFORCE_FOR_ADMINS'] == 'false'

    store = get_session_store()
    with store._connect() as conn:  # noqa: SLF001 - audit assertion
        rows = conn.execute(
            """
            SELECT action, details
            FROM identity_provider_config_audit_events
            WHERE provider_id = ?
            ORDER BY id ASC
            """,
            ('entra-rb',),
        ).fetchall()
    assert any(row['action'] == 'rollback' for row in rows)

def test_config_actions_emit_audit_records() -> None:
    client = _client(headers=ROOT_HEADERS)
    _seed_secret('entra-audit', 'secret://identity/entra-audit')

    create = client.post(
        '/auth/admin/sso/providers',
        json={
            'provider_id': 'entra-audit',
            'provider_type': 'oidc',
            'issuer': 'https://issuer.example.com',
            'client_id': 'client-audit',
            'secret_ref': 'secret://identity/entra-audit',
        },
    )
    assert create.status_code == 200

    update = client.put(
        '/auth/admin/sso/providers/entra-audit',
        json={'issuer': 'https://issuer-updated.example.com'},
    )
    assert update.status_code == 200

    assert client.post('/auth/admin/sso/providers/entra-audit/validate').status_code == 200
    assert client.post('/auth/admin/sso/providers/entra-audit/activate').status_code == 200
    assert client.post('/auth/admin/sso/providers/entra-audit/deactivate').status_code == 200

    store = get_session_store()
    with store._connect() as conn:  # noqa: SLF001 - direct audit assertion
        rows = conn.execute(
            """
            SELECT action
            FROM identity_provider_config_audit_events
            WHERE provider_id = ?
            ORDER BY id ASC
            """,
            ('entra-audit',),
        ).fetchall()

    actions = [row['action'] for row in rows]
    assert 'create' in actions
    assert 'update' in actions
    assert 'validate' in actions
    assert 'activate' in actions
    assert 'deactivate' in actions

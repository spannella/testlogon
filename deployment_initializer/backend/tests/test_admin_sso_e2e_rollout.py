from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

DB_PATH = '/tmp/deployment_initializer_admin_sso_e2e_rollout_test.db'
os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH
os.environ['ADMIN_SSO_STATE_SIGNING_KEY'] = 'e2e-rollout-signing-key'
os.environ['ADMIN_SSO_REDIRECT_URI'] = 'http://localhost:8000/auth/admin/sso/callback'
os.environ['ADMIN_SSO_SCOPE'] = 'openid profile email'
os.environ['ADMIN_SSO_STATE_TTL_SECONDS'] = '300'

from app.db.session_store import get_session_store
from app.main import app
from app.services.auth import issue_root_session_token
from app.services.secret_store import SqliteSecretStore


ROOT_HEADERS = {'Authorization': f'Bearer {issue_root_session_token("root@example.com")}' }


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def _make_id_token(
    *,
    secret: str,
    issuer: str,
    audience: str,
    nonce: str,
    exp: int,
    groups: list[str],
    sub: str = 'e2e-rollout-sub',
    email: str = 'admin@example.com',
    tid: str = 'tenant-rollout-1',
) -> str:
    header = {'alg': 'HS256', 'typ': 'JWT'}
    payload = {
        'iss': issuer,
        'aud': audience,
        'nonce': nonce,
        'exp': exp,
        'sub': sub,
        'email': email,
        'tid': tid,
        'groups': groups,
    }
    h = _b64url(json.dumps(header, separators=(',', ':')).encode())
    p = _b64url(json.dumps(payload, separators=(',', ':')).encode())
    sig = _b64url(hmac.new(secret.encode(), f'{h}.{p}'.encode(), hashlib.sha256).digest())
    return f'{h}.{p}.{sig}'


def _reset() -> tuple[TestClient, TestClient]:
    os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH
    get_session_store.cache_clear()
    db_path = Path(DB_PATH)
    if db_path.exists():
        db_path.unlink()
    root_client = TestClient(app, headers=ROOT_HEADERS)
    admin_client = TestClient(app, headers={'X-SSO-Email': 'admin@example.com', 'X-SSO-Role': 'admin'})
    return root_client, admin_client


def _seed_secret(provider_id: str, secret_ref: str, secret_value: str = 'rollout-secret') -> None:
    store = get_session_store()
    store.migrate()
    secret_store = SqliteSecretStore(db_path=DB_PATH)
    secret_store.put_identity_provider_secret(
        provider_id=provider_id,
        secret_ref=secret_ref,
        secret_value=secret_value,
        actor_email='root@example.com',
    )


def _configure_and_activate_provider(root_client: TestClient, provider_id: str) -> None:
    _seed_secret(provider_id, f'secret://identity/{provider_id}')

    created = root_client.post(
        '/auth/admin/sso/providers',
        json={
            'provider_id': provider_id,
            'provider_type': 'oidc',
            'issuer': 'https://issuer.example.com',
            'metadata_url': 'https://issuer.example.com/.well-known/openid-configuration',
            'client_id': 'client-id-rollout',
            'secret_ref': f'secret://identity/{provider_id}',
        },
    )
    assert created.status_code == 200

    mapping = root_client.post(
        f'/auth/admin/sso/providers/{provider_id}/role-mappings',
        params={
            'external_group_or_claim': 'group-admins',
            'internal_role': 'admin',
            'priority': 10,
        },
    )
    assert mapping.status_code == 200

    validated = root_client.post(f'/auth/admin/sso/providers/{provider_id}/validate')
    assert validated.status_code == 200

    activated = root_client.post(f'/auth/admin/sso/providers/{provider_id}/activate')
    assert activated.status_code == 200
    assert activated.json()['config_status'] == 'active'
    assert activated.json()['provider']['enabled'] is True


def test_e2e_rollout_root_configures_idp_admin_logs_in_and_role_is_enforced() -> None:
    root_client, admin_client = _reset()
    os.environ['ADMIN_SSO_ENFORCE_FOR_ADMINS'] = 'true'
    provider_id = 'entra-e2e-rollout'

    _configure_and_activate_provider(root_client, provider_id)

    # Non-SSO admin is blocked while enforcement flag is enabled.
    blocked = admin_client.get('/ops/metrics')
    assert blocked.status_code == 403
    assert blocked.json()['detail'] == 'forbidden_admin_sso_required'

    start = admin_client.get('/auth/admin/sso/start', params={'provider_id': provider_id}, follow_redirects=False)
    assert start.status_code == 302
    state = parse_qs(urlparse(start.headers['location']).query)['state'][0]
    nonce = parse_qs(urlparse(start.headers['location']).query)['nonce'][0]

    token = _make_id_token(
        secret='rollout-secret',
        issuer='https://issuer.example.com',
        audience='client-id-rollout',
        nonce=nonce,
        exp=int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
        groups=['group-admins'],
    )
    callback = admin_client.get('/auth/admin/sso/callback', params={'state': state, 'id_token': token})
    assert callback.status_code == 200
    assert callback.json()['session_role'] == 'admin'

    sso_session_token = callback.json()['session_token']
    sso_client = TestClient(app, headers={'Authorization': f'Bearer {sso_session_token}'})
    allowed = sso_client.get('/ops/metrics')
    assert allowed.status_code == 200


def test_e2e_rollout_rollback_disables_sso_and_restores_local_admin_path() -> None:
    root_client, admin_client = _reset()
    os.environ['ADMIN_SSO_ENFORCE_FOR_ADMINS'] = 'true'
    provider_id = 'entra-e2e-rollback'

    _configure_and_activate_provider(root_client, provider_id)

    rollback = root_client.post('/auth/admin/sso/rollback')
    assert rollback.status_code == 200
    assert rollback.json()['status'] == 'rolled_back'

    provider = root_client.get(f'/auth/admin/sso/providers/{provider_id}')
    assert provider.status_code == 200
    assert provider.json()['provider']['enabled'] is False
    assert provider.json()['config_status'] == 'draft'

    start = admin_client.get('/auth/admin/sso/start', params={'provider_id': provider_id}, follow_redirects=False)
    assert start.status_code == 400
    assert start.json()['detail'] == 'identity_provider_disabled'

    # rollback endpoint forces local-admin access mode by disabling enforcement
    assert os.environ['ADMIN_SSO_ENFORCE_FOR_ADMINS'] == 'false'
    local_admin_allowed = admin_client.get('/ops/metrics')
    assert local_admin_allowed.status_code == 200

from __future__ import annotations

import html
import os
import re
import sqlite3
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

DB_PATH = '/tmp/deployment_initializer_admin_sso_keycloak_rotation_test.db'
os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH
os.environ['ADMIN_SSO_STATE_SIGNING_KEY'] = 'keycloak-rotation-signing-key'
os.environ['ADMIN_SSO_REDIRECT_URI'] = 'http://localhost:8000/auth/admin/sso/callback'
os.environ['ADMIN_SSO_SCOPE'] = 'openid profile email'
os.environ['ADMIN_SSO_STATE_TTL_SECONDS'] = '300'
os.environ['ADMIN_SSO_JWKS_CACHE_TTL_SECONDS'] = '2'

from app.db.session_store import get_session_store
from app.main import app
from app.services import admin_sso as admin_sso_module
from app.services.auth import issue_root_session_token
from app.services.metrics import MetricsCollector
from app.services.secret_store import SqliteSecretStore


RUN_KEYCLOAK_ROTATION = os.getenv('RUN_LOCAL_KEYCLOAK_ROTATION', '0') == '1'
KEYCLOAK_BASE_URL = os.getenv('KEYCLOAK_BASE_URL', 'http://localhost:8081').rstrip('/')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'local-ad')
KEYCLOAK_ADMIN = os.getenv('KEYCLOAK_ADMIN', 'admin')
KEYCLOAK_ADMIN_PASSWORD = os.getenv('KEYCLOAK_ADMIN_PASSWORD', 'admin')
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'deployment-initializer-admin-sso')
KEYCLOAK_TEST_USER = os.getenv('KEYCLOAK_TEST_USER', 'admin@example.com')
KEYCLOAK_TEST_PASSWORD = os.getenv('KEYCLOAK_TEST_PASSWORD', 'DevAdmin123!')

ROOT_HEADERS = {'Authorization': f'Bearer {issue_root_session_token("root@example.com")}' }

pytestmark = pytest.mark.skipif(
    not RUN_KEYCLOAK_ROTATION,
    reason='Set RUN_LOCAL_KEYCLOAK_ROTATION=1 and run local-ad-sso-up.sh to execute Keycloak key-rotation integration test.',
)


def _reset_db() -> TestClient:
    os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH
    get_session_store.cache_clear()
    db_path = Path(DB_PATH)
    if db_path.exists():
        db_path.unlink()
    return TestClient(app, headers=ROOT_HEADERS)


def _keycloak_discovery() -> dict[str, str]:
    response = requests.get(
        f'{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration',
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def _keycloak_admin_access_token() -> str:
    response = requests.post(
        f'{KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token',
        data={
            'grant_type': 'password',
            'client_id': 'admin-cli',
            'username': KEYCLOAK_ADMIN,
            'password': KEYCLOAK_ADMIN_PASSWORD,
        },
        timeout=10,
    )
    response.raise_for_status()
    return response.json()['access_token']


def _keycloak_client_secret(admin_token: str) -> str:
    clients_response = requests.get(
        f'{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/clients',
        params={'clientId': KEYCLOAK_CLIENT_ID},
        headers={'Authorization': f'Bearer {admin_token}'},
        timeout=10,
    )
    clients_response.raise_for_status()
    clients = clients_response.json()
    assert clients, f'Keycloak client not found: {KEYCLOAK_CLIENT_ID}'
    client_internal_id = clients[0]['id']

    secret_response = requests.get(
        f'{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_internal_id}/client-secret',
        headers={'Authorization': f'Bearer {admin_token}'},
        timeout=10,
    )
    secret_response.raise_for_status()
    return secret_response.json()['value']


def _keycloak_active_signing_kid(admin_token: str) -> str:
    response = requests.get(
        f'{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/keys',
        headers={'Authorization': f'Bearer {admin_token}'},
        timeout=10,
    )
    response.raise_for_status()
    for key in response.json().get('keys', []):
        if key.get('type') == 'RSA' and key.get('status') == 'ACTIVE' and key.get('use') == 'SIG':
            kid = key.get('kid')
            if isinstance(kid, str) and kid:
                return kid
    raise AssertionError('active RSA signing key not found')


def _rotate_keycloak_signing_key(admin_token: str) -> tuple[str, str]:
    before = _keycloak_active_signing_kid(admin_token)

    create_response = requests.post(
        f'{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/components',
        headers={'Authorization': f'Bearer {admin_token}'},
        json={
            'name': f'rotation-test-{int(time.time())}',
            'providerId': 'rsa-generated',
            'providerType': 'org.keycloak.keys.KeyProvider',
            'parentId': KEYCLOAK_REALM,
            'config': {
                'enabled': ['true'],
                'active': ['true'],
                'priority': ['250'],
                'algorithm': ['RS256'],
            },
        },
        timeout=10,
    )
    assert create_response.status_code in (201, 204), create_response.text

    deadline = time.time() + 20
    after = before
    while time.time() < deadline:
        after = _keycloak_active_signing_kid(admin_token)
        if after != before:
            return before, after
        time.sleep(1)

    raise AssertionError('Key rotation did not change active signing kid in time')


def _keycloak_login_and_get_id_token(*, state: str, nonce: str, discovery: dict[str, str], client_secret: str) -> str:
    session = requests.Session()
    authorize_response = session.get(
        discovery['authorization_endpoint'],
        params={
            'client_id': KEYCLOAK_CLIENT_ID,
            'response_type': 'code',
            'scope': 'openid profile email',
            'redirect_uri': os.environ['ADMIN_SSO_REDIRECT_URI'],
            'state': state,
            'nonce': nonce,
        },
        timeout=15,
    )
    authorize_response.raise_for_status()

    action_match = re.search(r'action="([^"]+)"', authorize_response.text)
    assert action_match, 'Could not find login form action in Keycloak auth page.'
    action_url = html.unescape(action_match.group(1))

    login_response = session.post(
        action_url,
        data={
            'username': KEYCLOAK_TEST_USER,
            'password': KEYCLOAK_TEST_PASSWORD,
            'credentialId': '',
        },
        allow_redirects=False,
        timeout=15,
    )
    assert login_response.status_code in (302, 303), login_response.text

    query = parse_qs(urlparse(login_response.headers['location']).query)
    code = query['code'][0]

    token_response = requests.post(
        discovery['token_endpoint'],
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': os.environ['ADMIN_SSO_REDIRECT_URI'],
            'client_id': KEYCLOAK_CLIENT_ID,
            'client_secret': client_secret,
        },
        timeout=15,
    )
    token_response.raise_for_status()
    return token_response.json()['id_token']


def _create_and_activate_provider(root_client: TestClient, *, provider_id: str, issuer: str, metadata_url: str, client_secret: str) -> None:
    store = get_session_store()
    store.migrate()
    secret_store = SqliteSecretStore(db_path=DB_PATH)
    secret_ref = f'secret://identity/{provider_id}'
    secret_store.put_identity_provider_secret(
        provider_id=provider_id,
        secret_ref=secret_ref,
        secret_value=client_secret,
        actor_email='root@example.com',
    )

    created = root_client.post(
        '/auth/admin/sso/providers',
        json={
            'provider_id': provider_id,
            'provider_type': 'oidc',
            'issuer': issuer,
            'metadata_url': metadata_url,
            'client_id': KEYCLOAK_CLIENT_ID,
            'secret_ref': secret_ref,
        },
    )
    assert created.status_code == 200, created.text

    mapping = root_client.post(
        f'/auth/admin/sso/providers/{provider_id}/role-mappings',
        params={'external_group_or_claim': 'group-admins', 'internal_role': 'admin', 'priority': 10},
    )
    assert mapping.status_code == 200, mapping.text

    validated = root_client.post(f'/auth/admin/sso/providers/{provider_id}/validate')
    assert validated.status_code == 200, validated.text

    activated = root_client.post(f'/auth/admin/sso/providers/{provider_id}/activate')
    assert activated.status_code == 200, activated.text


def _start_state_nonce(root_client: TestClient, provider_id: str) -> tuple[str, str]:
    start = root_client.get('/auth/admin/sso/start', params={'provider_id': provider_id}, follow_redirects=False)
    assert start.status_code == 302
    query = parse_qs(urlparse(start.headers['location']).query)
    return query['state'][0], query['nonce'][0]


def _latest_audit_failure_reason() -> str:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT failure_reason
            FROM admin_sso_auth_audit_events
            WHERE outcome = 'failure'
            ORDER BY event_id DESC
            LIMIT 1
            """
        ).fetchone()
        assert row is not None
        return str(row['failure_reason'])
    finally:
        conn.close()


def test_key_rotation_stale_cache_failure_then_recovery_with_metrics_alerts() -> None:
    os.environ['ADMIN_SSO_CALLBACK_ERROR_ALERT_THRESHOLD'] = '1'
    os.environ['ADMIN_SSO_CALLBACK_ERROR_ALERT_WINDOW_MINUTES'] = '10'
    admin_sso_module.COLLECTOR = MetricsCollector()

    root_client = _reset_db()
    discovery = _keycloak_discovery()
    admin_token = _keycloak_admin_access_token()
    client_secret = _keycloak_client_secret(admin_token)

    provider_id = 'keycloak-rotation-drill'
    issuer = discovery['issuer']
    metadata_url = f'{issuer}/.well-known/openid-configuration'
    _create_and_activate_provider(
        root_client,
        provider_id=provider_id,
        issuer=issuer,
        metadata_url=metadata_url,
        client_secret=client_secret,
    )

    # Warm JWKS cache with an initial successful callback using current key.
    state1, nonce1 = _start_state_nonce(root_client, provider_id)
    token1 = _keycloak_login_and_get_id_token(state=state1, nonce=nonce1, discovery=discovery, client_secret=client_secret)
    ok1 = root_client.get('/auth/admin/sso/callback', params={'state': state1, 'id_token': token1})
    assert ok1.status_code == 200, ok1.text

    kid_before, kid_after = _rotate_keycloak_signing_key(admin_token)
    assert kid_before != kid_after

    # During stale cache interval, new key is not yet visible to cached JWKS client.
    state2, nonce2 = _start_state_nonce(root_client, provider_id)
    token2 = _keycloak_login_and_get_id_token(state=state2, nonce=nonce2, discovery=discovery, client_secret=client_secret)
    stale_failure = root_client.get('/auth/admin/sso/callback', params={'state': state2, 'id_token': token2})
    assert stale_failure.status_code == 400
    assert stale_failure.json()['detail'] == 'sso_callback_jwks_unreachable'

    failure_reason = _latest_audit_failure_reason()
    assert failure_reason == 'sso_callback_jwks_unreachable'

    snapshot = admin_sso_module.COLLECTOR.snapshot()
    assert snapshot['admin_sso_login_failure_total'] >= 1
    alert_codes = {alert['code'] for alert in snapshot['active_alerts']}
    assert 'admin_sso_callback_errors' in alert_codes

    # Recovery window: once JWKS cache TTL elapses, callbacks succeed again.
    time.sleep(3)
    state3, nonce3 = _start_state_nonce(root_client, provider_id)
    token3 = _keycloak_login_and_get_id_token(state=state3, nonce=nonce3, discovery=discovery, client_secret=client_secret)
    recovered = root_client.get('/auth/admin/sso/callback', params={'state': state3, 'id_token': token3})
    assert recovered.status_code == 200, recovered.text

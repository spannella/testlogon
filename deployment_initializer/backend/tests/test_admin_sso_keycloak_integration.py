from __future__ import annotations

import html
import os
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

DB_PATH = '/tmp/deployment_initializer_admin_sso_keycloak_integration_test.db'
os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH
os.environ['ADMIN_SSO_STATE_SIGNING_KEY'] = 'keycloak-integration-signing-key'
os.environ['ADMIN_SSO_REDIRECT_URI'] = 'http://localhost:8000/auth/admin/sso/callback'
os.environ['ADMIN_SSO_SCOPE'] = 'openid profile email'
os.environ['ADMIN_SSO_STATE_TTL_SECONDS'] = '300'

from app.db.session_store import get_session_store
from app.main import app
from app.services.auth import issue_root_session_token
from app.services.secret_store import SqliteSecretStore


RUN_KEYCLOAK_INTEGRATION = os.getenv('RUN_LOCAL_KEYCLOAK_INTEGRATION', '0') == '1'
KEYCLOAK_BASE_URL = os.getenv('KEYCLOAK_BASE_URL', 'http://localhost:8081').rstrip('/')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'local-ad')
KEYCLOAK_ADMIN = os.getenv('KEYCLOAK_ADMIN', 'admin')
KEYCLOAK_ADMIN_PASSWORD = os.getenv('KEYCLOAK_ADMIN_PASSWORD', 'admin')
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'deployment-initializer-admin-sso')
KEYCLOAK_TEST_USER = os.getenv('KEYCLOAK_TEST_USER', 'admin@example.com')
KEYCLOAK_TEST_PASSWORD = os.getenv('KEYCLOAK_TEST_PASSWORD', 'DevAdmin123!')

ROOT_HEADERS = {'Authorization': f'Bearer {issue_root_session_token("root@example.com")}' }


pytestmark = pytest.mark.skipif(
    not RUN_KEYCLOAK_INTEGRATION,
    reason='Set RUN_LOCAL_KEYCLOAK_INTEGRATION=1 and run local-ad-sso-up.sh to execute real Keycloak integration tests.',
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

    redirect_location = login_response.headers['location']
    parsed = urlparse(redirect_location)
    assert parsed.path == '/auth/admin/sso/callback'
    query = parse_qs(parsed.query)
    assert query['state'] == [state]
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

    create_response = root_client.post(
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
    assert create_response.status_code == 200, create_response.text

    mapping_response = root_client.post(
        f'/auth/admin/sso/providers/{provider_id}/role-mappings',
        params={
            'external_group_or_claim': 'group-admins',
            'internal_role': 'admin',
            'priority': 10,
        },
    )
    assert mapping_response.status_code == 200, mapping_response.text

    validate_response = root_client.post(f'/auth/admin/sso/providers/{provider_id}/validate')
    assert validate_response.status_code == 200, validate_response.text

    activate_response = root_client.post(f'/auth/admin/sso/providers/{provider_id}/activate')
    assert activate_response.status_code == 200, activate_response.text


def _start_state_and_nonce(root_client: TestClient, provider_id: str) -> tuple[str, str]:
    start_response = root_client.get('/auth/admin/sso/start', params={'provider_id': provider_id}, follow_redirects=False)
    assert start_response.status_code == 302
    parsed = urlparse(start_response.headers['location'])
    query = parse_qs(parsed.query)
    return query['state'][0], query['nonce'][0]


def test_keycloak_real_issuer_and_jwks_callback_flow() -> None:
    root_client = _reset_db()

    discovery = _keycloak_discovery()
    admin_token = _keycloak_admin_access_token()
    client_secret = _keycloak_client_secret(admin_token)

    provider_id = 'keycloak-real-jwks'
    issuer = discovery['issuer']
    metadata_url = f'{issuer}/.well-known/openid-configuration'

    _create_and_activate_provider(
        root_client,
        provider_id=provider_id,
        issuer=issuer,
        metadata_url=metadata_url,
        client_secret=client_secret,
    )

    state, nonce = _start_state_and_nonce(root_client, provider_id)
    id_token = _keycloak_login_and_get_id_token(
        state=state,
        nonce=nonce,
        discovery=discovery,
        client_secret=client_secret,
    )

    callback = root_client.get('/auth/admin/sso/callback', params={'state': state, 'id_token': id_token})
    assert callback.status_code == 200, callback.text
    body = callback.json()
    assert body['session_role'] == 'admin'
    assert body['identity']['email'] == KEYCLOAK_TEST_USER
    assert 'group-admins' in body['identity']['groups']


def test_keycloak_fail_closed_invalid_audience_nonce_and_signature() -> None:
    root_client = _reset_db()

    discovery = _keycloak_discovery()
    admin_token = _keycloak_admin_access_token()
    client_secret = _keycloak_client_secret(admin_token)
    issuer = discovery['issuer']
    metadata_url = f'{issuer}/.well-known/openid-configuration'

    _create_and_activate_provider(
        root_client,
        provider_id='keycloak-invalid-audience',
        issuer=issuer,
        metadata_url=metadata_url,
        client_secret=client_secret,
    )
    _create_and_activate_provider(
        root_client,
        provider_id='keycloak-invalid-issuer',
        issuer=f'{issuer}-wrong',
        metadata_url=metadata_url,
        client_secret=client_secret,
    )

    wrong_audience_provider = 'keycloak-invalid-audience'
    state_good, nonce_good = _start_state_and_nonce(root_client, wrong_audience_provider)
    good_token = _keycloak_login_and_get_id_token(
        state=state_good,
        nonce=nonce_good,
        discovery=discovery,
        client_secret=client_secret,
    )

    # audience failure
    bad_audience_update = root_client.put(
        f'/auth/admin/sso/providers/{wrong_audience_provider}',
        json={'client_id': 'different-client-id'},
    )
    assert bad_audience_update.status_code == 200
    bad_audience = root_client.get('/auth/admin/sso/callback', params={'state': state_good, 'id_token': good_token})
    assert bad_audience.status_code == 400
    assert bad_audience.json()['detail'] == 'sso_callback_invalid_audience'

    # issuer failure
    state_issuer, nonce_issuer = _start_state_and_nonce(root_client, 'keycloak-invalid-issuer')
    issuer_token = _keycloak_login_and_get_id_token(
        state=state_issuer,
        nonce=nonce_issuer,
        discovery=discovery,
        client_secret=client_secret,
    )
    bad_issuer = root_client.get('/auth/admin/sso/callback', params={'state': state_issuer, 'id_token': issuer_token})
    assert bad_issuer.status_code == 400
    assert bad_issuer.json()['detail'] == 'sso_callback_invalid_issuer'

    # nonce failure
    state_nonce_1, nonce_1 = _start_state_and_nonce(root_client, wrong_audience_provider)
    nonce_token = _keycloak_login_and_get_id_token(
        state=state_nonce_1,
        nonce=nonce_1,
        discovery=discovery,
        client_secret=client_secret,
    )
    state_nonce_2, _nonce_2 = _start_state_and_nonce(root_client, wrong_audience_provider)
    bad_nonce = root_client.get('/auth/admin/sso/callback', params={'state': state_nonce_2, 'id_token': nonce_token})
    assert bad_nonce.status_code == 400
    assert bad_nonce.json()['detail'] == 'sso_callback_invalid_nonce'

    # signature failure
    segments = nonce_token.split('.')
    assert len(segments) == 3
    tampered_signature = segments[2][:-1] + ('A' if segments[2][-1] != 'A' else 'B')
    tampered_token = f'{segments[0]}.{segments[1]}.{tampered_signature}'
    state_sig, _nonce_sig = _start_state_and_nonce(root_client, wrong_audience_provider)
    bad_signature = root_client.get('/auth/admin/sso/callback', params={'state': state_sig, 'id_token': tampered_token})
    assert bad_signature.status_code == 400
    assert bad_signature.json()['detail'] == 'sso_callback_invalid_signature'

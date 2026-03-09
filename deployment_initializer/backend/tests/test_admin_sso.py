from __future__ import annotations

import os
import json
import base64
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
import pytest
from fastapi import HTTPException

sys.path.append(str(Path(__file__).resolve().parents[1]))

DB_PATH = '/tmp/deployment_initializer_admin_sso_test.db'
os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH
os.environ['ADMIN_SSO_STATE_SIGNING_KEY'] = 'test-signing-key'
os.environ['ADMIN_SSO_REDIRECT_URI'] = 'http://localhost:8000/auth/admin/sso/callback'
os.environ['ADMIN_SSO_SCOPE'] = 'openid profile email'
os.environ['ADMIN_SSO_STATE_TTL_SECONDS'] = '300'

from app.db.session_store import get_session_store
from app.main import app
from app.services.secret_store import SqliteSecretStore
from app.services.auth import get_authenticated_principal


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def _make_id_token(
    *,
    secret: str,
    issuer: str,
    audience: str,
    nonce: str,
    exp: int,
    sub: str = 'user-sub-1',
    email: str = 'admin@example.com',
    tid: str = 'tenant-123',
    groups: list[str] | None = None,
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
        'groups': groups or ['group-admins'],
    }
    h = _b64url(json.dumps(header, separators=(',', ':')).encode())
    p = _b64url(json.dumps(payload, separators=(',', ':')).encode())
    sig = _b64url(hmac.new(secret.encode(), f'{h}.{p}'.encode(), hashlib.sha256).digest())
    return f'{h}.{p}.{sig}'


def _client() -> TestClient:
    os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH
    get_session_store.cache_clear()
    db_path = Path(DB_PATH)
    if db_path.exists():
        db_path.unlink()
    return TestClient(app)


def _provision_enabled_provider() -> None:
    os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH
    get_session_store.cache_clear()
    store = get_session_store()
    store.migrate()
    secret_store = SqliteSecretStore(db_path=DB_PATH)
    secret_store.put_identity_provider_secret(
        provider_id='entra-primary',
        secret_ref='secret://identity/entra-primary',
        secret_value='very-secret-value',
        actor_email='root@example.com',
    )
    store.create_identity_provider(
        provider_id='entra-primary',
        provider_type='oidc',
        issuer='https://issuer.example.com',
        metadata_url='https://issuer.example.com/.well-known/openid-configuration',
        client_id='client-id-123',
        secret_ref='secret://identity/entra-primary',
        created_by='root@example.com',
        enabled=True,
    )


def _add_mapping(provider_id: str, external_group_or_claim: str, internal_role: str, priority: int) -> None:
    os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH
    get_session_store.cache_clear()
    store = get_session_store()
    store.add_identity_provider_role_mapping(
        provider_id=provider_id,
        external_group_or_claim=external_group_or_claim,
        internal_role=internal_role,
        priority=priority,
    )


def test_admin_sso_start_redirects_and_persists_state_nonce() -> None:
    client = _client()
    _provision_enabled_provider()

    response = client.get('/auth/admin/sso/start', params={'provider_id': 'entra-primary'}, follow_redirects=False)
    assert response.status_code == 302

    location = response.headers['location']
    parsed = urlparse(location)
    params = parse_qs(parsed.query)

    assert parsed.scheme == 'https'
    assert parsed.netloc == 'issuer.example.com'
    assert parsed.path == '/authorize'
    assert params['client_id'] == ['client-id-123']
    assert params['response_type'] == ['code']
    assert params['redirect_uri'] == ['http://localhost:8000/auth/admin/sso/callback']
    assert params['scope'] == ['openid profile email']
    assert len(params['state'][0]) > 20
    assert len(params['nonce'][0]) > 10

    state = params['state'][0]
    consumed = get_session_store().consume_admin_sso_start_request(state)
    assert consumed['provider_id'] == 'entra-primary'


def test_admin_sso_start_rejects_disabled_or_misconfigured_provider() -> None:
    client = _client()
    os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH
    get_session_store.cache_clear()
    store = get_session_store()
    store.migrate()

    secret_store = SqliteSecretStore(db_path=DB_PATH)
    secret_store.put_identity_provider_secret(
        provider_id='disabled-provider',
        secret_ref='secret://identity/disabled-provider',
        secret_value='disabled-secret',
        actor_email='root@example.com',
    )
    store.create_identity_provider(
        provider_id='disabled-provider',
        provider_type='oidc',
        issuer='https://issuer.example.com',
        metadata_url=None,
        client_id='disabled-client',
        secret_ref='secret://identity/disabled-provider',
        created_by='root@example.com',
        enabled=False,
    )

    disabled = client.get('/auth/admin/sso/start', params={'provider_id': 'disabled-provider'}, follow_redirects=False)
    assert disabled.status_code == 400
    assert disabled.json()['detail'] == 'identity_provider_disabled'

    missing = client.get('/auth/admin/sso/start', params={'provider_id': 'does-not-exist'}, follow_redirects=False)
    assert missing.status_code == 404
    assert missing.json()['detail'] == 'identity_provider_not_found'


def test_sso_state_is_single_use_and_expires() -> None:
    _client()
    _provision_enabled_provider()
    os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH
    get_session_store.cache_clear()
    store = get_session_store()

    created_at = datetime.now(tz=timezone.utc) + timedelta(seconds=30)
    store.create_admin_sso_start_request(
        provider_id='entra-primary',
        state_signature='state-single-use',
        nonce='nonce-1',
        expires_at=created_at,
    )

    first = store.consume_admin_sso_start_request('state-single-use', now=datetime.now(tz=timezone.utc))
    assert first['nonce'] == 'nonce-1'

    with pytest.raises(HTTPException) as err:
        store.consume_admin_sso_start_request('state-single-use', now=datetime.now(tz=timezone.utc))
    assert 'sso_state_already_used' in str(err.value)

    store.create_admin_sso_start_request(
        provider_id='entra-primary',
        state_signature='state-expired',
        nonce='nonce-2',
        expires_at=datetime.now(tz=timezone.utc) - timedelta(seconds=1),
    )
    with pytest.raises(HTTPException) as expired_err:
        store.consume_admin_sso_start_request('state-expired', now=datetime.now(tz=timezone.utc))
    assert 'sso_state_expired' in str(expired_err.value)


def test_admin_sso_callback_valid_token_returns_normalized_identity() -> None:
    client = _client()
    _provision_enabled_provider()
    _add_mapping('entra-primary', 'group-admins', 'admin', 10)

    start = client.get('/auth/admin/sso/start', params={'provider_id': 'entra-primary'}, follow_redirects=False)
    state = parse_qs(urlparse(start.headers['location']).query)['state'][0]
    nonce = parse_qs(urlparse(start.headers['location']).query)['nonce'][0]

    id_token = _make_id_token(
        secret='very-secret-value',
        issuer='https://issuer.example.com',
        audience='client-id-123',
        nonce=nonce,
        exp=int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
    )

    callback = client.get('/auth/admin/sso/callback', params={'state': state, 'id_token': id_token})
    assert callback.status_code == 200
    body = callback.json()
    assert body['provider_id'] == 'entra-primary'
    assert body['auth_method'] == 'ad_sso'
    assert body['identity']['sub'] == 'user-sub-1'
    assert body['identity']['email'] == 'admin@example.com'
    assert body['identity']['tenant_id'] == 'tenant-123'
    assert body['identity']['groups'] == ['group-admins']
    assert body['session_role'] == 'admin'
    assert body['session_token'].startswith('sso:admin@example.com:admin:ad_sso')
    assert body['linked_user_id'] == 'admin@example.com'
    assert body['linked_external_identity_id'] > 0

    principal = get_authenticated_principal(authorization=f"Bearer {body['session_token']}")
    assert principal.email == 'admin@example.com'
    assert principal.role == 'admin'
    assert principal.provider == 'ad_sso'


def test_admin_sso_callback_rejects_invalid_or_expired_tokens() -> None:
    client = _client()
    _provision_enabled_provider()

    start1 = client.get('/auth/admin/sso/start', params={'provider_id': 'entra-primary'}, follow_redirects=False)
    state1 = parse_qs(urlparse(start1.headers['location']).query)['state'][0]
    nonce1 = parse_qs(urlparse(start1.headers['location']).query)['nonce'][0]
    bad_sig = _make_id_token(
        secret='wrong-secret',
        issuer='https://issuer.example.com',
        audience='client-id-123',
        nonce=nonce1,
        exp=int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
    )
    invalid_sig_response = client.get('/auth/admin/sso/callback', params={'state': state1, 'id_token': bad_sig})
    assert invalid_sig_response.status_code == 400
    assert invalid_sig_response.json()['detail'] == 'sso_callback_invalid_signature'

    start2 = client.get('/auth/admin/sso/start', params={'provider_id': 'entra-primary'}, follow_redirects=False)
    state2 = parse_qs(urlparse(start2.headers['location']).query)['state'][0]
    nonce2 = parse_qs(urlparse(start2.headers['location']).query)['nonce'][0]
    expired = _make_id_token(
        secret='very-secret-value',
        issuer='https://issuer.example.com',
        audience='client-id-123',
        nonce=nonce2,
        exp=int((datetime.now(tz=timezone.utc) - timedelta(minutes=5)).timestamp()),
    )
    expired_response = client.get('/auth/admin/sso/callback', params={'state': state2, 'id_token': expired})
    assert expired_response.status_code == 400
    assert expired_response.json()['detail'] == 'sso_callback_token_expired'

    start3 = client.get('/auth/admin/sso/start', params={'provider_id': 'entra-primary'}, follow_redirects=False)
    state3 = parse_qs(urlparse(start3.headers['location']).query)['state'][0]
    malformed = 'not-a-jwt'
    malformed_response = client.get('/auth/admin/sso/callback', params={'state': state3, 'id_token': malformed})
    assert malformed_response.status_code == 400
    assert malformed_response.json()['detail'] == 'sso_callback_malformed_token'


def test_repeated_login_reuses_linked_external_identity() -> None:
    client = _client()
    _provision_enabled_provider()
    _add_mapping('entra-primary', 'group-admins', 'admin', 10)

    start1 = client.get('/auth/admin/sso/start', params={'provider_id': 'entra-primary'}, follow_redirects=False)
    state1 = parse_qs(urlparse(start1.headers['location']).query)['state'][0]
    nonce1 = parse_qs(urlparse(start1.headers['location']).query)['nonce'][0]
    token1 = _make_id_token(
        secret='very-secret-value',
        issuer='https://issuer.example.com',
        audience='client-id-123',
        nonce=nonce1,
        exp=int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
        sub='repeat-user-sub',
        tid='repeat-tenant',
    )
    first = client.get('/auth/admin/sso/callback', params={'state': state1, 'id_token': token1})
    assert first.status_code == 200

    start2 = client.get('/auth/admin/sso/start', params={'provider_id': 'entra-primary'}, follow_redirects=False)
    state2 = parse_qs(urlparse(start2.headers['location']).query)['state'][0]
    nonce2 = parse_qs(urlparse(start2.headers['location']).query)['nonce'][0]
    token2 = _make_id_token(
        secret='very-secret-value',
        issuer='https://issuer.example.com',
        audience='client-id-123',
        nonce=nonce2,
        exp=int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
        sub='repeat-user-sub',
        tid='repeat-tenant',
    )
    second = client.get('/auth/admin/sso/callback', params={'state': state2, 'id_token': token2})
    assert second.status_code == 200

    first_body = first.json()
    second_body = second.json()
    assert first_body['linked_external_identity_id'] == second_body['linked_external_identity_id']
    assert first_body['linked_user_id'] == second_body['linked_user_id']


def test_unmapped_groups_are_denied_with_reason_code() -> None:
    client = _client()
    _provision_enabled_provider()
    _add_mapping('entra-primary', 'group-mapped', 'admin', 10)

    start = client.get('/auth/admin/sso/start', params={'provider_id': 'entra-primary'}, follow_redirects=False)
    state = parse_qs(urlparse(start.headers['location']).query)['state'][0]
    nonce = parse_qs(urlparse(start.headers['location']).query)['nonce'][0]
    token = _make_id_token(
        secret='very-secret-value',
        issuer='https://issuer.example.com',
        audience='client-id-123',
        nonce=nonce,
        exp=int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
        groups=['group-unmapped'],
    )
    response = client.get('/auth/admin/sso/callback', params={'state': state, 'id_token': token})
    assert response.status_code == 403
    assert response.json()['detail'] == 'sso_role_mapping_denied'


def test_role_mapping_precedence_and_simulation_endpoint() -> None:
    client = _client()
    _provision_enabled_provider()
    _add_mapping('entra-primary', 'group-low', 'operator', 20)
    _add_mapping('entra-primary', 'group-high', 'admin', 10)

    simulation = client.get(
        '/auth/admin/sso/simulate-role',
        params={'provider_id': 'entra-primary', 'groups': 'group-low,group-high'},
    )
    assert simulation.status_code == 200
    body = simulation.json()
    assert body['resolved_role'] == 'admin'
    assert body['reason_code'] == 'role_mapped'
    assert body['mapping_id'] is not None

    start = client.get('/auth/admin/sso/start', params={'provider_id': 'entra-primary'}, follow_redirects=False)
    state = parse_qs(urlparse(start.headers['location']).query)['state'][0]
    nonce = parse_qs(urlparse(start.headers['location']).query)['nonce'][0]
    token = _make_id_token(
        secret='very-secret-value',
        issuer='https://issuer.example.com',
        audience='client-id-123',
        nonce=nonce,
        exp=int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
        groups=['group-low', 'group-high'],
    )
    callback = client.get('/auth/admin/sso/callback', params={'state': state, 'id_token': token})
    assert callback.status_code == 200
    assert callback.json()['session_role'] == 'admin'


def test_external_root_role_mapping_is_always_rejected() -> None:
    client = _client()
    _provision_enabled_provider()
    _add_mapping('entra-primary', 'group-root', 'root', 1)

    simulation = client.get(
        '/auth/admin/sso/simulate-role',
        params={'provider_id': 'entra-primary', 'groups': 'group-root'},
    )
    assert simulation.status_code == 200
    assert simulation.json()['resolved_role'] is None
    assert simulation.json()['reason_code'] == 'sso_root_role_forbidden'

    start = client.get('/auth/admin/sso/start', params={'provider_id': 'entra-primary'}, follow_redirects=False)
    state = parse_qs(urlparse(start.headers['location']).query)['state'][0]
    nonce = parse_qs(urlparse(start.headers['location']).query)['nonce'][0]
    token = _make_id_token(
        secret='very-secret-value',
        issuer='https://issuer.example.com',
        audience='client-id-123',
        nonce=nonce,
        exp=int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
        groups=['group-root'],
    )
    callback = client.get('/auth/admin/sso/callback', params={'state': state, 'id_token': token})
    assert callback.status_code == 403
    assert callback.json()['detail'] == 'sso_root_role_forbidden'

def test_admin_sso_callback_success_emits_auth_audit_event() -> None:
    client = _client()
    _provision_enabled_provider()
    _add_mapping('entra-primary', 'group-admins', 'admin', 10)

    start = client.get('/auth/admin/sso/start', params={'provider_id': 'entra-primary'}, follow_redirects=False)
    state = parse_qs(urlparse(start.headers['location']).query)['state'][0]
    nonce = parse_qs(urlparse(start.headers['location']).query)['nonce'][0]

    id_token = _make_id_token(
        secret='very-secret-value',
        issuer='https://issuer.example.com',
        audience='client-id-123',
        nonce=nonce,
        exp=int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
    )
    response = client.get('/auth/admin/sso/callback', params={'state': state, 'id_token': id_token})
    assert response.status_code == 200

    store = get_session_store()
    with store._connect() as conn:  # noqa: SLF001 - direct audit assertion
        row = conn.execute(
            """
            SELECT outcome, auth_method, provider_id, actor_email, mapped_role, failure_reason
            FROM admin_sso_auth_audit_events
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    assert row is not None
    assert row['outcome'] == 'success'
    assert row['auth_method'] == 'ad_sso'
    assert row['provider_id'] == 'entra-primary'
    assert row['actor_email'] == 'admin@example.com'
    assert row['mapped_role'] == 'admin'
    assert row['failure_reason'] is None


def test_admin_sso_callback_failure_emits_auth_audit_event_with_reason() -> None:
    client = _client()
    _provision_enabled_provider()

    start = client.get('/auth/admin/sso/start', params={'provider_id': 'entra-primary'}, follow_redirects=False)
    state = parse_qs(urlparse(start.headers['location']).query)['state'][0]
    nonce = parse_qs(urlparse(start.headers['location']).query)['nonce'][0]

    id_token = _make_id_token(
        secret='wrong-secret',
        issuer='https://issuer.example.com',
        audience='client-id-123',
        nonce=nonce,
        exp=int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
    )
    response = client.get('/auth/admin/sso/callback', params={'state': state, 'id_token': id_token})
    assert response.status_code == 400
    assert response.json()['detail'] == 'sso_callback_invalid_signature'

    store = get_session_store()
    with store._connect() as conn:  # noqa: SLF001 - direct audit assertion
        row = conn.execute(
            """
            SELECT outcome, auth_method, provider_id, failure_reason
            FROM admin_sso_auth_audit_events
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    assert row is not None
    assert row['outcome'] == 'failure'
    assert row['auth_method'] == 'ad_sso'
    assert row['provider_id'] == 'entra-primary'
    assert row['failure_reason'] == 'sso_callback_invalid_signature'

@pytest.mark.parametrize(
    ('token_kwargs', 'expected_status', 'expected_detail'),
    [
        ({'issuer': 'https://issuer-bad.example.com'}, 400, 'sso_callback_invalid_issuer'),
        ({'audience': 'bad-client-id'}, 400, 'sso_callback_invalid_audience'),
        ({'nonce': 'tampered-nonce'}, 400, 'sso_callback_invalid_nonce'),
        ({'alg': 'none'}, 400, 'sso_callback_invalid_algorithm'),
        ({'sub': None}, 400, 'sso_callback_missing_required_claims'),
        ({'tid': None}, 400, 'sso_callback_missing_required_claims'),
    ],
)
def test_admin_sso_callback_security_negative_matrix(
    token_kwargs: dict[str, object],
    expected_status: int,
    expected_detail: str,
) -> None:
    client = _client()
    _provision_enabled_provider()
    _add_mapping('entra-primary', 'group-admins', 'admin', 10)

    start = client.get('/auth/admin/sso/start', params={'provider_id': 'entra-primary'}, follow_redirects=False)
    state = parse_qs(urlparse(start.headers['location']).query)['state'][0]
    nonce = parse_qs(urlparse(start.headers['location']).query)['nonce'][0]

    payload = {
        'secret': 'very-secret-value',
        'issuer': 'https://issuer.example.com',
        'audience': 'client-id-123',
        'nonce': nonce,
        'exp': int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
        'sub': 'user-sub-1',
        'email': 'admin@example.com',
        'tid': 'tenant-123',
        'groups': ['group-admins'],
    }
    payload.update(token_kwargs)
    alg = str(payload.pop('alg', 'HS256'))

    header = {'alg': alg, 'typ': 'JWT'}
    body = {
        'iss': payload['issuer'],
        'aud': payload['audience'],
        'nonce': payload['nonce'],
        'exp': payload['exp'],
        'sub': payload['sub'],
        'email': payload['email'],
        'tid': payload['tid'],
        'groups': payload['groups'],
    }
    h = _b64url(json.dumps(header, separators=(',', ':')).encode())
    p = _b64url(json.dumps(body, separators=(',', ':')).encode())
    sig = _b64url(hmac.new(str(payload['secret']).encode(), f'{h}.{p}'.encode(), hashlib.sha256).digest())
    token = f'{h}.{p}.{sig}'

    response = client.get('/auth/admin/sso/callback', params={'state': state, 'id_token': token})
    assert response.status_code == expected_status
    assert response.json()['detail'] == expected_detail


def test_admin_sso_callback_replay_rejected_after_first_success() -> None:
    client = _client()
    _provision_enabled_provider()
    _add_mapping('entra-primary', 'group-admins', 'admin', 10)

    start = client.get('/auth/admin/sso/start', params={'provider_id': 'entra-primary'}, follow_redirects=False)
    state = parse_qs(urlparse(start.headers['location']).query)['state'][0]
    nonce = parse_qs(urlparse(start.headers['location']).query)['nonce'][0]

    token = _make_id_token(
        secret='very-secret-value',
        issuer='https://issuer.example.com',
        audience='client-id-123',
        nonce=nonce,
        exp=int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
    )

    first = client.get('/auth/admin/sso/callback', params={'state': state, 'id_token': token})
    assert first.status_code == 200

    replay = client.get('/auth/admin/sso/callback', params={'state': state, 'id_token': token})
    assert replay.status_code == 400
    assert replay.json()['detail'] == 'sso_state_already_used'

import os
from pathlib import Path
import sys

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = '/tmp/deployment_initializer_auth_test.db'

from app.db.session_store import get_session_store
from app.main import app
from app.services.auth import get_authenticated_principal, issue_root_session_token


ADMIN_HEADERS = {'X-SSO-Email': 'admin@example.com', 'X-SSO-Role': 'admin'}
VIEWER_HEADERS = {'X-SSO-Email': 'viewer@example.com', 'X-SSO-Role': 'viewer'}


def _client(headers: dict[str, str] | None = None) -> TestClient:
    get_session_store.cache_clear()
    db_path = Path('/tmp/deployment_initializer_auth_test.db')
    if db_path.exists():
        db_path.unlink()
    if headers is None:
        return TestClient(app)
    return TestClient(app, headers=headers)


def _valid_config() -> dict:
    return {
        'schema_version': '1.0.0',
        'deployment_context': {
            'environment': 'prod-us-east-1',
            'region': 'us-east-1',
            'aws_account_id': '123456789012',
            'app_name': 'deployment-initializer',
            'owner_email': 'ops@example.com',
        },
        'required_secrets': {
            'database_password': 'supersecret-password',
            'jwt_signing_key': 'jwt-signing-key-12345',
            'internal_api_token': 'internal-api-token-12345',
            'stripe_api_key': 'sk_test_1234567890',
            'openai_api_key': 'sk-openai-1234567890',
        },
        'optional_features': {
            'enable_helpdesk': True,
            'enable_messaging': False,
            'enable_filemanager': True,
            'enable_alerting': True,
            'enable_signature_packets': False,
        },
        'feature_config': {
            'helpdesk': {'routing_queue': 'tier1', 'auto_assign': True},
            'messaging': {'retention_days': 30, 'allow_external_sharing': False},
            'filemanager': {'max_upload_mb': 250, 'enable_virus_scan': True},
            'alerting': {'slack_webhook_url': None, 'email_notifications_enabled': True},
            'signature_packets': {'reminder_interval_hours': 24},
        },
        'deployment_options': {
            'instance_count': 2,
            'instance_type': 't3.medium',
            'vpc_id': 'vpc-abc123',
            'subnet_ids': ['subnet-1', 'subnet-2'],
            'enable_multi_az': True,
            'log_level': 'info',
        },
    }


def test_unauthorized_cannot_access_sessions_routes() -> None:
    anon = _client(headers=None)
    response = anon.get('/sessions/anything')
    assert response.status_code == 401
    assert response.json()['detail'] == 'unauthorized'


def test_deploy_requires_operator_or_admin_role() -> None:
    admin = _client(headers=ADMIN_HEADERS)
    created = admin.post(
        '/sessions',
        json={
            'metadata': {'env': 'prod', 'region': 'us-east-1', 'created_by': 'ops@example.com'},
            'config': _valid_config(),
            'execution_mode': 'live',
        },
    )
    assert created.status_code == 200
    session_id = created.json()['session_id']
    assert admin.put(f'/sessions/{session_id}', json={'status': 'validated'}).status_code == 200
    assert admin.put(f'/sessions/{session_id}', json={'status': 'ready'}).status_code == 200

    viewer = TestClient(app, headers=VIEWER_HEADERS)
    denied = viewer.post(f'/sessions/{session_id}/deploy')
    assert denied.status_code == 403
    assert denied.json()['detail'] == 'forbidden_insufficient_role'


def test_enforce_sso_blocks_non_ad_sso_admin_but_allows_ad_sso() -> None:
    os.environ['ADMIN_SSO_ENFORCE_FOR_ADMINS'] = 'true'
    try:
        with_admin_header = _client(headers={'X-SSO-Email': 'admin@example.com', 'X-SSO-Role': 'admin'})
        blocked = with_admin_header.get('/ops/metrics')
        assert blocked.status_code == 403
        assert blocked.json()['detail'] == 'forbidden_admin_sso_required'

        ad_sso_token_client = _client(headers={'Authorization': 'Bearer sso:admin@example.com:admin:ad_sso'})
        allowed = ad_sso_token_client.get('/ops/metrics')
        assert allowed.status_code == 200
    finally:
        os.environ['ADMIN_SSO_ENFORCE_FOR_ADMINS'] = 'false'


def test_root_local_login_allowed_even_when_sso_enforced() -> None:
    os.environ['ADMIN_SSO_ENFORCE_FOR_ADMINS'] = 'true'
    try:
        token = issue_root_session_token('root@example.com')
        root_client = _client(headers={'Authorization': f'Bearer {token}'})
        response = root_client.get('/ops/metrics')
        assert response.status_code == 200

        principal = get_authenticated_principal(authorization=f'Bearer {token}')
        assert principal.role == 'root'
        assert principal.provider == 'local_root'
    finally:
        os.environ['ADMIN_SSO_ENFORCE_FOR_ADMINS'] = 'false'

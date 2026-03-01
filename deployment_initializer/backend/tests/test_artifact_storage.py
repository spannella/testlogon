import os
from pathlib import Path
import sys

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = '/tmp/deployment_initializer_artifact_access_test.db'
os.environ['ARTIFACT_STORAGE_DIR'] = '/tmp/deployment_initializer_artifacts'
os.environ['ARTIFACT_SIGNING_SECRET'] = 'artifact-test-secret'

from app.db.session_store import get_session_store
from app.main import app


AUTH_HEADERS = {'X-SSO-Email': 'ops@example.com', 'X-SSO-Role': 'admin'}

client = TestClient(app, headers=AUTH_HEADERS)


def _reset() -> None:
    get_session_store.cache_clear()
    db_path = Path('/tmp/deployment_initializer_artifact_access_test.db')
    if db_path.exists():
        db_path.unlink()
    store_dir = Path('/tmp/deployment_initializer_artifacts')
    if store_dir.exists():
        for path in sorted(store_dir.rglob('*'), reverse=True):
            if path.is_file():
                path.unlink()
            else:
                path.rmdir()


def _config() -> dict:
    return {
        'schema_version': '1.0.0',
        'deployment_context': {
            'environment': 'prod-us-east-1',
            'region': 'us-east-1',
            'aws_account_id': '123456789012',
            'app_name': 'deployment-initializer',
            'owner_email': 'owner@example.com',
        },
        'required_secrets': {
            'database_password': 'supersecret-password',
            'jwt_signing_key': 'jwt-signing-key-12345',
            'internal_api_token': 'internal-api-token-12345',
            'stripe_api_key': 'sk_live_1234567890',
            'openai_api_key': 'sk-live-1234567890',
        },
        'optional_features': {
            'enable_helpdesk': False,
            'enable_messaging': False,
            'enable_filemanager': False,
            'enable_alerting': True,
            'enable_signature_packets': False,
        },
        'feature_config': {
            'helpdesk': {'routing_queue': 'general', 'auto_assign': True},
            'messaging': {'retention_days': 30, 'allow_external_sharing': False},
            'filemanager': {'max_upload_mb': 100, 'enable_virus_scan': True},
            'alerting': {'slack_webhook_url': None, 'email_notifications_enabled': True},
            'signature_packets': {'reminder_interval_hours': 24},
        },
        'deployment_options': {
            'instance_count': 2,
            'instance_type': 't3.medium',
            'vpc_id': 'vpc-abc123',
            'subnet_ids': [],
            'enable_multi_az': True,
            'log_level': 'info',
        },
    }


def _create_session() -> str:
    resp = client.post(
        '/sessions',
        json={
            'metadata': {'env': 'prod', 'region': 'us-east-1', 'created_by': 'owner@example.com'},
            'config': _config(),
            'execution_mode': 'live',
        },
    )
    assert resp.status_code == 200
    return resp.json()['session_id']


def test_artifact_listing_requires_authorization() -> None:
    _reset()
    sid = _create_session()
    gen = client.post(f'/sessions/{sid}/generate')
    assert gen.status_code == 200

    denied = client.get(
        f'/sessions/{sid}/artifacts',
        headers={'X-SSO-Email': 'viewer@example.com', 'X-SSO-Role': 'viewer'},
    )
    assert denied.status_code == 403

    allowed = client.get(
        f'/sessions/{sid}/artifacts',
        headers={'X-SSO-Email': 'owner@example.com', 'X-SSO-Role': 'operator'},
    )
    assert allowed.status_code == 200
    payload = allowed.json()
    assert len(payload['artifacts']) >= 3
    assert payload['artifacts'][0]['run_id'] == gen.json()['run_id']


def test_signed_download_flow_returns_artifact_content() -> None:
    _reset()
    sid = _create_session()
    client.post(f'/sessions/{sid}/generate')

    listed = client.get(
        f'/sessions/{sid}/artifacts',
        headers={'X-SSO-Email': 'admin@example.com', 'X-SSO-Role': 'admin'},
    )
    assert listed.status_code == 200
    first = listed.json()['artifacts'][0]

    download = client.get(first['signed_download_url'])
    assert download.status_code == 200
    body = download.json()
    assert body['session_id'] == sid
    assert body['artifact_name'] == first['name']
    assert body['hash'] == first['hash']
    assert body['content']

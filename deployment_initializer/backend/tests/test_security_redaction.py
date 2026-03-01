import os
from pathlib import Path
import sys

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = '/tmp/deployment_initializer_security_test.db'

from app.db.session_store import get_session_store
from app.main import app


AUTH_HEADERS = {'X-SSO-Email': 'ops@example.com', 'X-SSO-Role': 'admin'}

client = TestClient(app, headers=AUTH_HEADERS)


def _reset_db() -> None:
    get_session_store.cache_clear()
    db_path = Path('/tmp/deployment_initializer_security_test.db')
    if db_path.exists():
        db_path.unlink()


def _contains_substring(obj: object, needle: str) -> bool:
    if isinstance(obj, dict):
        return any(_contains_substring(v, needle) for v in obj.values())
    if isinstance(obj, list):
        return any(_contains_substring(v, needle) for v in obj)
    if isinstance(obj, str):
        return needle in obj
    return False


def _config() -> dict:
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


def _create(mode: str) -> str:
    created = client.post(
        '/sessions',
        json={
            'metadata': {'env': 'prod', 'region': 'us-east-1', 'created_by': 'ops@example.com'},
            'config': _config(),
            'execution_mode': mode,
        },
    )
    assert created.status_code == 200
    return created.json()['session_id']


def _ready(session_id: str) -> None:
    assert client.put(f'/sessions/{session_id}', json={'status': 'validated'}).status_code == 200
    assert client.put(f'/sessions/{session_id}', json={'status': 'ready'}).status_code == 200


def test_no_plaintext_secrets_in_api_payloads() -> None:
    _reset_db()
    session_id = _create('live')

    create_payload = client.get(f'/sessions/{session_id}').json()
    update_payload = client.put(f'/sessions/{session_id}', json={'status': 'validated'}).json()
    cred_payload = client.post(f'/sessions/{session_id}/test-credentials').json()

    for payload in [create_payload, update_payload, cred_payload]:
        assert not _contains_substring(payload, 'supersecret-password')
        assert not _contains_substring(payload, 'sk_test_1234567890')
        assert not _contains_substring(payload, 'sk-openai-1234567890')


def test_no_plaintext_secrets_in_dryrun_and_mock_payloads() -> None:
    _reset_db()

    dry_session = _create('dry_run')
    _ready(dry_session)
    dry_payload = client.post(f'/sessions/{dry_session}/deploy').json()

    mock_session = _create('mock')
    _ready(mock_session)
    mock_payload = client.post(f'/sessions/{mock_session}/deploy', headers={'X-Mock-Scenario': 'apply_failure'}).json()

    for payload in [dry_payload, mock_payload]:
        assert not _contains_substring(payload, 'supersecret-password')
        assert not _contains_substring(payload, 'sk_test_1234567890')
        assert not _contains_substring(payload, 'sk-openai-1234567890')

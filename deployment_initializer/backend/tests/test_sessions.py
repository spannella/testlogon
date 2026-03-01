import os
from pathlib import Path
import sys

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = '/tmp/deployment_initializer_test.db'

from app.db.session_store import get_session_store
from app.main import app


AUTH_HEADERS = {'X-SSO-Email': 'ops@example.com', 'X-SSO-Role': 'admin'}


def _client() -> TestClient:
    get_session_store.cache_clear()
    db_path = Path('/tmp/deployment_initializer_test.db')
    if db_path.exists():
        db_path.unlink()
    return TestClient(app, headers=AUTH_HEADERS)


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


def _contains_substring(obj: object, needle: str) -> bool:
    if isinstance(obj, dict):
        return any(_contains_substring(v, needle) for v in obj.values())
    if isinstance(obj, list):
        return any(_contains_substring(v, needle) for v in obj)
    if isinstance(obj, str):
        return needle in obj
    return False


def test_create_get_update_session_happy_path() -> None:
    client = _client()

    create_payload = {
        'metadata': {'env': 'prod', 'region': 'us-east-1', 'created_by': 'alice@example.com'},
        'config': _valid_config(),
        'execution_mode': 'mock',
    }
    created = client.post('/sessions', json=create_payload)
    assert created.status_code == 200
    body = created.json()
    session_id = body['session_id']
    assert body['status'] == 'draft'
    assert body['execution_mode'] == 'mock'
    assert not _contains_substring(body, 'supersecret-password')
    assert not _contains_substring(body, 'sk_test_1234567890')

    fetched = client.get(f'/sessions/{session_id}')
    assert fetched.status_code == 200
    assert fetched.json()['metadata']['env'] == 'prod'
    fetched_body = fetched.json()
    assert fetched_body['config']['deployment_context']['app_name'] == 'deployment-initializer'
    assert not _contains_substring(fetched_body, 'supersecret-password')
    assert not _contains_substring(fetched_body, 'sk_test_1234567890')

    updated_config = _valid_config()
    updated_config['deployment_options']['instance_count'] = 3

    updated = client.put(
        f'/sessions/{session_id}',
        json={'status': 'validated', 'execution_mode': 'dry_run', 'config': updated_config},
    )
    assert updated.status_code == 200
    updated_body = updated.json()
    assert updated_body['status'] == 'validated'
    assert updated_body['execution_mode'] == 'dry_run'
    assert updated_body['config']['deployment_options']['instance_count'] == 3
    assert not _contains_substring(updated_body, 'supersecret-password')
    assert not _contains_substring(updated_body, 'sk_test_1234567890')


def test_invalid_status_transition_is_rejected() -> None:
    client = _client()
    created = client.post(
        '/sessions',
        json={
            'metadata': {'env': 'prod', 'region': 'us-east-1', 'created_by': 'bob@example.com'},
            'config': _valid_config(),
            'execution_mode': 'live',
        },
    )
    session_id = created.json()['session_id']

    invalid = client.put(f'/sessions/{session_id}', json={'status': 'deployed'})
    assert invalid.status_code == 400
    assert invalid.json()['detail'] == 'invalid_status_transition:draft->deployed'


def test_missing_session_returns_404() -> None:
    client = _client()
    response = client.get('/sessions/not-found')
    assert response.status_code == 404
    assert response.json()['detail'] == 'session_not_found'


def test_rejects_invalid_config_payload() -> None:
    client = _client()

    payload = {
        'metadata': {'env': 'prod', 'region': 'us-east-1', 'created_by': 'alice@example.com'},
        'config': {'schema_version': '1.0.0'},
        'execution_mode': 'live',
    }
    response = client.post('/sessions', json=payload)
    assert response.status_code == 422

import os
from pathlib import Path
import sys

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = '/tmp/deployment_initializer_generate_test.db'

from app.db.session_store import get_session_store
from app.main import app


AUTH_HEADERS = {'X-SSO-Email': 'ops@example.com', 'X-SSO-Role': 'admin'}

client = TestClient(app, headers=AUTH_HEADERS)


def _reset_db() -> None:
    get_session_store.cache_clear()
    db_path = Path('/tmp/deployment_initializer_generate_test.db')
    if db_path.exists():
        db_path.unlink()


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
            'stripe_api_key': 'sk_live_1234567890',
            'openai_api_key': 'sk-live-1234567890',
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


def _create_session() -> str:
    created = client.post(
        '/sessions',
        json={
            'metadata': {'env': 'prod', 'region': 'us-east-1', 'created_by': 'ops@example.com'},
            'config': _valid_config(),
            'execution_mode': 'live',
        },
    )
    assert created.status_code == 200
    return created.json()['session_id']


def test_generate_is_deterministic_and_persists_hashes() -> None:
    _reset_db()
    session_id = _create_session()

    first = client.post(f'/sessions/{session_id}/generate')
    assert first.status_code == 200
    first_body = first.json()

    second = client.post(f'/sessions/{session_id}/generate')
    assert second.status_code == 200
    second_body = second.json()

    first_artifacts = {item['name']: item for item in first_body['artifacts']}
    second_artifacts = {item['name']: item for item in second_body['artifacts']}

    assert set(first_artifacts.keys()) == {'.env.template', 'service.config.json', 'iac.params.json'}

    for name in first_artifacts:
        assert first_artifacts[name]['content'] == second_artifacts[name]['content']
        assert first_artifacts[name]['hash'] == second_artifacts[name]['hash']
        assert first_artifacts[name]['version'] == '1.0.0'

    # second run with same input should have empty diff
    assert second_body['diff'] == []


def test_generate_diff_changes_when_config_changes() -> None:
    _reset_db()
    session_id = _create_session()

    first = client.post(f'/sessions/{session_id}/generate')
    assert first.status_code == 200

    cfg = _valid_config()
    cfg['deployment_options']['vpc_id'] = 'vpc-changed'
    updated = client.put(f'/sessions/{session_id}', json={'config': cfg})
    assert updated.status_code == 200

    second = client.post(f'/sessions/{session_id}/generate')
    assert second.status_code == 200

    diff = second.json()['diff']
    assert any(entry['path'] == '.env.template' for entry in diff)
    assert any(entry['path'] == 'iac.params.json' for entry in diff)

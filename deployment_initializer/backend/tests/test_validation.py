import os
from pathlib import Path
import sys

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = '/tmp/deployment_initializer_validation_test.db'

from app.db.session_store import get_session_store
from app.main import app


AUTH_HEADERS = {'X-SSO-Email': 'ops@example.com', 'X-SSO-Role': 'admin'}

client = TestClient(app, headers=AUTH_HEADERS)


def _reset_db() -> None:
    get_session_store.cache_clear()
    db_path = Path('/tmp/deployment_initializer_validation_test.db')
    if db_path.exists():
        db_path.unlink()


def _base_config() -> dict:
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
            'enable_messaging': True,
            'enable_filemanager': True,
            'enable_alerting': True,
            'enable_signature_packets': True,
        },
        'feature_config': {
            'helpdesk': {'routing_queue': 'tier1', 'auto_assign': True},
            'messaging': {'retention_days': 30, 'allow_external_sharing': False},
            'filemanager': {'max_upload_mb': 250, 'enable_virus_scan': True},
            'alerting': {'slack_webhook_url': 'https://hooks.slack.com/services/example', 'email_notifications_enabled': True},
            'signature_packets': {'reminder_interval_hours': 24},
        },
        'deployment_options': {
            'instance_count': 2,
            'instance_type': 'm7g.large',
            'vpc_id': 'vpc-abc123',
            'subnet_ids': ['subnet-1', 'subnet-2'],
            'enable_multi_az': True,
            'log_level': 'info',
        },
    }


def _create_session(config: dict) -> str:
    created = client.post(
        '/sessions',
        json={
            'metadata': {'env': 'prod', 'region': 'us-east-1', 'created_by': 'validator@example.com'},
            'config': config,
            'execution_mode': 'live',
        },
    )
    assert created.status_code == 200
    return created.json()['session_id']


def test_validate_ready_session_passes() -> None:
    _reset_db()
    session_id = _create_session(_base_config())

    response = client.post(f'/sessions/{session_id}/validate')
    assert response.status_code == 200
    body = response.json()

    assert body['ready_to_deploy'] is True
    assert body['blocking_issue_count'] == 0
    assert body['warning_count'] == 0
    assert body['issues'] == []


def test_validate_returns_blocking_and_warning_issues() -> None:
    _reset_db()
    config = _base_config()
    config['required_secrets']['stripe_api_key'] = 'sk_test_1234567890'
    config['feature_config']['messaging']['retention_days'] = 3
    config['feature_config']['alerting']['slack_webhook_url'] = None
    config['deployment_options']['enable_multi_az'] = False

    session_id = _create_session(config)

    response = client.post(f'/sessions/{session_id}/validate')
    assert response.status_code == 200
    body = response.json()

    assert body['ready_to_deploy'] is False
    assert body['blocking_issue_count'] == 3
    assert body['warning_count'] == 1

    codes = {issue['code'] for issue in body['issues']}
    assert 'business.secrets.stripe_key_not_live' in codes
    assert 'business.messaging.retention_too_low' in codes
    assert 'readiness.prod_multi_az_disabled' in codes
    assert 'business.alerting.slack_webhook_missing' in codes


def test_validate_unknown_session_returns_404() -> None:
    _reset_db()
    response = client.post('/sessions/missing-session/validate')
    assert response.status_code == 404
    assert response.json()['detail'] == 'session_not_found'

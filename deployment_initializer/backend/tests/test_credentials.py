import os
from pathlib import Path
import sys

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = '/tmp/deployment_initializer_credentials_test.db'
os.environ['CREDENTIAL_TEST_MAX_RETRIES'] = '2'
os.environ['CREDENTIAL_TEST_TIMEOUT_SECONDS'] = '0.1'
os.environ['CREDENTIAL_TEST_RETRY_BACKOFF_SECONDS'] = '0'

from app.db.session_store import get_session_store
from app.main import app
AUTH_HEADERS = {'X-SSO-Email': 'ops@example.com', 'X-SSO-Role': 'admin'}

from app.services.provider_credentials import (
    CredentialAdapterRegistry,
    CredentialTestResult,
    CredentialTestStatus,
    ProviderCredentialInput,
    TransientCredentialError,
    run_provider_test,
)


client = TestClient(app, headers=AUTH_HEADERS)


def _reset_db() -> None:
    get_session_store.cache_clear()
    db_path = Path('/tmp/deployment_initializer_credentials_test.db')
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
            'enable_helpdesk': False,
            'enable_messaging': False,
            'enable_filemanager': False,
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


def test_test_credentials_endpoint_success_and_unknown_provider() -> None:
    _reset_db()
    session_id = _create_session()

    response = client.post(
        f'/sessions/{session_id}/test-credentials',
        json={'providers': ['openai', 'stripe', 'unknown_vendor']},
    )
    assert response.status_code == 200
    body = response.json()
    statuses = {item['provider']: item['status'] for item in body['results']}
    assert statuses['openai'] in {'pass', 'warning', 'fail'}
    assert statuses['stripe'] in {'pass', 'warning', 'fail'}
    assert statuses['unknown_vendor'] == 'unknown'


def test_transient_failures_map_to_warning_after_retries() -> None:
    class AlwaysTransientAdapter:
        provider_name = 'always_transient'

        def test(self, credential: ProviderCredentialInput, timeout_seconds: float) -> CredentialTestResult:
            _ = credential
            _ = timeout_seconds
            raise TransientCredentialError('transient_network_error')

    registry = CredentialAdapterRegistry()
    registry.register(AlwaysTransientAdapter())

    result = run_provider_test(
        registry,
        ProviderCredentialInput(provider='always_transient', secret='secret-value'),
    )
    assert result.status == CredentialTestStatus.WARNING
    assert result.attempts == 3


def test_unknown_provider_returns_non_500_structured_response() -> None:
    _reset_db()
    session_id = _create_session()

    response = client.post(
        f'/sessions/{session_id}/test-credentials',
        json={'providers': ['non_existent_provider']},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload['results'][0]['status'] == 'unknown'
    assert 'provider' in payload['results'][0]


def test_provider_messages_do_not_echo_raw_secret() -> None:
    _reset_db()
    session_id = _create_session()

    # write explicit test key and verify response does not include raw value
    updated = _valid_config()
    updated['required_secrets']['openai_api_key'] = 'sk-live-super-sensitive-value'
    put_resp = client.put(
        f'/sessions/{session_id}',
        json={'config': updated},
    )
    assert put_resp.status_code == 200

    response = client.post(
        f'/sessions/{session_id}/test-credentials',
        json={'providers': ['openai']},
    )
    assert response.status_code == 200
    message = response.json()['results'][0]['message']
    assert 'sk-live-super-sensitive-value' not in message

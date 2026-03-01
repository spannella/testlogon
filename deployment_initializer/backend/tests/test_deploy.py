import os
from pathlib import Path
import sys

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = '/tmp/deployment_initializer_deploy_test.db'

from app.db.session_store import get_session_store
from app.main import app


AUTH_HEADERS = {'X-SSO-Email': 'ops@example.com', 'X-SSO-Role': 'admin'}

client = TestClient(app, headers=AUTH_HEADERS)


def _reset_db() -> None:
    get_session_store.cache_clear()
    db_path = Path('/tmp/deployment_initializer_deploy_test.db')
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




def _mark_session_ready(session_id: str) -> None:
    validated = client.put(f'/sessions/{session_id}', json={'status': 'validated'})
    assert validated.status_code == 200
    ready = client.put(f'/sessions/{session_id}', json={'status': 'ready'})
    assert ready.status_code == 200

def _create_session(config: dict | None = None, execution_mode: str = 'live') -> str:
    created = client.post(
        '/sessions',
        json={
            'metadata': {'env': 'prod', 'region': 'us-east-1', 'created_by': 'ops@example.com'},
            'config': config or _valid_config(),
            'execution_mode': execution_mode,
        },
    )
    assert created.status_code == 200
    return created.json()['session_id']


def test_deploy_happy_path_persists_stage_events_and_outputs() -> None:
    _reset_db()
    session_id = _create_session()
    _mark_session_ready(session_id)

    response = client.post(f'/sessions/{session_id}/deploy')
    assert response.status_code == 200
    body = response.json()

    assert body['status'] == 'success'
    assert [event['stage'] for event in body['events']] == [
        'preflight_checks',
        'plan_change_set',
        'apply_changes',
        'post_deploy_checks',
    ]
    assert all(event['status'] == 'success' for event in body['events'])

    assert body['outputs']['stack_name'] == 'deployment-initializer-prod'
    assert body['outputs']['change_set_id'].startswith('cs-')
    assert body['outputs']['health_check'] == 'ok'

    fetched = client.get(f'/sessions/{session_id}')
    assert fetched.status_code == 200
    assert fetched.json()['status'] == 'deployed'


def test_deploy_failure_stops_downstream_and_marks_session_failed() -> None:
    _reset_db()
    config = _valid_config()
    config['deployment_options']['vpc_id'] = 'fail-apply-vpc'
    session_id = _create_session(config=config)
    _mark_session_ready(session_id)

    response = client.post(f'/sessions/{session_id}/deploy')
    assert response.status_code == 200
    body = response.json()

    assert body['status'] == 'failed'
    assert [event['stage'] for event in body['events']] == [
        'preflight_checks',
        'plan_change_set',
        'apply_changes',
    ]
    assert body['events'][-1]['status'] == 'failed'
    assert 'provisioning error' in body['events'][-1]['message'].lower()

    # apply failed, so post-deploy should not run
    assert 'health_check' not in body['outputs']

    fetched = client.get(f'/sessions/{session_id}')
    assert fetched.status_code == 200
    assert fetched.json()['status'] == 'failed'


def test_deploy_mock_mode_is_accepted() -> None:
    _reset_db()
    session_id = _create_session(execution_mode='mock')
    _mark_session_ready(session_id)

    response = client.post(f'/sessions/{session_id}/deploy')
    assert response.status_code == 200
    assert response.json()['execution_mode'] == 'mock'


def test_deploy_idempotency_key_deduplicates_duplicate_requests() -> None:
    _reset_db()
    session_id = _create_session()
    _mark_session_ready(session_id)

    headers = {'Idempotency-Key': 'same-key-1'}
    first = client.post(f'/sessions/{session_id}/deploy', headers=headers)
    assert first.status_code == 200

    second = client.post(f'/sessions/{session_id}/deploy', headers=headers)
    assert second.status_code == 200

    first_body = first.json()
    second_body = second.json()
    assert second_body == first_body


def test_deploy_conflict_when_environment_lock_already_held() -> None:
    _reset_db()
    session_id = _create_session()
    _mark_session_ready(session_id)

    store = get_session_store()
    locked = store.acquire_environment_lock('prod', 'us-east-1', session_id='other-session', run_id='other-run')
    assert locked is True

    response = client.post(f'/sessions/{session_id}/deploy')
    assert response.status_code == 409

    detail = response.json()['detail']
    assert detail['code'] == 'environment_deploy_locked'
    assert detail['env'] == 'prod'
    assert detail['region'] == 'us-east-1'


def test_dry_run_returns_simulated_reports_without_session_mutation() -> None:
    _reset_db()
    session_id = _create_session(execution_mode='dry_run')
    _mark_session_ready(session_id)

    response = client.post(f'/sessions/{session_id}/deploy')
    assert response.status_code == 200
    body = response.json()

    assert body['execution_mode'] == 'dry_run'
    assert body['simulated'] is True
    assert body['validation_summary']['blocking_issue_count'] == 0
    assert body['deploy_simulation_status'] == 'success'
    assert all(event['message'].startswith('SIMULATED:') for event in body['deploy_simulation_events'])
    assert all(step['simulated'] is True for step in body['would_do_steps'])

    fetched = client.get(f'/sessions/{session_id}')
    assert fetched.status_code == 200
    # dry-run should not mutate session status
    assert fetched.json()['status'] == 'ready'


def test_dry_run_marks_simulation_failed_but_does_not_change_status() -> None:
    _reset_db()
    cfg = _valid_config()
    cfg['deployment_options']['vpc_id'] = 'fail-apply-vpc'
    session_id = _create_session(config=cfg, execution_mode='dry_run')
    _mark_session_ready(session_id)

    response = client.post(f'/sessions/{session_id}/deploy')
    assert response.status_code == 200
    body = response.json()

    assert body['deploy_simulation_status'] == 'failed'
    assert body['deploy_simulation_events'][-1]['status'] == 'failed'

    fetched = client.get(f'/sessions/{session_id}')
    assert fetched.status_code == 200
    assert fetched.json()['status'] == 'ready'


def test_mock_mode_returns_synthetic_outputs_and_events() -> None:
    _reset_db()
    session_id = _create_session(execution_mode='mock')
    _mark_session_ready(session_id)

    response = client.post(f'/sessions/{session_id}/deploy')
    assert response.status_code == 200
    body = response.json()

    assert body['execution_mode'] == 'mock'
    assert body['simulated'] is True
    assert body['scenario'] == 'success'
    assert body['status'] == 'success'
    assert body['synthetic_outputs']['stack_name'].startswith('mock-stack-')
    assert body['synthetic_outputs']['change_set_id'].startswith('mock-cs-')
    assert all('SIMULATED:' in event['message'] for event in body['events'])


def test_mock_mode_scenario_selection_reproduces_failure_branch() -> None:
    _reset_db()
    session_id = _create_session(execution_mode='mock')
    _mark_session_ready(session_id)

    response = client.post(f'/sessions/{session_id}/deploy', headers={'X-Mock-Scenario': 'apply_failure'})
    assert response.status_code == 200
    body = response.json()

    assert body['scenario'] == 'apply_failure'
    assert body['status'] == 'failed'
    assert [event['stage'] for event in body['events']] == [
        'preflight_checks',
        'plan_change_set',
        'apply_changes',
    ]
    assert body['events'][-1]['status'] == 'failed'
    assert 'SIMULATED:' in body['events'][-1]['message']

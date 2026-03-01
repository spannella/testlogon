import os
from pathlib import Path
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = '/tmp/deployment_initializer_e2e_test.db'

from app.db.session_store import get_session_store
from app.main import app

from e2e_fixtures import AUTH_HEADERS, E2E_CONFIG


client = TestClient(app, headers=AUTH_HEADERS)


def _reset_db() -> None:
    get_session_store.cache_clear()
    db_path = Path('/tmp/deployment_initializer_e2e_test.db')
    if db_path.exists():
        db_path.unlink()


def _assert_ok(response, step: str) -> dict:
    assert response.status_code == 200, f'{step} failed with status={response.status_code} body={response.text}'
    return response.json()


def _create_and_ready_session(execution_mode: str) -> str:
    created = _assert_ok(
        client.post(
            '/sessions',
            json={
                'metadata': {'env': 'prod', 'region': 'us-east-1', 'created_by': 'ops@example.com'},
                'config': E2E_CONFIG,
                'execution_mode': execution_mode,
            },
        ),
        step=f'create_session[{execution_mode}]',
    )
    session_id = created['session_id']

    _assert_ok(client.put(f'/sessions/{session_id}', json={'status': 'validated'}), step='status_to_validated')
    _assert_ok(client.put(f'/sessions/{session_id}', json={'status': 'ready'}), step='status_to_ready')
    return session_id


@pytest.mark.parametrize('execution_mode,deploy_headers,expected_status', [
    ('dry_run', {}, 'success'),
    ('mock', {}, 'success'),
])
def test_e2e_core_flow_dry_run_and_mock(execution_mode: str, deploy_headers: dict[str, str], expected_status: str) -> None:
    _reset_db()
    session_id = _create_and_ready_session(execution_mode)

    validation = _assert_ok(client.post(f'/sessions/{session_id}/validate'), step='validate_session')
    assert validation['ready_to_deploy'] is True, f'validation not ready: {validation}'

    credentials = _assert_ok(client.post(f'/sessions/{session_id}/test-credentials'), step='test_credentials')
    provider_status = {entry['provider']: entry['status'] for entry in credentials['results']}
    assert provider_status.get('openai') in {'pass', 'warning'}, f'unexpected openai status: {provider_status}'
    assert provider_status.get('stripe') in {'pass', 'warning'}, f'unexpected stripe status: {provider_status}'

    generated = _assert_ok(client.post(f'/sessions/{session_id}/generate'), step='generate_artifacts')
    assert len(generated['artifacts']) >= 3, f'expected artifacts not generated: {generated}'

    deployed = _assert_ok(client.post(f'/sessions/{session_id}/deploy', headers=deploy_headers), step='deploy')
    deploy_status = deployed.get('status') or deployed.get('deploy_simulation_status')
    assert deploy_status == expected_status, f'unexpected deploy status for mode={execution_mode}: {deployed}'

    events = _assert_ok(client.get(f'/sessions/{session_id}/events'), step='fetch_events')
    assert len(events['events']) > 0, f'expected session events for mode={execution_mode}'


def test_e2e_mock_scenario_failure_is_deterministic_and_actionable() -> None:
    _reset_db()
    session_id = _create_and_ready_session('mock')

    deployed = _assert_ok(
        client.post(f'/sessions/{session_id}/deploy', headers={'X-Mock-Scenario': 'apply_failure'}),
        step='deploy_mock_apply_failure',
    )
    assert deployed['status'] == 'failed', f'expected failed mock scenario: {deployed}'
    assert deployed['events'][-1]['stage'] == 'apply_changes', f'expected apply stage failure: {deployed}'
    assert 'SIMULATED:' in deployed['events'][-1]['message'], f'missing actionable simulated error: {deployed}'

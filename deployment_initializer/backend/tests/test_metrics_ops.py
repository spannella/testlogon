import os
from pathlib import Path
import sys

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = '/tmp/deployment_initializer_metrics_test.db'
os.environ['DEPLOY_FAILURE_ALERT_THRESHOLD'] = '2'
os.environ['DEPLOY_FAILURE_ALERT_WINDOW_MINUTES'] = '30'

from app.db.session_store import get_session_store
from app.main import app


ADMIN = {'X-SSO-Email': 'admin@example.com', 'X-SSO-Role': 'admin'}
OPERATOR = {'X-SSO-Email': 'ops@example.com', 'X-SSO-Role': 'operator'}


def _reset() -> None:
    os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = '/tmp/deployment_initializer_metrics_test.db'
    get_session_store.cache_clear()
    db = Path('/tmp/deployment_initializer_metrics_test.db')
    if db.exists():
        db.unlink()


def _clear_locks() -> None:
    import sqlite3

    conn = sqlite3.connect('/tmp/deployment_initializer_metrics_test.db')
    try:
        conn.execute('DELETE FROM deploy_environment_locks')
        conn.commit()
    finally:
        conn.close()


def _config(vpc_id: str = 'vpc-abc123', region: str = 'us-east-1') -> dict:
    return {
        'schema_version': '1.0.0',
        'deployment_context': {
            'environment': 'prod-us-east-1',
            'region': region,
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
            'vpc_id': vpc_id,
            'subnet_ids': ['subnet-1', 'subnet-2'],
            'enable_multi_az': True,
            'log_level': 'info',
        },
    }


def _create_session(client: TestClient, vpc_id: str = 'vpc-abc123', region: str = 'us-east-1') -> str:
    created = client.post(
        '/sessions',
        json={
            'metadata': {'env': 'prod', 'region': region, 'created_by': 'ops@example.com'},
            'config': _config(vpc_id=vpc_id),
            'execution_mode': 'live',
        },
    )
    assert created.status_code == 200
    sid = created.json()['session_id']
    assert client.put(f'/sessions/{sid}', json={'status': 'validated'}).status_code == 200
    assert client.put(f'/sessions/{sid}', json={'status': 'ready'}).status_code == 200
    return sid


def test_metrics_dashboard_and_alerts_flow() -> None:
    _reset()
    operator = TestClient(app, headers=OPERATOR)
    admin = TestClient(app, headers=ADMIN)

    sid1 = _create_session(operator, vpc_id='fail-apply-vpc-1')
    sid2 = _create_session(operator, vpc_id='fail-apply-vpc-2', region='us-west-2')

    _clear_locks()

    assert operator.post(f'/sessions/{sid1}/deploy').status_code == 200
    assert operator.post(f'/sessions/{sid2}/deploy').status_code == 200

    metrics = admin.get('/ops/metrics')
    assert metrics.status_code == 200
    payload = metrics.json()
    assert payload['deploy_failure_total'] >= 2
    assert 'deploy_success_rate' in payload
    assert 'deploy_duration_avg_seconds' in payload

    alerts = admin.get('/ops/alerts')
    assert alerts.status_code == 200
    alert_items = alerts.json()['alerts']
    assert any(item['code'] == 'repeated_deploy_failures' for item in alert_items)
    assert all('runbook' in item for item in alert_items)

    dashboard = admin.get('/ops/dashboard-template')
    assert dashboard.status_code == 200
    db = dashboard.json()
    metrics_in_panels = {panel['metric'] for panel in db['panels']}
    assert {'validation_failures_total', 'deploy_success_rate', 'deploy_duration_avg_seconds'}.issubset(metrics_in_panels)

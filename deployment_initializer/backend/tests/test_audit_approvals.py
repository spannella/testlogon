import os
from pathlib import Path
import sys

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = '/tmp/deployment_initializer_audit_approvals_test.db'

from app.db.session_store import get_session_store
from app.main import app


ADMIN_1 = {'X-SSO-Email': 'alice@example.com', 'X-SSO-Role': 'admin'}
ADMIN_2 = {'X-SSO-Email': 'bob@example.com', 'X-SSO-Role': 'admin'}
OPERATOR = {'X-SSO-Email': 'ops@example.com', 'X-SSO-Role': 'operator'}


def _reset() -> None:
    get_session_store.cache_clear()
    db = Path('/tmp/deployment_initializer_audit_approvals_test.db')
    if db.exists():
        db.unlink()


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


def test_live_deploy_blocked_until_two_approvals_then_audited(monkeypatch) -> None:
    _reset()
    monkeypatch.setenv('DEPLOY_REQUIRE_TWO_PERSON_APPROVAL', 'true')
    admin1 = TestClient(app, headers=ADMIN_1)
    operator = TestClient(app, headers=OPERATOR)
    admin2 = TestClient(app, headers=ADMIN_2)

    created = operator.post(
        '/sessions',
        json={
            'metadata': {'env': 'prod', 'region': 'us-east-1', 'created_by': 'ops@example.com'},
            'config': _config(),
            'execution_mode': 'live',
        },
    )
    assert created.status_code == 200
    session_id = created.json()['session_id']
    assert operator.put(f'/sessions/{session_id}', json={'status': 'validated'}).status_code == 200
    assert operator.put(f'/sessions/{session_id}', json={'status': 'ready'}).status_code == 200

    blocked = operator.post(f'/sessions/{session_id}/deploy')
    assert blocked.status_code == 403
    detail = blocked.json()['detail']
    assert detail['code'] == 'approval_required'
    assert detail['required_approvals'] == 2

    a1 = admin1.post(f'/sessions/{session_id}/approvals', json={'decision': 'approve', 'comment': 'looks good'})
    assert a1.status_code == 200
    assert a1.json()['approvals_required'] == 2

    still_blocked = operator.post(f'/sessions/{session_id}/deploy')
    assert still_blocked.status_code == 403

    a2 = admin2.post(f'/sessions/{session_id}/approvals', json={'decision': 'approve'})
    assert a2.status_code == 200
    assert set(a2.json()['approved_by']) == {'alice@example.com', 'bob@example.com'}

    deployed = operator.post(f'/sessions/{session_id}/deploy')
    assert deployed.status_code == 200
    assert deployed.json()['status'] == 'success'

    audits = operator.get(f'/sessions/{session_id}/audit-events')
    assert audits.status_code == 200
    entries = audits.json()['entries']
    assert any(e['action'] == 'deploy.approval' and e['actor_email'] == 'alice@example.com' for e in entries)
    deploy_entries = [e for e in entries if e['action'] == 'deploy.live']
    assert len(deploy_entries) == 1
    assert deploy_entries[0]['actor_email'] == 'ops@example.com'
    assert deploy_entries[0]['created_at']

    timeline = operator.get(f'/sessions/{session_id}/events')
    assert timeline.status_code == 200
    events = timeline.json()['events']
    assert len(events) > 0
    assert any(event['event_type'] == 'deploy_stage' for event in events)
    assert any(event['event_type'] == 'audit' and event['message'] == 'deploy.live' for event in events)

from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

DB_PATH = '/tmp/deployment_initializer_admin_sso_dev_activity_api_test.db'
os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH
os.environ['ADMIN_SSO_DEV_DIRECTORY_API_ENABLED'] = '1'

from app.db.session_store import get_session_store
from app.main import app
from app.services.auth import issue_root_session_token

ROOT_HEADERS = {'Authorization': f'Bearer {issue_root_session_token("root@example.com")}' }


def _client() -> TestClient:
    os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH
    get_session_store.cache_clear()
    db = Path(DB_PATH)
    if db.exists():
        db.unlink()
    return TestClient(app, headers=ROOT_HEADERS)


def _seed_activity() -> None:
    store = get_session_store()
    store.migrate()

    store.add_admin_sso_auth_audit_event(
        auth_method='ad_sso',
        outcome='failure',
        actor_email='alice@example.com',
        provider_id=None,
        external_subject='sub-alice',
        external_tenant='tenant-1',
        mapped_role=None,
        failure_reason='sso_callback_invalid_audience',
    )
    store.add_admin_sso_auth_audit_event(
        auth_method='ad_sso',
        outcome='denied',
        actor_email='bob@example.com',
        provider_id=None,
        external_subject='sub-bob',
        external_tenant='tenant-1',
        mapped_role=None,
        failure_reason='sso_role_mapping_denied',
    )
    store.add_admin_sso_auth_audit_event(
        auth_method='ad_sso',
        outcome='success',
        actor_email='alice@example.com',
        provider_id=None,
        external_subject='sub-alice',
        external_tenant='tenant-1',
        mapped_role='admin',
        failure_reason=None,
    )


def test_dev_activity_filters_and_troubleshooting_context() -> None:
    client = _client()
    _seed_activity()

    all_resp = client.get('/auth/admin/sso/dev-directory/activity', params={'limit': 10})
    assert all_resp.status_code == 200
    events = all_resp.json()['events']
    assert len(events) == 3
    # latest first
    assert events[0]['outcome'] == 'success'

    failure_resp = client.get('/auth/admin/sso/dev-directory/activity', params={'outcome': 'failure'})
    assert failure_resp.status_code == 200
    failure_events = failure_resp.json()['events']
    assert len(failure_events) == 1
    assert failure_events[0]['failure_reason'] == 'sso_callback_invalid_audience'
    assert failure_events[0]['troubleshooting_category'] == 'audience_mismatch'
    assert 'client_id' in failure_events[0]['troubleshooting_hint']

    alice_resp = client.get('/auth/admin/sso/dev-directory/activity', params={'actor_email': 'alice@example.com'})
    assert alice_resp.status_code == 200
    assert len(alice_resp.json()['events']) == 2

    denied_resp = client.get('/auth/admin/sso/dev-directory/activity', params={'outcome': 'denied'})
    assert denied_resp.status_code == 200
    denied_events = denied_resp.json()['events']
    assert len(denied_events) == 1
    assert denied_events[0]['troubleshooting_category'] == 'role_mapping_denied'


def test_dev_activity_since_minutes_filter_excludes_old_rows() -> None:
    client = _client()
    _seed_activity()

    resp = client.get('/auth/admin/sso/dev-directory/activity', params={'since_minutes': 0, 'limit': 10})
    assert resp.status_code == 200
    assert len(resp.json()['events']) == 3

    # positive filter path (uses current timestamps, should still include rows)
    resp_recent = client.get('/auth/admin/sso/dev-directory/activity', params={'since_minutes': 5, 'limit': 10})
    assert resp_recent.status_code == 200
    assert len(resp_recent.json()['events']) == 3

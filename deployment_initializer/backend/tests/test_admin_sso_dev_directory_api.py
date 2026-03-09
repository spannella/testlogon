from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

DB_PATH = '/tmp/deployment_initializer_admin_sso_dev_directory_test.db'
os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH

from app.db.session_store import get_session_store
from app.main import app
from app.services.auth import issue_root_session_token

ROOT_HEADERS = {'Authorization': f'Bearer {issue_root_session_token("root@example.com")}' }


class _FakeUser:
    def __init__(self, user_id: str, username: str, email: str | None, enabled: bool, groups: list[str]) -> None:
        self.user_id = user_id
        self.username = username
        self.email = email
        self.enabled = enabled
        self.groups = groups


def _client() -> TestClient:
    os.environ['DEPLOYMENT_SESSIONS_DB_PATH'] = DB_PATH
    get_session_store.cache_clear()
    path = Path(DB_PATH)
    if path.exists():
        path.unlink()
    return TestClient(app, headers=ROOT_HEADERS)


def test_dev_directory_api_disabled_by_default() -> None:
    os.environ.pop('ADMIN_SSO_DEV_DIRECTORY_API_ENABLED', None)
    os.environ['DEV_ENABLE_KEYCLOAK'] = '0'
    client = _client()

    response = client.get('/auth/admin/sso/dev-directory/users')
    assert response.status_code == 404
    assert response.json()['detail'] == 'dev_directory_api_disabled'


def test_dev_directory_list_users_and_groups() -> None:
    os.environ['ADMIN_SSO_DEV_DIRECTORY_API_ENABLED'] = '1'
    client = _client()

    import app.routers.admin_sso as admin_sso_router

    admin_sso_router.keycloak_admin_token = lambda: 'fake-token'
    admin_sso_router.list_keycloak_users = lambda token: [
        _FakeUser('u1', 'admin@example.com', 'admin@example.com', True, ['group-admins']),
        _FakeUser('u2', 'ops@example.com', 'ops@example.com', True, ['group-ops']),
    ]
    admin_sso_router.list_keycloak_groups = lambda token: ['group-admins', 'group-ops']

    users = client.get('/auth/admin/sso/dev-directory/users')
    assert users.status_code == 200
    assert users.json()['users'][0]['username'] == 'admin@example.com'
    assert users.json()['users'][1]['groups'] == ['group-ops']

    groups = client.get('/auth/admin/sso/dev-directory/groups')
    assert groups.status_code == 200
    assert groups.json()['groups'] == ['group-admins', 'group-ops']


def test_dev_directory_create_update_and_group_membership() -> None:
    os.environ['ADMIN_SSO_DEV_DIRECTORY_API_ENABLED'] = '1'
    client = _client()

    import app.routers.admin_sso as admin_sso_router

    admin_sso_router.keycloak_admin_token = lambda: 'fake-token'
    admin_sso_router.create_keycloak_user = lambda token, username, email, password, groups: _FakeUser(
        'u3', username, email, True, groups
    )
    admin_sso_router.update_keycloak_user = lambda token, username, email=None, enabled=None: _FakeUser(
        'u3', username, email or 'new@example.com', bool(enabled), ['group-admins']
    )
    admin_sso_router.add_user_to_group = lambda token, username, group_name: _FakeUser(
        'u3', username, 'new@example.com', True, ['group-admins', group_name]
    )
    admin_sso_router.remove_user_from_group = lambda token, username, group_name: _FakeUser(
        'u3', username, 'new@example.com', True, ['group-admins']
    )

    created = client.post(
        '/auth/admin/sso/dev-directory/users',
        json={
            'username': 'new@example.com',
            'email': 'new@example.com',
            'password': 'Passw0rd!',
            'groups': ['group-admins'],
        },
    )
    assert created.status_code == 200
    assert created.json()['groups'] == ['group-admins']

    updated = client.put('/auth/admin/sso/dev-directory/users/new@example.com', json={'enabled': False})
    assert updated.status_code == 200
    assert updated.json()['enabled'] is False

    added = client.post(
        '/auth/admin/sso/dev-directory/users/new@example.com/groups',
        json={'group_name': 'group-ops'},
    )
    assert added.status_code == 200
    assert 'group-ops' in added.json()['groups']

    removed = client.delete('/auth/admin/sso/dev-directory/users/new@example.com/groups/group-ops')
    assert removed.status_code == 200
    assert removed.json()['groups'] == ['group-admins']


def test_dev_directory_activity_returns_recent_audit_rows() -> None:
    os.environ['ADMIN_SSO_DEV_DIRECTORY_API_ENABLED'] = '1'
    client = _client()

    store = get_session_store()
    store.migrate()
    store.add_admin_sso_auth_audit_event(
        auth_method='ad_sso',
        outcome='failure',
        actor_email='admin@example.com',
        provider_id=None,
        external_subject='sub-1',
        external_tenant='tenant-1',
        mapped_role=None,
        failure_reason='sso_callback_invalid_nonce',
    )
    store.add_admin_sso_auth_audit_event(
        auth_method='ad_sso',
        outcome='success',
        actor_email='admin@example.com',
        provider_id=None,
        external_subject='sub-1',
        external_tenant='tenant-1',
        mapped_role='admin',
        failure_reason=None,
    )

    activity = client.get('/auth/admin/sso/dev-directory/activity', params={'limit': 5})
    assert activity.status_code == 200
    events = activity.json()['events']
    assert len(events) == 2
    assert events[0]['outcome'] == 'success'
    assert events[1]['failure_reason'] == 'sso_callback_invalid_nonce'
    assert events[0]['provider_id'] is None

    # correlated with real persisted rows
    conn = sqlite3.connect(DB_PATH)
    try:
        row_count = conn.execute('SELECT COUNT(*) FROM admin_sso_auth_audit_events').fetchone()[0]
        assert row_count == 2
    finally:
        conn.close()

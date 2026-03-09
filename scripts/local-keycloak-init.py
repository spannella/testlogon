#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import time
from typing import Any

import requests


KEYCLOAK_BASE_URL = os.getenv('KEYCLOAK_BASE_URL', 'http://localhost:8081').rstrip('/')
ADMIN_USERNAME = os.getenv('KEYCLOAK_ADMIN', 'admin')
ADMIN_PASSWORD = os.getenv('KEYCLOAK_ADMIN_PASSWORD', 'admin')
REALM_NAME = os.getenv('KEYCLOAK_REALM', 'local-ad')
CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'deployment-initializer-admin-sso')
REDIRECT_URI = os.getenv('KEYCLOAK_REDIRECT_URI', 'http://localhost:8000/auth/admin/sso/callback')

GROUPS = ['group-admins', 'group-ops', 'group-root-test']
USERS = [
    {'username': 'admin@example.com', 'email': 'admin@example.com', 'password': 'DevAdmin123!', 'groups': ['group-admins']},
    {'username': 'ops@example.com', 'email': 'ops@example.com', 'password': 'DevOps123!', 'groups': ['group-ops']},
]


def _request(method: str, path: str, token: str | None = None, **kwargs: Any) -> requests.Response:
    headers = kwargs.pop('headers', {})
    if token:
        headers['Authorization'] = f'Bearer {token}'
    url = f'{KEYCLOAK_BASE_URL}{path}'
    response = requests.request(method, url, headers=headers, timeout=10, **kwargs)
    return response


def _wait_for_keycloak_ready() -> None:
    deadline = time.time() + 90
    health_path = '/realms/master/.well-known/openid-configuration'
    while time.time() < deadline:
        try:
            response = _request('GET', health_path)
            if response.status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise RuntimeError(f'keycloak_not_ready: {KEYCLOAK_BASE_URL}{health_path}')


def _get_admin_token() -> str:
    response = _request(
        'POST',
        '/realms/master/protocol/openid-connect/token',
        data={
            'grant_type': 'password',
            'client_id': 'admin-cli',
            'username': ADMIN_USERNAME,
            'password': ADMIN_PASSWORD,
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    if response.status_code != 200:
        raise RuntimeError(f'keycloak_admin_token_failed: {response.status_code} {response.text}')
    return response.json()['access_token']


def _ensure_realm(token: str) -> None:
    realm_get = _request('GET', f'/admin/realms/{REALM_NAME}', token=token)
    if realm_get.status_code == 200:
        return
    if realm_get.status_code != 404:
        raise RuntimeError(f'keycloak_realm_lookup_failed: {realm_get.status_code} {realm_get.text}')

    create = _request(
        'POST',
        '/admin/realms',
        token=token,
        json={
            'realm': REALM_NAME,
            'enabled': True,
            'displayName': 'Local AD Realm',
        },
    )
    if create.status_code not in (201, 409):
        raise RuntimeError(f'keycloak_realm_create_failed: {create.status_code} {create.text}')


def _find_client(token: str) -> dict[str, Any] | None:
    response = _request('GET', f'/admin/realms/{REALM_NAME}/clients', token=token, params={'clientId': CLIENT_ID})
    if response.status_code != 200:
        raise RuntimeError(f'keycloak_client_lookup_failed: {response.status_code} {response.text}')
    clients = response.json()
    if not clients:
        return None
    return clients[0]


def _ensure_client(token: str) -> None:
    client = _find_client(token)
    payload = {
        'clientId': CLIENT_ID,
        'name': 'Deployment Initializer Admin SSO',
        'enabled': True,
        'protocol': 'openid-connect',
        'publicClient': False,
        'standardFlowEnabled': True,
        'directAccessGrantsEnabled': True,
        'redirectUris': [REDIRECT_URI],
        'webOrigins': ['*'],
    }

    if client is None:
        create = _request('POST', f'/admin/realms/{REALM_NAME}/clients', token=token, json=payload)
        if create.status_code not in (201, 409):
            raise RuntimeError(f'keycloak_client_create_failed: {create.status_code} {create.text}')
        return

    client_id_internal = client['id']
    update = _request('PUT', f'/admin/realms/{REALM_NAME}/clients/{client_id_internal}', token=token, json=payload)
    if update.status_code not in (204,):
        raise RuntimeError(f'keycloak_client_update_failed: {update.status_code} {update.text}')


def _ensure_group(token: str, group_name: str) -> dict[str, Any]:
    response = _request('GET', f'/admin/realms/{REALM_NAME}/groups', token=token, params={'search': group_name})
    if response.status_code != 200:
        raise RuntimeError(f'keycloak_group_lookup_failed: {response.status_code} {response.text}')
    for item in response.json():
        if item.get('name') == group_name:
            return item

    create = _request('POST', f'/admin/realms/{REALM_NAME}/groups', token=token, json={'name': group_name})
    if create.status_code not in (201, 204, 409):
        raise RuntimeError(f'keycloak_group_create_failed: {create.status_code} {create.text}')

    # read again to fetch id
    response = _request('GET', f'/admin/realms/{REALM_NAME}/groups', token=token, params={'search': group_name})
    if response.status_code != 200:
        raise RuntimeError(f'keycloak_group_relookup_failed: {response.status_code} {response.text}')
    for item in response.json():
        if item.get('name') == group_name:
            return item
    raise RuntimeError(f'keycloak_group_not_found_after_create:{group_name}')


def _find_user(token: str, username: str) -> dict[str, Any] | None:
    response = _request('GET', f'/admin/realms/{REALM_NAME}/users', token=token, params={'username': username})
    if response.status_code != 200:
        raise RuntimeError(f'keycloak_user_lookup_failed: {response.status_code} {response.text}')
    users = response.json()
    if not users:
        return None
    return users[0]


def _ensure_user(token: str, user: dict[str, Any], groups_by_name: dict[str, str]) -> None:
    existing = _find_user(token, user['username'])
    user_payload = {
        'username': user['username'],
        'email': user['email'],
        'enabled': True,
        'emailVerified': True,
    }

    if existing is None:
        create = _request('POST', f'/admin/realms/{REALM_NAME}/users', token=token, json=user_payload)
        if create.status_code not in (201, 409):
            raise RuntimeError(f'keycloak_user_create_failed: {create.status_code} {create.text}')
        existing = _find_user(token, user['username'])
        if existing is None:
            raise RuntimeError(f'keycloak_user_missing_after_create:{user["username"]}')
    else:
        update = _request('PUT', f'/admin/realms/{REALM_NAME}/users/{existing["id"]}', token=token, json=user_payload)
        if update.status_code not in (204,):
            raise RuntimeError(f'keycloak_user_update_failed: {update.status_code} {update.text}')

    reset = _request(
        'PUT',
        f'/admin/realms/{REALM_NAME}/users/{existing["id"]}/reset-password',
        token=token,
        json={
            'type': 'password',
            'value': user['password'],
            'temporary': False,
        },
    )
    if reset.status_code not in (204,):
        raise RuntimeError(f'keycloak_user_password_set_failed: {reset.status_code} {reset.text}')

    current_groups_resp = _request('GET', f'/admin/realms/{REALM_NAME}/users/{existing["id"]}/groups', token=token)
    if current_groups_resp.status_code != 200:
        raise RuntimeError(f'keycloak_user_groups_lookup_failed: {current_groups_resp.status_code} {current_groups_resp.text}')
    current_group_ids = {group['id'] for group in current_groups_resp.json()}

    for group_name in user['groups']:
        group_id = groups_by_name[group_name]
        if group_id in current_group_ids:
            continue
        join = _request('PUT', f'/admin/realms/{REALM_NAME}/users/{existing["id"]}/groups/{group_id}', token=token)
        if join.status_code not in (204,):
            raise RuntimeError(f'keycloak_user_group_add_failed: {join.status_code} {join.text}')


def main() -> int:
    try:
        _wait_for_keycloak_ready()
        token = _get_admin_token()
        _ensure_realm(token)
        _ensure_client(token)

        groups_by_name: dict[str, str] = {}
        for group_name in GROUPS:
            group = _ensure_group(token, group_name)
            groups_by_name[group_name] = group['id']

        for user in USERS:
            _ensure_user(token, user, groups_by_name)

        discovery = _request('GET', f'/realms/{REALM_NAME}/.well-known/openid-configuration')
        if discovery.status_code != 200:
            raise RuntimeError(f'keycloak_discovery_unreachable: {discovery.status_code} {discovery.text}')
        jwks = _request('GET', f'/realms/{REALM_NAME}/protocol/openid-connect/certs')
        if jwks.status_code != 200:
            raise RuntimeError(f'keycloak_jwks_unreachable: {jwks.status_code} {jwks.text}')

        print(f'Keycloak realm seeded successfully: {REALM_NAME}')
        print(f'Issuer: {KEYCLOAK_BASE_URL}/realms/{REALM_NAME}')
        print(f'Client ID: {CLIENT_ID}')
        print(f'Redirect URI: {REDIRECT_URI}')
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f'local-keycloak-init failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

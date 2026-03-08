#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone
from typing import Any

import requests

KEYCLOAK_BASE_URL = os.getenv('KEYCLOAK_BASE_URL', 'http://localhost:8081').rstrip('/')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'local-ad')
KEYCLOAK_ADMIN = os.getenv('KEYCLOAK_ADMIN', 'admin')
KEYCLOAK_ADMIN_PASSWORD = os.getenv('KEYCLOAK_ADMIN_PASSWORD', 'admin')
KEY_PRIORITY = os.getenv('KEYCLOAK_ROTATED_KEY_PRIORITY', '200')


def _request(method: str, path: str, token: str | None = None, **kwargs: Any) -> requests.Response:
    headers = kwargs.pop('headers', {})
    if token:
        headers['Authorization'] = f'Bearer {token}'
    response = requests.request(method, f'{KEYCLOAK_BASE_URL}{path}', headers=headers, timeout=10, **kwargs)
    return response


def _admin_token() -> str:
    response = _request(
        'POST',
        '/realms/master/protocol/openid-connect/token',
        data={
            'grant_type': 'password',
            'client_id': 'admin-cli',
            'username': KEYCLOAK_ADMIN,
            'password': KEYCLOAK_ADMIN_PASSWORD,
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    response.raise_for_status()
    return response.json()['access_token']


def _active_rsa_kid(token: str) -> str:
    response = _request('GET', f'/admin/realms/{KEYCLOAK_REALM}/keys', token=token)
    response.raise_for_status()
    keys = response.json().get('keys', [])
    for key in keys:
        if key.get('type') == 'RSA' and key.get('status') == 'ACTIVE' and key.get('use') == 'SIG':
            kid = key.get('kid')
            if isinstance(kid, str) and kid:
                return kid
    raise RuntimeError('active_rsa_key_not_found')


def _create_rotated_key(token: str) -> None:
    component_name = f'rotation-{int(datetime.now(tz=timezone.utc).timestamp())}'
    response = _request(
        'POST',
        f'/admin/realms/{KEYCLOAK_REALM}/components',
        token=token,
        json={
            'name': component_name,
            'providerId': 'rsa-generated',
            'providerType': 'org.keycloak.keys.KeyProvider',
            'parentId': KEYCLOAK_REALM,
            'config': {
                'enabled': ['true'],
                'active': ['true'],
                'priority': [str(KEY_PRIORITY)],
                'algorithm': ['RS256'],
            },
        },
    )
    if response.status_code not in (201, 204):
        raise RuntimeError(f'rotation_component_create_failed: {response.status_code} {response.text}')


def main() -> int:
    try:
        token = _admin_token()
        before = _active_rsa_kid(token)
        _create_rotated_key(token)

        deadline = time.time() + 30
        after = before
        while time.time() < deadline:
            after = _active_rsa_kid(token)
            if after != before:
                break
            time.sleep(1)

        print(f'Key rotation requested for realm={KEYCLOAK_REALM}')
        print(f'Active signing kid before: {before}')
        print(f'Active signing kid after:  {after}')

        if after == before:
            print('Warning: active signing key did not change within timeout.', file=sys.stderr)
            return 2
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f'local-keycloak-rotate-keys failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

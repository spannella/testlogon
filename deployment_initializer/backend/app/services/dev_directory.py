from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import requests
from fastapi import HTTPException


@dataclass(frozen=True)
class DevDirectoryConfig:
    base_url: str
    realm: str
    admin_username: str
    admin_password: str


@dataclass(frozen=True)
class DevDirectoryUser:
    user_id: str
    username: str
    email: str | None
    enabled: bool
    groups: list[str]


def _dev_directory_enabled() -> bool:
    explicit = os.getenv('ADMIN_SSO_DEV_DIRECTORY_API_ENABLED')
    if explicit is not None:
        return explicit.lower() in {'1', 'true', 'yes', 'on'}
    return os.getenv('DEV_ENABLE_KEYCLOAK', '0') == '1'


def require_dev_directory_enabled() -> None:
    if not _dev_directory_enabled():
        raise HTTPException(status_code=404, detail='dev_directory_api_disabled')

    app_env = os.getenv('APP_ENV', os.getenv('ENV', 'dev')).lower()
    if app_env in {'prod', 'production'}:
        raise HTTPException(status_code=403, detail='dev_directory_api_forbidden_in_production')


def _config() -> DevDirectoryConfig:
    return DevDirectoryConfig(
        base_url=os.getenv('KEYCLOAK_BASE_URL', 'http://localhost:8081').rstrip('/'),
        realm=os.getenv('KEYCLOAK_REALM', 'local-ad'),
        admin_username=os.getenv('KEYCLOAK_ADMIN', 'admin'),
        admin_password=os.getenv('KEYCLOAK_ADMIN_PASSWORD', 'admin'),
    )


def _request(method: str, path: str, *, token: str | None = None, **kwargs: Any) -> requests.Response:
    cfg = _config()
    headers = kwargs.pop('headers', {})
    if token:
        headers['Authorization'] = f'Bearer {token}'
    try:
        response = requests.request(method, f'{cfg.base_url}{path}', headers=headers, timeout=10, **kwargs)
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail='dev_directory_unreachable') from exc
    return response


def _raise_for_unexpected(response: requests.Response, action: str) -> None:
    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=f'dev_directory_{action}_failed:{response.status_code}',
        )


def keycloak_admin_token() -> str:
    cfg = _config()
    response = _request(
        'POST',
        '/realms/master/protocol/openid-connect/token',
        data={
            'grant_type': 'password',
            'client_id': 'admin-cli',
            'username': cfg.admin_username,
            'password': cfg.admin_password,
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    _raise_for_unexpected(response, 'admin_token')
    token = response.json().get('access_token')
    if not isinstance(token, str) or not token:
        raise HTTPException(status_code=502, detail='dev_directory_admin_token_missing')
    return token


def list_keycloak_groups(token: str) -> list[str]:
    cfg = _config()
    response = _request('GET', f'/admin/realms/{cfg.realm}/groups', token=token)
    _raise_for_unexpected(response, 'list_groups')
    groups: list[str] = []
    for item in response.json():
        name = item.get('name')
        if isinstance(name, str):
            groups.append(name)
    return sorted(groups)


def _user_groups(token: str, user_id: str) -> list[str]:
    cfg = _config()
    response = _request('GET', f'/admin/realms/{cfg.realm}/users/{quote(user_id)}/groups', token=token)
    _raise_for_unexpected(response, 'list_user_groups')
    names: list[str] = []
    for item in response.json():
        name = item.get('name')
        if isinstance(name, str):
            names.append(name)
    return sorted(names)


def list_keycloak_users(token: str) -> list[DevDirectoryUser]:
    cfg = _config()
    response = _request('GET', f'/admin/realms/{cfg.realm}/users', token=token, params={'max': 200})
    _raise_for_unexpected(response, 'list_users')

    users: list[DevDirectoryUser] = []
    for item in response.json():
        user_id = str(item.get('id') or '')
        if not user_id:
            continue
        users.append(
            DevDirectoryUser(
                user_id=user_id,
                username=str(item.get('username') or ''),
                email=item.get('email') if isinstance(item.get('email'), str) else None,
                enabled=bool(item.get('enabled', True)),
                groups=_user_groups(token, user_id),
            )
        )
    users.sort(key=lambda u: u.username)
    return users


def _find_group(token: str, group_name: str) -> dict[str, Any]:
    cfg = _config()
    response = _request('GET', f'/admin/realms/{cfg.realm}/groups', token=token, params={'search': group_name})
    _raise_for_unexpected(response, 'find_group')
    for item in response.json():
        if item.get('name') == group_name:
            return item
    raise HTTPException(status_code=404, detail='dev_directory_group_not_found')


def _find_user(token: str, username: str) -> dict[str, Any]:
    cfg = _config()
    response = _request('GET', f'/admin/realms/{cfg.realm}/users', token=token, params={'username': username})
    _raise_for_unexpected(response, 'find_user')
    for item in response.json():
        if item.get('username') == username:
            return item
    raise HTTPException(status_code=404, detail='dev_directory_user_not_found')


def create_keycloak_user(token: str, *, username: str, email: str | None, password: str, groups: list[str]) -> DevDirectoryUser:
    cfg = _config()
    payload: dict[str, Any] = {
        'username': username,
        'enabled': True,
        'emailVerified': True,
    }
    if email:
        payload['email'] = email

    response = _request('POST', f'/admin/realms/{cfg.realm}/users', token=token, json=payload)
    if response.status_code not in (201, 409):
        _raise_for_unexpected(response, 'create_user')

    user = _find_user(token, username)
    user_id = str(user['id'])

    pwd_resp = _request(
        'PUT',
        f'/admin/realms/{cfg.realm}/users/{quote(user_id)}/reset-password',
        token=token,
        json={'type': 'password', 'value': password, 'temporary': False},
    )
    if pwd_resp.status_code != 204:
        _raise_for_unexpected(pwd_resp, 'set_user_password')

    for group_name in groups:
        add_user_to_group(token, username=username, group_name=group_name)

    return get_keycloak_user(token, username)


def update_keycloak_user(token: str, *, username: str, email: str | None = None, enabled: bool | None = None) -> DevDirectoryUser:
    cfg = _config()
    user = _find_user(token, username)
    user_id = str(user['id'])

    payload = {
        'username': username,
        'email': email if email is not None else user.get('email'),
        'enabled': bool(enabled) if enabled is not None else bool(user.get('enabled', True)),
        'emailVerified': True,
    }
    response = _request('PUT', f'/admin/realms/{cfg.realm}/users/{quote(user_id)}', token=token, json=payload)
    if response.status_code != 204:
        _raise_for_unexpected(response, 'update_user')

    return get_keycloak_user(token, username)


def add_user_to_group(token: str, *, username: str, group_name: str) -> DevDirectoryUser:
    cfg = _config()
    user = _find_user(token, username)
    group = _find_group(token, group_name)

    response = _request(
        'PUT',
        f'/admin/realms/{cfg.realm}/users/{quote(str(user["id"]))}/groups/{quote(str(group["id"]))}',
        token=token,
    )
    if response.status_code != 204:
        _raise_for_unexpected(response, 'add_user_group')
    return get_keycloak_user(token, username)


def remove_user_from_group(token: str, *, username: str, group_name: str) -> DevDirectoryUser:
    cfg = _config()
    user = _find_user(token, username)
    group = _find_group(token, group_name)

    response = _request(
        'DELETE',
        f'/admin/realms/{cfg.realm}/users/{quote(str(user["id"]))}/groups/{quote(str(group["id"]))}',
        token=token,
    )
    if response.status_code != 204:
        _raise_for_unexpected(response, 'remove_user_group')
    return get_keycloak_user(token, username)


def get_keycloak_user(token: str, username: str) -> DevDirectoryUser:
    user = _find_user(token, username)
    user_id = str(user['id'])
    return DevDirectoryUser(
        user_id=user_id,
        username=str(user.get('username') or username),
        email=user.get('email') if isinstance(user.get('email'), str) else None,
        enabled=bool(user.get('enabled', True)),
        groups=_user_groups(token, user_id),
    )


def _troubleshooting_context(failure_reason: str | None) -> tuple[str | None, str | None]:
    if not failure_reason:
        return None, None

    mapping = {
        'sso_callback_invalid_issuer': ('issuer_mismatch', 'Verify provider issuer matches OIDC discovery issuer exactly.'),
        'sso_callback_invalid_audience': ('audience_mismatch', 'Verify provider client_id matches the IdP client audience.'),
        'sso_callback_invalid_nonce': ('nonce_mismatch', 'Retry login flow from /start; nonce/state must be single-use and fresh.'),
        'sso_callback_invalid_signature': ('signature_invalid', 'Check IdP signing key/JWKS availability and token integrity.'),
        'sso_callback_jwks_unreachable': ('jwks_unreachable', 'Check JWKS endpoint reachability and refresh after key rotation.'),
        'sso_callback_token_expired': ('token_expired', 'Retry login to obtain a fresh id_token.'),
        'sso_role_mapping_denied': ('role_mapping_denied', 'User groups do not map to an internal role; adjust mappings.'),
        'sso_root_role_forbidden': ('root_forbidden', 'External identities cannot map to root; use admin/operator roles only.'),
        'sso_callback_missing_required_claims': ('claims_missing', 'Ensure token includes required claims (sub, tenant_id/tid).'),
    }
    if failure_reason in mapping:
        return mapping[failure_reason]
    return 'other', 'Inspect failure_reason and provider config for mismatch.'


def list_recent_admin_sso_activity(
    *,
    db_path: str,
    limit: int = 50,
    actor_email: str | None = None,
    provider_id: str | None = None,
    outcome: str | None = None,
    since_minutes: int | None = None,
) -> list[dict[str, Any]]:
    bounded_limit = max(1, min(limit, 200))

    filters: list[str] = []
    params: list[Any] = []
    if actor_email:
        filters.append('actor_email = ?')
        params.append(actor_email)
    if provider_id:
        filters.append('provider_id = ?')
        params.append(provider_id)
    if outcome:
        filters.append('outcome = ?')
        params.append(outcome)
    if since_minutes is not None and since_minutes > 0:
        since = datetime.now(tz=timezone.utc) - timedelta(minutes=since_minutes)
        filters.append('created_at >= ?')
        params.append(since.isoformat())

    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ''

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            f"""
            SELECT id AS event_id, 'callback' AS event_type, auth_method, outcome, actor_email, provider_id,
                   external_subject, external_tenant, mapped_role, failure_reason,
                   created_at
            FROM admin_sso_auth_audit_events
            {where_clause}
            ORDER BY id DESC
            LIMIT ?
            """,
            (*params, bounded_limit),
        ).fetchall()

        events: list[dict[str, Any]] = []
        for row in rows:
            event = dict(row)
            category, hint = _troubleshooting_context(event.get('failure_reason'))
            event['troubleshooting_category'] = category
            event['troubleshooting_hint'] = hint
            events.append(event)
        return events
    finally:
        conn.close()

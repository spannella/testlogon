from __future__ import annotations

from dataclasses import dataclass
import os

from fastapi import Header, HTTPException


@dataclass(frozen=True)
class Principal:
    email: str
    role: str
    provider: str = 'sso'


def _parse_bearer_token(authorization: str | None) -> Principal | None:
    if not authorization:
        return None
    if not authorization.lower().startswith('bearer '):
        return None
    token = authorization.split(' ', 1)[1].strip()
    if token.startswith('sso:'):
        parts = token.split(':')
        if len(parts) not in {3, 4}:
            return None
        _, email, role = parts[:3]
        provider = parts[3] if len(parts) == 4 else 'sso'
        return Principal(email=email, role=role, provider=provider)
    if token.startswith('root:'):
        parts = token.split(':')
        if len(parts) != 3:
            return None
        _, email, role = parts
        return Principal(email=email, role=role, provider='local_root')
    return None


def issue_sso_session_token(email: str, role: str, auth_method: str = 'sso') -> str:
    return f'sso:{email}:{role}:{auth_method}'


def issue_root_session_token(email: str) -> str:
    return f'root:{email}:root'


def _enforce_admin_sso_for_non_root() -> bool:
    return os.getenv('ADMIN_SSO_ENFORCE_FOR_ADMINS', 'false').lower() in {'1', 'true', 'yes', 'on'}


def get_authenticated_principal(
    authorization: str | None = Header(default=None, alias='Authorization'),
    sso_email: str | None = Header(default=None, alias='X-SSO-Email'),
    sso_role: str | None = Header(default=None, alias='X-SSO-Role'),
) -> Principal:
    principal = _parse_bearer_token(authorization)
    if principal is None and sso_email and sso_role:
        principal = Principal(email=sso_email, role=sso_role)

    if principal is None:
        raise HTTPException(status_code=401, detail='unauthorized')

    normalized_role = principal.role.lower()
    if normalized_role not in {'viewer', 'operator', 'admin', 'root'}:
        raise HTTPException(status_code=403, detail='forbidden_invalid_role')

    if normalized_role == 'admin' and _enforce_admin_sso_for_non_root():
        if principal.provider != 'ad_sso':
            raise HTTPException(status_code=403, detail='forbidden_admin_sso_required')

    return Principal(email=principal.email, role=normalized_role, provider=principal.provider)


def require_role(principal: Principal, allowed_roles: set[str]) -> None:
    if principal.role == 'root':
        return
    if principal.role not in allowed_roles:
        raise HTTPException(status_code=403, detail='forbidden_insufficient_role')

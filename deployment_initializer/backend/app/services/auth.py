from __future__ import annotations

from dataclasses import dataclass

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
    if not token.startswith('sso:'):
        return None
    parts = token.split(':')
    if len(parts) != 3:
        return None
    _, email, role = parts
    return Principal(email=email, role=role)


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
    if normalized_role not in {'viewer', 'operator', 'admin'}:
        raise HTTPException(status_code=403, detail='forbidden_invalid_role')

    return Principal(email=principal.email, role=normalized_role, provider=principal.provider)


def require_role(principal: Principal, allowed_roles: set[str]) -> None:
    if principal.role not in allowed_roles:
        raise HTTPException(status_code=403, detail='forbidden_insufficient_role')

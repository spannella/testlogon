from __future__ import annotations

from typing import Iterable

from fastapi import Depends, HTTPException

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role, normalize_role


def role_required_error(*, required: Iterable[Role], actual: Role) -> HTTPException:
    required_values = sorted({r.value for r in required})
    return HTTPException(
        status_code=403,
        detail={
            "code": "role_required",
            "required_roles": required_values,
            "actual_role": actual.value,
        },
    )


def require_roles(user: AuthenticatedUser, allowed: set[Role]) -> AuthenticatedUser:
    role = normalize_role(user.role)
    if role not in allowed:
        raise role_required_error(required=allowed, actual=role)
    return user


def require_role_value(role_value: str | Role | None, allowed: set[Role]) -> Role:
    role = normalize_role(role_value)
    if role not in allowed:
        raise role_required_error(required=allowed, actual=role)
    return role


async def require_root(user: AuthenticatedUser = Depends(get_authenticated_user)) -> AuthenticatedUser:
    return require_roles(user, {Role.ROOT})


async def require_admin_or_root(user: AuthenticatedUser = Depends(get_authenticated_user)) -> AuthenticatedUser:
    return require_roles(user, {Role.ADMIN, Role.ROOT})


def require_self_or_admin(*, actor: AuthenticatedUser, target_user_sub: str) -> AuthenticatedUser:
    if actor.sub == target_user_sub:
        return actor
    return require_roles(actor, {Role.ADMIN, Role.ROOT})


def require_assignable_role(role_value: str | Role | None) -> Role:
    """Disallow granting root through mutable API paths."""
    role = normalize_role(role_value)
    if role is Role.ROOT:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "role_required",
                "required_roles": [Role.ADMIN.value],
                "actual_role": Role.ROOT.value,
            },
        )
    return role

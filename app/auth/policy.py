from __future__ import annotations

from typing import Callable, Iterable

from fastapi import Depends, HTTPException, Request

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import AdminProfileType, AdminScope, Role, admin_profile_has_scope, normalize_admin_profile, normalize_admin_scope, normalize_role
from app.metrics import record_admin_scope_denied
from app.services.alerts import audit_event


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


def role_required_scope_error(*, required_scope: AdminScope, user: AuthenticatedUser) -> HTTPException:
    return HTTPException(
        status_code=403,
        detail={
            "code": "role_required_scope",
            "required_scope": required_scope.value,
            "actual_role": normalize_role(user.role).value,
            "actual_admin_profile": normalize_admin_profile(getattr(user, "admin_profile", None)).to_dict(),
        },
    )


def role_required_admin_profile_type_error(*, required_profile_type: AdminProfileType, user: AuthenticatedUser) -> HTTPException:
    return HTTPException(
        status_code=403,
        detail={
            "code": "role_required_admin_profile_type",
            "required_admin_profile_type": required_profile_type.value,
            "actual_role": normalize_role(user.role).value,
            "actual_admin_profile": normalize_admin_profile(getattr(user, "admin_profile", None)).to_dict(),
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


async def require_general_admin_or_root(user: AuthenticatedUser = Depends(get_authenticated_user)) -> AuthenticatedUser:
    role = normalize_role(user.role)
    if role is Role.ROOT:
        return user
    if role is not Role.ADMIN:
        raise role_required_error(required={Role.ADMIN, Role.ROOT}, actual=role)

    profile = normalize_admin_profile(getattr(user, "admin_profile", None))
    if profile.type is not AdminProfileType.GENERAL:
        raise role_required_admin_profile_type_error(required_profile_type=AdminProfileType.GENERAL, user=user)
    return user


def require_admin_scope(scope: AdminScope | str) -> Callable[..., AuthenticatedUser]:
    normalized_scope = normalize_admin_scope(scope)
    if normalized_scope is None:
        raise ValueError(f"Unknown admin scope: {scope}")

    async def _require_admin_scope(
        request: Request,
        user: AuthenticatedUser = Depends(get_authenticated_user),
    ) -> AuthenticatedUser:
        role = normalize_role(user.role)
        if role is Role.ROOT:
            return user
        if role is not Role.ADMIN:
            raise role_required_error(required={Role.ADMIN, Role.ROOT}, actual=role)

        profile = normalize_admin_profile(getattr(user, "admin_profile", None))
        if not admin_profile_has_scope(profile, normalized_scope):
            route = "unknown"
            request_scope = getattr(request, "scope", None)
            if isinstance(request_scope, dict):
                route_obj = request_scope.get("route")
                route_path = getattr(route_obj, "path", None)
                if isinstance(route_path, str) and route_path:
                    route = route_path
            if route == "unknown":
                request_url = getattr(request, "url", None)
                url_path = getattr(request_url, "path", None)
                if isinstance(url_path, str) and url_path:
                    route = url_path
            record_admin_scope_denied(
                route=route,
                required_scope=normalized_scope.value,
                admin_profile_type=profile.type.value,
            )
            audit_event(
                "admin_scope_denied",
                user.sub,
                request,
                outcome="error",
                status_code=403,
                required_scope=normalized_scope.value,
                actual_role=role.value,
                actual_admin_profile=profile.to_dict(),
            )
            raise role_required_scope_error(required_scope=normalized_scope, user=user)
        return user

    return _require_admin_scope


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

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Role(str, Enum):
    ROOT = "root"
    ADMIN = "admin"
    USER = "user"


class AdminScope(str, Enum):
    AUTH_SUPPORT = "auth_support"
    BILLING_SUPPORT = "billing_support"
    CONTENT_MODERATION = "content_moderation"


class AdminProfileType(str, Enum):
    GENERAL = "general"
    SCOPED = "scoped"


CANONICAL_ADMIN_SCOPES: tuple[AdminScope, ...] = (
    AdminScope.AUTH_SUPPORT,
    AdminScope.BILLING_SUPPORT,
    AdminScope.CONTENT_MODERATION,
)


@dataclass(frozen=True)
class AdminProfile:
    type: AdminProfileType = AdminProfileType.GENERAL
    scopes: tuple[AdminScope, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        if self.type is AdminProfileType.GENERAL:
            return {"type": AdminProfileType.GENERAL.value}
        return {
            "type": AdminProfileType.SCOPED.value,
            "scopes": [scope.value for scope in self.scopes],
        }


def normalize_role(value: Any) -> Role:
    """Return canonical role. Unknown/missing values default to `user`."""
    if isinstance(value, Role):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        for role in Role:
            if role.value == normalized:
                return role
    return Role.USER


def role_allows_admin_features(role: Role) -> bool:
    return role in {Role.ADMIN, Role.ROOT}


def normalize_admin_scope(value: Any) -> AdminScope | None:
    if isinstance(value, AdminScope):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        for scope in CANONICAL_ADMIN_SCOPES:
            if normalized == scope.value:
                return scope
    return None


def normalize_admin_profile(value: Any) -> AdminProfile:
    """
    Return canonical admin profile.

    Fallback is always `general` to preserve current broad-admin behavior when
    data is missing/malformed.
    """
    if isinstance(value, AdminProfile):
        if value.type is AdminProfileType.GENERAL:
            return AdminProfile(type=AdminProfileType.GENERAL)
        scopes = sorted(set(value.scopes), key=lambda item: item.value)
        if not scopes:
            return AdminProfile(type=AdminProfileType.GENERAL)
        return AdminProfile(type=AdminProfileType.SCOPED, scopes=tuple(scopes))

    if not isinstance(value, dict):
        return AdminProfile(type=AdminProfileType.GENERAL)

    profile_type_raw = value.get("type")
    profile_type = None
    if isinstance(profile_type_raw, AdminProfileType):
        profile_type = profile_type_raw
    elif isinstance(profile_type_raw, str):
        normalized_type = profile_type_raw.strip().lower()
        for candidate in AdminProfileType:
            if candidate.value == normalized_type:
                profile_type = candidate
                break

    if profile_type is not AdminProfileType.SCOPED:
        return AdminProfile(type=AdminProfileType.GENERAL)

    raw_scopes = value.get("scopes")
    if not isinstance(raw_scopes, list):
        return AdminProfile(type=AdminProfileType.GENERAL)

    normalized_scopes = [normalize_admin_scope(scope) for scope in raw_scopes]
    scoped = sorted({scope for scope in normalized_scopes if scope is not None}, key=lambda item: item.value)
    if not scoped:
        return AdminProfile(type=AdminProfileType.GENERAL)
    return AdminProfile(type=AdminProfileType.SCOPED, scopes=tuple(scoped))


def admin_profile_has_scope(profile: AdminProfile, scope: AdminScope | str) -> bool:
    normalized = normalize_admin_scope(scope)
    if normalized is None:
        return False
    if profile.type is AdminProfileType.GENERAL:
        return True
    return normalized in profile.scopes

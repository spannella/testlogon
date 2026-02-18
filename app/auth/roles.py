from __future__ import annotations

from enum import Enum
from typing import Any


class Role(str, Enum):
    ROOT = "root"
    ADMIN = "admin"
    USER = "user"


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

from __future__ import annotations

import re

from fastapi import HTTPException

from app.auth.roles import Role, normalize_role
from app.core.settings import S

_ROOT_SUB_RE = re.compile(r"^[A-Za-z0-9._:@/-]{3,128}$")


def validate_root_user_sub_config() -> str:
    root_sub = (S.root_user_sub or "").strip()
    if not root_sub:
        raise RuntimeError("ROOT_USER_SUB must be configured")
    if not _ROOT_SUB_RE.fullmatch(root_sub):
        raise RuntimeError("ROOT_USER_SUB is invalid; use 3-128 chars [A-Za-z0-9._:@/-]")
    return root_sub


def enforce_root_role_invariant(*, user_sub: str, role: Role) -> Role:
    normalized_role = normalize_role(role)
    if normalized_role is not Role.ROOT:
        return normalized_role
    root_sub = validate_root_user_sub_config()
    if user_sub != root_sub:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "role_required",
                "required_roles": [Role.USER.value],
                "actual_role": Role.ROOT.value,
                "message": "root role reserved for configured ROOT_USER_SUB",
            },
        )
    return Role.ROOT


def validate_startup_root_invariant() -> None:
    validate_root_user_sub_config()

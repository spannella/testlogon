from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_role_value, require_roles, require_self_or_admin
from app.auth.roles import Role


def test_require_roles_allows_admin() -> None:
    user = AuthenticatedUser(sub="u1", role=Role.ADMIN)
    allowed = require_roles(user, {Role.ADMIN, Role.ROOT})
    assert allowed is user


def test_require_roles_denies_user_with_standardized_error() -> None:
    user = AuthenticatedUser(sub="u1", role=Role.USER)
    with pytest.raises(HTTPException) as exc:
        require_roles(user, {Role.ADMIN, Role.ROOT})
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "role_required"
    assert exc.value.detail["required_roles"] == ["admin", "root"]
    assert exc.value.detail["actual_role"] == "user"


def test_require_role_value_defaults_unknown_to_user_and_denies() -> None:
    with pytest.raises(HTTPException) as exc:
        require_role_value("nonsense", {Role.ADMIN})
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "role_required"


def test_require_self_or_admin_allows_self() -> None:
    actor = AuthenticatedUser(sub="u1", role=Role.USER)
    out = require_self_or_admin(actor=actor, target_user_sub="u1")
    assert out is actor


def test_require_self_or_admin_denies_non_admin_other_user() -> None:
    actor = AuthenticatedUser(sub="u1", role=Role.USER)
    with pytest.raises(HTTPException) as exc:
        require_self_or_admin(actor=actor, target_user_sub="u2")
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "role_required"

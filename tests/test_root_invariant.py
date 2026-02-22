from __future__ import annotations

import pytest

from app.auth.policy import require_assignable_role
from app.auth.root_invariant import validate_root_user_sub_config
from app.auth.roles import Role
from app.core.settings import S


@pytest.fixture(autouse=True)
def restore_root_user_sub():
    """Restore S.root_user_sub after each test that may mutate it."""
    original = S.root_user_sub
    yield
    object.__setattr__(S, "root_user_sub", original)


def test_validate_root_user_sub_config_rejects_missing() -> None:
    object.__setattr__(S, "root_user_sub", "")
    with pytest.raises(RuntimeError):
        validate_root_user_sub_config()


def test_validate_root_user_sub_config_rejects_invalid_chars() -> None:
    object.__setattr__(S, "root_user_sub", "bad root!")
    with pytest.raises(RuntimeError):
        validate_root_user_sub_config()


def test_validate_root_user_sub_config_accepts_valid_value() -> None:
    object.__setattr__(S, "root_user_sub", "root-user_1")
    assert validate_root_user_sub_config() == "root-user_1"


def test_require_assignable_role_blocks_root() -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        require_assignable_role("root")
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "role_required"


def test_require_assignable_role_allows_admin_and_user() -> None:
    assert require_assignable_role("admin") == Role.ADMIN
    assert require_assignable_role("user") == Role.USER

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from fastapi import HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root, require_root, require_self_or_admin
from app.auth.roles import Role
from app.routers import admin_impersonation, billing, filemanager, root_auth


@pytest.mark.parametrize(
    "actor_role, target, allowed",
    [
        (Role.USER, "u1", True),
        (Role.USER, "u2", False),
        (Role.ADMIN, "u2", True),
        (Role.ROOT, "u2", True),
    ],
)
def test_policy_matrix_self_or_admin(actor_role: Role, target: str, allowed: bool) -> None:
    actor = AuthenticatedUser(sub="u1", role=actor_role)
    if allowed:
        out = require_self_or_admin(actor=actor, target_user_sub=target)
        assert out is actor
    else:
        with pytest.raises(HTTPException) as exc:
            require_self_or_admin(actor=actor, target_user_sub=target)
        assert exc.value.status_code == 403
        assert exc.value.detail["code"] == "role_required"


@pytest.mark.parametrize(
    "role, requires_root_ok, admin_or_root_ok",
    [
        (Role.USER, False, False),
        (Role.ADMIN, False, True),
        (Role.ROOT, True, True),
    ],
)
def test_policy_matrix_root_vs_admin_guards(role: Role, requires_root_ok: bool, admin_or_root_ok: bool) -> None:
    user = AuthenticatedUser(sub="u1", role=role)

    if requires_root_ok:
        import asyncio
        out = asyncio.run(require_root(user=user))
        assert out is user
    else:
        with pytest.raises(HTTPException):
            import asyncio
            asyncio.run(require_root(user=user))

    if admin_or_root_ok:
        import asyncio
        out = asyncio.run(require_admin_or_root(user=user))
        assert out is user
    else:
        with pytest.raises(HTTPException):
            import asyncio
            asyncio.run(require_admin_or_root(user=user))


@pytest.mark.parametrize(
    "ctx,target,allowed",
    [
        ({"user_sub": "u1", "role": "user"}, None, True),
        ({"user_sub": "u1", "role": "user"}, "u1", True),
        ({"user_sub": "u1", "role": "user"}, "u2", False),
        ({"user_sub": "a1", "role": "admin"}, "u2", True),
        ({"user_sub": "r1", "role": "root"}, "u2", True),
    ],
)
def test_policy_matrix_billing_read_scope(ctx: dict, target: str | None, allowed: bool) -> None:
    if allowed:
        out = billing._billing_read_user_sub(ctx, target)
        assert out == (target or ctx["user_sub"])
    else:
        with pytest.raises(HTTPException) as exc:
            billing._billing_read_user_sub(ctx, target)
        assert exc.value.status_code == 403
        assert exc.value.detail["code"] == "role_required"


@pytest.mark.parametrize(
    "ctx,target,allowed,expected_target",
    [
        ({"user_sub": "u1", "role": "user"}, None, True, "u1"),
        ({"user_sub": "u1", "role": "user"}, "u1", True, "u1"),
        ({"user_sub": "u1", "role": "user"}, "u2", False, None),
        ({"user_sub": "a1", "role": "admin"}, "u2", True, "u2"),
        ({"user_sub": "r1", "role": "root"}, "u2", True, "u2"),
    ],
)
def test_policy_matrix_billing_write_scope(ctx: dict, target: str | None, allowed: bool, expected_target: str | None) -> None:
    if allowed:
        user_sub, tags = billing._billing_write_user_context(ctx, target)
        assert user_sub == expected_target
        if target and target != ctx["user_sub"]:
            assert tags["viewed_as_admin"] is True
            assert tags["effective_sub"] == target
        else:
            assert tags == {}
    else:
        with pytest.raises(HTTPException):
            billing._billing_write_user_context(ctx, target)


def test_policy_matrix_file_admin_ctx_guard() -> None:
    assert filemanager._admin_or_root_ctx({"user_sub": "a1", "role": "admin"})["role"] == "admin"
    assert filemanager._admin_or_root_ctx({"user_sub": "r1", "role": "root"})["role"] == "root"
    with pytest.raises(HTTPException):
        filemanager._admin_or_root_ctx({"user_sub": "u1", "role": "user"})


@pytest.mark.parametrize(
    "tier,role,allowed",
    [
        ("none", "admin", False),
        ("none", "root", False),
        ("root_only", "admin", False),
        ("root_only", "root", True),
        ("admin_root", "admin", True),
        ("admin_root", "root", True),
    ],
)
def test_policy_matrix_file_content_access_tier(tier: str, role: str, allowed: bool) -> None:
    old = filemanager.S.filemgr_admin_content_access_tier
    object.__setattr__(filemanager.S, "filemgr_admin_content_access_tier", tier)
    try:
        assert filemanager._admin_can_read_content({"role": role}) is allowed
    finally:
        object.__setattr__(filemanager.S, "filemgr_admin_content_access_tier", old)


def test_policy_matrix_root_login_network_gate_applies() -> None:
    req = SimpleNamespace(headers={}, client=SimpleNamespace(host="198.51.100.8"))
    body = SimpleNamespace()
    fake_settings = SimpleNamespace(root_user_sub="root-sub")
    with patch.object(root_auth, "S", fake_settings), patch.object(root_auth, "audit_event"), patch.object(
        root_auth, "enforce_root_network_gate", side_effect=HTTPException(status_code=403, detail={"code": "root_network_restricted"})
    ):
        with pytest.raises(HTTPException) as exc:
            import asyncio

            asyncio.run(root_auth.root_login(req=req, body=body, user_sub="root-sub"))
    assert exc.value.status_code == 403


@pytest.mark.parametrize(
    "target_role, actor_role, emergency_enabled, allowed",
    [
        ("user", Role.ADMIN, False, True),
        ("admin", Role.ADMIN, False, False),
        ("root", Role.ADMIN, False, False),
        ("admin", Role.ROOT, True, True),
        ("root", Role.ROOT, True, True),
    ],
)
def test_policy_matrix_impersonation_restrictions(target_role: str, actor_role: Role, emergency_enabled: bool, allowed: bool) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "target", "role": target_role}}
    sessions = Mock()
    fake_settings = SimpleNamespace(
        impersonation_ttl_seconds=600,
        impersonation_max_ttl_seconds=3600,
        impersonation_allow_privileged_targets=emergency_enabled,
        ui_access_token_secret="secret",
    )

    with patch.object(admin_impersonation, "T", SimpleNamespace(users=users, sessions=sessions)), patch.object(
        admin_impersonation, "S", fake_settings
    ), patch.object(admin_impersonation, "now_ts", return_value=1000), patch.object(
        admin_impersonation, "with_ttl", side_effect=lambda item, ttl_epoch: {**item, "ttl_epoch": ttl_epoch}
    ), patch.object(admin_impersonation, "audit_event"):
        if allowed:
            resp = admin_impersonation.start_impersonation(
                SimpleNamespace(headers={}, client=SimpleNamespace(host="127.0.0.1")),
                body={"target_user_sub": "target", "reason": "support"},
                _ctx={"user_sub": "actor", "session_id": "sid", "role": actor_role.value},
                actor=AuthenticatedUser(sub="actor", role=actor_role),
            )
            assert resp["ok"] is True
            assert resp["effective_sub"] == "target"
        else:
            with pytest.raises(HTTPException) as exc:
                admin_impersonation.start_impersonation(
                    SimpleNamespace(headers={}, client=SimpleNamespace(host="127.0.0.1")),
                    body={"target_user_sub": "target", "reason": "support"},
                    _ctx={"user_sub": "actor", "session_id": "sid", "role": actor_role.value},
                    actor=AuthenticatedUser(sub="actor", role=actor_role),
                )
            assert exc.value.status_code == 403
            assert exc.value.detail == "impersonation_not_allowed"

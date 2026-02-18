from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root, require_root, require_self_or_admin
from app.auth.roles import AdminProfile, AdminProfileType, AdminScope, Role
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
    "ctx,actor,target,allowed",
    [
        ({"user_sub": "u1", "role": "user"}, AuthenticatedUser(sub="u1", role=Role.USER), None, True),
        ({"user_sub": "u1", "role": "user"}, AuthenticatedUser(sub="u1", role=Role.USER), "u1", True),
        ({"user_sub": "u1", "role": "user"}, AuthenticatedUser(sub="u1", role=Role.USER), "u2", False),
        (
            {"user_sub": "a1", "role": "admin"},
            AuthenticatedUser(
                sub="a1",
                role=Role.ADMIN,
                admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.BILLING_SUPPORT,)),
            ),
            "u2",
            True,
        ),
        (
            {"user_sub": "a1", "role": "admin"},
            AuthenticatedUser(
                sub="a1",
                role=Role.ADMIN,
                admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.AUTH_SUPPORT,)),
            ),
            "u2",
            False,
        ),
        ({"user_sub": "r1", "role": "root"}, AuthenticatedUser(sub="r1", role=Role.ROOT), "u2", True),
    ],
)
def test_policy_matrix_billing_read_scope(ctx: dict, actor: AuthenticatedUser, target: str | None, allowed: bool) -> None:
    if allowed:
        out = billing._billing_read_user_sub(ctx, target, actor)
        assert out == (target or ctx["user_sub"])
    else:
        with pytest.raises(HTTPException) as exc:
            billing._billing_read_user_sub(ctx, target, actor)
        assert exc.value.status_code == 403
        assert exc.value.detail["code"] in {"role_required", "role_required_scope"}


@pytest.mark.parametrize(
    "ctx,actor,target,allowed,expected_target",
    [
        ({"user_sub": "u1", "role": "user"}, AuthenticatedUser(sub="u1", role=Role.USER), None, True, "u1"),
        ({"user_sub": "u1", "role": "user"}, AuthenticatedUser(sub="u1", role=Role.USER), "u1", True, "u1"),
        ({"user_sub": "u1", "role": "user"}, AuthenticatedUser(sub="u1", role=Role.USER), "u2", False, None),
        (
            {"user_sub": "a1", "role": "admin"},
            AuthenticatedUser(
                sub="a1",
                role=Role.ADMIN,
                admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.BILLING_SUPPORT,)),
            ),
            "u2",
            True,
            "u2",
        ),
        (
            {"user_sub": "a1", "role": "admin"},
            AuthenticatedUser(
                sub="a1",
                role=Role.ADMIN,
                admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
            ),
            "u2",
            False,
            None,
        ),
        ({"user_sub": "r1", "role": "root"}, AuthenticatedUser(sub="r1", role=Role.ROOT), "u2", True, "u2"),
    ],
)
def test_policy_matrix_billing_write_scope(ctx: dict, actor: AuthenticatedUser, target: str | None, allowed: bool, expected_target: str | None) -> None:
    if allowed:
        user_sub, tags = billing._billing_write_user_context(ctx, target, actor)
        assert user_sub == expected_target
        if target and target != ctx["user_sub"]:
            assert tags["viewed_as_admin"] is True
            assert tags["effective_sub"] == target
        else:
            assert tags == {}
    else:
        with pytest.raises(HTTPException):
            billing._billing_write_user_context(ctx, target, actor)


def test_policy_matrix_file_admin_ctx_guard() -> None:
    moderation_admin = AuthenticatedUser(
        sub="a1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
    )
    non_moderation_admin = AuthenticatedUser(
        sub="a2",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.AUTH_SUPPORT,)),
    )

    assert filemanager._admin_or_root_ctx({"user_sub": "a1", "role": "admin"}, moderation_admin)["role"] == "admin"
    assert filemanager._admin_or_root_ctx({"user_sub": "r1", "role": "root"}, AuthenticatedUser(sub="r1", role=Role.ROOT))["role"] == "root"
    with pytest.raises(HTTPException) as exc:
        filemanager._admin_or_root_ctx({"user_sub": "a2", "role": "admin"}, non_moderation_admin)
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "role_required_scope"
    assert exc.value.detail["required_scope"] == "content_moderation"

    with pytest.raises(HTTPException):
        filemanager._admin_or_root_ctx({"user_sub": "u1", "role": "user"}, AuthenticatedUser(sub="u1", role=Role.USER))


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


def test_policy_matrix_billing_dev_add_charge_route_uses_billing_scope_dependency() -> None:
    route = next(
        r for r in billing.router.routes
        if isinstance(r, APIRoute) and r.path == "/api/billing/_dev/add-charge" and "POST" in r.methods
    )
    deps = {dep.call for dep in route.dependant.dependencies}
    assert billing.require_billing_admin_operator in deps


@pytest.mark.parametrize("scope", [AdminScope.AUTH_SUPPORT, AdminScope.CONTENT_MODERATION])
def test_policy_matrix_billing_scope_dependency_denies_non_billing_scoped_admin(scope: AdminScope) -> None:
    import asyncio

    actor = AuthenticatedUser(
        sub="a1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(scope,)),
    )
    req = SimpleNamespace(headers={"user-agent": "pytest"}, client=SimpleNamespace(host="127.0.0.1"), state=SimpleNamespace())

    with pytest.raises(HTTPException) as exc:
        asyncio.run(billing.require_billing_support_admin(request=req, user=actor))

    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "role_required_scope"
    assert exc.value.detail["required_scope"] == "billing_support"


def test_policy_matrix_billing_scope_dependency_allows_billing_scoped_admin() -> None:
    import asyncio

    actor = AuthenticatedUser(
        sub="a1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.BILLING_SUPPORT,)),
    )
    req = SimpleNamespace(headers={"user-agent": "pytest"}, client=SimpleNamespace(host="127.0.0.1"), state=SimpleNamespace())

    out = asyncio.run(billing.require_billing_support_admin(request=req, user=actor))
    assert out is actor



def test_policy_matrix_file_admin_route_uses_content_moderation_scope_dependency() -> None:
    route = next(
        r for r in filemanager.router.routes
        if isinstance(r, APIRoute) and r.path == "/v1/fs/admin/read" and "GET" in r.methods
    )
    deps = {dep.call for dep in route.dependant.dependencies}
    assert filemanager._admin_or_root_ctx in deps


@pytest.mark.parametrize("scope", [AdminScope.AUTH_SUPPORT, AdminScope.BILLING_SUPPORT])
def test_policy_matrix_content_moderation_scope_dependency_denies_non_moderation_scoped_admin(scope: AdminScope) -> None:
    import asyncio

    actor = AuthenticatedUser(
        sub="a1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(scope,)),
    )
    req = SimpleNamespace(headers={"user-agent": "pytest"}, client=SimpleNamespace(host="127.0.0.1"), state=SimpleNamespace())

    with pytest.raises(HTTPException) as exc:
        asyncio.run(filemanager.require_content_moderation_admin(request=req, user=actor))

    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "role_required_scope"
    assert exc.value.detail["required_scope"] == "content_moderation"


def test_policy_matrix_content_moderation_scope_dependency_allows_moderation_scoped_admin() -> None:
    import asyncio

    actor = AuthenticatedUser(
        sub="a1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
    )
    req = SimpleNamespace(headers={"user-agent": "pytest"}, client=SimpleNamespace(host="127.0.0.1"), state=SimpleNamespace())

    out = asyncio.run(filemanager.require_content_moderation_admin(request=req, user=actor))
    assert out is actor


def test_policy_matrix_billing_operator_falls_back_to_admin_or_root_when_flag_disabled() -> None:
    import asyncio

    actor = AuthenticatedUser(
        sub="a1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.AUTH_SUPPORT,)),
    )
    with patch.object(billing, "S", SimpleNamespace(admin_scope_enforce_billing_support=False)):
        out = asyncio.run(billing.require_billing_admin_operator(user=actor, request=SimpleNamespace()))

    assert out is actor


def test_policy_matrix_billing_operator_enforces_scope_when_flag_enabled() -> None:
    import asyncio

    actor = AuthenticatedUser(
        sub="a1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.AUTH_SUPPORT,)),
    )
    req = SimpleNamespace(headers={"user-agent": "pytest"}, client=SimpleNamespace(host="127.0.0.1"), state=SimpleNamespace())

    with patch.object(billing, "S", SimpleNamespace(admin_scope_enforce_billing_support=True)):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(billing.require_billing_admin_operator(user=actor, request=req))

    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "role_required_scope"
    assert exc.value.detail["required_scope"] == "billing_support"


def test_policy_matrix_content_moderation_operator_falls_back_to_admin_or_root_when_flag_disabled() -> None:
    import asyncio

    actor = AuthenticatedUser(
        sub="a1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.BILLING_SUPPORT,)),
    )
    with patch.object(filemanager, "S", SimpleNamespace(admin_scope_enforce_content_moderation=False)):
        out = asyncio.run(filemanager.require_content_moderation_operator(user=actor, request=SimpleNamespace()))

    assert out is actor


def test_policy_matrix_content_moderation_operator_enforces_scope_when_flag_enabled() -> None:
    import asyncio

    actor = AuthenticatedUser(
        sub="a1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.BILLING_SUPPORT,)),
    )
    req = SimpleNamespace(headers={"user-agent": "pytest"}, client=SimpleNamespace(host="127.0.0.1"), state=SimpleNamespace())

    with patch.object(filemanager, "S", SimpleNamespace(admin_scope_enforce_content_moderation=True)):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(filemanager.require_content_moderation_operator(user=actor, request=req))

    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "role_required_scope"
    assert exc.value.detail["required_scope"] == "content_moderation"

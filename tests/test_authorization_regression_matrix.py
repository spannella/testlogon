from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from fastapi import HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_general_admin_or_root
from app.auth.roles import AdminProfile, AdminProfileType, AdminScope, Role
from app.routers import admin_impersonation, billing, filemanager


def _actor(role: Role, scope: AdminScope | None = None) -> AuthenticatedUser:
    if role is Role.ADMIN and scope is not None:
        return AuthenticatedUser(
            sub=f"admin-{scope.value}",
            role=Role.ADMIN,
            admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(scope,)),
        )
    if role is Role.ADMIN:
        return AuthenticatedUser(
            sub="admin-general",
            role=Role.ADMIN,
            admin_profile=AdminProfile(type=AdminProfileType.GENERAL),
        )
    return AuthenticatedUser(sub=role.value, role=role)


def _policy_request(path: str) -> SimpleNamespace:
    return SimpleNamespace(
        headers={"user-agent": "pytest"},
        client=SimpleNamespace(host="127.0.0.1"),
        state=SimpleNamespace(),
        scope={"route": SimpleNamespace(path=path)},
        url=SimpleNamespace(path=path),
    )


@pytest.mark.parametrize(
    "label,dep,module,flag_name,path,actor,allowed,expected_code,expected_required_scope",
    [
        (
            "auth_scope_allows_auth_admin",
            admin_impersonation.require_impersonation_operator,
            admin_impersonation,
            "admin_scope_enforce_auth_support",
            "/admin/impersonation/start",
            _actor(Role.ADMIN, AdminScope.AUTH_SUPPORT),
            True,
            None,
            None,
        ),
        (
            "auth_scope_denies_billing_admin",
            admin_impersonation.require_impersonation_operator,
            admin_impersonation,
            "admin_scope_enforce_auth_support",
            "/admin/impersonation/start",
            _actor(Role.ADMIN, AdminScope.BILLING_SUPPORT),
            False,
            "role_required_scope",
            "auth_support",
        ),
        (
            "billing_scope_allows_billing_admin",
            billing.require_billing_admin_operator,
            billing,
            "admin_scope_enforce_billing_support",
            "/api/billing/_dev/add-charge",
            _actor(Role.ADMIN, AdminScope.BILLING_SUPPORT),
            True,
            None,
            None,
        ),
        (
            "billing_scope_denies_moderation_admin",
            billing.require_billing_admin_operator,
            billing,
            "admin_scope_enforce_billing_support",
            "/api/billing/_dev/add-charge",
            _actor(Role.ADMIN, AdminScope.CONTENT_MODERATION),
            False,
            "role_required_scope",
            "billing_support",
        ),
        (
            "moderation_scope_allows_moderation_admin",
            filemanager.require_content_moderation_operator,
            filemanager,
            "admin_scope_enforce_content_moderation",
            "/v1/fs/admin/read",
            _actor(Role.ADMIN, AdminScope.CONTENT_MODERATION),
            True,
            None,
            None,
        ),
        (
            "moderation_scope_denies_auth_admin",
            filemanager.require_content_moderation_operator,
            filemanager,
            "admin_scope_enforce_content_moderation",
            "/v1/fs/admin/read",
            _actor(Role.ADMIN, AdminScope.AUTH_SUPPORT),
            False,
            "role_required_scope",
            "content_moderation",
        ),
        (
            "general_admin_allowed_across_scoped_domains",
            billing.require_billing_admin_operator,
            billing,
            "admin_scope_enforce_billing_support",
            "/api/billing/_dev/add-charge",
            _actor(Role.ADMIN),
            True,
            None,
            None,
        ),
        (
            "root_allowed_across_scoped_domains",
            filemanager.require_content_moderation_operator,
            filemanager,
            "admin_scope_enforce_content_moderation",
            "/v1/fs/admin/read",
            _actor(Role.ROOT),
            True,
            None,
            None,
        ),
        (
            "user_denied_scoped_domain",
            billing.require_billing_admin_operator,
            billing,
            "admin_scope_enforce_billing_support",
            "/api/billing/_dev/add-charge",
            _actor(Role.USER),
            False,
            "role_required",
            None,
        ),
    ],
)
def test_authorization_regression_matrix_scoped_domains(
    label: str,
    dep,
    module,
    flag_name: str,
    path: str,
    actor: AuthenticatedUser,
    allowed: bool,
    expected_code: str | None,
    expected_required_scope: str | None,
) -> None:
    req = _policy_request(path)
    with patch.object(module, "S", SimpleNamespace(**{flag_name: True})):
        if allowed:
            out = asyncio.run(dep(user=actor, request=req))
            assert out is actor, label
        else:
            with pytest.raises(HTTPException) as exc:
                asyncio.run(dep(user=actor, request=req))
            assert exc.value.status_code == 403, label
            assert exc.value.detail["code"] == expected_code, label
            if expected_required_scope:
                assert exc.value.detail["required_scope"] == expected_required_scope, label


@pytest.mark.parametrize(
    "actor,allowed",
    [
        (_actor(Role.USER), False),
        (_actor(Role.ADMIN, AdminScope.AUTH_SUPPORT), False),
        (_actor(Role.ADMIN, AdminScope.BILLING_SUPPORT), False),
        (_actor(Role.ADMIN, AdminScope.CONTENT_MODERATION), False),
        (_actor(Role.ADMIN), True),
        (_actor(Role.ROOT), True),
    ],
)
def test_authorization_regression_matrix_general_admin_or_root_control(actor: AuthenticatedUser, allowed: bool) -> None:
    if allowed:
        out = asyncio.run(require_general_admin_or_root(user=actor))
        assert out is actor
    else:
        with pytest.raises(HTTPException) as exc:
            asyncio.run(require_general_admin_or_root(user=actor))
        assert exc.value.status_code == 403
        assert exc.value.detail["code"] in {"role_required", "role_required_admin_profile_type"}


@pytest.mark.parametrize(
    "dep,module,flag_name,path,required_scope",
    [
        (
            admin_impersonation.require_impersonation_operator,
            admin_impersonation,
            "admin_scope_enforce_auth_support",
            "/admin/impersonation/start",
            "auth_support",
        ),
        (
            billing.require_billing_admin_operator,
            billing,
            "admin_scope_enforce_billing_support",
            "/api/billing/_dev/add-charge",
            "billing_support",
        ),
        (
            filemanager.require_content_moderation_operator,
            filemanager,
            "admin_scope_enforce_content_moderation",
            "/v1/fs/admin/read",
            "content_moderation",
        ),
    ],
)
def test_authorization_regression_matrix_denials_emit_scope_audit_event(dep, module, flag_name: str, path: str, required_scope: str) -> None:
    actor = _actor(Role.ADMIN, AdminScope.AUTH_SUPPORT)
    if required_scope == "auth_support":
        actor = _actor(Role.ADMIN, AdminScope.BILLING_SUPPORT)

    events: list[dict] = []

    def _capture(event: str, user_sub: str, request=None, **fields):
        events.append({"event": event, "user_sub": user_sub, "fields": fields})

    with patch.object(module, "S", SimpleNamespace(**{flag_name: True})), patch("app.auth.policy.audit_event", side_effect=_capture):
        with pytest.raises(HTTPException):
            asyncio.run(dep(user=actor, request=_policy_request(path)))

    assert len(events) == 1
    assert events[0]["event"] == "admin_scope_denied"
    assert events[0]["fields"]["required_scope"] == required_scope
    assert events[0]["fields"]["status_code"] == 403


def test_authorization_regression_matrix_impersonation_success_emits_audit_event() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "target", "role": "user"}}
    sessions = Mock()

    fake_settings = SimpleNamespace(
        impersonation_ttl_seconds=600,
        impersonation_max_ttl_seconds=3600,
        impersonation_allow_privileged_targets=False,
        ui_access_token_secret="secret",
    )

    with patch.object(admin_impersonation, "T", SimpleNamespace(users=users, sessions=sessions)), patch.object(
        admin_impersonation, "S", fake_settings
    ), patch.object(admin_impersonation, "now_ts", return_value=1000), patch.object(
        admin_impersonation, "with_ttl", side_effect=lambda item, ttl_epoch: {**item, "ttl_epoch": ttl_epoch}
    ), patch.object(admin_impersonation, "audit_event") as audit_mock:
        resp = admin_impersonation.start_impersonation(
            req=_policy_request("/admin/impersonation/start"),
            body={"target_user_sub": "target", "reason": "support"},
            _ctx={"user_sub": "admin-auth", "session_id": "sid", "role": "admin"},
            actor=_actor(Role.ADMIN, AdminScope.AUTH_SUPPORT),
        )

    assert resp["ok"] is True
    assert audit_mock.call_count == 1
    assert audit_mock.call_args.args[0] == "admin_impersonation_start"
    assert audit_mock.call_args.kwargs["outcome"] == "success"

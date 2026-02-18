from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import (
    require_admin_scope,
    require_general_admin_or_root,
    require_role_value,
    require_roles,
    require_self_or_admin,
)
from app.auth.roles import AdminProfile, AdminProfileType, AdminScope, Role


def run_async(coro):
    return asyncio.run(coro)


def _mock_request(path: str = "/_test") -> SimpleNamespace:
    return SimpleNamespace(
        headers={"user-agent": "pytest"},
        state=SimpleNamespace(),
        scope={"route": SimpleNamespace(path=path)},
        url=SimpleNamespace(path=path),
    )


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


def test_require_general_admin_or_root_allows_root() -> None:
    user = AuthenticatedUser(sub="root", role=Role.ROOT)
    out = run_async(require_general_admin_or_root(user=user))
    assert out is user


def test_require_general_admin_or_root_allows_general_admin() -> None:
    user = AuthenticatedUser(sub="a1", role=Role.ADMIN, admin_profile=AdminProfile(type=AdminProfileType.GENERAL))
    out = run_async(require_general_admin_or_root(user=user))
    assert out is user


def test_require_general_admin_or_root_denies_scoped_admin() -> None:
    user = AuthenticatedUser(
        sub="a1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.AUTH_SUPPORT,)),
    )
    with pytest.raises(HTTPException) as exc:
        run_async(require_general_admin_or_root(user=user))
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "role_required_admin_profile_type"


def test_require_admin_scope_allows_root() -> None:
    dep = require_admin_scope(AdminScope.BILLING_SUPPORT)
    user = AuthenticatedUser(sub="root", role=Role.ROOT)
    out = run_async(dep(request=_mock_request(), user=user))
    assert out is user


def test_require_admin_scope_allows_general_admin() -> None:
    dep = require_admin_scope(AdminScope.BILLING_SUPPORT)
    user = AuthenticatedUser(sub="a1", role=Role.ADMIN, admin_profile=AdminProfile(type=AdminProfileType.GENERAL))
    out = run_async(dep(request=_mock_request(), user=user))
    assert out is user


def test_require_admin_scope_allows_scoped_admin_with_scope() -> None:
    dep = require_admin_scope(AdminScope.AUTH_SUPPORT)
    user = AuthenticatedUser(
        sub="a1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.AUTH_SUPPORT,)),
    )
    out = run_async(dep(request=_mock_request(), user=user))
    assert out is user


def test_require_admin_scope_denies_scoped_admin_missing_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    events = []
    metric_events = []

    def _capture(event: str, user_sub: str, request=None, **fields):
        events.append({"event": event, "user_sub": user_sub, "fields": fields})

    def _capture_metric(*, route: str, required_scope: str, admin_profile_type: str):
        metric_events.append(
            {
                "route": route,
                "required_scope": required_scope,
                "admin_profile_type": admin_profile_type,
            }
        )

    monkeypatch.setattr("app.auth.policy.audit_event", _capture)
    monkeypatch.setattr("app.auth.policy.record_admin_scope_denied", _capture_metric)

    dep = require_admin_scope(AdminScope.BILLING_SUPPORT)
    user = AuthenticatedUser(
        sub="a1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.AUTH_SUPPORT,)),
    )
    with pytest.raises(HTTPException) as exc:
        run_async(dep(request=_mock_request(path="/api/billing/_dev/add-charge"), user=user))
    assert exc.value.status_code == 403
    assert exc.value.detail == {
        "code": "role_required_scope",
        "required_scope": "billing_support",
        "actual_role": "admin",
        "actual_admin_profile": {"type": "scoped", "scopes": ["auth_support"]},
    }

    assert len(events) == 1
    assert events[0]["event"] == "admin_scope_denied"
    assert events[0]["user_sub"] == "a1"
    assert events[0]["fields"]["required_scope"] == "billing_support"
    assert events[0]["fields"]["status_code"] == 403

    assert metric_events == [
        {
            "route": "/api/billing/_dev/add-charge",
            "required_scope": "billing_support",
            "admin_profile_type": "scoped",
        }
    ]


def test_require_admin_scope_denies_non_admin_user() -> None:
    dep = require_admin_scope(AdminScope.BILLING_SUPPORT)
    user = AuthenticatedUser(sub="u1", role=Role.USER)
    with pytest.raises(HTTPException) as exc:
        run_async(dep(request=_mock_request(), user=user))
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "role_required"

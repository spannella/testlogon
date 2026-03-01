from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.roles import Role
from app.routers import admin_entitlements as r


class _Req:
    scope = {"route": type("Route", (), {"path": "/v1/admin/entitlements/e1/revoke"})()}
    url = type("Url", (), {"path": "/v1/admin/entitlements/e1/revoke"})()
    headers = {}
    client = type("Client", (), {"host": "127.0.0.1"})()


def test_require_entitlement_admin_operator_enforces_scope(monkeypatch):
    actor = AuthenticatedUser(sub="admin-1", role=Role.ADMIN, admin_profile={"type": "scoped", "scopes": ["auth_support"]})

    with pytest.raises(HTTPException) as exc:
        asyncio.run(r.require_entitlement_admin_operator(user=actor, request=_Req()))

    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "role_required_scope"


def test_revoke_route_audits_success(monkeypatch):
    class _Actor:
        sub = "admin-1"

    called = {"audit": 0}
    monkeypatch.setattr(r, "revoke_entitlement_admin", lambda **kwargs: {"ok": True, "entitlement_id": "e1", "status": "revoked", "audit_event_id": "evt1"})

    def _audit(*args, **kwargs):
        called["audit"] += 1

    monkeypatch.setattr(r, "audit_event", _audit)

    out = r.revoke_entitlement(
        "e1",
        r.RevokeEntitlementIn(reason_code="customer_support", audit_comment="customer requested revoke"),
        req=None,
        actor=_Actor(),
    )
    assert out["ok"] is True
    assert called["audit"] == 1

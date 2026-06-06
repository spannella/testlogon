"""Regression test for GAP-0171 (ENTERPRISE-001).

``AuthenticatedUser`` carried no ``tenant_id`` field and ``require_ui_session``
never compared the session's tenant against ``request.state.tenant_id``. As a
result a session cookie minted for tenant-A worked transparently when replayed
on tenant-B (cross-tenant session reuse).

The fix:
  * adds ``tenant_id: str = "default"`` to ``AuthenticatedUser`` and populates it
    from the request's resolved tenant,
  * stores ``tenant_id`` on the session record at creation time,
  * in ``require_ui_session`` rejects with 403 when multi-tenancy is enabled AND
    both the stored session tenant and the request tenant are present AND differ.

Backward compatibility is preserved: legacy sessions without a stored
``tenant_id`` and requests where the middleware did not set
``request.state.tenant_id`` are treated as ``"default"`` and pass through.

This test runs fully offline. ``TestClient`` is unusable in this repo (multipart
is stubbed), so ``require_ui_session`` is invoked directly with a minimal fake
``Request`` and an in-memory fake sessions table. The frozen ``S`` settings
object is toggled via ``object.__setattr__``.
"""
from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.auth.deps import AuthenticatedUser  # noqa: E402
from app.auth.roles import Role  # noqa: E402
from app.services import sessions as sessions_mod  # noqa: E402


_USER = "alice@example.com"
_SESSION_ID = "sid-tenant-test"


# ---------------------------------------------------------------------------
# Field-level: AuthenticatedUser carries tenant_id with a "default" fallback.
# ---------------------------------------------------------------------------

def test_authenticated_user_has_tenant_id_default():
    u = AuthenticatedUser(sub=_USER, role=Role.USER)
    assert u.tenant_id == "default"


def test_authenticated_user_tenant_id_explicit():
    u = AuthenticatedUser(sub=_USER, role=Role.USER, tenant_id="tenantA")
    assert u.tenant_id == "tenantA"


# ---------------------------------------------------------------------------
# Offline harness for require_ui_session.
# ---------------------------------------------------------------------------

@dataclass
class _FakeSessionsTable:
    item: Optional[Dict[str, Any]] = None

    def get_item(self, *, Key):
        if (
            self.item
            and self.item.get("user_sub") == Key.get("user_sub")
            and self.item.get("session_id") == Key.get("session_id")
        ):
            return {"Item": dict(self.item)}
        return {}

    def update_item(self, **kwargs):  # touch last_seen / revoke — no-op in tests
        return {}


class _FakeState:
    def __init__(self, tenant_id):
        if tenant_id is not None:
            self.tenant_id = tenant_id


class _FakeRequest:
    def __init__(self, *, tenant_id):
        self.state = _FakeState(tenant_id)
        self.cookies: Dict[str, str] = {"ui_session": _SESSION_ID}
        self.headers: Dict[str, str] = {}
        self.method = "GET"


def _make_session_item(*, tenant_id):
    item: Dict[str, Any] = {
        "user_sub": _USER,
        "session_id": _SESSION_ID,
        "csrf_token": "csrf-test",
        "created_at": 1_700_000_000,
        "last_seen_at": 0,
        "ip": "127.0.0.1",
        "revoked": False,
        "pending_auth": False,
    }
    if tenant_id is not None:
        item["tenant_id"] = tenant_id
    return item


def _run_require_ui_session(monkeypatch, *, multi_tenancy, session_tenant, request_tenant):
    """Invoke require_ui_session with controlled tenants. Returns the ctx dict."""
    table = _FakeSessionsTable(item=_make_session_item(tenant_id=session_tenant))
    # T is a frozen dataclass; swap the sessions table for the fake via
    # object.__setattr__ and restore it afterwards.
    real_sessions_table = sessions_mod.T.sessions
    object.__setattr__(sessions_mod.T, "sessions", table)
    # Keep the device-trust block dormant and the ban check inert.
    monkeypatch.setattr(sessions_mod, "is_user_currently_banned", lambda *_a, **_k: False)
    monkeypatch.setattr(sessions_mod, "record_device_login", lambda *_a, **_k: {"trusted": True})
    monkeypatch.setattr(sessions_mod, "_resolve_impersonation_context", lambda *_a, **_k: {})

    # S is a frozen dataclass — toggle the flags we depend on via __setattr__.
    saved = {
        k: getattr(sessions_mod.S, k)
        for k in ("multi_tenancy_enabled", "ddb_sessions_table", "ui_inactivity_seconds", "ddb_ttl_attr")
    }
    object.__setattr__(sessions_mod.S, "multi_tenancy_enabled", multi_tenancy)
    object.__setattr__(sessions_mod.S, "ddb_sessions_table", "")  # skip device-trust block
    object.__setattr__(sessions_mod.S, "ui_inactivity_seconds", 0)
    object.__setattr__(sessions_mod.S, "ddb_ttl_attr", "")
    try:
        req = _FakeRequest(tenant_id=request_tenant)
        auth_user = AuthenticatedUser(sub=_USER, role=Role.USER, tenant_id=request_tenant or "default")
        return asyncio.run(
            sessions_mod.require_ui_session(req, auth_user=auth_user, user_sub=_USER)
        )
    finally:
        for k, v in saved.items():
            object.__setattr__(sessions_mod.S, k, v)
        object.__setattr__(sessions_mod.T, "sessions", real_sessions_table)


# ---------------------------------------------------------------------------
# Behavioural cases.
# ---------------------------------------------------------------------------

def test_matching_tenant_allowed(monkeypatch):
    """Same tenant on session and request: allowed, ctx carries tenant_id."""
    ctx = _run_require_ui_session(
        monkeypatch, multi_tenancy=True, session_tenant="tenantA", request_tenant="tenantA"
    )
    assert ctx["user_sub"] == _USER
    assert ctx["tenant_id"] == "tenantA"


def test_mismatched_tenant_rejected_403(monkeypatch):
    """Session minted on tenantA replayed on tenantB: 403 when multi-tenancy on."""
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        _run_require_ui_session(
            monkeypatch, multi_tenancy=True, session_tenant="tenantA", request_tenant="tenantB"
        )
    assert exc.value.status_code == 403
    assert "tenant" in str(exc.value.detail).lower()


def test_legacy_session_without_tenant_allowed(monkeypatch):
    """Old session record lacking tenant_id is treated as default and allowed."""
    ctx = _run_require_ui_session(
        monkeypatch, multi_tenancy=True, session_tenant=None, request_tenant="tenantB"
    )
    assert ctx["user_sub"] == _USER
    # Missing stored tenant surfaces as "default" in the ctx.
    assert ctx["tenant_id"] == "default"


def test_no_request_tenant_allowed(monkeypatch):
    """Single-tenant request (no request.state.tenant_id) is never rejected."""
    ctx = _run_require_ui_session(
        monkeypatch, multi_tenancy=True, session_tenant="tenantA", request_tenant=None
    )
    assert ctx["user_sub"] == _USER
    assert ctx["tenant_id"] == "tenantA"


def test_multi_tenancy_disabled_skips_check(monkeypatch):
    """With multi-tenancy off, mismatched tenants are NOT rejected."""
    ctx = _run_require_ui_session(
        monkeypatch, multi_tenancy=False, session_tenant="tenantA", request_tenant="tenantB"
    )
    assert ctx["user_sub"] == _USER

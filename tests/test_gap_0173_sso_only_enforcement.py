"""Regression test for GAP-0173 (ENTERPRISE-002).

SSO-only enforcement was implemented in ``app/services/sso_saml_provider.py``
(``is_sso_only_tenant``) but never wired into the password-login endpoint
``POST /ui/session/start`` (``ui_session_start`` in ``app/routers/ui_session.py``).
A user belonging to a tenant whose active SSO provider has ``sso_only=True``
could therefore still authenticate with a username/password, bypassing the
enterprise SSO policy.

Fails-before: ``ui_session_start`` contained no SSO-only guard, so for an
``sso_only`` tenant it proceeds past the root-check straight into
``rate_limit_login_attempt`` (no 403 with ``code='sso_only'``).
Passes-after: the guard raises ``HTTPException(403, {"code": "sso_only", ...})``
before any session work, and is skipped for non-sso_only tenants / when
``S.sso_saml_enabled`` is False.

Fully offline: the endpoint coroutine is invoked directly (TestClient is
unusable under this repo's starlette/httpx pairing — same approach as
tests/test_saml_relay_state.py). ``user_sub`` is passed explicitly (bypassing
the ``Depends`` resolver), ``is_sso_only_tenant`` is patched in the router
module, and the post-guard helpers are patched so the non-sso_only path stops
at a recognisable sentinel rather than touching DynamoDB. No real AWS access.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import sys
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture(autouse=True)
def _mock_env(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "1")
    monkeypatch.setenv("DDB_ENDPOINT_URL", "http://localhost:8001")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("UI_ACCESS_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("API_KEY_PEPPER", "test-pepper")


def _make_request(tenant_id: str | None = None) -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/ui/session/start",
        "raw_path": b"/ui/session/start",
        "query_string": b"",
        "headers": [
            (b"user-agent", b"pytest"),
            (b"host", b"testserver"),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
        "scheme": "http",
        "state": {},
    }
    req = Request(scope)
    if tenant_id is not None:
        req.state.tenant_id = tenant_id
    return req


class _StopAfterGuard(Exception):
    """Sentinel raised by the patched post-guard helper to prove the SSO-only
    guard let the request through (non-sso_only / disabled paths)."""


@contextlib.contextmanager
def _patched_settings(*, sso_saml_enabled: bool):
    from app.routers import ui_session

    saved = {k: getattr(ui_session.S, k) for k in ("sso_saml_enabled", "root_user_sub")}
    object.__setattr__(ui_session.S, "sso_saml_enabled", sso_saml_enabled)
    object.__setattr__(ui_session.S, "root_user_sub", "root@example.com")
    try:
        yield ui_session
    finally:
        for k, v in saved.items():
            object.__setattr__(ui_session.S, k, v)


def _call(user_sub: str, *, sso_only: bool, sso_saml_enabled: bool, tenant_id: str | None):
    body = object()  # body is not read before the guard
    with _patched_settings(sso_saml_enabled=sso_saml_enabled) as ui_session:
        with patch.object(ui_session, "is_sso_only_tenant", return_value=sso_only), \
             patch.object(
                 ui_session,
                 "rate_limit_login_attempt",
                 side_effect=_StopAfterGuard("reached post-guard logic"),
             ):
            return asyncio.run(
                ui_session.ui_session_start(
                    _make_request(tenant_id),
                    body,
                    user_sub=user_sub,
                )
            )


def test_password_login_blocked_for_sso_only_tenant():
    """sso_only tenant -> 403 with code='sso_only' before any session work."""
    with pytest.raises(HTTPException) as ei:
        _call("alice@acme.com", sso_only=True, sso_saml_enabled=True, tenant_id="acmecorp")
    exc = ei.value
    assert exc.status_code == 403
    assert isinstance(exc.detail, dict)
    assert exc.detail["code"] == "sso_only"
    assert "sso_login_url" in exc.detail
    assert "acmecorp" in exc.detail["sso_login_url"]


def test_password_login_allowed_for_non_sso_only_tenant():
    """Non-sso_only tenant must pass the guard and reach post-guard logic."""
    with pytest.raises(_StopAfterGuard):
        _call("bob@acme.com", sso_only=False, sso_saml_enabled=True, tenant_id="acmecorp")


def test_guard_skipped_when_sso_disabled():
    """When the SSO feature flag is off, the guard (and the DDB lookup) is skipped."""
    from app.routers import ui_session

    # is_sso_only_tenant must NOT even be consulted when sso_saml_enabled is False.
    with _patched_settings(sso_saml_enabled=False):
        with patch.object(
            ui_session,
            "is_sso_only_tenant",
            side_effect=AssertionError("is_sso_only_tenant must not be called when SSO disabled"),
        ), patch.object(
            ui_session,
            "rate_limit_login_attempt",
            side_effect=_StopAfterGuard("reached post-guard logic"),
        ):
            with pytest.raises(_StopAfterGuard):
                asyncio.run(
                    ui_session.ui_session_start(
                        _make_request("acmecorp"),
                        object(),
                        user_sub="carol@acme.com",
                    )
                )


def test_falls_back_to_default_tenant_when_state_missing():
    """No request.state.tenant_id -> guard uses S.default_tenant_id and still enforces."""
    with pytest.raises(HTTPException) as ei:
        _call("dave@example.com", sso_only=True, sso_saml_enabled=True, tenant_id=None)
    assert ei.value.status_code == 403
    assert ei.value.detail["code"] == "sso_only"

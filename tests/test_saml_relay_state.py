"""Regression test for GAP-0018 (SAML RelayState open redirect, CWE-601).

The SAML Assertion Consumer Service (ACS) endpoint in ``app/routers/sso_saml.py``
read the ``RelayState`` POST field and redirected the browser to it verbatim after
a successful login (lines 212 and 568). Because ``RelayState`` is attacker-controllable,
a value like ``https://evil.example/phish`` (or a ``javascript:`` URI) was used as the
303 ``Location`` target, leaking the just-set session cookies to an external origin.

The fix adds ``_safe_relay_state()`` which only permits same-origin/relative targets
and otherwise falls back to ``"/"``. It is applied at both redirect sites.

These tests FAIL before the fix (external host used as redirect target) and PASS
after (external/dangerous values fall back to ``/`` while relative paths are
preserved). They run fully offline: the DynamoDB-touching session helpers are
patched out, so no real AWS / moto table setup is required. The dev-bypass ACS
path is exercised because it shares the identical ``_safe_relay_state`` call site.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

import pytest

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
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://platform.example.com")


# ---------------------------------------------------------------------------
# Unit tests for the validator itself (no HTTP / no AWS).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        (None, "/"),
        ("", "/"),
        ("/messages", "/messages"),
        ("/messages/conv_abc?x=1", "/messages/conv_abc?x=1"),
        ("https://evil.example/phish", "/"),
        ("https://evil.example/phish?token=abc", "/"),
        ("//evil.example/phish", "/"),
        ("javascript:alert(1)", "/"),
        ("data:text/html,<script>1</script>", "/"),
        ("https://platform.example.com/dashboard", "https://platform.example.com/dashboard"),
        ("/" + "a" * 5000, "/"),  # oversized
        ("/foo\r\nLocation: https://evil.example", "/"),  # non-printable / CRLF injection
    ],
)
def test_safe_relay_state(value, expected):
    from app.routers.sso_saml import _safe_relay_state

    assert _safe_relay_state(value) == expected


# ---------------------------------------------------------------------------
# Integration: exercise the real dev-bypass ACS handler directly.
#
# ``_dev_bypass_acs`` contains one of the two guarded redirect sites (line 568)
# and shares the identical ``_safe_relay_state`` call as the production path
# (line 212). We invoke the coroutine directly (the direct-call style used by
# tests/test_activity_feed_idor.py) with a minimal ASGI ``Request`` and patched-
# out DynamoDB helpers, keeping the test fully offline. We assert on the
# ``Location`` header of the returned ``RedirectResponse``.
#
# (We call the helper directly rather than driving the full ``saml_acs`` endpoint
# because the test conftest stubs out ``python-multipart``, which disables
# starlette form parsing — and ``TestClient`` is unusable under this repo's
# starlette/httpx version pairing.)
# ---------------------------------------------------------------------------

import asyncio
import contextlib

from starlette.requests import Request


def _make_request() -> Request:
    """Build a minimal POST ``Request`` (no body needed: relay_state is an arg)."""
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/saml/acs",
        "raw_path": b"/saml/acs",
        "query_string": b"dev_bypass=1",
        "headers": [
            (b"x-user-sub", b"user@example.com"),
            (b"user-agent", b"pytest"),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
        "scheme": "http",
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


@contextlib.contextmanager
def _patched_acs():
    from app.routers import sso_saml
    from app.services.sessions import SessionInfo

    fake_session = SessionInfo(
        session_id="sid-test", csrf_token="csrf-test", user_sub="user@example.com"
    )

    # ``S`` is a frozen dataclass; toggle dev/SSO flags via object.__setattr__.
    saved = {k: getattr(sso_saml.S, k) for k in ("sso_saml_enabled", "dev_mode")}
    object.__setattr__(sso_saml.S, "sso_saml_enabled", True)
    object.__setattr__(sso_saml.S, "dev_mode", True)
    try:
        with patch.object(sso_saml, "get_active_provider_for_tenant", return_value=None), \
            patch.object(sso_saml, "ensure_user_exists", return_value=None), \
            patch.object(sso_saml, "create_real_session", return_value=fake_session), \
            patch.object(sso_saml, "set_session_cookies", return_value=None), \
            patch.object(sso_saml, "audit_event", return_value=None):
            yield sso_saml
    finally:
        for k, v in saved.items():
            object.__setattr__(sso_saml.S, k, v)


def _acs_location(relay_state: str) -> tuple[int, str]:
    with _patched_acs() as sso_saml:
        resp = asyncio.run(
            sso_saml._dev_bypass_acs(
                _make_request(),
                user_sub="user@example.com",
                tenant_id="default",
                relay_state=relay_state,
            )
        )
    return resp.status_code, resp.headers.get("location", "")


def test_acs_external_url_rejected():
    """An absolute foreign-host RelayState must not become the redirect target."""
    status, loc = _acs_location("https://evil.example/phish")
    assert status == 303
    assert "evil.example" not in loc
    assert loc == "/"


def test_acs_javascript_scheme_rejected():
    """A javascript: RelayState must fall back to a safe local path."""
    status, loc = _acs_location("javascript:alert(1)")
    assert status == 303
    assert loc == "/"


def test_acs_relative_path_preserved():
    """A legitimate relative RelayState must be preserved unchanged."""
    status, loc = _acs_location("/messages")
    assert status == 303
    assert loc == "/messages"

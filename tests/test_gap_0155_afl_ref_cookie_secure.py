"""Regression test for GAP-0155.

The affiliate redirect endpoint (``GET /r/{tracking_code}``) sets the ``afl_ref``
attribution cookie. Before the fix, ``set_cookie`` was called without a ``secure``
argument, so Starlette defaulted to ``secure=False`` in *all* environments —
including production (HTTPS), where the cookie should be ``Secure=True``.

Fix: ``secure=S.ui_cookie_secure`` is passed, matching the session-cookie pattern
in ``app/services/sessions.py``. This yields:
  - dev  (``ui_cookie_secure=False``) -> cookie NOT Secure (HTTP-deliverable)  -> affiliate tracking works over http://localhost
  - prod (``ui_cookie_secure=True``)  -> cookie Secure (HTTPS-only)

Fully offline: ``get_link_by_code`` and ``record_click`` are monkeypatched so no
real AWS / DynamoDB access occurs. TestClient is avoided (broken in this repo);
the handler coroutine is invoked directly. The frozen ``Settings`` dataclass is
mutated via ``object.__setattr__``.
"""
from __future__ import annotations

import asyncio

from app.core.settings import S
from app.routers import affiliate_links as mod


def _invoke(monkeypatch, *, ui_cookie_secure: bool):
    """Run the affiliate_redirect handler with stubbed services and return the response."""
    object.__setattr__(S, "ui_cookie_secure", ui_cookie_secure)

    monkeypatch.setattr(
        mod,
        "get_link_by_code",
        lambda code: {
            "link_id": "link_test",
            "tracking_code": code,
            "status": "active",
            "destination_url": "https://example.com/product",
        },
    )
    monkeypatch.setattr(mod, "record_click", lambda **kwargs: None)

    class _FakeClient:
        host = "127.0.0.1"

    class _FakeRequest:
        client = _FakeClient()
        headers: dict[str, str] = {}

    return asyncio.get_event_loop().run_until_complete(
        mod.affiliate_redirect(tracking_code="TESTCODE", request=_FakeRequest())
    )


def _afl_ref_set_cookie(response) -> str:
    """Extract the raw Set-Cookie header line for the afl_ref cookie."""
    for key, value in response.raw_headers:
        if key.lower() == b"set-cookie" and b"afl_ref=" in value:
            return value.decode()
    raise AssertionError("afl_ref Set-Cookie header not found")


def test_afl_ref_cookie_not_secure_in_dev(monkeypatch):
    """Dev (ui_cookie_secure=False): cookie set, Secure attribute absent so it survives HTTP."""
    original = S.ui_cookie_secure
    try:
        response = _invoke(monkeypatch, ui_cookie_secure=False)
        assert response.status_code == 302
        header = _afl_ref_set_cookie(response)
        assert "afl_ref=TESTCODE" in header
        assert "secure" not in header.lower(), f"Secure must be absent in dev. Got: {header}"
        # Hardening attributes must remain in all environments.
        assert "httponly" in header.lower()
        assert "samesite=lax" in header.lower()
    finally:
        object.__setattr__(S, "ui_cookie_secure", original)


def test_afl_ref_cookie_secure_in_prod(monkeypatch):
    """Prod (ui_cookie_secure=True): Secure attribute present (FAILS before the fix)."""
    original = S.ui_cookie_secure
    try:
        response = _invoke(monkeypatch, ui_cookie_secure=True)
        assert response.status_code == 302
        header = _afl_ref_set_cookie(response)
        assert "afl_ref=TESTCODE" in header
        assert "secure" in header.lower(), f"Secure must be present in prod. Got: {header}"
        assert "httponly" in header.lower()
        assert "samesite=lax" in header.lower()
    finally:
        object.__setattr__(S, "ui_cookie_secure", original)

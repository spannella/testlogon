"""
GAP-0172 regression: TenantMiddleware must let ROOT sessions bypass the
suspended-tenant 503 wall so operators can remediate a suspension without
break-glass access. Regular users must still be blocked, and a `deleted`
tenant must block everyone (no root bypass).

Offline: the TestClient path is unreliable in this environment, so we drive
``TenantMiddleware.dispatch`` directly with a fake Request + call_next.
Settings ``S`` is frozen, so toggles use object.__setattr__.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from unittest.mock import patch

import jwt
from starlette.responses import JSONResponse

from app.core.settings import S
from app.middleware.tenant import TenantMiddleware


# ── helpers ──────────────────────────────────────────────────────────────────

@contextmanager
def _override(name: str, value):
    sentinel = object()
    old = getattr(S, name, sentinel)
    object.__setattr__(S, name, value)
    try:
        yield
    finally:
        if old is sentinel:
            object.__delattr__(S, name)
        else:
            object.__setattr__(S, name, old)


# A known signing secret used by tests so the HMAC-verified bypass path is
# exercised even when the ambient settings secret is empty.
_TEST_SECRET = "gap0172-test-secret"


def _make_root_cookie(secret: str = _TEST_SECRET) -> str:
    return jwt.encode(
        {"sub": "root@example.com", "role": "root"},
        secret,
        algorithm="HS256",
    )


class _FakeRequest:
    """Minimal stand-in for starlette Request used by TenantMiddleware."""

    def __init__(self, cookies=None, headers=None):
        self.cookies = cookies or {}
        # headers.get is used case-insensitively in the middleware; the real
        # tests only read lowercase keys, so a plain dict suffices.
        self._headers = {k.lower(): v for k, v in (headers or {}).items()}

        class _State:
            pass

        self.state = _State()

    @property
    def headers(self):
        return self._headers


async def _call_next(_request):
    return JSONResponse(status_code=200, content={"ok": True})


def _dispatch(request) -> int:
    mw = TenantMiddleware(app=None)
    resp = asyncio.run(mw.dispatch(request, _call_next))
    return resp.status_code


def _suspended_record():
    return {"tenant_id": "default", "status": "suspended", "settings_overrides": {}}


def _deleted_record():
    return {"tenant_id": "default", "status": "deleted"}


_RESOLVE = "app.middleware.tenant._resolve_tenant_from_domain"


# ── tests ────────────────────────────────────────────────────────────────────

def test_suspended_tenant_blocks_regular_user():
    """Regular (non-root) request must still receive 503 — behavior unchanged."""
    req = _FakeRequest(headers={"host": "tenant.example.com"})
    with _override("multi_tenancy_enabled", True), _override("dev_mode", False), \
            patch(_RESOLVE, return_value=("default", _suspended_record())):
        assert _dispatch(req) == 503


def test_suspended_tenant_allows_root():
    """ROOT cookie must bypass the 503 wall and reach the downstream app.

    BEFORE fix: 503 (root locked out — the bug).
    AFTER fix:  200 (call_next reached).
    """
    req = _FakeRequest(
        cookies={S.ui_access_token_cookie_name: _make_root_cookie()},
        headers={"host": "tenant.example.com"},
    )
    with _override("multi_tenancy_enabled", True), _override("dev_mode", False), \
            _override("ui_access_token_secret", _TEST_SECRET), \
            patch(_RESOLVE, return_value=("default", _suspended_record())):
        assert _dispatch(req) == 200


def test_suspended_tenant_forged_root_cookie_blocked():
    """A cookie not signed with the real secret must NOT grant bypass."""
    forged = jwt.encode({"role": "root"}, "wrong-secret", algorithm="HS256")
    req = _FakeRequest(
        cookies={S.ui_access_token_cookie_name: forged},
        headers={"host": "tenant.example.com"},
    )
    with _override("multi_tenancy_enabled", True), _override("dev_mode", False), \
            _override("ui_access_token_secret", "the-real-secret"), \
            patch(_RESOLVE, return_value=("default", _suspended_record())):
        assert _dispatch(req) == 503


def test_deleted_tenant_blocks_even_root():
    """A deleted tenant returns 410 for everyone, including root."""
    req = _FakeRequest(
        cookies={S.ui_access_token_cookie_name: _make_root_cookie()},
        headers={"host": "tenant.example.com"},
    )
    with _override("multi_tenancy_enabled", True), _override("dev_mode", False), \
            _override("ui_access_token_secret", _TEST_SECRET), \
            patch(_RESOLVE, return_value=("default", _deleted_record())):
        assert _dispatch(req) == 410


def test_multi_tenancy_disabled_is_unchanged():
    """With multi-tenancy off, the status check is never reached (no regression)."""
    req = _FakeRequest(headers={"host": "tenant.example.com"})
    with _override("multi_tenancy_enabled", False), \
            patch(_RESOLVE, return_value=("default", _suspended_record())) as resolver:
        assert _dispatch(req) == 200
        resolver.assert_not_called()
        assert req.state.tenant_id == S.default_tenant_id

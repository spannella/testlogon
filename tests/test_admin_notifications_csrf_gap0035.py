"""GAP-0035 regression: CSRF protection on admin notification template mutations.

The three mutation endpoints (PATCH update, POST preview, POST test-send) must
enforce CSRF for cookie-authenticated browser sessions via
``require_admin_or_root_csrf``. Bearer/API clients (no session cookie) and safe
GET requests remain exempt.

This test is fully offline (no AWS/DynamoDB, no network). The broken
``TestClient`` constructor in this environment (starlette/httpx mismatch) is
avoided by:

1. Asserting the actual fix: each mutation route's dependency tree contains the
   CSRF-enforcing dependency ``require_admin_or_root_csrf`` (not the bare
   ``require_admin_or_root``).
2. Exercising that dependency's real CSRF logic against mock ``Request`` objects
   so the fails-before/passes-after behaviour is verified end to end.

Before the fix the mutation endpoints used ``require_admin_or_root`` (no CSRF),
so part (1) fails (the CSRF dependency is absent from the route).
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from app.auth import policy as policy_mod
from app.auth.deps import AuthenticatedUser
from app.auth.policy import (
    enforce_cookie_csrf,
    require_admin_or_root,
    require_admin_or_root_csrf,
)
from app.auth.roles import Role
from app.core.settings import S
from app.routers import admin_notifications as router_mod
from app.routers.admin_notifications import router as admin_notifications_router

SESSION_COOKIE = S.ui_session_cookie_name  # "ui_session"
CSRF_COOKIE = S.ui_csrf_cookie_name  # "ui_csrf"
CSRF_HEADER = S.ui_csrf_header_name  # "x-csrf-token"

# (method, path-suffix) of the three mutation endpoints that MUST be CSRF-guarded.
MUTATION_ROUTES = {
    ("PATCH", "/ui/admin/notifications/templates/{template_id}"),
    ("POST", "/ui/admin/notifications/templates/{template_id}/preview"),
    ("POST", "/ui/admin/notifications/templates/{template_id}/test-send"),
}
# Read-only routes that must NOT be forced to use the CSRF dependency.
GET_ROUTES = {
    ("GET", "/ui/admin/notifications/templates"),
    ("GET", "/ui/admin/notifications/templates/{template_id}"),
}


def _route_dependency_callables(route) -> set:
    """All dependency callables in a route's dependant tree (recursive)."""
    out = set()

    def _walk(dependant):
        if dependant is None:
            return
        if getattr(dependant, "call", None) is not None:
            out.add(dependant.call)
        for sub in getattr(dependant, "dependencies", []) or []:
            _walk(sub)

    _walk(getattr(route, "dependant", None))
    return out


def _routes_by_key():
    mapping = {}
    for route in admin_notifications_router.routes:
        methods = getattr(route, "methods", None) or set()
        for m in methods:
            mapping[(m, route.path)] = route
    return mapping


# --- Part 1: the fix itself (route wiring) -------------------------------------


@pytest.mark.parametrize("method,path", sorted(MUTATION_ROUTES))
def test_mutation_route_uses_csrf_dependency(method, path):
    """Each mutation endpoint must depend on require_admin_or_root_csrf.

    FAILS BEFORE FIX: route used require_admin_or_root (no CSRF dependency).
    """
    route = _routes_by_key().get((method, path))
    assert route is not None, f"route {method} {path} not found"
    deps = _route_dependency_callables(route)
    assert require_admin_or_root_csrf in deps, (
        f"{method} {path} must use require_admin_or_root_csrf; deps={deps}"
    )
    assert require_admin_or_root not in deps, (
        f"{method} {path} must NOT still use the non-CSRF require_admin_or_root"
    )


@pytest.mark.parametrize("method,path", sorted(GET_ROUTES))
def test_get_route_does_not_require_csrf_dependency(method, path):
    """Read-only routes keep the plain (non-CSRF) dependency."""
    route = _routes_by_key().get((method, path))
    assert route is not None, f"route {method} {path} not found"
    deps = _route_dependency_callables(route)
    assert require_admin_or_root in deps
    assert require_admin_or_root_csrf not in deps


def test_router_imports_csrf_dependency():
    """The router module must import the CSRF-enforcing dependency."""
    assert getattr(router_mod, "require_admin_or_root_csrf", None) is require_admin_or_root_csrf


# --- Part 2: the dependency's real CSRF behaviour ------------------------------


def _request(method: str, *, cookies: dict, headers: dict):
    return SimpleNamespace(method=method, cookies=cookies, headers=headers)


def test_enforce_csrf_rejects_cookie_session_without_header():
    req = _request(
        "POST",
        cookies={SESSION_COOKIE: "sid", CSRF_COOKIE: "tok"},
        headers={},
    )
    with pytest.raises(policy_mod.HTTPException) as exc:
        enforce_cookie_csrf(req)
    assert exc.value.status_code == 403
    assert exc.value.detail == "Missing CSRF token"


def test_enforce_csrf_rejects_mismatched_token():
    req = _request(
        "PATCH",
        cookies={SESSION_COOKIE: "sid", CSRF_COOKIE: "tok"},
        headers={CSRF_HEADER: "wrong"},
    )
    with pytest.raises(policy_mod.HTTPException) as exc:
        enforce_cookie_csrf(req)
    assert exc.value.status_code == 403
    assert exc.value.detail == "CSRF validation failed"


def test_enforce_csrf_accepts_matching_token():
    req = _request(
        "POST",
        cookies={SESSION_COOKIE: "sid", CSRF_COOKIE: "tok"},
        headers={CSRF_HEADER: "tok"},
    )
    enforce_cookie_csrf(req)  # no raise


def test_enforce_csrf_exempts_bearer_clients_without_session_cookie():
    req = _request("POST", cookies={}, headers={"authorization": "Bearer x"})
    enforce_cookie_csrf(req)  # no raise


def test_enforce_csrf_exempts_get():
    req = _request("GET", cookies={SESSION_COOKIE: "sid"}, headers={})
    enforce_cookie_csrf(req)  # no raise


def test_require_admin_or_root_csrf_blocks_admin_without_token():
    """Even a valid admin principal is rejected when CSRF token is missing."""
    admin = AuthenticatedUser(sub="admin-1", role=Role.ADMIN)
    req = _request(
        "POST",
        cookies={SESSION_COOKIE: "sid", CSRF_COOKIE: "tok"},
        headers={},
    )
    with pytest.raises(policy_mod.HTTPException) as exc:
        asyncio.run(require_admin_or_root_csrf(request=req, user=admin))
    assert exc.value.status_code == 403


def test_require_admin_or_root_csrf_allows_admin_with_token():
    admin = AuthenticatedUser(sub="admin-1", role=Role.ADMIN)
    req = _request(
        "POST",
        cookies={SESSION_COOKIE: "sid", CSRF_COOKIE: "tok"},
        headers={CSRF_HEADER: "tok"},
    )
    result = asyncio.run(require_admin_or_root_csrf(request=req, user=admin))
    assert result is admin

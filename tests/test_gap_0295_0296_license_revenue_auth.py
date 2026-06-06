"""Regression tests for GAP-0295 + GAP-0296 (license_revenue auth gating).

GAP-0295: POST /ui/licenses/revenue/register-license previously accepted a
body-supplied ``licensor_id`` (defaulting to the caller's sub) under plain
``require_ui_session`` auth, letting any authenticated user spoof the licensor.

GAP-0296: POST /ui/licenses/revenue/process-split and POST .../revoke-license
were guarded only by ``require_ui_session`` (no role check), letting any
authenticated user fire arbitrary revenue splits / revoke others' licenses.

Fix: all three endpoints are now gated behind ``require_admin_or_root`` and the
licensor/licensee defaults derive from the authenticated admin's sub.

Fully offline: no AWS / DDB / TestClient. We assert the route-level dependency
and drive the handler coroutines directly with stubbed service functions.
"""

from __future__ import annotations

import asyncio

import pytest

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root, require_roles
from app.auth.roles import Role
from app.routers import license_revenue as mod


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _route_dependency_callables(path: str, method: str = "POST"):
    """Return the set of dependency callables wired onto a route."""
    method = method.upper()
    for route in mod.router.routes:
        if getattr(route, "path", None) == path and method in getattr(route, "methods", set()):
            dep = route.dependant
            calls = set()

            def _walk(d):
                if d.call is not None:
                    calls.add(d.call)
                for sub in d.dependencies:
                    _walk(sub)

            _walk(dep)
            return calls
    raise AssertionError(f"route {method} {path} not found")


# ---------------------------------------------------------------------------
# Gating: each protected route must depend on require_admin_or_root
# (fails before the fix, which used require_ui_session).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/ui/licenses/revenue/register-license",
        "/ui/licenses/revenue/revoke-license",
        "/ui/licenses/revenue/process-split",
    ],
)
def test_protected_routes_require_admin_or_root(path):
    calls = _route_dependency_callables(path)
    assert require_admin_or_root in calls, (
        f"{path} must be gated by require_admin_or_root; deps={calls}"
    )
    # And must NOT be gated only by the plain session dependency.
    assert mod.require_ui_session not in calls, (
        f"{path} must not rely on require_ui_session for auth"
    )


# ---------------------------------------------------------------------------
# require_admin_or_root actually rejects a regular USER (403) and accepts ADMIN.
# ---------------------------------------------------------------------------


def test_require_admin_or_root_rejects_regular_user():
    user = AuthenticatedUser(sub="alice", role=Role.USER)
    with pytest.raises(Exception) as exc:
        _run(require_admin_or_root(user=user))
    assert getattr(exc.value, "status_code", None) == 403


def test_require_admin_or_root_accepts_admin_and_root():
    for role in (Role.ADMIN, Role.ROOT):
        user = AuthenticatedUser(sub="charlie", role=role)
        out = _run(require_admin_or_root(user=user))
        assert out is user


# ---------------------------------------------------------------------------
# Handler behaviour: licensor/licensee derive from the authenticated admin sub.
# ---------------------------------------------------------------------------


def test_register_license_ignores_body_licensor_default(monkeypatch):
    """No body licensor_id -> admin's own sub is recorded (not spoofable)."""
    captured = {}

    def _fake_register(**kwargs):
        captured.update(kwargs)
        return dict(kwargs)

    monkeypatch.setattr(mod.svc, "register_content_license", _fake_register)
    admin = AuthenticatedUser(sub="admin_sub", role=Role.ADMIN)
    body = {"issued_license_id": "il1", "content_id": "c1", "licensee_id": "lee"}

    res = _run(mod.register_license(body=body, admin=admin))

    assert res["ok"] is True
    assert captured["licensor_id"] == "admin_sub"


def test_register_license_admin_may_specify_licensor(monkeypatch):
    """An admin (already gated) may explicitly register on behalf of a licensor."""
    captured = {}
    monkeypatch.setattr(
        mod.svc,
        "register_content_license",
        lambda **kw: captured.update(kw) or dict(kw),
    )
    admin = AuthenticatedUser(sub="admin_sub", role=Role.ROOT)
    body = {"content_id": "c1", "licensor_id": "creator_x", "licensee_id": "lee"}

    _run(mod.register_license(body=body, admin=admin))
    assert captured["licensor_id"] == "creator_x"


def test_process_split_defaults_licensee_to_admin_sub(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        mod.svc,
        "process_revenue_split",
        lambda **kw: captured.update(kw) or ["split"],
    )
    admin = AuthenticatedUser(sub="admin_sub", role=Role.ADMIN)
    body = {"content_id": "c1", "source_amount_cents": "100"}

    res = _run(mod.process_split(body=body, admin=admin))

    assert res == {"ok": True, "splits": ["split"]}
    assert captured["licensee_id"] == "admin_sub"
    assert captured["source_amount_cents"] == 100


def test_revoke_license_calls_service(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        mod.svc,
        "revoke_content_license",
        lambda **kw: captured.update(kw),
    )
    admin = AuthenticatedUser(sub="admin_sub", role=Role.ROOT)
    body = {"content_id": "c1", "issued_license_id": "il1"}

    res = _run(mod.revoke_license(body=body, admin=admin))

    assert res == {"ok": True}
    assert captured == {"content_id": "c1", "issued_license_id": "il1"}


# Sanity: require_roles raises 403 for USER (underpins the gate above).
def test_require_roles_blocks_user():
    user = AuthenticatedUser(sub="alice", role=Role.USER)
    with pytest.raises(Exception) as exc:
        require_roles(user, {Role.ADMIN, Role.ROOT})
    assert getattr(exc.value, "status_code", None) == 403

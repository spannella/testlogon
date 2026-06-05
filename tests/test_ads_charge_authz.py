"""Regression test for GAP-0003 (ADS-007): internal ad-charge endpoints lacked
access control.

The three ``POST /ui/ads/internal/charge-*`` endpoints were registered on the
user-facing ``router`` with only ``Depends(require_ui_session)`` and never
verified that the caller owned the supplied ``account_id`` (``ctx`` was fetched
and discarded). Any authenticated user could drain any advertiser's balance by
POSTing an arbitrary ``account_id``.

The fix (per docs/tickets/gap-tickets/writeups/GAP-0003.md, preferred Option A)
moves the three endpoints onto ``admin_router`` (prefix ``/ui/admin/ads``) behind
``require_admin_or_root``.

Fails-before / passes-after contract:
  * The three charge routes must NO LONGER be reachable on the user-facing
    ``router`` (prefix ``/ui/ads``). Before the fix they were registered there
    with ``require_ui_session`` (any authed user) -> horizontal priv-esc.
  * The three charge routes MUST now live on ``admin_router`` (prefix
    ``/ui/admin/ads``) and each MUST depend on ``require_admin_or_root``.
  * Behaviourally: a non-admin user (Alice) is rejected with 403 by
    ``require_admin_or_root``; an admin reaches the handler and the charge runs.

Runs fully offline -- it inspects the real router registration and invokes the
real handlers directly (the direct-call style used by
``tests/test_activity_feed_idor.py``). No DynamoDB/AWS needed: the billing
functions imported lazily inside each handler are monkeypatched.
"""

from __future__ import annotations

import asyncio
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

ALICE = "alice_user_sub"
ADMIN = "admin_user_sub"
BOB_ACCOUNT = "ACCT#bob_test_account"

CHARGE_PATHS = ["/internal/charge-impression", "/internal/charge-click",
                "/internal/charge-conversion"]


@pytest.fixture(autouse=True)
def _mock_env(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "1")
    monkeypatch.setenv("DDB_ENDPOINT_URL", "http://localhost:8001")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("UI_ACCESS_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("API_KEY_PEPPER", "test-pepper")


def _routes(router):
    """Map ``path -> route`` for a router. ``APIRoute.path`` already includes the
    router prefix once the decorator has run."""
    return {r.path: r for r in router.routes if hasattr(r, "path")}


# ---------------------------------------------------------------------------
# Routing contract: the charge endpoints must be admin-only, not user-facing.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", CHARGE_PATHS)
def test_charge_route_not_on_user_facing_router(path):
    """The vulnerable user-facing routes must be gone from ``/ui/ads``."""
    from app.routers import ads as ads_router

    user_routes = _routes(ads_router.router)
    assert "/ui/ads" + path not in user_routes, (
        f"vulnerable user-facing route still registered: /ui/ads{path}"
    )


@pytest.mark.parametrize("path", CHARGE_PATHS)
def test_charge_route_on_admin_router(path):
    """Each charge route must now live on the admin router."""
    from app.routers import ads as ads_router

    admin_routes = _routes(ads_router.admin_router)
    assert "/ui/admin/ads" + path in admin_routes, (
        f"charge route missing from admin router: /ui/admin/ads{path}"
    )


@pytest.mark.parametrize("path", CHARGE_PATHS)
def test_charge_route_guarded_by_admin_dependency(path):
    """Each admin charge route must declare ``require_admin_or_root`` as a
    dependency (and must NOT use ``require_ui_session``)."""
    from app.routers import ads as ads_router
    from app.auth.policy import require_admin_or_root
    from app.services.sessions import require_ui_session

    route = _routes(ads_router.admin_router)["/ui/admin/ads" + path]
    dep_calls = {d.call for d in route.dependant.dependencies}
    # require_admin_or_root may be nested under get_authenticated_user; check the
    # flattened dependant tree.
    all_calls = set()

    def _walk(dep):
        all_calls.add(dep.call)
        for sub in dep.dependencies:
            _walk(sub)

    for d in route.dependant.dependencies:
        _walk(d)

    assert require_admin_or_root in all_calls, (
        f"{path} not guarded by require_admin_or_root"
    )
    assert require_ui_session not in all_calls, (
        f"{path} still uses require_ui_session"
    )


# ---------------------------------------------------------------------------
# Behavioural contract: invoke handlers directly with forged auth contexts.
# ---------------------------------------------------------------------------

HANDLERS = [
    ("internal_charge_impression", "charge_impression"),
    ("internal_charge_click", "charge_click"),
    ("internal_charge_conversion", "charge_conversion"),
]


@pytest.fixture()
def charge_recorder(monkeypatch):
    calls: list[dict] = []
    import app.services.ad_billing as ad_billing

    def _mk(name):
        def _fn(**kwargs):
            calls.append({"fn": name, **kwargs})
            return {"ok": True, "fn": name}
        return _fn

    monkeypatch.setattr(ad_billing, "charge_impression", _mk("impression"))
    monkeypatch.setattr(ad_billing, "charge_click", _mk("click"))
    monkeypatch.setattr(ad_billing, "charge_conversion", _mk("conversion"))
    return calls


def _body():
    return {
        "account_id": BOB_ACCOUNT,
        "campaign_id": "CAMPAIGN#c1",
        "bid_cpm_cents": 50000,
        "bid_cpc_cents": 50000,
        "bid_cpa_cents": 50000,
    }


@pytest.mark.parametrize("handler_name,_svc", HANDLERS)
def test_admin_invocation_charges(charge_recorder, handler_name, _svc):
    """An admin-authenticated call reaches the billing engine."""
    from app.routers import ads as ads_router
    from app.auth.deps import AuthenticatedUser
    from app.auth.roles import Role

    handler = getattr(ads_router, handler_name)
    admin = AuthenticatedUser(sub=ADMIN, role=Role.ADMIN)
    result = asyncio.run(handler(_body(), user=admin))
    assert result.get("ok") is True
    assert any(c.get("account_id") == BOB_ACCOUNT for c in charge_recorder), (
        f"admin charge did not reach billing engine: {charge_recorder}"
    )


@pytest.mark.parametrize("handler_name,_svc", HANDLERS)
def test_non_admin_rejected_by_dependency(charge_recorder, handler_name, _svc):
    """A non-admin (USER) is rejected by ``require_admin_or_root`` (403) before
    any charge runs.

    This exercises the real auth dependency the handler now depends on.
    """
    from fastapi import HTTPException

    from app.auth.policy import require_admin_or_root
    from app.auth.deps import AuthenticatedUser
    from app.auth.roles import Role

    alice = AuthenticatedUser(sub=ALICE, role=Role.USER)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(require_admin_or_root(user=alice))
    assert exc.value.status_code == 403
    assert charge_recorder == []

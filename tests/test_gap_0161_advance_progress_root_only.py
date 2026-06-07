"""Regression test for GAP-0161.

The ``POST /ui/achievements/admin/advance`` endpoint forcibly advances any
achievement metric counter for the caller and can unlock any badge. It was
guarded only by ``require_ui_session`` — any authenticated USER could call it
and self-award achievements/leaderboard standing.

Fix: the endpoint must depend on ``require_root_session`` (ROOT only), and the
handler must read the user sub from the returned ``AuthenticatedUser`` dataclass
(``ctx.sub``) instead of subscripting a dict (``ctx["user_sub"]``).

Fails-before:
  * The endpoint's wired dependency was ``require_ui_session`` (no role check),
    so a USER-role caller was admitted.
  * Calling the handler with an ``AuthenticatedUser`` would have raised
    ``TypeError`` because of ``ctx["user_sub"]``.

Passes-after:
  * The endpoint's dependency is ``require_root_session`` → USER callers get 403.
  * ROOT callers are admitted and the handler reads ``ctx.sub`` correctly.

Fully offline: no real AWS / DynamoDB. ``require_root_session`` is driven via the
dev-header fallback against a fake Request, and ``advance_progress`` is
monkeypatched so the handler does not touch DynamoDB.
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

from app.auth.deps import AuthenticatedUser, require_root_session
from app.auth.roles import Role
from app.services.sessions import require_ui_session
from app.core.settings import S


ROOT_SUB = "root.test@gap0161.local"
ALICE_SUB = "alice@gap0161.local"


class _FakeRequest:
    """Minimal stand-in for starlette Request used by the auth resolver."""

    def __init__(self, headers: dict[str, str]):
        # The resolver reads headers case-insensitively via .get(lower-case key).
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.cookies = {}


@pytest.fixture
def dev_root_settings():
    """Freeze-safe override: dev-header fallback enabled, Cognito disabled,
    ROOT_USER_SUB pinned to our test root sub. Restored afterwards."""
    saved = {
        "dev_mode": S.dev_mode,
        "cognito_user_pool_id": S.cognito_user_pool_id,
        "cognito_app_client_id": S.cognito_app_client_id,
        "root_user_sub": S.root_user_sub,
    }
    object.__setattr__(S, "dev_mode", True)
    object.__setattr__(S, "cognito_user_pool_id", "")
    object.__setattr__(S, "cognito_app_client_id", "")
    object.__setattr__(S, "root_user_sub", ROOT_SUB)
    try:
        yield
    finally:
        for k, v in saved.items():
            object.__setattr__(S, k, v)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_advance_endpoint_is_root_guarded(dev_root_settings):
    """The endpoint must be wired to require_root_session, not require_ui_session.

    FAILS-BEFORE: the endpoint depended on require_ui_session.
    """
    import inspect

    from app.routers import achievements as ach

    # Pull the Depends marker off the function signature robustly.
    sig = inspect.signature(ach.admin_advance_progress)
    ctx_default = sig.parameters["ctx"].default
    dependency = getattr(ctx_default, "dependency", None)

    assert dependency is require_root_session, (
        "admin_advance_progress must be guarded by require_root_session"
    )
    assert dependency is not require_ui_session, (
        "admin_advance_progress must NOT be guarded by require_ui_session"
    )


def test_require_root_session_rejects_normal_user(dev_root_settings):
    """A USER-role caller hitting the root guard must get HTTP 403.

    FAILS-BEFORE: the endpoint used require_ui_session, which admits any USER.
    """
    req = _FakeRequest({"x-user-sub": ALICE_SUB, "x-user-role": "USER"})
    with pytest.raises(HTTPException) as exc:
        _run(require_root_session(req))
    assert exc.value.status_code == 403


def test_root_caller_advances_progress(dev_root_settings, monkeypatch):
    """ROOT caller is admitted; handler reads ctx.sub and advances progress.

    FAILS-BEFORE: handler did ctx["user_sub"] which raises TypeError on an
    AuthenticatedUser dataclass.
    """
    from app.routers import achievements as ach

    # 1. Root guard admits the configured ROOT sub.
    req = _FakeRequest({"x-user-sub": ROOT_SUB, "x-user-role": "ROOT"})
    ctx = _run(require_root_session(req))
    assert isinstance(ctx, AuthenticatedUser)
    assert ctx.role is Role.ROOT
    assert ctx.sub == ROOT_SUB

    # 2. The handler reads ctx.sub and forwards to advance_progress (mocked).
    captured: dict = {}

    def _fake_advance(user_sub, metric_key, delta=1):
        captured["user_sub"] = user_sub
        captured["metric_key"] = metric_key
        captured["delta"] = delta
        return [{"achievement_id": "ach_first_post"}]

    import app.services.achievement_progress as prog
    monkeypatch.setattr(prog, "advance_progress", _fake_advance)

    body = ach.AdvanceProgressIn(metric_key="post_count", delta=3)
    result = _run(ach.admin_advance_progress(req=body, ctx=ctx))

    assert result == {"ok": True, "newly_unlocked": [{"achievement_id": "ach_first_post"}]}
    assert captured == {"user_sub": ROOT_SUB, "metric_key": "post_count", "delta": 3}

"""Regression test for GAP-0153.

`app/services/milestones.py:check_milestone` was a complete, idempotent milestone
detector that had ZERO call sites — milestones could only appear by manually
seeding DynamoDB. The fix wires `check_milestone` into the subscription signup
path so the ``subscribers`` metric is evaluated in real time after each new
subscription is written.

Fails-before: the ``subscribe`` endpoint never imported or called
``check_milestone``.
Passes-after: ``subscribe`` calls ``check_milestone(creator_id, "subscribers",
<active count>)`` after persisting the subscription.

Fully offline: every side-effecting collaborator (DynamoDB read/write, billing,
notifications, audit, calendar, profile lookups) is monkeypatched, and the
``subscribe`` coroutine is invoked directly (no TestClient/httpx coupling).
"""
from __future__ import annotations

import asyncio

import app.services.milestones as milestones_module
from app.routers import subscription_server as ss


def _stub_subscribe_io(monkeypatch, *, active_count):
    """Neutralize all I/O in the subscribe path, return recorded check_milestone calls."""
    plan = {
        "plan_id": "plan_1",
        "creator_id": "creator_1",
        "status": "active",
        "interval": "month",
        "price_cents": 500,
        "currency": "USD",
    }

    # Plan lookup
    monkeypatch.setattr(ss, "ddb_get_item", lambda pk, sk: dict(plan))
    # Persistence + side effects (no-ops / minimal returns)
    monkeypatch.setattr(ss, "save_subscription", lambda sub: None)
    monkeypatch.setattr(ss, "record_billing_subscription", lambda sub: None)
    monkeypatch.setattr(ss, "put_notification", lambda **kw: None)
    monkeypatch.setattr(ss, "audit_event", lambda *a, **kw: None)
    monkeypatch.setattr(ss, "refresh_subscription_calendar_events", lambda sub, plan=None: None)
    monkeypatch.setattr(ss, "attach_subscription_profiles", lambda sub: sub)
    monkeypatch.setattr(ss, "get_subscription_settings", lambda creator_id: {})
    # Active-subscriber count comes back as our seeded value.
    monkeypatch.setattr(ss, "count_active_subscribers", lambda creator_id: active_count)

    # Spy on check_milestone where the router imports it from.
    calls: list[tuple] = []

    def spy_check_milestone(user_id, metric, value):
        calls.append((user_id, metric, value))
        return None

    monkeypatch.setattr(milestones_module, "check_milestone", spy_check_milestone)
    return calls


class _FakeRequest:
    client = None
    headers: dict = {}


def test_subscribe_calls_check_milestone_for_subscribers(monkeypatch):
    calls = _stub_subscribe_io(monkeypatch, active_count=10)

    body = ss.SubscribeIn(interval="month", trial_days=7)  # trialing: skips invoice/billing block
    result = asyncio.run(
        ss.subscribe(
            plan_id="plan_1",
            body=body,
            request=_FakeRequest(),
            x_user_id="subscriber_1",
        )
    )
    assert result["creator_id"] == "creator_1"

    # FAILS-BEFORE: no check_milestone call recorded.
    subs_calls = [c for c in calls if c[1] == "subscribers"]
    assert len(subs_calls) == 1, "subscribe must call check_milestone once for the subscribers metric"
    user_id, metric, value = subs_calls[0]
    assert user_id == "creator_1"
    assert metric == "subscribers"
    assert value == 10


def test_count_active_subscribers_filters_inactive(monkeypatch):
    """count_active_subscribers counts only active/trialing/past_due SUB# items."""
    items = [
        {"sk": "SUB#a", "status": "active"},
        {"sk": "SUB#b", "status": "trialing"},
        {"sk": "SUB#c", "status": "past_due"},
        {"sk": "SUB#d", "status": "canceled"},
        {"sk": "SUB#e", "status": "expired"},
        {"sk": "META", "status": "active"},  # non-subscription row ignored
    ]
    monkeypatch.setattr(ss, "ddb_query", lambda pk: items)
    assert ss.count_active_subscribers("creator_1") == 3

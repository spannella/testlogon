from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from app.services import subscription_entitlement_backfill as svc


class _Table:
    def __init__(self):
        self.items = {}

    def put_item(self, Item):
        self.items[(Item["user_id"], Item["entitlement_id"])] = dict(Item)

    def scan(self, **kwargs):
        return {"Items": list(self.items.values())}

    def update_item(self, *, Key, **kwargs):
        item = self.items[(Key["user_id"], Key["entitlement_id"])]
        values = kwargs.get("ExpressionAttributeValues", {})
        if ":rev" in values:
            item["status"] = values[":rev"]
        if ":b" in values:
            item["rollback_batch_id"] = values[":b"]


def _active_sub() -> dict:
    return {
        "subscription_id": "sub-1",
        "subscriber_id": "u1",
        "plan_id": "pro",
        "status": "active",
        "interval": "month",
        "current_period_start": "2026-01-01T00:00:00Z",
        "current_period_end": "2026-02-01T00:00:00Z",
    }


def _plan() -> dict:
    return {
        "plan_id": "pro",
        "plan_version": 2,
        "product_type": "api_package",
        "sku": "subscription_plan:pro",
        "interval": "month",
        "limit_overrides": {"monthly_call_limit": 1000},
    }


def test_backfill_dry_run_reports_missing_entitlement_with_owner_tags() -> None:
    report = svc.plan_subscription_entitlement_backfill(
        subscriptions=[_active_sub()],
        plans_by_id={"pro": _plan()},
        existing_entitlements=[],
        batch_id="batch-1",
        now=datetime(2026, 1, 15, tzinfo=timezone.utc),
    )
    assert report["drift_count"] == 1
    drift = report["drifts"][0]
    assert drift["drift_type"] == "missing_entitlement"
    assert drift["owner_team"] == "api"


def test_apply_mode_is_deterministic_on_rerun(monkeypatch) -> None:
    table = _Table()
    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=table))

    report = svc.plan_subscription_entitlement_backfill(
        subscriptions=[_active_sub()],
        plans_by_id={"pro": _plan()},
        existing_entitlements=[],
        batch_id="batch-2",
        now=datetime(2026, 1, 15, tzinfo=timezone.utc),
    )
    first = svc.apply_subscription_entitlement_backfill(report)
    second = svc.apply_subscription_entitlement_backfill(report)

    assert first.applied == 1
    assert second.applied == 1
    assert len(table.items) == 1


def test_rollback_revokes_batch_entitlements(monkeypatch) -> None:
    table = _Table()
    table.put_item(
        {
            "user_id": "u1",
            "entitlement_id": "e1",
            "status": "active",
            "backfill_batch_id": "batch-3",
        }
    )
    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=table))

    out = svc.rollback_subscription_entitlement_backfill("batch-3")
    assert out["revoked"] == 1
    assert table.items[("u1", "e1")]["status"] == "revoked"

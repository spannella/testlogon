from __future__ import annotations

import asyncio

from app.routers import subscription_server as router


def _base_plan() -> dict:
    return {
        "plan_id": "plan-pro",
        "creator_id": "creator-1",
        "status": "active",
        "price_cents": 1000,
        "currency": "usd",
        "interval": "month",
    }


def _base_subscription() -> dict:
    return {
        "subscription_id": "sub-1",
        "plan_id": "plan-pro",
        "creator_id": "creator-1",
        "subscriber_id": "user-1",
        "interval": "month",
        "provider": "stub",
        "provider_subscription_id": "stub-sub",
        "status": "active",
        "start_at": 100,
        "current_period_end": 200,
        "cancel_at_period_end": False,
        "price_cents": 1000,
        "currency": "usd",
        "auto_renew": True,
        "created_at": 100,
        "updated_at": 100,
    }


def _patch_common(monkeypatch, *, calls: list[dict], plan: dict | None = None, sub: dict | None = None) -> None:
    plan = dict(plan or _base_plan())
    sub = dict(sub or _base_subscription())

    def _ddb_get_item(pk: str, sk: str):
        if pk == router.pk_plan(plan["plan_id"]):
            return dict(plan)
        if pk == router.pk_subscription(sub["subscription_id"]):
            return dict(sub)
        return None

    monkeypatch.setattr(router, "now_ts", lambda: 100)
    monkeypatch.setattr(router, "new_id", lambda prefix: f"{prefix}-id")
    monkeypatch.setattr(router, "ddb_get_item", _ddb_get_item)
    monkeypatch.setattr(router, "ddb_put_item", lambda item: None)
    monkeypatch.setattr(router, "save_subscription", lambda item: None)
    monkeypatch.setattr(router, "record_billing_subscription", lambda item: None)
    monkeypatch.setattr(router, "save_invoice", lambda item: None)
    monkeypatch.setattr(router, "record_billing_payment", lambda invoice, sid: None)
    monkeypatch.setattr(router, "record_billing_transaction", lambda **kwargs: None)
    monkeypatch.setattr(router, "save_ledger_entry", lambda creator_id, entry: None)
    monkeypatch.setattr(router, "put_notification", lambda **kwargs: None)
    monkeypatch.setattr(router, "audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(router, "refresh_subscription_calendar_events", lambda *args, **kwargs: None)
    monkeypatch.setattr(router, "get_subscription_settings", lambda creator_id: {"disable_auto_renew": False})
    monkeypatch.setattr(router, "get_profile_identity", lambda user_id: {"user_id": user_id})
    monkeypatch.setattr(router, "emit_subscription_cycle_order_and_reconcile", lambda **kwargs: calls.append(kwargs) or {"order_id": "ord-1", "reconciliation": {"status": "processed"}})


def test_subscribe_path_uses_shared_emit_and_reconcile(monkeypatch) -> None:
    calls: list[dict] = []
    _patch_common(monkeypatch, calls=calls)

    body = router.SubscribeIn()
    out = asyncio.run(router.subscribe("plan-pro", body, None, x_user_id="user-1"))

    assert out["subscription_id"]
    assert len(calls) == 1
    assert calls[0]["invoice"]["invoice_id"] == "inv-id"


def test_trial_convert_path_uses_shared_emit_and_reconcile(monkeypatch) -> None:
    calls: list[dict] = []
    sub = _base_subscription()
    sub["status"] = "trialing"
    _patch_common(monkeypatch, calls=calls, sub=sub)

    out = asyncio.run(router.convert_trial("sub-1", None, x_user_id="user-1"))

    assert out["status"] == "active"
    assert len(calls) == 1
    assert calls[0]["invoice"]["invoice_id"] == "inv-id"


def test_change_plan_proration_path_uses_shared_emit_and_reconcile(monkeypatch) -> None:
    calls: list[dict] = []
    _patch_common(monkeypatch, calls=calls)

    body = router.SubscriptionChangePlanIn(plan_id="plan-pro", effective="immediate", proration_amount_cents=250)
    out = asyncio.run(router.change_subscription_plan("sub-1", body, None, x_user_id="user-1"))

    assert out["plan_id"] == "plan-pro"
    assert len(calls) == 1
    assert calls[0]["invoice"]["is_proration"] is True


def test_webhook_proration_path_uses_shared_emit_and_reconcile(monkeypatch) -> None:
    calls: list[dict] = []
    _patch_common(monkeypatch, calls=calls)

    body = router.WebhookIn(
        event_type="invoice.proration",
        subscription_id="sub-1",
        metadata={"proration_amount_cents": 300, "invoice_id": "inv-pror", "currency": "usd"},
    )
    out = asyncio.run(router.billing_webhook("stub", body))

    assert out["ok"] is True
    assert len(calls) == 1
    assert calls[0]["invoice"]["invoice_id"] == "inv-pror"


def test_webhook_invoice_paid_path_uses_shared_emit_and_reconcile(monkeypatch) -> None:
    calls: list[dict] = []
    _patch_common(monkeypatch, calls=calls)

    body = router.WebhookIn(
        event_type="invoice.paid",
        subscription_id="sub-1",
        invoice_id="inv-renew",
        metadata={"amount_cents": 1000, "currency": "usd"},
    )
    out = asyncio.run(router.billing_webhook("stub", body))

    assert out["ok"] is True
    assert len(calls) == 1
    assert calls[0]["invoice"]["invoice_id"] == "inv-renew"

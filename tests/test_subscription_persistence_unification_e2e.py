from __future__ import annotations

import asyncio

from app.routers import subscription_server as router
from app.services import entitlements_service as entitlements_service
from app.services import entitlements_visibility as visibility
from app.services import payment_reconciliation as payment_reconciliation
from app.services import subscription_cycle_orders as svc


class _OrdersTable:
    def __init__(self, order=None):
        self.order = order

    def get_item(self, Key):
        if self.order and self.order.get("order_id") == Key.get("order_id"):
            return {"Item": dict(self.order)}
        return {}


class _OrderItemsTable:
    def __init__(self, rows=None):
        self.rows = list(rows or [])

    def query(self, KeyConditionExpression):
        return {"Items": list(self.rows)}

    def scan(self):
        return {"Items": list(self.rows)}


class _EntitlementsTable:
    def __init__(self):
        self.items = []

    def put_item(self, Item, ConditionExpression=None):
        item = dict(Item)
        if ConditionExpression and any(x.get("user_id") == item.get("user_id") and x.get("entitlement_id") == item.get("entitlement_id") for x in self.items):
            class _CExc(Exception):
                def __init__(self):
                    self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}

            raise _CExc()
        self.items = [x for x in self.items if not (x.get("user_id") == item.get("user_id") and x.get("entitlement_id") == item.get("entitlement_id"))]
        self.items.append(item)

    def query(self, KeyConditionExpression):
        return {"Items": list(self.items)}

    def scan(self, **kwargs):
        return {"Items": list(self.items)}


def _table_backed_gateway(order_id: str, user_id: str, ent_table: _EntitlementsTable) -> svc.SubscriptionCycleReconciliationGateway:
    repo = svc.TableBackedEntitlementsRepository(
        orders_table=_OrdersTable({"order_id": order_id, "user_id": user_id, "status": "paid", "created_by": "system"}),
        order_items_table=_OrderItemsTable([
            {"order_id": order_id, "item_id": "1", "sku": "subscription_plan:pro", "product_type": "api_package", "scope": {"allowed_actions": ["request_units"], "resource": {}}, "usage_limit": 5, "source_system": "subscription_cycle"}
        ]),
        entitlements_table=ent_table,
    )
    return svc.SubscriptionCycleReconciliationGateway(entitlements_repo=repo)


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


def _patch_router_common(monkeypatch, *, calls: list[dict], plan: dict | None = None, sub: dict | None = None) -> None:
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


def test_e2e_renewal_to_visibility_with_audit_chain(monkeypatch) -> None:
    events = []
    ent_table = _EntitlementsTable()
    gateway = _table_backed_gateway("ord-e2e-1", "u-e2e", ent_table)
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: events.append((args, kwargs)))
    monkeypatch.setattr(entitlements_service, "audit_event", lambda *args, **kwargs: events.append((args, kwargs)))
    monkeypatch.setattr(payment_reconciliation, "audit_event", lambda *args, **kwargs: events.append((args, kwargs)))
    monkeypatch.setattr(visibility.T.entitlements, "query", ent_table.query)

    out = gateway.process_webhook_event(
        provider=svc.SUBSCRIPTION_SYSTEM_PROVIDER,
        payload={
            "event_id": "subscription_charge:inv-e2e-1",
            "order_id": "ord-e2e-1",
            "status": "succeeded",
            "occurred_at": "2026-01-01T00:00:00Z",
            "raw": {"subscriber_id": "u-e2e", "invoice_id": "inv-e2e-1", "subscription_id": "sub-e2e-1"},
        },
    )

    assert out["status"] == "processed"
    listed = visibility.list_user_entitlements("u-e2e")
    assert listed["count"] == 1
    assert listed["items"][0]["status"] == "active"
    assert any(evt[0][0] == "payment_webhook_entitlement_link" for evt in events)


def test_e2e_duplicate_invoice_no_duplicate_entitlement(monkeypatch) -> None:
    ent_table = _EntitlementsTable()
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(visibility.T.entitlements, "query", ent_table.query)

    payload = {
        "event_id": "subscription_charge:inv-e2e-dup",
        "order_id": "ord-e2e-dup",
        "status": "succeeded",
        "occurred_at": "2026-01-01T00:00:00Z",
        "raw": {"subscriber_id": "u-dup", "invoice_id": "inv-e2e-dup", "subscription_id": "sub-dup"},
    }

    g1 = _table_backed_gateway("ord-e2e-dup", "u-dup", ent_table)
    g2 = _table_backed_gateway("ord-e2e-dup", "u-dup", ent_table)
    first = g1.process_webhook_event(provider=svc.SUBSCRIPTION_SYSTEM_PROVIDER, payload=payload)
    second = g2.process_webhook_event(provider=svc.SUBSCRIPTION_SYSTEM_PROVIDER, payload=payload)

    assert first["status"] == "processed"
    assert second["status"] == "processed"
    listed = visibility.list_user_entitlements("u-dup")
    assert listed["count"] == 1


def test_e2e_transient_failure_dead_letter_then_replay_to_active(monkeypatch) -> None:
    ent_table = _EntitlementsTable()
    gateway = _table_backed_gateway("ord-e2e-transient", "u-transient", ent_table)
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(visibility.T.entitlements, "query", ent_table.query)

    original = gateway._service.entitlements.grant_entitlement

    def _flaky(order_id: str):
        if not getattr(_flaky, "done", False):
            _flaky.done = True
            raise RuntimeError("transient fail")
        return original(order_id)

    gateway._service.entitlements.grant_entitlement = _flaky  # type: ignore[assignment]

    payload = {
        "event_id": "subscription_charge:inv-e2e-transient",
        "order_id": "ord-e2e-transient",
        "status": "succeeded",
        "occurred_at": "2026-01-01T00:00:00Z",
        "raw": {"subscriber_id": "u-transient", "invoice_id": "inv-e2e-transient", "subscription_id": "sub-transient"},
    }

    first = gateway.process_webhook_event(provider=svc.SUBSCRIPTION_SYSTEM_PROVIDER, payload=payload)
    assert first["status"] == "dead_lettered"

    replay = gateway.replay_dead_letters_for_invoice_range(invoice_start="inv-e2e-transient", invoice_end="inv-e2e-transient")
    assert replay["replayed"] == 1
    assert replay["processed"] == 1

    listed = visibility.list_user_entitlements("u-transient")
    assert listed["count"] == 1
    assert listed["items"][0]["status"] == "active"


def test_e2e_all_five_subscription_charge_paths_use_shared_flow(monkeypatch) -> None:
    calls: list[dict] = []
    _patch_router_common(monkeypatch, calls=calls)

    asyncio.run(router.subscribe("plan-pro", router.SubscribeIn(), None, x_user_id="user-1"))

    trial_sub = _base_subscription()
    trial_sub["status"] = "trialing"
    _patch_router_common(monkeypatch, calls=calls, sub=trial_sub)
    asyncio.run(router.convert_trial("sub-1", None, x_user_id="user-1"))

    _patch_router_common(monkeypatch, calls=calls)
    asyncio.run(router.change_subscription_plan("sub-1", router.SubscriptionChangePlanIn(plan_id="plan-pro", effective="immediate", proration_amount_cents=250), None, x_user_id="user-1"))

    _patch_router_common(monkeypatch, calls=calls)
    asyncio.run(router.billing_webhook("stub", router.WebhookIn(event_type="invoice.proration", subscription_id="sub-1", metadata={"proration_amount_cents": 100, "invoice_id": "inv-pror", "currency": "usd"})))

    _patch_router_common(monkeypatch, calls=calls)
    asyncio.run(router.billing_webhook("stub", router.WebhookIn(event_type="invoice.paid", subscription_id="sub-1", invoice_id="inv-renew", metadata={"amount_cents": 1000, "currency": "usd"})))

    assert len(calls) == 5

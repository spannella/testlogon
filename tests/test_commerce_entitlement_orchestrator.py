from __future__ import annotations

import time

from app.services import commerce_entitlement_orchestrator as orchestrator
from app.services import entitlements_visibility as visibility
from app.services.entitlements_service import EntitlementsService
from app.services.subscription_cycle_orders import TableBackedEntitlementsRepository


class _OrdersTable:
    def __init__(self, rows=None):
        self.rows = dict(rows or {})

    def get_item(self, Key):
        order_id = str((Key or {}).get("order_id") or "")
        row = self.rows.get(order_id)
        return {"Item": dict(row)} if row else {}


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
        existing = any(
            x.get("user_id") == item.get("user_id") and x.get("entitlement_id") == item.get("entitlement_id")
            for x in self.items
        )
        if ConditionExpression and existing:
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


class _DeadLettersTable:
    def __init__(self):
        self.items = []

    def put_item(self, Item):
        self.items.append(dict(Item))

    def query(self, KeyConditionExpression):
        # orchestrator falls back to scan when KeyConditionExpression is not a real condition object
        raise RuntimeError("query not supported in fake")

    def scan(self):
        return {"Items": list(self.items)}


def _make_orchestrator(order_id: str = "ord-1", user_id: str = "u-1", *, status: str = "paid", amount_cents: int = 100):
    orders_table = _OrdersTable({order_id: {"order_id": order_id, "user_id": user_id, "status": status, "created_by": "system"}})
    entitlements_table = _EntitlementsTable()
    dead_letters_table = _DeadLettersTable()
    repo = TableBackedEntitlementsRepository(
        orders_table=orders_table,
        order_items_table=_OrderItemsTable([
            {
                "order_id": order_id,
                "item_id": "1",
                "sku": "subscription_plan:pro",
                "product_type": "api_package",
                "scope": {"allowed_actions": ["request_units"], "resource": {}},
                "usage_limit": 100,
                "source_system": "shopping_cart",
                "unit_price_cents": amount_cents,
                "billing_model": "one_time",
            }
        ]),
        entitlements_table=entitlements_table,
    )
    service = EntitlementsService(repo)
    return orchestrator.CommerceEntitlementOrchestrator(entitlements_service=service, dead_letter_table=dead_letters_table), repo, orders_table, entitlements_table, dead_letters_table


def test_process_order_entitlements_grants_from_canonical_order(monkeypatch):
    monkeypatch.setattr(orchestrator, "audit_event", lambda *args, **kwargs: None)
    sut, repo, _orders, _ent_table, _dlq = _make_orchestrator(order_id="ord-canonical", user_id="u-canonical")

    out = sut.process_order_entitlements(
        "ord-canonical",
        trigger_event_id="cart_purchase:u-canonical:cart-1:ord-canonical",
        source_system="shopping_cart",
    )

    assert out["status"] == "processed"
    assert out["entitlement_count"] == 1
    assert len(out["entitlement_ids"]) == 1
    rows = repo.list_entitlements_for_subject("u-canonical")
    assert len(rows) == 1
    assert rows[0].sku == "subscription_plan:pro"


def test_process_order_entitlements_is_idempotent_for_same_trigger(monkeypatch):
    monkeypatch.setattr(orchestrator, "audit_event", lambda *args, **kwargs: None)
    sut, repo, _orders, _ent_table, _dlq = _make_orchestrator(order_id="ord-idem", user_id="u-idem")

    first = sut.process_order_entitlements(
        "ord-idem",
        trigger_event_id="cart_purchase:u-idem:cart-1:ord-idem",
        source_system="shopping_cart",
    )
    second = sut.process_order_entitlements(
        "ord-idem",
        trigger_event_id="cart_purchase:u-idem:cart-1:ord-idem",
        source_system="shopping_cart",
    )

    assert first["status"] == "processed"
    assert second["status"] == "duplicate"
    rows = repo.list_entitlements_for_subject("u-idem")
    assert len(rows) == 1


def test_replay_failed_order_reprocesses_failed_event(monkeypatch):
    monkeypatch.setattr(orchestrator, "audit_event", lambda *args, **kwargs: None)
    sut, _repo, _orders, _ent_table, _dlq = _make_orchestrator(order_id="ord-replay", user_id="u-replay")

    original = sut.entitlements_service.grant_entitlement

    def _flaky(order_id: str):
        if not getattr(_flaky, "done", False):
            _flaky.done = True
            raise RuntimeError("temporary")
        return original(order_id)

    sut.entitlements_service.grant_entitlement = _flaky  # type: ignore[assignment]

    first = sut.process_order_entitlements(
        "ord-replay",
        trigger_event_id="cart_purchase:u-replay:cart-1:ord-replay",
        source_system="shopping_cart",
    )
    replay = sut.replay_failed_order("ord-replay")

    assert first["status"] == "failed"
    assert replay["replayed"] is True
    assert replay["result"]["status"] == "processed"


def test_billable_order_is_deferred_until_payment_success(monkeypatch):
    monkeypatch.setattr(orchestrator, "audit_event", lambda *args, **kwargs: None)
    sut, repo, orders, _ent_table, _dlq = _make_orchestrator(order_id="ord-gated", user_id="u-gated", status="pending_payment", amount_cents=500)

    deferred = sut.process_order_entitlements(
        "ord-gated",
        trigger_event_id="cart_purchase:u-gated:c1:ord-gated",
        source_system="shopping_cart",
    )

    assert deferred["status"] == "deferred"
    assert deferred["gate"]["decision"] == "deferred"
    assert repo.list_entitlements_for_subject("u-gated") == []

    orders.rows["ord-gated"]["status"] = "paid"
    repo.orders["ord-gated"]["status"] = "paid"
    processed = sut.process_order_entitlements(
        "ord-gated",
        trigger_event_id="payment_webhook:ord-gated:succeeded",
        source_system="payment_reconciliation",
    )
    duplicate = sut.process_order_entitlements(
        "ord-gated",
        trigger_event_id="payment_webhook:ord-gated:succeeded",
        source_system="payment_reconciliation",
    )

    assert processed["status"] == "processed"
    assert processed["entitlement_count"] == 1
    assert duplicate["status"] == "duplicate"
    assert len(repo.list_entitlements_for_subject("u-gated")) == 1


def test_dead_letter_persistence_query_and_replay(monkeypatch):
    monkeypatch.setattr(orchestrator, "audit_event", lambda *args, **kwargs: None)
    sut, repo, _orders, ent_table, dlq = _make_orchestrator(order_id="ord-dlq", user_id="u-dlq")
    monkeypatch.setattr(visibility.T.entitlements, "query", ent_table.query)

    original = sut.entitlements_service.grant_entitlement

    def _flaky(order_id: str):
        if not getattr(_flaky, "done", False):
            _flaky.done = True
            raise RuntimeError("temporary dead-letter")
        return original(order_id)

    sut.entitlements_service.grant_entitlement = _flaky  # type: ignore[assignment]

    failed = sut.process_order_entitlements(
        "ord-dlq",
        trigger_event_id="cart_purchase:u-dlq:cart-dlq:ord-dlq",
        source_system="shopping_cart",
    )
    assert failed["status"] == "failed"
    assert failed["dead_letter"]["owner_team"] == "commerce_platform"
    assert failed["dead_letter"]["remediation_hint"] == "replay_cart_entitlement_dead_letters"

    by_order = sut.list_dead_letters_for_order("ord-dlq")
    by_cart = sut.list_dead_letters_for_cart("cart-dlq")
    now = int(time.time())
    by_window = sut.list_dead_letters_for_time_window(start_ts=now - 60, end_ts=now + 60)

    assert len(by_order) == 1
    assert len(by_cart) == 1
    assert len(by_window) == 1
    assert len(dlq.items) == 1

    replay = sut.replay_dead_letters_for_order("ord-dlq")
    assert replay["replayed"] == 1
    assert replay["processed"] == 1

    listed = visibility.list_user_entitlements("u-dlq")
    assert listed["count"] == 1
    assert listed["items"][0]["status"] == "active"

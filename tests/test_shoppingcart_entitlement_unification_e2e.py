from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

from app.services import commerce_entitlement_orchestrator as orchestrator_module
from app.services import entitlements_visibility as visibility
from app.services import shoppingcart
from app.services.entitlements_service import EntitlementsService
from app.services.subscription_cycle_orders import TableBackedEntitlementsRepository


class _FakeShoppingCartTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item):
        self.items[(Item["PK"], Item["SK"])] = dict(Item)

    def get_item(self, Key):
        return {"Item": self.items.get((Key["PK"], Key["SK"]))}

    def query(self, **kwargs):
        pk = next(iter(self.items))[0]
        items = [dict(item) for item in self.items.values() if item.get("PK") == pk and item.get("type") == "item"]
        return {"Items": items}

    def update_item(self, *, Key, UpdateExpression, ExpressionAttributeValues, **kwargs):
        k = (Key["PK"], Key["SK"])
        item = self.items[k]
        if kwargs.get("ConditionExpression") == "#status = :open" and item.get("status") != ExpressionAttributeValues[":open"]:
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "conditional"}}, "UpdateItem")

        if "#status" in kwargs.get("ExpressionAttributeNames", {}):
            item["status"] = ExpressionAttributeValues[":status"]
        if ":purchased_at" in ExpressionAttributeValues:
            item["purchased_at"] = ExpressionAttributeValues[":purchased_at"]
        if ":total" in ExpressionAttributeValues:
            item["purchased_total_cents"] = ExpressionAttributeValues[":total"]
        if ":order_id" in ExpressionAttributeValues:
            item["last_order_id"] = ExpressionAttributeValues[":order_id"]
        if ":idempotency_key" in ExpressionAttributeValues:
            item["purchase_idempotency_key"] = ExpressionAttributeValues[":idempotency_key"]
        if ":txn_id" in ExpressionAttributeValues:
            item["purchase_txn_id"] = ExpressionAttributeValues[":txn_id"]


class _OrdersTable:
    def __init__(self):
        self.rows = {}

    def get_item(self, Key):
        row = self.rows.get(str(Key.get("order_id") or ""))
        return {"Item": dict(row)} if row else {}


class _OrderItemsTable:
    def __init__(self):
        self.rows = []

    def query(self, KeyConditionExpression):
        return {"Items": list(self.rows)}

    def scan(self):
        return {"Items": list(self.rows)}


class _EntitlementsTable:
    def __init__(self):
        self.items = []

    def put_item(self, Item, ConditionExpression=None):
        item = dict(Item)
        existing = any(x.get("user_id") == item.get("user_id") and x.get("entitlement_id") == item.get("entitlement_id") for x in self.items)
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
        raise RuntimeError("unsupported")

    def scan(self):
        return {"Items": list(self.items)}


def _seed_cart(table: _FakeShoppingCartTable, user_sub: str, cart_id: str):
    table.put_item(Item={"PK": f"USER#{user_sub}", "SK": f"CART#{cart_id}", "type": "cart", "cart_id": cart_id, "status": "OPEN", "created_at": "2026-01-01T00:00:00+00:00", "currency": "USD"})
    table.put_item(
        Item={
            "PK": f"USER#{user_sub}",
            "SK": f"CART#{cart_id}#ITEM#api-1",
            "type": "item",
            "cart_id": cart_id,
            "sku": "api-1",
            "name": "API",
            "quantity": 1,
            "unit_price_cents": 300,
            "product_type": "api_package",
            "scope": {"allowed_actions": ["request_units"], "resource": {}},
            "updated_at": "2026-01-01T00:00:00+00:00",
        }
    )


def _build_runtime(order_status: str = "paid"):
    orders_table = _OrdersTable()
    order_items_table = _OrderItemsTable()
    ent_table = _EntitlementsTable()
    dlq_table = _DeadLettersTable()
    repo = TableBackedEntitlementsRepository(orders_table=orders_table, order_items_table=order_items_table, entitlements_table=ent_table)
    orch = orchestrator_module.CommerceEntitlementOrchestrator(entitlements_service=EntitlementsService(repo), dead_letter_table=dlq_table)

    def _create_order(*, user_id, source_system, correlation_id, line_items, metadata):
        order_id = "ord-cart-1"
        orders_table.rows[order_id] = {"order_id": order_id, "user_id": user_id, "status": order_status, "created_by": "system", "metadata": dict(metadata or {})}
        order_items_table.rows = [{"order_id": order_id, "item_id": "1", "sku": "api-1", "product_type": "api_package", "scope": {"allowed_actions": ["request_units"], "resource": {}}, "usage_limit": 100, "billing_model": "one_time", "unit_price_cents": 300}]
        return {"order_id": order_id}

    return orch, repo, ent_table, dlq_table, _create_order


def test_cart_purchase_success_visible_via_list_user_entitlements(monkeypatch):
    table = _FakeShoppingCartTable()
    _seed_cart(table, "u1", "c1")
    orch, _repo, ent_table, _dlq, create_order = _build_runtime(order_status="paid")
    fake_tables = SimpleNamespace(shopping_cart=table)
    fake_order_service = Mock()
    fake_order_service.create_order_from_line_items.side_effect = create_order

    monkeypatch.setattr(visibility.T.entitlements, "query", ent_table.query)
    with patch.object(shoppingcart, "T", fake_tables), patch.object(shoppingcart, "commerce_order_service", fake_order_service), patch.object(shoppingcart, "commerce_entitlement_orchestrator", orch), patch.object(shoppingcart, "get_profile", return_value={}), patch.object(shoppingcart, "record_cart_purchase", return_value="txn-1"):
        shoppingcart.purchase_cart("u1", "c1")

    listed = visibility.list_user_entitlements("u1")
    assert listed["count"] == 1
    assert listed["items"][0]["status"] == "active"


def test_duplicate_purchase_invocation_no_duplicate_entitlement(monkeypatch):
    table = _FakeShoppingCartTable()
    _seed_cart(table, "u1", "c1")
    orch, _repo, ent_table, _dlq, create_order = _build_runtime(order_status="paid")
    fake_tables = SimpleNamespace(shopping_cart=table)
    fake_order_service = Mock()
    fake_order_service.create_order_from_line_items.side_effect = create_order

    monkeypatch.setattr(visibility.T.entitlements, "query", ent_table.query)
    with patch.object(shoppingcart, "T", fake_tables), patch.object(shoppingcart, "commerce_order_service", fake_order_service), patch.object(shoppingcart, "commerce_entitlement_orchestrator", orch), patch.object(shoppingcart, "get_profile", return_value={}), patch.object(shoppingcart, "record_cart_purchase", return_value="txn-1"):
        shoppingcart.purchase_cart("u1", "c1")
        shoppingcart.purchase_cart("u1", "c1")

    listed = visibility.list_user_entitlements("u1")
    assert listed["count"] == 1


def test_payment_delayed_then_success_deferred_then_granted(monkeypatch):
    table = _FakeShoppingCartTable()
    _seed_cart(table, "u1", "c1")
    orch, repo, ent_table, _dlq, create_order = _build_runtime(order_status="pending_payment")
    fake_tables = SimpleNamespace(shopping_cart=table)
    fake_order_service = Mock()
    fake_order_service.create_order_from_line_items.side_effect = create_order

    monkeypatch.setattr(visibility.T.entitlements, "query", ent_table.query)
    with patch.object(shoppingcart, "T", fake_tables), patch.object(shoppingcart, "commerce_order_service", fake_order_service), patch.object(shoppingcart, "commerce_entitlement_orchestrator", orch), patch.object(shoppingcart, "get_profile", return_value={}), patch.object(shoppingcart, "record_cart_purchase", return_value="txn-1"):
        shoppingcart.purchase_cart("u1", "c1")

    assert visibility.list_user_entitlements("u1")["count"] == 0

    repo.orders["ord-cart-1"]["status"] = "paid"
    out = orch.process_order_entitlements("ord-cart-1", trigger_event_id="payment_webhook:ord-cart-1:succeeded", source_system="payment_reconciliation")
    assert out["status"] == "processed"
    assert visibility.list_user_entitlements("u1")["count"] == 1


def test_orchestrator_failure_dead_letter_replay_to_active(monkeypatch):
    table = _FakeShoppingCartTable()
    _seed_cart(table, "u1", "c1")
    orch, _repo, ent_table, _dlq, create_order = _build_runtime(order_status="paid")
    fake_tables = SimpleNamespace(shopping_cart=table)
    fake_order_service = Mock()
    fake_order_service.create_order_from_line_items.side_effect = create_order

    original = orch.entitlements_service.grant_entitlement

    def _flaky(order_id: str):
        if not getattr(_flaky, "done", False):
            _flaky.done = True
            raise RuntimeError("temporary")
        return original(order_id)

    orch.entitlements_service.grant_entitlement = _flaky  # type: ignore[assignment]

    monkeypatch.setattr(visibility.T.entitlements, "query", ent_table.query)
    with patch.object(shoppingcart, "T", fake_tables), patch.object(shoppingcart, "commerce_order_service", fake_order_service), patch.object(shoppingcart, "commerce_entitlement_orchestrator", orch), patch.object(shoppingcart, "get_profile", return_value={}), patch.object(shoppingcart, "record_cart_purchase", return_value="txn-1"):
        shoppingcart.purchase_cart("u1", "c1")

    assert visibility.list_user_entitlements("u1")["count"] == 0
    replay = orch.replay_dead_letters_for_order("ord-cart-1")
    assert replay["replayed"] == 1
    assert replay["processed"] == 1
    assert visibility.list_user_entitlements("u1")["count"] == 1

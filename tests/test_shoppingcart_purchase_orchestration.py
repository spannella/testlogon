from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

from app.services import shoppingcart


class _FakeShoppingCartTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item):
        self.items[(Item["PK"], Item["SK"])] = dict(Item)

    def get_item(self, Key):
        return {"Item": self.items.get((Key["PK"], Key["SK"]))}

    def query(self, **kwargs):
        pk = next(iter(self.items))[0]
        items = [
            dict(item)
            for item in self.items.values()
            if item.get("PK") == pk and item.get("type") == "item"
        ]
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
        if ":buyer" in ExpressionAttributeValues:
            item["buyer_profile"] = ExpressionAttributeValues[":buyer"]
        if ":txn_id" in ExpressionAttributeValues:
            item["purchase_txn_id"] = ExpressionAttributeValues[":txn_id"]


def _seed_cart(table: _FakeShoppingCartTable, user_sub: str, cart_id: str):
    table.put_item(
        Item={
            "PK": f"USER#{user_sub}",
            "SK": f"CART#{cart_id}",
            "type": "cart",
            "cart_id": cart_id,
            "status": "OPEN",
            "created_at": "2026-01-01T00:00:00+00:00",
            "currency": "USD",
        }
    )


def test_purchase_cart_routes_through_commerce_order_service_and_records_history() -> None:
    table = _FakeShoppingCartTable()
    _seed_cart(table, "u1", "c1")
    table.put_item(
        Item={
            "PK": "USER#u1",
            "SK": "CART#c1#ITEM#fb-1",
            "type": "item",
            "cart_id": "c1",
            "sku": "fb-1",
            "name": "Bundle",
            "quantity": 1,
            "unit_price_cents": 300,
            "product_type": "file_bundle",
            "scope": {
                "selection_type": "date_range",
                "date_start": "2026-01-01T00:00:00Z",
                "date_end": "2026-01-02T00:00:00Z",
                "access_mode": "purchase",
            },
            "access_mode": "purchase",
            "updated_at": "2026-01-01T00:00:00+00:00",
        }
    )

    fake_tables = SimpleNamespace(shopping_cart=table)
    fake_order_service = Mock()
    fake_order_service.create_order_from_line_items.return_value = {"order_id": "ord-1"}
    fake_orchestrator = Mock()

    with patch.object(shoppingcart, "T", fake_tables), patch.object(shoppingcart, "commerce_order_service", fake_order_service), patch.object(
        shoppingcart, "commerce_entitlement_orchestrator", fake_orchestrator
    ), patch.object(shoppingcart, "get_profile", return_value={}), patch.object(shoppingcart, "record_cart_purchase", return_value="txn-1"):
        out = shoppingcart.purchase_cart("u1", "c1")

    assert out["order_id"] == "ord-1"
    fake_order_service.create_order_from_line_items.assert_called_once()
    _, kwargs = fake_order_service.create_order_from_line_items.call_args
    assert kwargs["source_system"] == "shopping_cart"
    assert kwargs["correlation_id"] == "cart_purchase:u1:c1"
    assert table.get_item(Key={"PK": "USER#u1", "SK": "CART#c1"})["Item"]["status"] == "PURCHASED"
    fake_orchestrator.process_order_entitlements.assert_called_once_with(
        "ord-1",
        trigger_event_id="cart_purchase:u1:c1:ord-1",
        source_system="shopping_cart",
    )


def test_purchase_cart_is_idempotent_for_already_purchased_cart() -> None:
    table = _FakeShoppingCartTable()
    _seed_cart(table, "u1", "c1")
    cart = table.get_item(Key={"PK": "USER#u1", "SK": "CART#c1"})["Item"]
    cart.update(
        {
            "status": "PURCHASED",
            "last_order_id": "ord-1",
            "purchased_at": "2026-01-01T01:00:00+00:00",
            "purchased_total_cents": 300,
            "purchase_txn_id": "txn-1",
        }
    )

    fake_tables = SimpleNamespace(shopping_cart=table)
    fake_order_service = Mock()
    fake_orchestrator = Mock()

    with patch.object(shoppingcart, "T", fake_tables), patch.object(shoppingcart, "commerce_order_service", fake_order_service), patch.object(
        shoppingcart, "commerce_entitlement_orchestrator", fake_orchestrator
    ):
        out = shoppingcart.purchase_cart("u1", "c1")

    assert out["order_id"] == "ord-1"
    fake_order_service.create_order_from_line_items.assert_not_called()
    fake_orchestrator.process_order_entitlements.assert_not_called()

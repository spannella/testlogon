"""Unit tests for broadcast product shelf (LCOM-001)."""
from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest

from app.services import broadcast_product_shelf as shelf_mod
from app.services.broadcast_product_shelf import (
    add_product_to_shelf,
    remove_product_from_shelf,
    list_shelf_products,
    reorder_shelf,
    MAX_SHELF_ITEMS,
    _shelf_item_out,
)


MOCK_CATALOG_ITEM = {
    "name": "Test Product",
    "description": "A test product for unit testing the broadcast shelf",
    "price_cents": 999,
    "currency": "USD",
    "image_urls": ["https://example.com/img1.jpg", "https://example.com/img2.jpg"],
    "attributes": {"color": "blue", "size": "M"},
}

MOCK_CATALOG_ITEM_NO_IMAGES = {
    "name": "No-Image Product",
    "price_cents": 1499,
    "currency": "USD",
    "image_urls": [],
}


class _FakeShelfTable:
    """In-memory DynamoDB table mock for product shelf."""

    def __init__(self):
        self.items: dict[tuple[str, str], dict] = {}

    def put_item(self, *, Item):
        key = (Item["session_id"], Item["SK"])
        self.items[key] = dict(Item)

    def get_item(self, *, Key):
        key = (Key["session_id"], Key["SK"])
        item = self.items.get(key)
        return {"Item": dict(item)} if item else {}

    def delete_item(self, *, Key):
        key = (Key["session_id"], Key["SK"])
        self.items.pop(key, None)

    def update_item(self, *, Key, UpdateExpression, ExpressionAttributeValues=None, **kw):
        key = (Key["session_id"], Key["SK"])
        item = self.items.get(key)
        if item and ExpressionAttributeValues:
            # Simple parser for "SET display_order = :order"
            for attr_name, attr_val in ExpressionAttributeValues.items():
                # Extract the field name from the SET expression
                real_name = attr_name.lstrip(":")
                item[real_name] = attr_val
                # Also handle the explicit field name
                if "display_order" in UpdateExpression:
                    item["display_order"] = ExpressionAttributeValues.get(":order", attr_val)

    def query(self, *, KeyConditionExpression=None, Select=None, Limit=None, **kw):
        # Extract session_id from the condition
        session_id = None
        if hasattr(KeyConditionExpression, "_values"):
            # Simple extraction for eq condition
            vals = KeyConditionExpression._values
            if len(vals) >= 2:
                if hasattr(vals[0], "_values"):
                    # AND condition
                    for child in vals:
                        child_vals = getattr(child, "_values", [])
                        if len(child_vals) >= 2:
                            key_name = getattr(child_vals[0], "name", None)
                            if key_name == "session_id":
                                session_id = child_vals[1]
                else:
                    key_name = getattr(vals[0], "name", None)
                    if key_name == "session_id":
                        session_id = vals[1]

        # Filter by session_id
        results = []
        for (sid, sk), item in self.items.items():
            if session_id is None or sid == session_id:
                results.append(dict(item))

        if Limit:
            results = results[:Limit]

        if Select == "COUNT":
            return {"Count": len(results)}

        return {"Items": results}


@pytest.fixture(autouse=True)
def _mock_table():
    table = _FakeShelfTable()
    mock_t = MagicMock()
    mock_t.broadcast_product_shelf = table
    with patch.object(shelf_mod, "T", mock_t):
        yield table


@pytest.fixture(autouse=True)
def _mock_sse():
    with patch.object(shelf_mod, "broadcast_sse_publish") as mock_pub:
        yield mock_pub


class TestShelfItemOut:
    def test_converts_decimal_to_int(self):
        item = {
            "session_id": "s1",
            "item_id": "i1",
            "category_id": "c1",
            "name": "Test",
            "price_cents": Decimal("999"),
            "display_order": Decimal("0"),
            "added_at": Decimal("1700000000"),
            "added_by": "u1",
            "currency": "USD",
        }
        out = _shelf_item_out(item)
        assert isinstance(out["price_cents"], int)
        assert out["price_cents"] == 999
        assert isinstance(out["display_order"], int)
        assert isinstance(out["added_at"], int)

    def test_provides_defaults_for_missing_fields(self):
        item = {"session_id": "s1", "item_id": "i1"}
        out = _shelf_item_out(item)
        assert out["category_id"] == ""
        assert out["name"] == ""
        assert out["description"] is None
        assert out["price_cents"] == 0
        assert out["currency"] == "USD"
        assert out["image_url"] is None
        assert out["display_order"] == 0
        assert out["added_by"] == ""
        assert out["added_at"] == 0


class TestAddProductToShelf:
    def test_add_product_success(self):
        result = add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1")
        assert result["item_id"] == "item1"
        assert result["name"] == "Test Product"
        assert result["price_cents"] == 999
        assert result["currency"] == "USD"
        assert result["image_url"] == "https://example.com/img1.jpg"
        assert result["category_id"] == "cat1"
        assert result["added_by"] == "user1"
        assert result["added_at"] > 0
        assert result["session_id"] == "sess1"

    def test_add_product_no_images_returns_none_image_url(self):
        result = add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM_NO_IMAGES, "user1")
        assert result["image_url"] is None

    def test_add_product_truncates_description_to_500(self, _mock_table):
        long_desc_item = {**MOCK_CATALOG_ITEM, "description": "x" * 1000}
        add_product_to_shelf("sess1", "item1", "cat1", long_desc_item, "user1")
        ddb_item = _mock_table.items[("sess1", "ITEM#item1")]
        assert len(ddb_item["description"]) == 500

    def test_add_duplicate_raises_409(self):
        add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1")
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1")
        assert exc_info.value.status_code == 409

    def test_add_over_max_shelf_size_raises_400(self):
        for i in range(MAX_SHELF_ITEMS):
            add_product_to_shelf("sess1", f"item{i}", "cat1", MOCK_CATALOG_ITEM, "user1")
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            add_product_to_shelf("sess1", "item_overflow", "cat1", MOCK_CATALOG_ITEM, "user1")
        assert exc_info.value.status_code == 400
        assert "50" in str(exc_info.value.detail)

    def test_add_product_sets_ttl(self, _mock_table):
        result = add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1")
        ddb_item = _mock_table.items[("sess1", "ITEM#item1")]
        assert "ttl" in ddb_item
        assert ddb_item["ttl"] > result["added_at"]

    def test_add_product_publishes_sse_when_live(self, _mock_sse):
        add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1", is_live=True)
        _mock_sse.assert_called_once()
        event = _mock_sse.call_args[0][1]
        assert event["_type"] == "shelf:add"
        assert event["item_id"] == "item1"

    def test_add_product_no_sse_when_not_live(self, _mock_sse):
        add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1", is_live=False)
        _mock_sse.assert_not_called()

    def test_add_product_with_display_order(self):
        result = add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1", display_order=5)
        assert result["display_order"] == 5

    def test_add_product_with_none_description(self):
        item = {**MOCK_CATALOG_ITEM, "description": None}
        result = add_product_to_shelf("sess1", "item1", "cat1", item, "user1")
        assert result["name"] == "Test Product"


class TestRemoveProductFromShelf:
    def test_remove_existing_product(self):
        add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1")
        result = remove_product_from_shelf("sess1", "item1")
        assert result is True
        items = list_shelf_products("sess1")
        assert len(items) == 0

    def test_remove_nonexistent_returns_false(self):
        result = remove_product_from_shelf("sess1", "item999")
        assert result is False

    def test_remove_publishes_sse_when_live(self, _mock_sse):
        add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1")
        _mock_sse.reset_mock()
        remove_product_from_shelf("sess1", "item1", is_live=True)
        _mock_sse.assert_called_once()
        event = _mock_sse.call_args[0][1]
        assert event["_type"] == "shelf:remove"
        assert event["item_id"] == "item1"

    def test_remove_no_sse_when_not_live(self, _mock_sse):
        add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1")
        _mock_sse.reset_mock()
        remove_product_from_shelf("sess1", "item1", is_live=False)
        _mock_sse.assert_not_called()


class TestListShelfProducts:
    def test_list_empty_shelf(self):
        items = list_shelf_products("nonexistent_session")
        assert items == []

    def test_list_shelf_products_ordered(self):
        add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1", display_order=2)
        add_product_to_shelf("sess1", "item2", "cat1", MOCK_CATALOG_ITEM, "user1", display_order=0)
        add_product_to_shelf("sess1", "item3", "cat1", MOCK_CATALOG_ITEM, "user1", display_order=1)
        items = list_shelf_products("sess1")
        assert [i["item_id"] for i in items] == ["item2", "item3", "item1"]


class TestReorderShelf:
    def test_reorder_shelf(self):
        for i in range(3):
            add_product_to_shelf("sess1", f"item{i}", "cat1", MOCK_CATALOG_ITEM, "user1")
        reorder_shelf("sess1", ["item2", "item0", "item1"])
        items = list_shelf_products("sess1")
        assert [i["item_id"] for i in items] == ["item2", "item0", "item1"]

    def test_reorder_publishes_sse_when_live(self, _mock_sse):
        for i in range(2):
            add_product_to_shelf("sess1", f"item{i}", "cat1", MOCK_CATALOG_ITEM, "user1")
        _mock_sse.reset_mock()
        reorder_shelf("sess1", ["item1", "item0"], is_live=True)
        _mock_sse.assert_called_once()
        event = _mock_sse.call_args[0][1]
        assert event["_type"] == "shelf:reorder"
        assert "items" in event

    def test_reorder_no_sse_when_not_live(self, _mock_sse):
        for i in range(2):
            add_product_to_shelf("sess1", f"item{i}", "cat1", MOCK_CATALOG_ITEM, "user1")
        _mock_sse.reset_mock()
        reorder_shelf("sess1", ["item1", "item0"], is_live=False)
        _mock_sse.assert_not_called()

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.services import shoppingcart


class FakeShoppingCartTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item):
        self.items[(Item["PK"], Item["SK"])] = dict(Item)

    def get_item(self, Key):
        return {"Item": self.items.get((Key["PK"], Key["SK"]))}

    def query(self, **kwargs):
        pk = None
        for (item_pk, _), _item in self.items.items():
            pk = item_pk
            break
        rows = [
            dict(item)
            for item in self.items.values()
            if item.get("PK") == pk and item.get("type") == "item"
        ]
        return {"Items": rows}


def _seed_open_cart(table: FakeShoppingCartTable, user_sub: str, cart_id: str) -> None:
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


def test_add_item_rejects_invalid_file_bundle_scope() -> None:
    table = FakeShoppingCartTable()
    _seed_open_cart(table, "u1", "c1")
    fake_tables = SimpleNamespace(shopping_cart=table)

    with patch.object(shoppingcart, "T", fake_tables):
        with pytest.raises(HTTPException) as exc:
            shoppingcart.add_item(
                "u1",
                "c1",
                {
                    "sku": "fb-1",
                    "name": "Date Bundle",
                    "quantity": 1,
                    "unit_price_cents": 100,
                    "product_type": "file_bundle",
                    "access_mode": "purchase",
                    "scope": {
                        "selection_type": "date_range",
                        "date_start": "2026-01-01T00:00:00Z",
                    },
                },
            )
    assert exc.value.status_code == 422
    assert "invalid commercialization cart item" in str(exc.value.detail)


def test_add_item_rejects_invalid_api_package_template() -> None:
    table = FakeShoppingCartTable()
    _seed_open_cart(table, "u1", "c1")
    fake_tables = SimpleNamespace(shopping_cart=table)

    with patch.object(shoppingcart, "T", fake_tables):
        with pytest.raises(HTTPException) as exc:
            shoppingcart.add_item(
                "u1",
                "c1",
                {
                    "sku": "api-1",
                    "name": "API Tier",
                    "quantity": 1,
                    "unit_price_cents": 100,
                    "product_type": "api_package",
                    "entitlement_template_metadata": {},
                },
            )
    assert exc.value.status_code == 422


def test_mixed_cart_totals_and_listing_stable() -> None:
    table = FakeShoppingCartTable()
    _seed_open_cart(table, "u1", "c1")
    fake_tables = SimpleNamespace(shopping_cart=table)

    with patch.object(shoppingcart, "T", fake_tables):
        shoppingcart.add_item(
            "u1",
            "c1",
            {
                "sku": "legacy-1",
                "name": "Legacy",
                "quantity": 2,
                "unit_price_cents": 50,
            },
        )
        shoppingcart.add_item(
            "u1",
            "c1",
            {
                "sku": "fb-1",
                "name": "Date Bundle",
                "quantity": 1,
                "unit_price_cents": 300,
                "product_type": "file_bundle",
                "access_mode": "rental",
                "rental_metadata": {"rental_duration_hours": 24},
                "scope": {
                    "selection_type": "date_range",
                    "date_start": "2026-01-01T00:00:00Z",
                    "date_end": "2026-01-05T00:00:00Z",
                },
            },
        )

        items = shoppingcart.list_items("u1", "c1")
        total = shoppingcart.cart_total_cents("u1", "c1")

    assert len(items) == 2
    assert total == 400
    commercial_item = next(item for item in items if item["sku"] == "fb-1")
    assert commercial_item["product_type"] == "file_bundle"
    assert commercial_item["scope"]["date_end"] == "2026-01-05T00:00:00Z"

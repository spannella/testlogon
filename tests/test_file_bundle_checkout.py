from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services import file_bundle_checkout as svc


class _FakeTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item):
        key = (Item.get("PK") or Item.get("order_id"), Item.get("SK") or Item.get("item_id"))
        self.items[key] = dict(Item)

    def get_item(self, Key):
        key = (Key.get("PK") or Key.get("order_id"), Key.get("SK") or Key.get("item_id"))
        item = self.items.get(key)
        return {"Item": dict(item)} if item else {}


@pytest.fixture()
def fake_tables(monkeypatch: pytest.MonkeyPatch):
    catalog_products = _FakeTable()
    orders = _FakeTable()
    order_items = _FakeTable()
    monkeypatch.setattr(svc, "T", SimpleNamespace(catalog_products=catalog_products, orders=orders, order_items=order_items))
    return SimpleNamespace(catalog_products=catalog_products, orders=orders, order_items=order_items)


def test_create_purchase_file_bundle_sku_and_checkout_success(fake_tables) -> None:
    sku = svc.create_file_bundle_sku(
        "author-1",
        body=SimpleNamespace(
            sku="bundle-jan",
            display_name="January Bundle",
            amount_cents=1999,
            currency="usd",
            date_start="2026-01-01T00:00:00Z",
            date_end="2026-01-31T23:59:59Z",
            access_mode="purchase",
            rental_duration_hours=None,
        ),
    )
    assert sku["product_type"] == "file_bundle"

    out = svc.create_file_bundle_checkout_session(
        "user-1",
        body=SimpleNamespace(
            sku="bundle-jan",
            date_start="2026-01-05T00:00:00Z",
            date_end="2026-01-10T00:00:00Z",
            access_mode="purchase",
        ),
    )
    assert out["status"] == "pending_payment"
    assert out["sku"] == "bundle-jan"


def test_create_rental_file_bundle_requires_rental_duration(fake_tables) -> None:
    with pytest.raises(HTTPException, match="rental_duration_hours"):
        svc.create_file_bundle_sku(
            "author-1",
            body=SimpleNamespace(
                sku="bundle-rental-bad",
                display_name="Rental Bundle",
                amount_cents=2999,
                currency="USD",
                date_start="2026-01-01T00:00:00Z",
                date_end="2026-01-31T23:59:59Z",
                access_mode="rental",
                rental_duration_hours=None,
            ),
        )


def test_checkout_rejects_outside_date_window(fake_tables) -> None:
    svc.create_file_bundle_sku(
        "author-1",
        body=SimpleNamespace(
            sku="bundle-feb",
            display_name="Feb Bundle",
            amount_cents=1999,
            currency="USD",
            date_start="2026-02-01T00:00:00Z",
            date_end="2026-02-28T23:59:59Z",
            access_mode="purchase",
            rental_duration_hours=None,
        ),
    )

    with pytest.raises(HTTPException, match="within SKU date window"):
        svc.create_file_bundle_checkout_session(
            "user-2",
            body=SimpleNamespace(
                sku="bundle-feb",
                date_start="2026-01-31T00:00:00Z",
                date_end="2026-02-02T00:00:00Z",
                access_mode="purchase",
            ),
        )


def test_checkout_rejects_access_mode_mismatch(fake_tables) -> None:
    svc.create_file_bundle_sku(
        "author-1",
        body=SimpleNamespace(
            sku="bundle-rental",
            display_name="Rental Bundle",
            amount_cents=3999,
            currency="USD",
            date_start="2026-03-01T00:00:00Z",
            date_end="2026-03-31T23:59:59Z",
            access_mode="rental",
            rental_duration_hours=48,
        ),
    )

    with pytest.raises(HTTPException, match="access_mode"):
        svc.create_file_bundle_checkout_session(
            "user-3",
            body=SimpleNamespace(
                sku="bundle-rental",
                date_start="2026-03-01T00:00:00Z",
                date_end="2026-03-02T00:00:00Z",
                access_mode="purchase",
            ),
        )

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.models import UnifiedCheckoutSessionIn
from app.services import unified_checkout as svc


def test_create_unified_checkout_session_cart(monkeypatch) -> None:
    monkeypatch.setattr(svc, "get_cart", lambda user_id, cart_id: {"status": "OPEN"})
    monkeypatch.setattr(
        svc,
        "list_items",
        lambda user_id, cart_id: [{"sku": "a", "quantity": 1, "unit_price_cents": 100, "line_total_cents": 100}],
    )
    monkeypatch.setattr(svc, "_commercial_line_items_from_cart_items", lambda items, cart_id: [{"sku": "a", "source_system": "shopping_cart", "product_type": "internal_api_package", "billing_model": "one_time", "quantity": 1, "scope": {}, "pricing_ref": {"unit_price_cents": 100, "currency": "USD"}}])
    order_service = Mock()
    order_service.create_order_from_line_items.return_value = {
        "order_id": "ord-1",
        "status": "pending_payment",
        "line_items": [{"sku": "a"}],
    }
    monkeypatch.setattr(svc, "commerce_order_service", order_service)

    out = svc.create_unified_checkout_session("u1", UnifiedCheckoutSessionIn(source="cart", cart_id="c1"))
    assert out["source"] == "cart"
    assert out["order_id"] == "ord-1"


def test_create_unified_checkout_session_direct(monkeypatch) -> None:
    order_service = Mock()
    order_service.create_order_from_line_items.return_value = {
        "order_id": "ord-2",
        "status": "pending_payment",
        "line_items": [{"sku": "fb-1"}],
    }
    monkeypatch.setattr(svc, "commerce_order_service", order_service)

    out = svc.create_unified_checkout_session(
        "u1",
        UnifiedCheckoutSessionIn(
            source="direct",
            sku="fb-1",
            product_type="file_bundle",
            billing_model="one_time",
            scope={
                "selection_type": "date_range",
                "date_start": "2026-01-01T00:00:00Z",
                "date_end": "2026-01-02T00:00:00Z",
                "access_mode": "purchase",
            },
            pricing_ref={"amount_cents": 100, "currency": "USD"},
        ),
    )
    assert out["source"] == "direct"
    assert out["order_id"] == "ord-2"


def test_create_unified_checkout_session_rejects_missing_cart_id() -> None:
    with pytest.raises(Exception):
        svc.create_unified_checkout_session("u1", UnifiedCheckoutSessionIn(source="cart"))

from __future__ import annotations

from types import SimpleNamespace

from app.services import commerce_order_service as svc
from app.services.commercial_line_items import from_direct_checkout_request, from_shopping_cart_item, from_subscription_plan


class _Table:
    def __init__(self):
        self.items = []

    def put_item(self, Item):
        self.items.append(dict(Item))


def _service(monkeypatch):
    orders = _Table()
    order_items = _Table()
    monkeypatch.setattr(svc, "T", SimpleNamespace(orders=orders, order_items=order_items))
    out = svc.CommerceOrderService()
    return out, orders, order_items


def test_create_order_from_shopping_cart_source(monkeypatch):
    service, orders, order_items = _service(monkeypatch)
    audits = []
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: audits.append((args, kwargs)))

    li = from_shopping_cart_item(
        {
            "cart_id": "cart-1",
            "sku": "api-pro",
            "product_type": "api_package",
            "billing_model": "credit_pack",
            "quantity": 2,
            "unit_price_cents": 100,
            "currency": "USD",
            "scope": {"credit_amount": 1000},
        }
    )
    out = service.create_order_from_line_items(user_id="u1", source_system="shopping_cart", line_items=[li], correlation_id="cart:cart-1")

    assert out["source_system"] == "shopping_cart"
    assert out["correlation_id"] == "cart:cart-1"
    assert len(orders.items) == 1
    assert len(order_items.items) == 1
    assert orders.items[0]["line_item_count"] == 1
    assert audits and audits[0][0][0] == "commerce_order_created"


def test_create_order_from_direct_checkout_source(monkeypatch):
    service, orders, order_items = _service(monkeypatch)
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: None)

    li = from_direct_checkout_request(
        {
            "sku": "files-rental",
            "product_type": "file_bundle",
            "billing_model": "rental",
            "scope": {"selection_type": "date_range"},
            "pricing_ref": {"amount_cents": 1999, "currency": "USD"},
        }
    )
    out = service.create_order(user_id="u2", source_system="commercial_direct", line_items=[li], metadata={"checkout_session_id": "chk_1"})

    assert out["source_system"] == "commercial_direct"
    assert out["checkout_session_id"] == "chk_1"
    assert orders.items[0]["amount_cents"] == 1999
    assert order_items.items[0]["product_type"] == "file_bundle"


def test_create_order_from_subscription_cycle_source(monkeypatch):
    service, orders, order_items = _service(monkeypatch)
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: None)

    li = from_subscription_plan(
        {
            "plan_id": "creator-plus",
            "subscription_id": "sub_123",
            "product_type": "internal_api_package",
            "price_cents": 1500,
            "currency": "USD",
            "scope": {"internal_namespaces": ["messaging.*"]},
        }
    )
    out = service.create_order_from_line_items(
        user_id="u3",
        source_system="subscription_cycle",
        line_items=[li],
        correlation_id="sub:sub_123:2026-03",
    )

    assert out["source_system"] == "subscription_cycle"
    assert out["correlation_id"] == "sub:sub_123:2026-03"
    assert order_items.items[0]["source_system"] == "subscription_cycle"
    assert orders.items[0]["currency"] == "USD"


def test_create_order_is_idempotent_by_correlation_id(monkeypatch):
    service, orders, order_items = _service(monkeypatch)
    li = from_shopping_cart_item(
        {
            "cart_id": "c1",
            "sku": "fb-1",
            "product_type": "file_bundle",
            "billing_model": "one_time",
            "quantity": 1,
            "unit_price_cents": 100,
            "currency": "USD",
            "scope": {
                "selection_type": "date_range",
                "date_start": "2026-01-01T00:00:00Z",
                "date_end": "2026-01-02T00:00:00Z",
                "access_mode": "purchase",
            },
        }
    )

    first = service.create_order_from_line_items(
        user_id="u1",
        source_system="shopping_cart",
        line_items=[li],
        correlation_id="cart_purchase:u1:c1",
    )
    second = service.create_order_from_line_items(
        user_id="u1",
        source_system="shopping_cart",
        line_items=[li],
        correlation_id="cart_purchase:u1:c1",
    )

    assert first["order_id"] == second["order_id"]
    assert order_items.items[0]["order_id"] == order_items.items[1]["order_id"]

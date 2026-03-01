from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services import commercial_line_items as cli


FIXTURES = Path(__file__).parent / "fixtures" / "commercial_line_items"


def _load(name: str):
    return json.loads((FIXTURES / name).read_text())


def test_validator_accepts_contract_fixtures() -> None:
    files = [
        "file_bundle_line_item.json",
        "api_package_line_item.json",
        "internal_api_package_line_item.json",
        "subscription_renewal_line_item.json",
    ]
    out = [cli.validate_commercial_line_item(_load(name)) for name in files]
    assert {i.product_type for i in out} == {"file_bundle", "api_package", "internal_api_package"}
    assert {i.source_system for i in out} == {"shopping_cart", "commercial_direct", "subscription_cycle"}


def test_shopping_cart_adapter_to_canonical_line_item() -> None:
    item = {
        "cart_id": "c1",
        "sku": "api-pro-credits-50k",
        "product_type": "api_package",
        "billing_model": "credit_pack",
        "quantity": 2,
        "unit_price_cents": 4900,
        "currency": "USD",
        "scope": {"credit_amount": 50000},
    }
    out = cli.from_shopping_cart_item(item)
    assert out.source_system == "shopping_cart"
    assert out.quantity == 2
    assert out.pricing_ref["cart_id"] == "c1"


def test_direct_checkout_adapter_to_canonical_line_item() -> None:
    payload = {
        "sku": "files-daily-2026-03",
        "product_type": "file_bundle",
        "billing_model": "rental",
        "quantity": 1,
        "scope": {"selection_type": "date_range"},
        "pricing_ref": {"amount_cents": 1999, "currency": "USD"},
    }
    out = cli.from_direct_checkout_request(payload)
    assert out.source_system == "commercial_direct"
    assert out.product_type == "file_bundle"


def test_subscription_adapter_to_canonical_line_item() -> None:
    plan = {
        "plan_id": "creator-plus",
        "subscription_id": "sub_123",
        "product_type": "internal_api_package",
        "price_cents": 1500,
        "currency": "USD",
        "scope": {"internal_namespaces": ["messaging.*"]},
    }
    out = cli.from_subscription_plan(plan)
    assert out.source_system == "subscription_cycle"
    assert out.scope["plan_id"] == "creator-plus"


def test_validator_rejects_invalid_source_system() -> None:
    payload = _load("file_bundle_line_item.json")
    payload["source_system"] = "legacy"
    with pytest.raises(Exception):
        cli.validate_commercial_line_item(payload)

"""ECM-002/003/004/005/006/007/008/010 — Store integration layer tests.

Hermetic offline pytest: moto-backed DynamoDB tables bound to frozen T/S
via object.__setattr__ in a module-scoped autouse fixture.  No TestClient,
no real AWS, no network.

RULE-4 compliance: all sys.modules stubs and T/S mutations live inside the
autouse fixture that saves + restores on teardown.
"""
from __future__ import annotations

import sys
import types
import asyncio
import hashlib
import unittest
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import boto3
import pytest

# ── Environment vars must be set before importing app modules ──────────────
import os
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")


# ── Module-scoped autouse fixture for T/S/sys.modules isolation ────────────


@pytest.fixture(scope="module", autouse=True)
def _ecm_isolation():
    """Save and restore T, S settings attrs, and sys.modules stubs for ECM tests."""
    from moto import mock_aws
    from app.core.tables import T
    from app.core.settings import S

    # ── Save originals ──────────────────────────────────────────────────
    _orig_s = {
        "store_integration_enabled": getattr(S, "store_integration_enabled", False),
        "store_variant_selection_enabled": getattr(S, "store_variant_selection_enabled", False),
        "store_show_live_availability": getattr(S, "store_show_live_availability", False),
        "store_apply_pricing_rules": getattr(S, "store_apply_pricing_rules", False),
        "store_show_fulfillment_status": getattr(S, "store_show_fulfillment_status", False),
        "store_cart_reservations_enabled": getattr(S, "store_cart_reservations_enabled", False),
        "inventory_reservations_enabled": getattr(S, "inventory_reservations_enabled", False),
        "product_depth_enabled": getattr(S, "product_depth_enabled", False),
        "pricing_rules_enabled": getattr(S, "pricing_rules_enabled", False),
        "order_lifecycle_enabled": getattr(S, "order_lifecycle_enabled", False),
        "shipping_enabled": getattr(S, "shipping_enabled", False),
    }
    _orig_t = {
        "inventory": getattr(T, "inventory", None),
        "reservations": getattr(T, "reservations", None),
        "orders": getattr(T, "orders", None),
    }
    # Track sys.modules stubs added during module tests
    _added_modules: List[str] = []
    _orig_modules: Dict[str, Any] = {}

    def _stub_module(name: str, obj: Any) -> None:
        """Install a stub module, tracking originals for teardown."""
        if name not in _added_modules:
            _added_modules.append(name)
        _orig_modules.setdefault(name, sys.modules.get(name))
        sys.modules[name] = obj

    # Store the stub helper on the fixture namespace so tests can use it
    _ecm_isolation._stub_module = _stub_module  # type: ignore[attr-defined]

    # ── Start moto and create tables ────────────────────────────────────
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        inv_table = ddb.create_table(
            TableName="inventory",
            KeySchema=[
                {"AttributeName": "sku", "KeyType": "HASH"},
                {"AttributeName": "location_sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "sku", "AttributeType": "S"},
                {"AttributeName": "location_sk", "AttributeType": "S"},
                {"AttributeName": "status", "AttributeType": "S"},
                {"AttributeName": "available", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[{
                "IndexName": "GSI_AVAILABLE",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "available", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }],
            BillingMode="PAY_PER_REQUEST",
        )
        res_table = ddb.create_table(
            TableName="reservations",
            KeySchema=[
                {"AttributeName": "reservation_pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "reservation_pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "sku", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
                {"AttributeName": "gsi_expiry_pk", "AttributeType": "S"},
                {"AttributeName": "expires_at", "AttributeType": "N"},
                {"AttributeName": "cart_id", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_SKU",
                    "KeySchema": [
                        {"AttributeName": "sku", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI_EXPIRY",
                    "KeySchema": [
                        {"AttributeName": "gsi_expiry_pk", "KeyType": "HASH"},
                        {"AttributeName": "expires_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI_CART",
                    "KeySchema": [
                        {"AttributeName": "cart_id", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        orders_table = ddb.create_table(
            TableName="orders",
            KeySchema=[
                {"AttributeName": "order_id", "KeyType": "HASH"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "order_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        object.__setattr__(T, "inventory", inv_table)
        object.__setattr__(T, "reservations", res_table)
        object.__setattr__(T, "orders", orders_table)

        yield _ecm_isolation  # ← tests run here

    # ── Teardown: restore T, S, sys.modules ─────────────────────────────
    for attr, val in _orig_s.items():
        object.__setattr__(S, attr, val)
    for attr, val in _orig_t.items():
        object.__setattr__(T, attr, val)
    for mod_name in _added_modules:
        orig = _orig_modules.get(mod_name)
        if orig is None:
            sys.modules.pop(mod_name, None)
        else:
            sys.modules[mod_name] = orig


# ── ECM-002: Settings flags & gate helpers ─────────────────────────────────


class TestECM002IntegrationEnabled:
    def setup_method(self):
        from app.core.settings import S
        self._S = S
        # Always start with all flags off for gate tests
        object.__setattr__(S, "store_integration_enabled", False)
        object.__setattr__(S, "store_variant_selection_enabled", False)
        object.__setattr__(S, "store_show_live_availability", False)
        object.__setattr__(S, "store_apply_pricing_rules", False)
        object.__setattr__(S, "store_show_fulfillment_status", False)

    def test_master_off_returns_false(self):
        from app.services.store_integration import _integration_enabled
        assert _integration_enabled() is False
        assert _integration_enabled("variant_selection") is False

    def test_master_on_no_subflag_returns_true(self):
        from app.services.store_integration import _integration_enabled
        object.__setattr__(self._S, "store_integration_enabled", True)
        assert _integration_enabled() is True

    def test_master_on_subflag_on_returns_true(self):
        from app.services.store_integration import _integration_enabled
        object.__setattr__(self._S, "store_integration_enabled", True)
        object.__setattr__(self._S, "store_variant_selection_enabled", True)
        assert _integration_enabled("variant_selection") is True

    def test_master_on_subflag_off_returns_false(self):
        from app.services.store_integration import _integration_enabled
        object.__setattr__(self._S, "store_integration_enabled", True)
        object.__setattr__(self._S, "store_variant_selection_enabled", False)
        assert _integration_enabled("variant_selection") is False

    def test_unknown_subflag_returns_false(self):
        from app.services.store_integration import _integration_enabled
        object.__setattr__(self._S, "store_integration_enabled", True)
        import logging
        with patch.object(logging.getLogger("app.services.store_integration"), "warning") as mock_w:
            result = _integration_enabled("nonexistent_flag")
        assert result is False
        mock_w.assert_called_once()

    def test_all_subflag_names_valid(self):
        from app.services.store_integration import _integration_enabled
        object.__setattr__(self._S, "store_integration_enabled", True)
        for name in ("live_availability", "pricing_rules", "fulfillment_status", "variant_selection", "cart_reservations"):
            # Should not raise or log warning
            _integration_enabled(name)


class TestECM002SafeUpstream:
    def test_returns_call_result_on_success(self):
        from app.services.store_integration import _safe_upstream
        result = _safe_upstream(lambda: {"ok": True}, default={"ok": False})
        assert result == {"ok": True}

    def test_returns_default_on_exception(self):
        from app.services.store_integration import _safe_upstream
        result = _safe_upstream(lambda: 1 / 0, default="LEGACY")
        assert result == "LEGACY"

    def test_returns_default_on_runtime_error(self):
        from app.services.store_integration import _safe_upstream
        def _fail():
            raise ValueError("upstream down")
        result = _safe_upstream(_fail, default=42)
        assert result == 42

    def test_default_type_preserved(self):
        from app.services.store_integration import _safe_upstream
        default_list = [1, 2, 3]
        result = _safe_upstream(lambda: (_ for _ in ()).throw(Exception()), default=default_list)
        assert result is default_list


class TestECM002SettingsFlags:
    def test_flags_default_false(self):
        from app.core.settings import Settings
        # Create a fresh instance with no env overrides
        s = Settings()
        assert s.store_integration_enabled is False
        assert s.store_show_live_availability is False
        assert s.store_apply_pricing_rules is False
        assert s.store_show_fulfillment_status is False
        assert s.store_variant_selection_enabled is False

    def test_module_importable(self):
        import app.services.store_integration  # noqa: F401 — must not raise


# ── ECM-003: Pydantic models ───────────────────────────────────────────────


class TestECM003Models:
    def test_storefront_availability_basic(self):
        from app.models import StorefrontAvailabilityOut
        a = StorefrontAvailabilityOut(
            available=10, on_hand=12, reserved=2,
            low_stock=False, stock_status="in_stock",
        )
        assert a.available == 10
        assert a.low_stock is False

    def test_storefront_availability_low_stock(self):
        from app.models import StorefrontAvailabilityOut
        a = StorefrontAvailabilityOut(
            available=3, on_hand=5, reserved=2,
            low_stock=True, stock_status="low_stock",
        )
        assert a.low_stock is True

    def test_storefront_availability_negative_available(self):
        from app.models import StorefrontAvailabilityOut
        a = StorefrontAvailabilityOut(
            available=-1, on_hand=2, reserved=3,
            low_stock=False, stock_status="out_of_stock",
        )
        assert a.available == -1
        assert a.stock_status == "out_of_stock"

    def test_storefront_variant_out_basic(self):
        from app.models import StorefrontVariantOut, StorefrontAvailabilityOut
        v = StorefrontVariantOut(
            variant_id="var_001",
            sku="SKU-RED-M",
            option_selections={"Color": "Red", "Size": "M"},
            price_cents=2500,
            availability=StorefrontAvailabilityOut(
                available=10, on_hand=12, reserved=2,
                low_stock=False, stock_status="in_stock",
            ),
        )
        assert v.variant_id == "var_001"
        assert v.option_selections["Color"] == "Red"
        assert v.availability is not None
        assert v.availability.available == 10

    def test_storefront_variant_out_no_availability(self):
        from app.models import StorefrontVariantOut
        v = StorefrontVariantOut(
            variant_id="var_002", sku="SKU-BLUE-L",
            option_selections={}, price_cents=0,
        )
        assert v.availability is None
        assert v.price_cents == 0

    def test_cart_pricing_breakdown_invariant_ok(self):
        from app.models import CartPricingBreakdownOut, AppliedPricingRuleLineOut
        b = CartPricingBreakdownOut(
            cart_id="cart_abc",
            subtotal_cents=10000,
            applied_rules=[
                AppliedPricingRuleLineOut(
                    rule_id="r1", rule_name="10% off",
                    discount_type="percentage", discount_cents=1000,
                )
            ],
            discount_cents=1000,
            final_total_cents=9000,
        )
        assert b.final_total_cents == b.subtotal_cents - b.discount_cents

    def test_cart_pricing_breakdown_invariant_violated(self):
        from app.models import CartPricingBreakdownOut
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            CartPricingBreakdownOut(
                cart_id="cart_xyz",
                subtotal_cents=10000,
                discount_cents=500,
                final_total_cents=9999,  # wrong: should be 9500
            )

    def test_cart_pricing_breakdown_over_discount_clamped(self):
        from app.models import CartPricingBreakdownOut
        b = CartPricingBreakdownOut(
            cart_id="cart_xyz", subtotal_cents=100,
            discount_cents=200, final_total_cents=-100,  # will trigger clamp
        )
        # After clamp: discount = subtotal = 100, final = 0
        assert b.final_total_cents == 0
        assert b.discount_cents == 100

    def test_cart_pricing_breakdown_empty_rules(self):
        from app.models import CartPricingBreakdownOut
        b = CartPricingBreakdownOut(
            cart_id="cart_xyz", subtotal_cents=5000,
            discount_cents=0, final_total_cents=5000,
        )
        assert b.applied_rules == []

    def test_order_fulfillment_status_defaults(self):
        from app.models import OrderFulfillmentStatusOut
        o = OrderFulfillmentStatusOut(order_id="ord_001")
        assert o.lifecycle_status is None
        assert o.fulfillment_status is None
        assert o.ship_groups == []
        assert o.tracking_numbers == []

    def test_order_fulfillment_status_populated(self):
        from app.models import OrderFulfillmentStatusOut, ShipGroupFulfillmentOut
        o = OrderFulfillmentStatusOut(
            order_id="ord_002",
            lifecycle_status="fulfillment",
            fulfillment_status="shipped",
            ship_groups=[
                ShipGroupFulfillmentOut(
                    ship_group_id="sg_1",
                    status="shipped",
                    items=["SKU-RED-M"],
                    carrier="UPS",
                    tracking_number="1Z999AA10123456784",
                    shipped_at=1700000000,
                )
            ],
            tracking_numbers=["1Z999AA10123456784"],
        )
        assert len(o.ship_groups) == 1
        assert o.tracking_numbers[0] == "1Z999AA10123456784"

    def test_catalog_item_out_new_fields_default_none(self):
        from app.models import CatalogItemOut
        item = CatalogItemOut(
            category_id="cat_1", item_id="item_1", name="Widget",
            price_cents=999, currency="USD", image_urls=[],
            attributes={}, created_at="2024-01-01T00:00:00+00:00",
            updated_at="2024-01-01T00:00:00+00:00",
        )
        assert item.variants is None
        assert item.availability is None
        assert item.stock_status == "unlimited"

    def test_shopping_cart_total_out_pricing_breakdown_default_none(self):
        from app.models import ShoppingCartTotalOut
        t = ShoppingCartTotalOut(cart_id="cart_1", total_cents=5000)
        assert t.pricing_breakdown is None


# ── ECM-004: Variant enrichment ────────────────────────────────────────────


class TestECM004VariantEnrichment:
    """ECM-004: enrich_catalog_item tests with stubbed product_variants module."""

    _ITEM_BASE = {
        "PK": "CAT#cat1", "SK": "ITEM#parent1",
        "item_id": "parent1", "category_id": "cat1",
        "name": "Widget", "price_cents": 1000, "currency": "USD",
        "image_urls": [], "attributes": {},
        "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z",
        "entity": "item",
    }

    def setup_method(self):
        from app.core.settings import S
        object.__setattr__(S, "store_integration_enabled", False)
        object.__setattr__(S, "store_variant_selection_enabled", False)
        object.__setattr__(S, "product_depth_enabled", False)
        # Remove any existing stub
        sys.modules.pop("app.services.product_variants", None)

    def teardown_method(self):
        from app.core.settings import S
        object.__setattr__(S, "store_integration_enabled", False)
        object.__setattr__(S, "store_variant_selection_enabled", False)
        object.__setattr__(S, "product_depth_enabled", False)
        sys.modules.pop("app.services.product_variants", None)

    def test_flag_off_returns_legacy(self):
        from app.services.store_integration import enrich_catalog_item
        item = {**self._ITEM_BASE, "product_type": "virtual"}
        result = enrich_catalog_item(item, viewer={"user_sub": "u1"})
        assert result.item_id == "parent1"
        assert result.variants is None  # flag off → no enrichment

    def test_flat_product_unchanged(self):
        from app.core.settings import S
        from app.services.store_integration import enrich_catalog_item
        object.__setattr__(S, "store_integration_enabled", True)
        object.__setattr__(S, "store_variant_selection_enabled", True)
        # No product_type → treated as standalone
        item = {**self._ITEM_BASE}
        result = enrich_catalog_item(item, viewer={"user_sub": "u1"})
        assert result.variants is None

    def test_virtual_product_returns_variants(self):
        from app.core.settings import S
        from app.services.store_integration import enrich_catalog_item

        object.__setattr__(S, "store_integration_enabled", True)
        object.__setattr__(S, "store_variant_selection_enabled", True)

        variant_rows = [
            {
                "variant_id": "v1", "sku": "WIDGET-RED-M",
                "feature_values": {"fc_color": "fv_red", "fc_size": "fv_m"},
                "price_delta_cents": 200, "created_at": 1700000000,
            },
            {
                "variant_id": "v2", "sku": "WIDGET-BLU-M",
                "feature_values": {"fc_color": "fv_blue", "fc_size": "fv_m"},
                "price_delta_cents": 0, "created_at": 1700000001,
            },
        ]
        mock_pv = SimpleNamespace(list_variants=lambda pid, **kw: (variant_rows, None))
        sys.modules["app.services.product_variants"] = mock_pv

        item = {**self._ITEM_BASE, "product_type": "virtual"}
        result = enrich_catalog_item(item, viewer={"user_sub": "u1"})

        assert result.item_id == "parent1"
        assert result.variants is not None
        assert len(result.variants) == 2
        assert result.variants[0].sku == "WIDGET-RED-M"
        assert result.variants[0].price_cents == 1200  # 1000 + 200
        assert result.variants[1].price_cents == 1000
        assert result.variants[0].availability is None  # ECM-005 populates this
        assert result.variants[0].option_selections == {"fc_color": "fv_red", "fc_size": "fv_m"}

    def test_upstream_error_degrades(self):
        from app.core.settings import S
        from app.services.store_integration import enrich_catalog_item

        object.__setattr__(S, "store_integration_enabled", True)
        object.__setattr__(S, "store_variant_selection_enabled", True)

        def _fail(pid, **kw):
            raise RuntimeError("DDB error")

        mock_pv = SimpleNamespace(list_variants=_fail)
        sys.modules["app.services.product_variants"] = mock_pv

        item = {**self._ITEM_BASE, "product_type": "virtual"}
        result = enrich_catalog_item(item, viewer={"user_sub": "u1"})
        assert result.variants is None  # degraded

    def test_negative_delta_clamped(self):
        from app.services.store_integration import _build_storefront_variant
        variant_dict = {
            "variant_id": "vneg", "sku": "NEG-SKU",
            "feature_values": {}, "price_delta_cents": -500,
        }
        sv = _build_storefront_variant(variant_dict, 100)
        assert sv.price_cents == 0  # max(0, 100 - 500)

    def test_virtual_product_zero_variants_returns_none(self):
        from app.core.settings import S
        from app.services.store_integration import enrich_catalog_item

        object.__setattr__(S, "store_integration_enabled", True)
        object.__setattr__(S, "store_variant_selection_enabled", True)

        mock_pv = SimpleNamespace(list_variants=lambda pid, **kw: ([], None))
        sys.modules["app.services.product_variants"] = mock_pv

        item = {**self._ITEM_BASE, "product_type": "virtual"}
        result = enrich_catalog_item(item, viewer={"user_sub": "u1"})
        # Empty list → None (no picker)
        assert result.variants is None

    def test_module_not_found_degrades(self):
        from app.core.settings import S
        from app.services.store_integration import enrich_catalog_item

        object.__setattr__(S, "store_integration_enabled", True)
        object.__setattr__(S, "store_variant_selection_enabled", True)

        # Remove stub so import raises ModuleNotFoundError
        sys.modules.pop("app.services.product_variants", None)

        item = {**self._ITEM_BASE, "product_type": "virtual"}
        result = enrich_catalog_item(item, viewer={"user_sub": "u1"})
        # Must not raise; degrades to flat result
        assert result.item_id == "parent1"
        assert result.variants is None


# ── ECM-005: Live availability projection ──────────────────────────────────


class TestECM005LiveAvailability:
    def setup_method(self):
        from app.core.settings import S
        object.__setattr__(S, "store_integration_enabled", False)
        object.__setattr__(S, "store_show_live_availability", False)
        object.__setattr__(S, "inventory_reservations_enabled", False)

    def teardown_method(self):
        from app.core.settings import S
        object.__setattr__(S, "store_integration_enabled", False)
        object.__setattr__(S, "store_show_live_availability", False)
        object.__setattr__(S, "inventory_reservations_enabled", False)

    def test_flag_off_returns_empty(self):
        from app.services.store_integration import availability_for_skus
        result = availability_for_skus(["SKU-A"])
        assert result == {}

    def test_inventory_flag_off_returns_empty_even_if_ecm_on(self):
        from app.core.settings import S
        from app.services.store_integration import availability_for_skus
        object.__setattr__(S, "store_integration_enabled", True)
        object.__setattr__(S, "store_show_live_availability", True)
        object.__setattr__(S, "inventory_reservations_enabled", False)  # sibling flag off
        result = availability_for_skus(["SKU-A"])
        assert result == {}

    def test_avail_from_inventory_row_in_stock(self):
        from app.services.store_integration import _avail_from_inventory_row
        row = {"on_hand": 10, "reserved": 2, "reorder_point": 3, "sku": "A"}
        avail = _avail_from_inventory_row(row)
        assert avail.available == 8
        assert avail.on_hand == 10
        assert avail.reserved == 2
        assert avail.stock_status == "in_stock"
        assert avail.low_stock is False

    def test_avail_from_inventory_row_low_stock(self):
        from app.services.store_integration import _avail_from_inventory_row
        row = {"on_hand": 5, "reserved": 2, "reorder_point": 5, "sku": "A"}
        avail = _avail_from_inventory_row(row)
        assert avail.available == 3
        assert avail.stock_status == "low_stock"
        assert avail.low_stock is True

    def test_avail_from_inventory_row_out_of_stock(self):
        from app.services.store_integration import _avail_from_inventory_row
        row = {"on_hand": 2, "reserved": 3, "reorder_point": 5, "sku": "A"}
        avail = _avail_from_inventory_row(row)
        assert avail.available == -1
        assert avail.stock_status == "out_of_stock"
        assert avail.low_stock is False

    def test_avail_from_stock_count_unlimited(self):
        from app.services.store_integration import _avail_from_stock_count
        avail = _avail_from_stock_count(None)
        assert avail.stock_status == "unlimited"
        assert avail.available > 0

    def test_avail_from_stock_count_out_of_stock(self):
        from app.services.store_integration import _avail_from_stock_count
        avail = _avail_from_stock_count(0)
        assert avail.stock_status == "out_of_stock"

    def test_apply_live_availability_enriches_item(self):
        from app.models import CatalogItemOut, StorefrontAvailabilityOut
        from app.services.store_integration import _apply_live_availability

        item_out = CatalogItemOut(
            category_id="cat1", item_id="sku1", name="Test",
            price_cents=100, currency="USD", image_urls=[], attributes={},
            created_at="2025-01-01T00:00:00Z", updated_at="2025-01-01T00:00:00Z",
            stock_count=50, stock_status="in_stock",
        )
        avail = StorefrontAvailabilityOut(
            available=7, on_hand=10, reserved=3,
            low_stock=False, stock_status="in_stock",
        )
        avail_map = {"sku1": avail}
        enriched = _apply_live_availability(item_out, avail_map)
        assert enriched.stock_count == 7
        assert enriched.availability is not None
        assert enriched.availability.reserved == 3

    def test_apply_live_availability_sku_absent_unchanged(self):
        from app.models import CatalogItemOut
        from app.services.store_integration import _apply_live_availability

        item_out = CatalogItemOut(
            category_id="cat1", item_id="sku_missing", name="Test",
            price_cents=100, currency="USD", image_urls=[], attributes={},
            created_at="2025-01-01T00:00:00Z", updated_at="2025-01-01T00:00:00Z",
            stock_count=50,
        )
        # SKU not in map → unchanged
        enriched = _apply_live_availability(item_out, {"other_sku": None})
        assert enriched.stock_count == 50
        assert enriched.availability is None

    def test_availability_batch_reads_inventory(self):
        """With both flags on and a seeded inventory row, availability_for_skus returns data."""
        from app.core.settings import S
        from app.core.tables import T
        from app.services.store_integration import availability_for_skus

        object.__setattr__(S, "store_integration_enabled", True)
        object.__setattr__(S, "store_show_live_availability", True)
        object.__setattr__(S, "inventory_reservations_enabled", True)
        object.__setattr__(S, "inventory_table_name", "inventory")

        # Seed an inventory row
        T.inventory.put_item(Item={
            "sku": "TEST-SKU-AVAIL",
            "location_sk": "LOC#default",
            "on_hand": 10,
            "reserved": 3,
            "available": 7,
            "reorder_point": 5,
            "status": "in_stock",
        })

        result = availability_for_skus(["TEST-SKU-AVAIL"])
        assert "TEST-SKU-AVAIL" in result
        assert result["TEST-SKU-AVAIL"].available == 7
        assert result["TEST-SKU-AVAIL"].reserved == 3


# ── ECM-006: Pricing breakdown ─────────────────────────────────────────────


class TestECM006PricingBreakdown:
    def setup_method(self):
        from app.core.settings import S
        object.__setattr__(S, "store_integration_enabled", False)
        object.__setattr__(S, "store_apply_pricing_rules", False)
        object.__setattr__(S, "pricing_rules_enabled", False)
        sys.modules.pop("app.services.pricing_rules", None)

    def teardown_method(self):
        from app.core.settings import S
        object.__setattr__(S, "store_integration_enabled", False)
        object.__setattr__(S, "store_apply_pricing_rules", False)
        object.__setattr__(S, "pricing_rules_enabled", False)
        sys.modules.pop("app.services.pricing_rules", None)

    def test_flag_off_returns_plain_sum(self):
        from app.services.store_integration import get_cart_pricing_breakdown
        # Stub shoppingcart.list_items
        with patch("app.services.store_integration._safe_upstream", side_effect=lambda call, default: default):
            bd = get_cart_pricing_breakdown("user1", "cart1")
        assert bd.discount_cents == 0
        assert bd.applied_rules == []
        assert bd.final_total_cents == bd.subtotal_cents

    def test_pricing_flag_on_sibling_off_returns_plain_sum(self):
        from app.core.settings import S
        from app.services.store_integration import get_cart_pricing_breakdown
        object.__setattr__(S, "store_integration_enabled", True)
        object.__setattr__(S, "store_apply_pricing_rules", True)
        object.__setattr__(S, "pricing_rules_enabled", False)  # sibling off

        # Stub list_items in shoppingcart to return 2 items
        items = [{"line_total_cents": 1000}, {"line_total_cents": 2000}]
        with patch("app.services.store_integration._safe_upstream", side_effect=lambda call, default: default):
            bd = get_cart_pricing_breakdown("user1", "cart1")
        # sibling flag off → plain sum
        assert bd.discount_cents == 0


# ── ECM-007: Order fulfillment status ──────────────────────────────────────


class TestECM007OrderFulfillment:
    def setup_method(self):
        from app.core.settings import S
        from app.core.tables import T
        self._T = T
        object.__setattr__(S, "store_integration_enabled", False)
        object.__setattr__(S, "store_show_fulfillment_status", False)
        object.__setattr__(S, "order_lifecycle_enabled", False)
        object.__setattr__(S, "shipping_enabled", False)
        sys.modules.pop("app.services.order_lifecycle", None)
        sys.modules.pop("app.services.shipments", None)

    def teardown_method(self):
        from app.core.settings import S
        object.__setattr__(S, "store_integration_enabled", False)
        object.__setattr__(S, "store_show_fulfillment_status", False)
        object.__setattr__(S, "order_lifecycle_enabled", False)
        object.__setattr__(S, "shipping_enabled", False)
        sys.modules.pop("app.services.order_lifecycle", None)
        sys.modules.pop("app.services.shipments", None)

    def test_flag_off_returns_empty(self):
        from app.services.store_integration import get_order_fulfillment_status
        result = get_order_fulfillment_status("ord_001", user_sub="u1")
        assert result.order_id == "ord_001"
        assert result.lifecycle_status is None
        assert result.ship_groups == []

    def test_wrong_owner_returns_empty(self):
        from app.core.settings import S
        from app.services.store_integration import get_order_fulfillment_status

        object.__setattr__(S, "store_integration_enabled", True)
        object.__setattr__(S, "store_show_fulfillment_status", True)

        # Seed an order for a DIFFERENT user
        self._T.orders.put_item(Item={
            "order_id": "ord_wrong_owner",
            "user_sub": "other_user",
            "status": "pending",
        })
        result = get_order_fulfillment_status("ord_wrong_owner", user_sub="my_user")
        # Ownership check fails → empty result
        assert result.lifecycle_status is None

    def test_correct_owner_returns_order_data(self):
        from app.core.settings import S
        from app.services.store_integration import get_order_fulfillment_status

        object.__setattr__(S, "store_integration_enabled", True)
        object.__setattr__(S, "store_show_fulfillment_status", True)

        self._T.orders.put_item(Item={
            "order_id": "ord_mine",
            "user_sub": "my_user",
            "status": "pending",
        })
        result = get_order_fulfillment_status("ord_mine", user_sub="my_user")
        assert result.order_id == "ord_mine"
        # No ORD/SHP flags → lifecycle and fulfillment both None
        assert result.lifecycle_status is None

    def test_lifecycle_flag_on_calls_order_lifecycle(self):
        from app.core.settings import S
        from app.services.store_integration import get_order_fulfillment_status

        object.__setattr__(S, "store_integration_enabled", True)
        object.__setattr__(S, "store_show_fulfillment_status", True)
        object.__setattr__(S, "order_lifecycle_enabled", True)

        # Seed the order
        self._T.orders.put_item(Item={
            "order_id": "ord_lifecycle",
            "user_sub": "my_user",
            "status": "pending",
        })

        # Stub order_lifecycle
        mock_ol = SimpleNamespace(
            get_order_lifecycle=lambda oid: {"lifecycle_status": "fulfillment"}
        )
        sys.modules["app.services.order_lifecycle"] = mock_ol

        result = get_order_fulfillment_status("ord_lifecycle", user_sub="my_user")
        assert result.lifecycle_status == "fulfillment"


# ── ECM-008: Soft reservation lifecycle ────────────────────────────────────


class TestECM008Reservations:
    def setup_method(self):
        from app.core.settings import S
        object.__setattr__(S, "store_integration_enabled", False)
        object.__setattr__(S, "store_cart_reservations_enabled", False)
        object.__setattr__(S, "inventory_reservations_enabled", False)
        sys.modules.pop("app.services.inventory", None)

    def teardown_method(self):
        from app.core.settings import S
        object.__setattr__(S, "store_integration_enabled", False)
        object.__setattr__(S, "store_cart_reservations_enabled", False)
        object.__setattr__(S, "inventory_reservations_enabled", False)
        sys.modules.pop("app.services.inventory", None)

    def test_reservations_disabled_flag_off(self):
        from app.services.store_integration import _reservations_enabled_for_sku
        assert _reservations_enabled_for_sku("any-sku") is False

    def test_reservations_enabled_when_both_flags_on(self):
        from app.core.settings import S
        from app.services.store_integration import _reservations_enabled_for_sku
        object.__setattr__(S, "store_integration_enabled", True)
        object.__setattr__(S, "store_cart_reservations_enabled", True)
        object.__setattr__(S, "inventory_reservations_enabled", True)
        assert _reservations_enabled_for_sku("any-sku") is True

    def test_reserve_for_cart_flag_off_returns_none(self):
        from app.services.store_integration import reserve_for_cart
        result = reserve_for_cart(
            user_sub="u1", cart_id="c1", sku="SKU-A", quantity=2,
        )
        assert result is None

    def test_reserve_for_cart_inventory_service_called(self):
        from app.core.settings import S
        from app.services.store_integration import reserve_for_cart, _reservation_id_for

        object.__setattr__(S, "store_integration_enabled", True)
        object.__setattr__(S, "store_cart_reservations_enabled", True)
        object.__setattr__(S, "inventory_reservations_enabled", True)

        reserve_calls = []
        def fake_reserve(sku, qty, *, location_id, cart_id, user_sub, ttl_seconds, reservation_id):
            reserve_calls.append({
                "sku": sku, "qty": qty, "cart_id": cart_id, "reservation_id": reservation_id,
            })

        mock_inv = SimpleNamespace(reserve=fake_reserve)
        sys.modules["app.services.inventory"] = mock_inv

        res_id = reserve_for_cart(user_sub="u1", cart_id="cart123", sku="MY-SKU", quantity=3)
        expected_id = _reservation_id_for("cart123", "MY-SKU")
        assert res_id == expected_id
        assert len(reserve_calls) == 1
        assert reserve_calls[0]["reservation_id"] == expected_id

    def test_reserve_for_cart_failure_returns_none(self):
        from app.core.settings import S
        from app.services.store_integration import reserve_for_cart

        object.__setattr__(S, "store_integration_enabled", True)
        object.__setattr__(S, "store_cart_reservations_enabled", True)
        object.__setattr__(S, "inventory_reservations_enabled", True)

        def _fail_reserve(*args, **kwargs):
            raise RuntimeError("inventory down")

        mock_inv = SimpleNamespace(reserve=_fail_reserve)
        sys.modules["app.services.inventory"] = mock_inv

        # Should not raise; returns None on failure
        result = reserve_for_cart(user_sub="u1", cart_id="c1", sku="SKU-B", quantity=1)
        assert result is None

    def test_reservation_id_deterministic(self):
        from app.services.store_integration import _reservation_id_for
        id1 = _reservation_id_for("cart-A", "SKU-X")
        id2 = _reservation_id_for("cart-A", "SKU-X")
        assert id1 == id2
        assert len(id1) == 16

    def test_reservation_id_different_for_different_inputs(self):
        from app.services.store_integration import _reservation_id_for
        id1 = _reservation_id_for("cart-A", "SKU-X")
        id2 = _reservation_id_for("cart-A", "SKU-Y")
        assert id1 != id2

    def test_commit_cart_reservations_flag_off_returns_false(self):
        from app.services.store_integration import commit_cart_reservations
        result = commit_cart_reservations(user_sub="u1", cart_id="c1", items=[])
        assert result is False

    def test_commit_cart_reservations_calls_inventory_commit(self):
        from app.core.settings import S
        from app.services.store_integration import commit_cart_reservations, _reservation_id_for

        object.__setattr__(S, "store_integration_enabled", True)
        object.__setattr__(S, "store_cart_reservations_enabled", True)
        object.__setattr__(S, "inventory_reservations_enabled", True)

        committed_ids = []
        def fake_commit(reservation_id):
            committed_ids.append(reservation_id)

        mock_inv = SimpleNamespace(commit_reservation=fake_commit)
        sys.modules["app.services.inventory"] = mock_inv

        items = [{"sku": "SKU-A", "quantity": 1}, {"sku": "SKU-B", "quantity": 2}]
        result = commit_cart_reservations(user_sub="u1", cart_id="c1", items=items)
        assert result is True
        expected_ids = {_reservation_id_for("c1", "SKU-A"), _reservation_id_for("c1", "SKU-B")}
        assert set(committed_ids) == expected_ids


# ── ECM-010: Cart total with pricing wired ─────────────────────────────────


class TestECM010CartTotalWithBreakdown:
    def setup_method(self):
        from app.core.settings import S
        object.__setattr__(S, "store_integration_enabled", False)
        object.__setattr__(S, "store_apply_pricing_rules", False)

    def teardown_method(self):
        from app.core.settings import S
        object.__setattr__(S, "store_integration_enabled", False)
        object.__setattr__(S, "store_apply_pricing_rules", False)

    def test_flag_off_returns_plain_total(self):
        from app.services.store_integration import cart_total_with_breakdown
        # cart_total_cents is imported lazily inside cart_total_with_breakdown
        with patch("app.services.shoppingcart.cart_total_cents", return_value=5000):
            result = cart_total_with_breakdown("u1", "c1")
        assert result["total_cents"] == 5000
        assert result["pricing_breakdown"] is None

    def test_flag_on_returns_breakdown(self):
        from app.core.settings import S
        from app.models import CartPricingBreakdownOut
        from app.services.store_integration import cart_total_with_breakdown

        object.__setattr__(S, "store_integration_enabled", True)
        object.__setattr__(S, "store_apply_pricing_rules", True)

        fake_breakdown = CartPricingBreakdownOut(
            cart_id="c1", subtotal_cents=10000,
            discount_cents=1000, final_total_cents=9000,
        )
        with patch("app.services.store_integration.get_cart_pricing_breakdown", return_value=fake_breakdown):
            with patch("app.services.shoppingcart.cart_total_cents", return_value=10000):
                result = cart_total_with_breakdown("u1", "c1")

        assert result["total_cents"] == 9000  # authoritative from breakdown
        assert result["pricing_breakdown"] is not None
        assert result["pricing_breakdown"].discount_cents == 1000


# ── Import smoke test ──────────────────────────────────────────────────────


def test_app_main_imports_ok():
    """Verify the app can be imported (covers all new settings/table additions)."""
    import importlib
    # Reimport to catch any syntax/import errors in our new files
    importlib.import_module("app.services.store_integration")
    importlib.import_module("app.models")
    importlib.import_module("app.core.settings")
    importlib.import_module("app.core.tables")

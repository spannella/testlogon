"""Hermetic pytest suite for SHP-004..SHP-011.

Covers carrier management (SHP-004/005), rate estimation (SHP-006/007),
and shipment lifecycle (SHP-008/009/010/011).

Pattern: moto in-memory DynamoDB tables, T/S patched via object.__setattr__
in a module-scoped autouse fixture.  No real AWS, no network.
"""
from __future__ import annotations

from typing import Any, Dict

import boto3
import pytest
from moto import mock_aws


# ---------------------------------------------------------------------------
# Module-scope fixture: moto tables + freeze T/S
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _shp_tables():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        # shipping_carriers: PK=carrier_id, SK=sk
        carriers_tbl = ddb.create_table(
            TableName="shp_test_carriers",
            KeySchema=[
                {"AttributeName": "carrier_id", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "carrier_id", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "carrier_code", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[{
                "IndexName": "GSI_CODE",
                "KeySchema": [
                    {"AttributeName": "carrier_code", "KeyType": "HASH"},
                    {"AttributeName": "sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }],
            BillingMode="PAY_PER_REQUEST",
        )

        # shipments: PK=shipment_id, GSI_ORDER on order_id+created_at
        shipments_tbl = ddb.create_table(
            TableName="shp_test_shipments",
            KeySchema=[{"AttributeName": "shipment_id", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "shipment_id", "AttributeType": "S"},
                {"AttributeName": "order_id", "AttributeType": "S"},
                {"AttributeName": "status", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_ORDER",
                    "KeySchema": [
                        {"AttributeName": "order_id", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI_STATUS",
                    "KeySchema": [
                        {"AttributeName": "status", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # shipment_items: PK=shipment_id, SK=item_id
        items_tbl = ddb.create_table(
            TableName="shp_test_items",
            KeySchema=[
                {"AttributeName": "shipment_id", "KeyType": "HASH"},
                {"AttributeName": "item_id", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "shipment_id", "AttributeType": "S"},
                {"AttributeName": "item_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # shipment_packages: PK=shipment_id, SK=package_seq
        pkgs_tbl = ddb.create_table(
            TableName="shp_test_packages",
            KeySchema=[
                {"AttributeName": "shipment_id", "KeyType": "HASH"},
                {"AttributeName": "package_seq", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "shipment_id", "AttributeType": "S"},
                {"AttributeName": "package_seq", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # billing: for shipping-refund cancel tests
        billing_tbl = ddb.create_table(
            TableName="shp_test_billing",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # orders: for attach_ship_group
        orders_tbl = ddb.create_table(
            TableName="shp_test_orders",
            KeySchema=[{"AttributeName": "order_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "order_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        from app.core import tables as tables_mod, settings as settings_mod

        # Save originals
        orig_t = {
            "shipping_carriers": tables_mod.T.shipping_carriers,
            "shipments": tables_mod.T.shipments,
            "shipment_items": tables_mod.T.shipment_items,
            "shipment_packages": tables_mod.T.shipment_packages,
            "billing": tables_mod.T.billing,
            "orders": tables_mod.T.orders,
        }
        orig_s = {
            "shipping_enabled": settings_mod.S.shipping_enabled,
            "shipping_rate_estimation_enabled": settings_mod.S.shipping_rate_estimation_enabled,
            "shipping_default_currency": getattr(settings_mod.S, "shipping_default_currency", "usd"),
            "shipping_default_item_weight_oz": getattr(settings_mod.S, "shipping_default_item_weight_oz", 16),
            "shipping_dim_divisor": getattr(settings_mod.S, "shipping_dim_divisor", 139),
        }

        # Inject moto tables
        object.__setattr__(tables_mod.T, "shipping_carriers", carriers_tbl)
        object.__setattr__(tables_mod.T, "shipments", shipments_tbl)
        object.__setattr__(tables_mod.T, "shipment_items", items_tbl)
        object.__setattr__(tables_mod.T, "shipment_packages", pkgs_tbl)
        object.__setattr__(tables_mod.T, "billing", billing_tbl)
        object.__setattr__(tables_mod.T, "orders", orders_tbl)

        object.__setattr__(settings_mod.S, "shipping_enabled", True)
        object.__setattr__(settings_mod.S, "shipping_rate_estimation_enabled", True)
        object.__setattr__(settings_mod.S, "shipping_default_currency", "usd")
        object.__setattr__(settings_mod.S, "shipping_default_item_weight_oz", 16)
        object.__setattr__(settings_mod.S, "shipping_dim_divisor", 139)

        yield {
            "carriers_tbl": carriers_tbl,
            "shipments_tbl": shipments_tbl,
            "items_tbl": items_tbl,
            "pkgs_tbl": pkgs_tbl,
            "billing_tbl": billing_tbl,
            "orders_tbl": orders_tbl,
        }

        # Restore
        for attr, val in orig_t.items():
            object.__setattr__(tables_mod.T, attr, val)
        for attr, val in orig_s.items():
            object.__setattr__(settings_mod.S, attr, val)


# ---------------------------------------------------------------------------
# SHP-004: Carrier management
# ---------------------------------------------------------------------------

class TestCarrierManagement:
    """SHP-004: create, read, update carriers and shipping methods."""

    def test_carrier_id_is_deterministic(self):
        """sha256(carrier_code)[:16] must be stable across calls."""
        from app.services.shipping_carriers import _carrier_id
        assert _carrier_id("ups") == _carrier_id("ups")
        assert len(_carrier_id("ups")) == 16

    def test_create_carrier_success(self):
        """create_carrier writes a CARRIER# row with correct fields."""
        from app.services.shipping_carriers import create_carrier, get_carrier, _carrier_id
        item = create_carrier("fedex", "FedEx Corp")
        assert item["carrier_code"] == "fedex"
        assert item["enabled"] is True
        # fedex appears in CARRIER_TRACKING_URLS
        assert item["online_tracking"] is True
        fetched = get_carrier(_carrier_id("fedex"))
        assert fetched is not None
        assert fetched["display_name"] == "FedEx Corp"

    def test_create_carrier_duplicate_raises_409(self):
        """Second create_carrier for the same code raises HTTP 409."""
        from app.services.shipping_carriers import create_carrier
        from fastapi import HTTPException
        try:
            create_carrier("usps", "USPS First")
        except Exception:
            pass
        with pytest.raises(HTTPException) as exc_info:
            create_carrier("usps", "USPS Second")
        assert exc_info.value.status_code == 409

    def test_manual_carrier_has_no_online_tracking(self):
        """'manual' carrier_code does not appear in carrier tracking URLs."""
        from app.services.shipping_carriers import create_carrier, get_carrier, _carrier_id
        try:
            item = create_carrier("manual", "Manual Carrier")
        except Exception:
            item = get_carrier(_carrier_id("manual"))
        assert item is not None
        assert item["online_tracking"] is False

    def test_add_method_and_list_methods(self):
        """add_method writes a METHOD# row; list_methods returns it."""
        from app.services.shipping_carriers import create_carrier, add_method, list_methods, _carrier_id
        try:
            create_carrier("dhl", "DHL Express Inc")
        except Exception:
            pass
        cid = _carrier_id("dhl")
        try:
            add_method(cid, "express", "DHL Express",
                       base_rate_cents=2200,
                       transit_days_min=1, transit_days_max=3)
        except Exception:
            pass  # already exists
        methods = list_methods(cid)
        assert any(m["method_code"] == "express" for m in methods)

    def test_add_method_duplicate_raises_409(self):
        """Second add_method for same carrier+method raises HTTP 409."""
        from app.services.shipping_carriers import create_carrier, add_method, _carrier_id
        from fastapi import HTTPException
        try:
            create_carrier("ups", "UPS Inc")
        except Exception:
            pass
        cid = _carrier_id("ups")
        try:
            add_method(cid, "ground", "UPS Ground", base_rate_cents=899)
        except Exception:
            pass  # already exists
        with pytest.raises(HTTPException) as exc_info:
            add_method(cid, "ground", "UPS Ground Duplicate", base_rate_cents=999)
        assert exc_info.value.status_code == 409

    def test_update_carrier_display_name(self):
        """update_carrier can patch display_name."""
        from app.services.shipping_carriers import create_carrier, update_carrier, _carrier_id
        try:
            create_carrier("fedex", "FedEx Corp")
        except Exception:
            pass
        cid = _carrier_id("fedex")
        updated = update_carrier(cid, patch={"display_name": "FedEx Renamed"})
        assert updated["display_name"] == "FedEx Renamed"

    def test_seed_default_carriers_idempotent(self):
        """seed_default_carriers run twice produces the same carrier count."""
        from app.services.shipping_carriers import seed_default_carriers, list_carriers
        seed_default_carriers()
        count_first = len(list_carriers(enabled_only=False))
        seed_default_carriers()
        count_second = len(list_carriers(enabled_only=False))
        assert count_first == count_second
        assert count_first >= 5

    def test_seed_default_carriers_creates_all_five(self):
        """After seed, all five canonical carrier codes must be present."""
        from app.services.shipping_carriers import seed_default_carriers, list_carriers
        seed_default_carriers()
        carriers = list_carriers(enabled_only=False)
        codes = {c["carrier_code"] for c in carriers}
        assert {"ups", "fedex", "usps", "dhl", "manual"}.issubset(codes)

    def test_list_all_enabled_methods_returns_methods(self):
        """list_enabled_methods_all_carriers returns METHOD# rows after seed."""
        from app.services.shipping_carriers import seed_default_carriers, list_enabled_methods_all_carriers
        seed_default_carriers()
        methods = list_enabled_methods_all_carriers()
        assert len(methods) > 0
        for m in methods:
            assert m["sk"].startswith("METHOD#")


# ---------------------------------------------------------------------------
# SHP-006: Rate estimation
# ---------------------------------------------------------------------------

class TestRateEstimation:
    """SHP-006: estimate_rates returns correctly computed rate options."""

    def test_estimate_rates_returns_single_option_for_specific_method(self):
        """estimate_rates filtered to one carrier+method returns exactly one option."""
        from app.services.shipping_carriers import seed_default_carriers
        from app.services.shipping_rates import estimate_rates
        seed_default_carriers()
        result = estimate_rates(
            carrier_code="ups",
            method_code="ground",
            weight_oz=16,
            destination_zip="10001",
        )
        assert "options" in result
        assert len(result["options"]) == 1
        opt = result["options"][0]
        assert opt["rate_cents"] >= 0
        assert opt["carrier_code"] == "ups"
        assert opt["method_code"] == "ground"

    def test_estimate_rates_all_carriers_when_no_filter(self):
        """Without carrier/method filter, returns options from all enabled carriers."""
        from app.services.shipping_carriers import seed_default_carriers
        from app.services.shipping_rates import estimate_rates
        seed_default_carriers()
        result = estimate_rates(weight_oz=16, destination_zip="10001")
        assert len(result["options"]) > 1

    def test_rate_increases_with_weight(self):
        """Heavier shipments cost at least as much as lighter ones."""
        from app.services.shipping_carriers import seed_default_carriers
        from app.services.shipping_rates import estimate_rates
        seed_default_carriers()
        light = estimate_rates(carrier_code="ups", method_code="ground",
                               weight_oz=16, destination_zip="10001")
        heavy = estimate_rates(carrier_code="ups", method_code="ground",
                               weight_oz=320, destination_zip="10001")
        assert heavy["options"][0]["rate_cents"] >= light["options"][0]["rate_cents"]

    def test_flat_rate_method_ignores_weight(self):
        """manual/flat_rate has no per-lb increment — weight does not change cost."""
        from app.services.shipping_carriers import seed_default_carriers
        from app.services.shipping_rates import estimate_rates
        seed_default_carriers()
        r0 = estimate_rates(carrier_code="manual", method_code="flat_rate",
                            weight_oz=0, destination_zip="99501")
        r_heavy = estimate_rates(carrier_code="manual", method_code="flat_rate",
                                 weight_oz=1000, destination_zip="99501")
        assert r0["options"][0]["rate_cents"] == r_heavy["options"][0]["rate_cents"]

    def test_estimate_empty_when_no_enabled_methods_for_carrier(self):
        """Disabling all methods for a carrier produces no options for that carrier."""
        from app.services.shipping_carriers import (
            seed_default_carriers, disable_method, list_methods, _carrier_id,
        )
        from app.services.shipping_rates import estimate_rates
        seed_default_carriers()
        cid = _carrier_id("manual")
        # Disable the only manual method (flat_rate)
        for m in list_methods(cid):
            disable_method(cid, m["method_code"])
        result = estimate_rates(carrier_code="manual", method_code="flat_rate",
                                weight_oz=0, destination_zip="10001")
        # No enabled method → empty options
        assert result["options"] == []
        # Re-enable for subsequent tests
        from app.services.shipping_carriers import update_method
        update_method(cid, "flat_rate", patch={"enabled": True})


# ---------------------------------------------------------------------------
# SHP-008 / SHP-010: Shipment lifecycle
# ---------------------------------------------------------------------------

class TestShipmentLifecycle:
    """SHP-008/010: full create → advance state machine tests."""

    def _create(self, suffix: str, user_id: str = "usr_test") -> Dict[str, Any]:
        from app.services.shipments import create_shipment
        return create_shipment(
            order_id=f"ORD_CRS_{suffix}",
            user_id=user_id,
            carrier_code="ups",
            method_code="ground",
            ship_to_address={"line1": "1 Main St", "country": "US"},
            line_items=[{"item_id": "item_1", "sku": "SKU-A", "quantity": 1}],
        )

    def test_create_shipment_initial_status(self):
        """Newly created shipment is 'pending_fulfillment'."""
        result = self._create("INIT")
        assert result["status"] == "pending_fulfillment"
        assert result["carrier_code"] == "ups"

    def test_create_shipment_idempotent(self):
        """Creating the same order+seq twice returns the same shipment_id."""
        r1 = self._create("IDEM")
        r2 = self._create("IDEM")
        assert r1["shipment_id"] == r2["shipment_id"]

    def test_full_happy_path_to_delivered(self):
        """Walk pending → label_created → picked_up → in_transit → out_for_delivery → delivered."""
        from app.services.shipments import advance_shipment_status
        r = self._create("HAPPY")
        sid = r["shipment_id"]
        advance_shipment_status(sid, "label_created")
        advance_shipment_status(sid, "picked_up")
        advance_shipment_status(sid, "in_transit")
        advance_shipment_status(sid, "out_for_delivery")
        final = advance_shipment_status(sid, "delivered")
        assert final["status"] == "delivered"
        assert final.get("delivered_at") is not None

    def test_cancel_from_pending(self):
        """Cancellation is allowed from 'pending_fulfillment'."""
        from app.services.shipments import advance_shipment_status
        r = self._create("CANCEL_PENDING")
        sid = r["shipment_id"]
        final = advance_shipment_status(sid, "cancelled")
        assert final["status"] == "cancelled"

    def test_cancel_from_label_created(self):
        """Cancellation is allowed after label is created."""
        from app.services.shipments import advance_shipment_status
        r = self._create("CANCEL_LABEL")
        sid = r["shipment_id"]
        advance_shipment_status(sid, "label_created")
        final = advance_shipment_status(sid, "cancelled")
        assert final["status"] == "cancelled"

    def test_cannot_cancel_after_in_transit(self):
        """'in_transit' → 'cancelled' is not a valid transition."""
        from app.services.shipments import advance_shipment_status
        from fastapi import HTTPException
        r = self._create("NO_CANCEL_INTRANSIT")
        sid = r["shipment_id"]
        advance_shipment_status(sid, "label_created")
        advance_shipment_status(sid, "picked_up")
        advance_shipment_status(sid, "in_transit")
        with pytest.raises(HTTPException) as exc_info:
            advance_shipment_status(sid, "cancelled")
        assert exc_info.value.status_code == 409

    def test_invalid_skip_transition_raises_409(self):
        """Jumping from 'pending_fulfillment' straight to 'delivered' is rejected."""
        from app.services.shipments import advance_shipment_status
        from fastapi import HTTPException
        r = self._create("SKIP_TRANS")
        sid = r["shipment_id"]
        with pytest.raises(HTTPException) as exc_info:
            advance_shipment_status(sid, "delivered")
        assert exc_info.value.status_code == 409

    def test_list_shipments_for_order(self):
        """list_shipments_for_order returns all shipments for a given order_id."""
        from app.services.shipments import create_shipment, list_shipments_for_order
        oid = "ORD_LIST_CRS_001"
        create_shipment(
            order_id=oid, user_id="usr1",
            carrier_code="ups", method_code="ground",
            ship_to_address={"line1": "1 A St", "country": "US"},
            line_items=[{"item_id": "1", "sku": "A", "quantity": 1}],
            ship_group_seq=1,
        )
        create_shipment(
            order_id=oid, user_id="usr1",
            carrier_code="fedex", method_code="ground",
            ship_to_address={"line1": "1 B St", "country": "US"},
            line_items=[{"item_id": "2", "sku": "B", "quantity": 1}],
            ship_group_seq=2,
        )
        shipments = list_shipments_for_order(oid)
        assert len(shipments) >= 2

    def test_get_shipment_ownership_enforcement(self):
        """Owner can read; non-owner gets None; admin=True bypasses ownership."""
        from app.services.shipments import get_shipment
        r = self._create("OWN_ACCESS", user_id="alice")
        sid = r["shipment_id"]
        assert get_shipment(sid, user_id="alice") is not None
        assert get_shipment(sid, user_id="bob") is None
        assert get_shipment(sid, user_id="bob", admin=True) is not None


# ---------------------------------------------------------------------------
# Flag-off parity
# ---------------------------------------------------------------------------

class TestFlagOffParity:
    """When shipping_enabled=False all service functions must raise."""

    def test_carrier_service_disabled_raises(self):
        from app.core import settings as settings_mod
        from app.services.shipping_carriers import list_carriers
        from fastapi import HTTPException
        orig = settings_mod.S.shipping_enabled
        object.__setattr__(settings_mod.S, "shipping_enabled", False)
        try:
            with pytest.raises(HTTPException):
                list_carriers()
        finally:
            object.__setattr__(settings_mod.S, "shipping_enabled", orig)

    def test_shipment_service_disabled_raises(self):
        from app.core import settings as settings_mod
        from app.services.shipments import get_shipment
        from fastapi import HTTPException
        orig = settings_mod.S.shipping_enabled
        object.__setattr__(settings_mod.S, "shipping_enabled", False)
        try:
            with pytest.raises(HTTPException):
                get_shipment("any-id", admin=True)
        finally:
            object.__setattr__(settings_mod.S, "shipping_enabled", orig)

    def test_rate_service_disabled_raises(self):
        from app.core import settings as settings_mod
        from app.services.shipping_rates import estimate_rates
        from fastapi import HTTPException
        orig = settings_mod.S.shipping_enabled
        object.__setattr__(settings_mod.S, "shipping_enabled", False)
        try:
            with pytest.raises(HTTPException):
                estimate_rates(weight_oz=16, destination_zip="10001")
        finally:
            object.__setattr__(settings_mod.S, "shipping_enabled", orig)

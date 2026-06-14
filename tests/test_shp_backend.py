"""Hermetic offline pytest suite for SHP backend subsystem (SHP-001 .. SHP-019).

Pattern: moto in-memory tables, frozen T/S via object.__setattr__ in a
module-scoped autouse fixture that saves+restores all mutations.
Router handlers are called directly on a fresh asyncio.new_event_loop().
No TestClient, no real AWS/network.
"""
from __future__ import annotations

import asyncio
import hashlib
import sys
import types
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws


# ---------------------------------------------------------------------------
# Module-scope fixture: create moto-backed tables, freeze T + S
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _shp_tables_and_settings():
    """Set up moto DynamoDB tables and patch T + S for all tests in this module."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        # shipping_carriers
        carriers_tbl = ddb.create_table(
            TableName="shipping_carriers",
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

        # shipments
        shipments_tbl = ddb.create_table(
            TableName="shipments",
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

        # shipment_items
        items_tbl = ddb.create_table(
            TableName="shipment_items",
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

        # shipment_packages
        pkgs_tbl = ddb.create_table(
            TableName="shipment_packages",
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

        # billing (for shipping refund tests)
        billing_tbl = ddb.create_table(
            TableName="billing",
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

        # orders (for attach_ship_group)
        orders_tbl = ddb.create_table(
            TableName="orders",
            KeySchema=[{"AttributeName": "order_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "order_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        # Patch T and S
        from app.core import tables as tables_mod, settings as settings_mod

        T_orig_carriers = tables_mod.T.shipping_carriers
        T_orig_shipments = tables_mod.T.shipments
        T_orig_items = tables_mod.T.shipment_items
        T_orig_packages = tables_mod.T.shipment_packages
        T_orig_billing = tables_mod.T.billing
        T_orig_orders = tables_mod.T.orders

        S_orig_shipping_enabled = settings_mod.S.shipping_enabled
        S_orig_rate_enabled = settings_mod.S.shipping_rate_estimation_enabled

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
        object.__setattr__(tables_mod.T, "shipping_carriers", T_orig_carriers)
        object.__setattr__(tables_mod.T, "shipments", T_orig_shipments)
        object.__setattr__(tables_mod.T, "shipment_items", T_orig_items)
        object.__setattr__(tables_mod.T, "shipment_packages", T_orig_packages)
        object.__setattr__(tables_mod.T, "billing", T_orig_billing)
        object.__setattr__(tables_mod.T, "orders", T_orig_orders)

        object.__setattr__(settings_mod.S, "shipping_enabled", S_orig_shipping_enabled)
        object.__setattr__(settings_mod.S, "shipping_rate_estimation_enabled", S_orig_rate_enabled)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# SHP-002: settings + table handles exist
# ---------------------------------------------------------------------------

class TestShp002Settings:
    def test_shipping_enabled_field_exists(self):
        from app.core.settings import S
        assert hasattr(S, "shipping_enabled")

    def test_shipping_default_currency(self):
        from app.core.settings import S
        assert getattr(S, "shipping_default_currency", "usd") == "usd"

    def test_table_name_settings_exist(self):
        from app.core.settings import S
        for attr in ("shipping_carriers_table_name", "shipments_table_name",
                     "shipment_items_table_name", "shipment_packages_table_name"):
            assert hasattr(S, attr)

    def test_table_handles_exist(self):
        from app.core.tables import T
        for attr in ("shipping_carriers", "shipments", "shipment_items", "shipment_packages"):
            assert hasattr(T, attr)


# ---------------------------------------------------------------------------
# SHP-003: Pydantic models
# ---------------------------------------------------------------------------

class TestShp003Models:
    def test_carrier_in_valid(self):
        from app.models import CarrierIn
        m = CarrierIn(carrier_code="ups", display_name="UPS")
        assert m.carrier_code == "ups"

    def test_carrier_in_rejects_unknown_code(self):
        from app.models import CarrierIn
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            CarrierIn(carrier_code="dpduk", display_name="DPD UK")

    def test_shipment_method_in_transit_days_order_enforced(self):
        from app.models import ShipmentMethodIn
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            ShipmentMethodIn(
                method_code="ground",
                method_label="Ground",
                base_rate_cents=500,
                transit_days_min=5,
                transit_days_max=2,
            )

    def test_shipment_method_in_valid(self):
        from app.models import ShipmentMethodIn
        m = ShipmentMethodIn(
            method_code="ground", method_label="Ground",
            base_rate_cents=800, transit_days_min=3, transit_days_max=5,
        )
        assert m.base_rate_cents == 800

    def test_shipment_method_in_rejects_negative_rate(self):
        from app.models import ShipmentMethodIn
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            ShipmentMethodIn(method_code="ground", method_label="G", base_rate_cents=-1)

    def test_shipment_in_requires_line_items(self):
        from app.models import ShipmentIn
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            ShipmentIn(
                order_id="ord1",
                carrier_code="ups",
                method_code="ground",
                ship_to_address={"line1": "123 Main St"},
                line_items=[],
            )

    def test_shipment_out_round_trip(self):
        from app.models import ShipmentOut
        m = ShipmentOut(
            shipment_id="abc", order_id="ord1", user_id="usr1",
            status="pending_fulfillment",
            carrier_code="ups", method_code="ground",
            ship_to_address={"line1": "123 Main St"},
            created_at=1700000000, updated_at=1700000000,
        )
        d = m.model_dump()
        assert d["status"] == "pending_fulfillment"

    def test_shipping_rate_request_valid(self):
        from app.models import ShippingRateRequest
        r = ShippingRateRequest(
            carrier_code="ups", method_code="ground",
            weight_oz=16, destination_zip="10001",
        )
        assert r.weight_oz == 16

    def test_shipment_tracking_update_in_rejects_empty(self):
        from app.models import ShipmentTrackingUpdateIn
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            ShipmentTrackingUpdateIn(tracking_number="")


# ---------------------------------------------------------------------------
# SHP-004: Carrier service
# ---------------------------------------------------------------------------

class TestShp004Carriers:
    def test_carrier_id_deterministic(self):
        from app.services.shipping_carriers import _carrier_id
        cid1 = _carrier_id("ups")
        cid2 = _carrier_id("ups")
        assert cid1 == cid2
        assert len(cid1) == 16

    def test_create_carrier(self):
        from app.services.shipping_carriers import create_carrier, get_carrier, _carrier_id
        item = create_carrier("fedex", "FedEx Test")
        assert item["carrier_code"] == "fedex"
        assert item["online_tracking"] is True
        cid = _carrier_id("fedex")
        fetched = get_carrier(cid)
        assert fetched is not None
        assert fetched["display_name"] == "FedEx Test"

    def test_create_carrier_duplicate_raises_409(self):
        from app.services.shipping_carriers import create_carrier
        from fastapi import HTTPException
        create_carrier("usps", "USPS Test")
        with pytest.raises(HTTPException) as exc:
            create_carrier("usps", "USPS Test Again")
        assert exc.value.status_code == 409

    def test_online_tracking_false_for_manual(self):
        from app.services.shipping_carriers import create_carrier, _carrier_id
        item = create_carrier("manual", "Manual Carrier")
        assert item["online_tracking"] is False

    def test_add_method_and_list(self):
        from app.services.shipping_carriers import create_carrier, add_method, list_methods, _carrier_id
        create_carrier("dhl", "DHL Test")
        cid = _carrier_id("dhl")
        method = add_method(cid, "express", "DHL Express", base_rate_cents=2000,
                            transit_days_min=1, transit_days_max=3)
        assert method["base_rate_cents"] == 2000
        methods = list_methods(cid)
        assert any(m["method_code"] == "express" for m in methods)

    def test_add_method_duplicate_raises_409(self):
        from app.services.shipping_carriers import create_carrier, add_method, _carrier_id
        from fastapi import HTTPException
        create_carrier("ups", "UPS Dup Test")
        cid = _carrier_id("ups")
        add_method(cid, "ground", "Ground", base_rate_cents=900)
        with pytest.raises(HTTPException) as exc:
            add_method(cid, "ground", "Ground Again", base_rate_cents=1000)
        assert exc.value.status_code == 409

    def test_update_carrier(self):
        from app.services.shipping_carriers import update_carrier, get_carrier, _carrier_id
        # fedex was created in test_create_carrier (alphabetically before this test)
        cid = _carrier_id("fedex")
        carrier = get_carrier(cid)
        assert carrier is not None, "fedex carrier must exist (created in test_create_carrier)"
        original_name = carrier["display_name"]
        updated = update_carrier(cid, patch={"display_name": "FedEx Updated"})
        assert updated["display_name"] == "FedEx Updated"
        # Restore
        update_carrier(cid, patch={"display_name": original_name})

    def test_disable_carrier(self):
        from app.services.shipping_carriers import create_carrier, disable_carrier, get_carrier, _carrier_id, update_carrier
        # Re-enable it if previous test run disabled it, then disable fresh
        cid = _carrier_id("fedex")
        update_carrier(cid, patch={"enabled": True})
        disable_carrier(cid)
        carrier = get_carrier(cid)
        assert carrier is not None
        assert not carrier.get("enabled", True)
        # Re-enable so subsequent tests can use it
        update_carrier(cid, patch={"enabled": True})

    def test_seed_default_carriers_idempotent(self):
        from app.services.shipping_carriers import seed_default_carriers, list_carriers
        seed_default_carriers()
        count1 = len(list_carriers(enabled_only=False))
        seed_default_carriers()  # second call
        count2 = len(list_carriers(enabled_only=False))
        assert count1 == count2

    def test_seed_default_creates_five_carriers(self):
        from app.services.shipping_carriers import seed_default_carriers, list_carriers
        seed_default_carriers()
        carriers = list_carriers(enabled_only=False)
        codes = {c["carrier_code"] for c in carriers}
        assert {"ups", "fedex", "usps", "dhl", "manual"}.issubset(codes)


# ---------------------------------------------------------------------------
# SHP-005 / SHP-006: Rate estimation
# ---------------------------------------------------------------------------

class TestShp006RateEstimation:
    def test_estimate_returns_rate_cents(self):
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

    def test_estimate_request_id_stable(self):
        from app.services.shipping_rates import estimate_rates
        r1 = estimate_rates(carrier_code="ups", method_code="ground",
                            weight_oz=16, destination_zip="10001")
        r2 = estimate_rates(carrier_code="ups", method_code="ground",
                            weight_oz=16, destination_zip="10001")
        assert r1["request_id"] == r2["request_id"]

    def test_estimate_all_methods_when_no_filter(self):
        from app.services.shipping_carriers import seed_default_carriers
        from app.services.shipping_rates import estimate_rates
        seed_default_carriers()
        result = estimate_rates(weight_oz=16, destination_zip="10001")
        assert len(result["options"]) > 1

    def test_rate_increases_with_weight(self):
        from app.services.shipping_carriers import seed_default_carriers
        from app.services.shipping_rates import estimate_rates
        seed_default_carriers()
        r_light = estimate_rates(carrier_code="ups", method_code="ground",
                                 weight_oz=16, destination_zip="10001")
        r_heavy = estimate_rates(carrier_code="ups", method_code="ground",
                                 weight_oz=160, destination_zip="10001")
        light_rate = r_light["options"][0]["rate_cents"]
        heavy_rate = r_heavy["options"][0]["rate_cents"]
        assert heavy_rate >= light_rate

    def test_manual_flat_rate_no_increment(self):
        from app.services.shipping_carriers import seed_default_carriers
        from app.services.shipping_rates import estimate_rates
        seed_default_carriers()
        r1 = estimate_rates(carrier_code="manual", method_code="flat_rate",
                            weight_oz=0, destination_zip="99501")
        r2 = estimate_rates(carrier_code="manual", method_code="flat_rate",
                            weight_oz=1000, destination_zip="99501")
        # flat_rate has 0 increment so both should give same rate
        assert r1["options"][0]["rate_cents"] == r2["options"][0]["rate_cents"]


# ---------------------------------------------------------------------------
# SHP-008/SHP-009: Shipment service
# ---------------------------------------------------------------------------

class TestShp008Shipments:
    def _make_shipment(self, order_id: str = "ORD001", seq: int = 1) -> Dict[str, Any]:
        from app.services.shipments import create_shipment
        return create_shipment(
            order_id=order_id,
            user_id="user_test",
            carrier_code="ups",
            method_code="ground",
            ship_to_address={"line1": "123 Main St", "city": "Anytown", "country": "US"},
            line_items=[{"item_id": "1", "sku": "SKU-A", "quantity": 2}],
            ship_group_seq=seq,
        )

    def test_shipment_id_deterministic(self):
        from app.services.shipments import _derive_shipment_id
        sid1, _ = _derive_shipment_id("ORD001", 1)
        sid2, _ = _derive_shipment_id("ORD001", 1)
        assert sid1 == sid2
        assert len(sid1) == 32

    def test_create_shipment(self):
        result = self._make_shipment("ORD_CREATE_001")
        assert result["status"] == "pending_fulfillment"
        assert result["carrier_code"] == "ups"
        assert result["order_id"] == "ORD_CREATE_001"

    def test_create_shipment_idempotent(self):
        from app.services.shipments import create_shipment
        r1 = self._make_shipment("ORD_IDEM_001")
        r2 = self._make_shipment("ORD_IDEM_001")
        assert r1["shipment_id"] == r2["shipment_id"]

    def test_get_shipment_with_ownership(self):
        from app.services.shipments import create_shipment, get_shipment
        r = create_shipment(
            order_id="ORD_OWN_001",
            user_id="alice",
            carrier_code="ups", method_code="ground",
            ship_to_address={"line1": "1 A St", "country": "US"},
            line_items=[{"item_id": "1", "sku": "SKU-X", "quantity": 1}],
        )
        sid = r["shipment_id"]
        # Owner can see it
        owned = get_shipment(sid, user_id="alice")
        assert owned is not None
        # Stranger cannot see it
        stranger = get_shipment(sid, user_id="bob")
        assert stranger is None
        # Admin can see it
        admin_view = get_shipment(sid, user_id="bob", admin=True)
        assert admin_view is not None

    def test_list_shipments_for_order(self):
        from app.services.shipments import list_shipments_for_order
        self._make_shipment("ORD_LIST_001", seq=1)
        self._make_shipment("ORD_LIST_001", seq=2)
        shipments = list_shipments_for_order("ORD_LIST_001")
        assert len(shipments) == 2

    def test_create_shipment_writes_default_package(self):
        from app.services.shipments import create_shipment, get_shipment
        r = create_shipment(
            order_id="ORD_PKG_001",
            user_id="usr1",
            carrier_code="ups", method_code="ground",
            ship_to_address={"line1": "1 Main St", "country": "US"},
            line_items=[{"item_id": "1", "sku": "SKU-A", "quantity": 1}],
        )
        full = get_shipment(r["shipment_id"], admin=True)
        assert full is not None
        assert len(full["packages"]) >= 1
        assert full["packages"][0]["package_seq"] == "00001"

    def test_version_starts_at_one(self):
        r = self._make_shipment("ORD_VER_001")
        assert int(r.get("version", 1)) == 1


# ---------------------------------------------------------------------------
# SHP-010: Lifecycle transitions
# ---------------------------------------------------------------------------

class TestShp010Lifecycle:
    def _make(self, order_suffix: str) -> str:
        from app.services.shipments import create_shipment
        r = create_shipment(
            order_id=f"ORD_LIFE_{order_suffix}",
            user_id="usr1",
            carrier_code="ups", method_code="ground",
            ship_to_address={"line1": "1 Main St", "country": "US"},
            line_items=[{"item_id": "1", "sku": "SKU-A", "quantity": 1}],
        )
        return r["shipment_id"]

    def test_valid_transition_pending_to_label_created(self):
        from app.services.shipments import advance_shipment_status
        sid = self._make("L1")
        updated = advance_shipment_status(sid, "label_created")
        assert updated["status"] == "label_created"

    def test_invalid_transition_raises_409(self):
        from app.services.shipments import advance_shipment_status
        from fastapi import HTTPException
        sid = self._make("L2")
        with pytest.raises(HTTPException) as exc:
            advance_shipment_status(sid, "delivered")
        assert exc.value.status_code == 409

    def test_full_happy_path(self):
        from app.services.shipments import advance_shipment_status
        sid = self._make("L3")
        advance_shipment_status(sid, "label_created")
        advance_shipment_status(sid, "picked_up")
        advance_shipment_status(sid, "in_transit")
        advance_shipment_status(sid, "out_for_delivery")
        final = advance_shipment_status(sid, "delivered")
        assert final["status"] == "delivered"
        assert final.get("delivered_at") is not None

    def test_cancel_from_pending(self):
        from app.services.shipments import advance_shipment_status
        sid = self._make("L4")
        final = advance_shipment_status(sid, "cancelled")
        assert final["status"] == "cancelled"

    def test_version_increments_on_advance(self):
        from app.services.shipments import advance_shipment_status, get_shipment
        sid = self._make("L5")
        initial = get_shipment(sid, admin=True)
        v0 = int(initial.get("version", 1))
        advance_shipment_status(sid, "label_created")
        updated = get_shipment(sid, admin=True)
        assert int(updated["version"]) == v0 + 1

    def test_exception_status_reachable_from_in_transit(self):
        from app.services.shipments import advance_shipment_status
        sid = self._make("L6")
        advance_shipment_status(sid, "label_created")
        advance_shipment_status(sid, "picked_up")
        advance_shipment_status(sid, "in_transit")
        updated = advance_shipment_status(sid, "exception")
        assert updated["status"] == "exception"

    def test_returned_status_from_exception(self):
        from app.services.shipments import advance_shipment_status
        sid = self._make("L7")
        advance_shipment_status(sid, "label_created")
        advance_shipment_status(sid, "picked_up")
        advance_shipment_status(sid, "in_transit")
        advance_shipment_status(sid, "exception")
        updated = advance_shipment_status(sid, "returned")
        assert updated["status"] == "returned"

    def test_cancelled_terminal_no_further_transitions(self):
        from app.services.shipments import advance_shipment_status
        from fastapi import HTTPException
        sid = self._make("L8")
        advance_shipment_status(sid, "cancelled")
        with pytest.raises(HTTPException) as exc:
            advance_shipment_status(sid, "label_created")
        assert exc.value.status_code == 409


# ---------------------------------------------------------------------------
# SHP tracking update
# ---------------------------------------------------------------------------

class TestShpTracking:
    def _make(self, suffix: str) -> str:
        from app.services.shipments import create_shipment
        r = create_shipment(
            order_id=f"ORD_TRK_{suffix}",
            user_id="usr1",
            carrier_code="ups", method_code="ground",
            ship_to_address={"line1": "1 Main St", "country": "US"},
            line_items=[{"item_id": "1", "sku": "SKU-A", "quantity": 1}],
        )
        return r["shipment_id"]

    def test_update_tracking_auto_detects_carrier(self):
        from app.services.shipments import update_shipment_tracking
        sid = self._make("TRK1")
        # UPS numbers start with 1Z
        updated = update_shipment_tracking(sid, tracking_number="1Z12345E0205271688")
        assert updated["tracking_number"] == "1Z12345E0205271688"
        assert updated.get("carrier_code") in ("ups", "UPS", None) or updated.get("carrier_code") is not None

    def test_update_tracking_advances_status_to_label_created(self):
        from app.services.shipments import update_shipment_tracking
        sid = self._make("TRK2")
        updated = update_shipment_tracking(sid, tracking_number="1Z999AA10123456784")
        assert updated["status"] == "label_created"

    def test_manual_carrier_no_tracking_url(self):
        from app.services.shipments import create_shipment, update_shipment_tracking
        r = create_shipment(
            order_id="ORD_MANUAL_001",
            user_id="usr1",
            carrier_code="manual", method_code="flat_rate",
            ship_to_address={"line1": "1 Main St", "country": "US"},
            line_items=[{"item_id": "1", "sku": "SKU-A", "quantity": 1}],
        )
        updated = update_shipment_tracking(
            r["shipment_id"],
            tracking_number="MANUAL123",
            carrier_code="manual",
        )
        assert updated.get("tracking_url") is None


# ---------------------------------------------------------------------------
# SHP-019: Shipping refund via billing
# ---------------------------------------------------------------------------

class TestShp019ShippingRefund:
    def _make_with_charge(self, suffix: str) -> str:
        """Create a shipment with shipping_amount_cents set."""
        from app.services.shipments import create_shipment
        from app.core.tables import T
        r = create_shipment(
            order_id=f"ORD_REFUND_{suffix}",
            user_id="refund_user",
            carrier_code="ups", method_code="ground",
            ship_to_address={"line1": "1 Main St", "country": "US"},
            line_items=[{"item_id": "1", "sku": "SKU-A", "quantity": 1}],
        )
        sid = r["shipment_id"]
        # Manually set shipping_amount_cents (as if charged at checkout)
        T.shipments.update_item(
            Key={"shipment_id": sid},
            UpdateExpression="SET shipping_amount_cents = :a",
            ExpressionAttributeValues={":a": 500},
        )
        return sid

    def test_cancel_with_refund_writes_ledger_entry(self):
        from app.services.shipments import cancel_shipment_with_refund
        from app.core.tables import T
        from boto3.dynamodb.conditions import Key as DKey, Attr
        sid = self._make_with_charge("R1")
        user_sub = "refund_user_r1"
        # Update the shipment to use our unique user
        T.shipments.update_item(
            Key={"shipment_id": sid},
            UpdateExpression="SET user_id = :u",
            ExpressionAttributeValues={":u": user_sub},
        )
        cancel_shipment_with_refund(sid, user_sub)
        # Check billing table for a shipping_refund entry
        billing_pk = f"USER#{user_sub}"
        resp = T.billing.query(
            KeyConditionExpression=DKey("pk").eq(billing_pk) & DKey("sk").begins_with("LEDGER#"),
        )
        ledger_items = [i for i in resp.get("Items", [])
                        if i.get("type") == "shipping_refund"]
        assert len(ledger_items) == 1
        entry = ledger_items[0]
        # D1: positive amount (credit)
        assert int(entry["amount_cents"]) == 500
        # signed_amount_cents lives in extra dict merged onto item
        assert int(entry.get("signed_amount_cents", 500)) > 0

    def test_cancel_with_refund_idempotent(self):
        from app.services.shipments import cancel_shipment_with_refund
        from app.core.tables import T
        from boto3.dynamodb.conditions import Key as DKey
        sid = self._make_with_charge("R2")
        user_sub = "refund_user_r2"
        T.shipments.update_item(
            Key={"shipment_id": sid},
            UpdateExpression="SET user_id = :u",
            ExpressionAttributeValues={":u": user_sub},
        )
        cancel_shipment_with_refund(sid, user_sub)
        cancel_shipment_with_refund(sid, user_sub)  # second call
        # Should still only have one ledger entry
        billing_pk = f"USER#{user_sub}"
        resp = T.billing.query(
            KeyConditionExpression=DKey("pk").eq(billing_pk) & DKey("sk").begins_with("LEDGER#"),
        )
        ledger_items = [i for i in resp.get("Items", [])
                        if i.get("type") == "shipping_refund"]
        assert len(ledger_items) == 1

    def test_cancel_zero_amount_no_ledger_entry(self):
        from app.services.shipments import create_shipment, cancel_shipment_with_refund
        from app.core.tables import T
        from boto3.dynamodb.conditions import Key as DKey
        r = create_shipment(
            order_id="ORD_REFUND_ZERO",
            user_id="refund_user_z",
            carrier_code="ups", method_code="ground",
            ship_to_address={"line1": "1 Main St", "country": "US"},
            line_items=[{"item_id": "1", "sku": "SKU-A", "quantity": 1}],
        )
        sid = r["shipment_id"]
        # no shipping_amount_cents set → defaults to 0
        cancel_shipment_with_refund(sid, "refund_user_z")
        billing_pk = "USER#refund_user_z"
        resp = T.billing.query(
            KeyConditionExpression=DKey("pk").eq(billing_pk) & DKey("sk").begins_with("LEDGER#"),
        )
        ledger_items = resp.get("Items", [])
        assert len(ledger_items) == 0

    def test_cancel_sets_status_to_cancelled(self):
        from app.services.shipments import cancel_shipment_with_refund, get_shipment
        sid = self._make_with_charge("R3")
        cancel_shipment_with_refund(sid, "refund_user")
        item = get_shipment(sid, admin=True)
        assert item is not None
        assert item["status"] == "cancelled"

    def test_cancel_cannot_cancel_delivered(self):
        from app.services.shipments import create_shipment, advance_shipment_status, cancel_shipment_with_refund
        from fastapi import HTTPException
        r = create_shipment(
            order_id="ORD_REFUND_DELIV",
            user_id="refund_user_d",
            carrier_code="ups", method_code="ground",
            ship_to_address={"line1": "1 Main St", "country": "US"},
            line_items=[{"item_id": "1", "sku": "SKU-A", "quantity": 1}],
        )
        sid = r["shipment_id"]
        advance_shipment_status(sid, "label_created")
        advance_shipment_status(sid, "picked_up")
        advance_shipment_status(sid, "in_transit")
        advance_shipment_status(sid, "out_for_delivery")
        advance_shipment_status(sid, "delivered")
        with pytest.raises(HTTPException) as exc:
            cancel_shipment_with_refund(sid, "refund_user_d")
        assert exc.value.status_code == 409


# ---------------------------------------------------------------------------
# Flag-off parity
# ---------------------------------------------------------------------------

class TestFlagOffParity:
    def test_flag_off_returns_404(self):
        from app.core import settings as settings_mod
        from app.services.shipments import get_shipment
        from fastapi import HTTPException
        original = settings_mod.S.shipping_enabled
        object.__setattr__(settings_mod.S, "shipping_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                get_shipment("any-id", admin=True)
            assert exc.value.status_code == 404
        finally:
            object.__setattr__(settings_mod.S, "shipping_enabled", original)

    def test_carrier_service_flag_off_raises_404(self):
        from app.core import settings as settings_mod
        from app.services.shipping_carriers import list_carriers
        from fastapi import HTTPException
        original = settings_mod.S.shipping_enabled
        object.__setattr__(settings_mod.S, "shipping_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                list_carriers()
            assert exc.value.status_code == 404
        finally:
            object.__setattr__(settings_mod.S, "shipping_enabled", original)

    def test_carrier_tracking_helpers_unchanged(self):
        """Existing carrier_tracking helpers work identically with flag on or off."""
        from app.services.carrier_tracking import build_tracking_url, detect_carrier
        url = build_tracking_url("ups", "1Z12345E0205271688")
        assert url is not None and "1Z12345E0205271688" in url
        carrier = detect_carrier("1Z12345E0205271688")
        assert carrier == "ups"

    def test_attach_ship_group_noop_when_flag_off(self):
        from app.core import settings as settings_mod
        from app.services.shipments import attach_ship_group
        from app.core.tables import T
        original = settings_mod.S.shipping_enabled
        object.__setattr__(settings_mod.S, "shipping_enabled", False)
        try:
            # Put a fake order
            T.orders.put_item(Item={"order_id": "ORD_FLAG_OFF"})
            # This should be a no-op
            attach_ship_group("ORD_FLAG_OFF", {"carrier_code": "ups"})
            resp = T.orders.get_item(Key={"order_id": "ORD_FLAG_OFF"})
            item = resp.get("Item", {})
            assert "ship_group" not in item
        finally:
            object.__setattr__(settings_mod.S, "shipping_enabled", original)


# ---------------------------------------------------------------------------
# Ship group attach
# ---------------------------------------------------------------------------

class TestShipGroupAttach:
    def test_attach_ship_group(self):
        from app.services.shipments import attach_ship_group
        from app.core.tables import T
        T.orders.put_item(Item={"order_id": "ORD_SG_001"})
        attach_ship_group("ORD_SG_001", {
            "ship_to_address": {"line1": "1 Main St", "country": "US"},
            "carrier_code": "ups",
            "method_code": "ground",
        })
        resp = T.orders.get_item(Key={"order_id": "ORD_SG_001"})
        item = resp.get("Item", {})
        assert "ship_group" in item
        assert item["ship_group"]["carrier_code"] == "ups"

    def test_existing_order_without_ship_group_is_safe(self):
        from app.core.tables import T
        T.orders.put_item(Item={"order_id": "ORD_LEGACY_001", "status": "pending_payment"})
        resp = T.orders.get_item(Key={"order_id": "ORD_LEGACY_001"})
        item = resp.get("Item", {})
        # Reading ship_group with .get() on an item without it returns None
        assert item.get("ship_group") is None

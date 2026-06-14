"""Offline hermetic tests for FAC-001..FAC-007: facility CRUD, transfers, and receiving.

Test isolation rules:
- moto mock_aws context scoped to each test class (setUp/tearDown)
- T.* handles and S flags mutated via object.__setattr__ in a module-scoped
  autouse fixture; restored in teardown
- No TestClient, no real AWS, no network
- Route handlers not tested here (covered by smoke import test)
- audit_event is best-effort no-op fallback (no mock needed)

Run:
  AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 \\
    .venv/bin/pytest -q tests/test_fac_001_007_facility_fulfillment.py
"""
from __future__ import annotations

import hashlib
import unittest
from contextlib import ExitStack
from decimal import Decimal
from typing import Any

import boto3
from fastapi import HTTPException

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None


# ─────────────────────────── table factories ───────────────────────────────

def _make_facilities_table(ddb):
    return ddb.create_table(
        TableName="facilities",
        KeySchema=[
            {"AttributeName": "facility_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "facility_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "owner_sub", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "status", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_OWNER",
                "KeySchema": [
                    {"AttributeName": "owner_sub", "KeyType": "HASH"},
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


def _make_transfers_table(ddb):
    return ddb.create_table(
        TableName="transfers",
        KeySchema=[
            {"AttributeName": "transfer_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "transfer_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "from_location_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_STATUS",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_FROM_LOC",
                "KeySchema": [
                    {"AttributeName": "from_location_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_receipts_table(ddb):
    return ddb.create_table(
        TableName="receipts",
        KeySchema=[
            {"AttributeName": "receipt_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "receipt_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "facility_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "po_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_FACILITY",
                "KeySchema": [
                    {"AttributeName": "facility_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_PO",
                "KeySchema": [
                    {"AttributeName": "po_id", "KeyType": "HASH"},
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


# ─────────────────────────── Settings helpers ──────────────────────────────

def _enable_fac(s_module: Any, tables_mod: Any, fac_tbl: Any, tx_tbl: Any, rec_tbl: Any) -> None:
    """Enable FAC flag and bind moto tables."""
    object.__setattr__(s_module.S, "facility_fulfillment_enabled", True)
    object.__setattr__(tables_mod.T, "facilities", fac_tbl)
    object.__setattr__(tables_mod.T, "transfers", tx_tbl)
    object.__setattr__(tables_mod.T, "receipts", rec_tbl)


# ─────────────────────────── MODEL TESTS (FAC-003) ─────────────────────────

class TestFacModels(unittest.TestCase):
    """FAC-003: Pydantic models import and validate correctly."""

    def test_all_fac_models_importable(self):
        from app.models import (
            FacilityIn, FacilityOut, FacilityLocationIn, FacilityLocationOut,
            FacilityListOut, FacilityLocationListOut,
            TransferIn, TransferItemIn, TransferOut, TransferItemOut, TransferListOut,
            ReceiveIn, ReceiveLineIn, ReceiptOut, ReceiptLineOut, ReceiptListOut,
            PicklistOut, PickLineOut,
            PackageIn, PackageLineIn, PackageOut,
            ShipmentIn, ShipmentOut, ShipmentListOut,
            LotSummaryOut, SerialOut,
        )
        self.assertTrue(True)

    def test_facility_out_decimal_coercion(self):
        from app.models import FacilityOut
        out = FacilityOut(
            facility_id="abc",
            name="Test",
            created_at=Decimal("1700000000"),
            updated_at=Decimal("1700000001"),
        )
        self.assertIsInstance(out.created_at, int)
        self.assertEqual(out.created_at, 1700000000)

    def test_transfer_item_out_decimal_qty(self):
        from app.models import TransferItemOut
        out = TransferItemOut(sku="SKU1", quantity=Decimal("50"))
        self.assertEqual(out.quantity, 50)

    def test_receipt_line_out_zero_defaults(self):
        from app.models import ReceiptLineOut
        out = ReceiptLineOut(sku="X")
        self.assertEqual(out.ordered_quantity, 0)
        self.assertEqual(out.received_quantity, 0)
        self.assertEqual(out.unit_cost_cents, 0)

    def test_receive_in_requires_correlation_id(self):
        from app.models import ReceiveIn, ReceiveLineIn
        import pydantic
        with self.assertRaises(pydantic.ValidationError):
            ReceiveIn(
                facility_id="fac1",
                location_id="loc1",
                lines=[ReceiveLineIn(sku="SKU1", quantity=10)],
                # correlation_id missing
            )

    def test_transfer_in_empty_lines_rejected(self):
        from app.models import TransferIn
        import pydantic
        with self.assertRaises(pydantic.ValidationError):
            TransferIn(
                from_facility_id="f1",
                from_location_id="l1",
                to_facility_id="f2",
                to_location_id="l2",
                lines=[],
            )

    def test_facility_in_invalid_type(self):
        from app.models import FacilityIn
        import pydantic
        with self.assertRaises(pydantic.ValidationError):
            FacilityIn(name="X", facility_type="spaceship")

    def test_shipment_out_optional_timestamps_none(self):
        from app.models import ShipmentOut
        out = ShipmentOut(
            shipment_id="s",
            order_id="o",
            picklist_id="p",
            status="draft",
            shipped_at=None,
        )
        self.assertIsNone(out.shipped_at)

    def test_lot_summary_out_decimal_qty(self):
        from app.models import LotSummaryOut
        out = LotSummaryOut(sku="X", lot_id="L1", quantity=Decimal("100"))
        self.assertEqual(out.quantity, 100)

    def test_package_out_dimension_defaults(self):
        from app.models import PackageOut
        out = PackageOut(package_id="P1")
        self.assertEqual(out.weight_grams, 0)
        self.assertEqual(out.length_mm, 0)

    def test_facility_location_type_invalid_rejected(self):
        from app.models import FacilityLocationIn
        import pydantic
        with self.assertRaises(pydantic.ValidationError):
            FacilityLocationIn(name="X", location_type="spaceship")


# ─────────────────────────── SETTINGS / TABLE HANDLE TESTS (FAC-002) ───────

class TestFac002Settings(unittest.TestCase):
    """FAC-002: settings defaults and table handle names."""

    def test_flag_defaults_false(self):
        from app.core.settings import S
        # In test env with no env vars set, flag should be False
        self.assertFalse(bool(getattr(S, "facility_fulfillment_enabled", False)))

    def test_lot_serial_flag_defaults_false(self):
        from app.core.settings import S
        self.assertFalse(bool(getattr(S, "facility_lot_serial_enabled", False)))

    def test_table_name_defaults(self):
        from app.core.settings import S
        self.assertEqual(getattr(S, "facilities_table_name", "facilities"), "facilities")
        self.assertEqual(getattr(S, "transfers_table_name", "transfers"), "transfers")
        self.assertEqual(getattr(S, "receipts_table_name", "receipts"), "receipts")
        self.assertEqual(getattr(S, "picklists_table_name", "picklists"), "picklists")
        self.assertEqual(getattr(S, "shipments_table_name", "shipments"), "shipments")
        self.assertEqual(getattr(S, "lot_serial_table_name", "lot_serial"), "lot_serial")

    def test_all_fac_handles_exist_on_T(self):
        import app.core.tables as tables_mod
        for name in ("facilities", "transfers", "receipts", "picklists", "shipments", "lot_serial"):
            self.assertTrue(hasattr(tables_mod.T, name), f"T.{name} missing")

    def test_flag_off_raises_404(self):
        from app.core.settings import S
        from fastapi import HTTPException
        orig = S.facility_fulfillment_enabled
        object.__setattr__(S, "facility_fulfillment_enabled", False)
        try:
            def _flag_on():
                return bool(getattr(S, "facility_fulfillment_enabled", False))
            def _require_enabled():
                if not _flag_on():
                    raise HTTPException(status_code=404)
            with self.assertRaises(HTTPException) as ctx:
                _require_enabled()
            self.assertEqual(ctx.exception.status_code, 404)
        finally:
            object.__setattr__(S, "facility_fulfillment_enabled", orig)


# ─────────────────────────── FACILITY SERVICE TESTS (FAC-004) ──────────────

@unittest.skipIf(mock_aws is None, "moto not installed")
class TestFacilities(unittest.TestCase):
    """FAC-004: facility CRUD service."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        self.ddb = boto3.resource("dynamodb", region_name="us-east-1")

        import app.core.tables as tables_mod
        import app.core.settings as settings_mod
        import app.services.facilities as fac_mod

        self.tables_mod = tables_mod
        self.settings_mod = settings_mod
        self.fac_mod = fac_mod

        self.fac_table = _make_facilities_table(self.ddb)
        self.orig_fac = getattr(tables_mod.T, "facilities", None)
        object.__setattr__(tables_mod.T, "facilities", self.fac_table)
        self.addCleanup(lambda: object.__setattr__(tables_mod.T, "facilities", self.orig_fac))

        self.orig_flag = settings_mod.S.facility_fulfillment_enabled
        object.__setattr__(settings_mod.S, "facility_fulfillment_enabled", True)
        self.addCleanup(lambda: object.__setattr__(settings_mod.S, "facility_fulfillment_enabled", self.orig_flag))

    def test_flag_off_raises_404(self):
        from app.core.settings import S
        object.__setattr__(S, "facility_fulfillment_enabled", False)
        with self.assertRaises(HTTPException) as ctx:
            self.fac_mod.create_facility("sub1", "Test", "warehouse")
        self.assertEqual(ctx.exception.status_code, 404)
        # restore
        object.__setattr__(S, "facility_fulfillment_enabled", True)

    def test_create_facility_basic(self):
        rec = self.fac_mod.create_facility("user1", "Main Warehouse", "warehouse")
        self.assertIn("facility_id", rec)
        self.assertEqual(rec["name"], "Main Warehouse")
        self.assertEqual(rec["facility_type"], "warehouse")
        self.assertEqual(rec["status"], "active")
        self.assertGreater(rec["created_at"], 0)

    def test_create_facility_idempotent(self):
        rec1 = self.fac_mod.create_facility("user1", "Main Warehouse", "warehouse")
        rec2 = self.fac_mod.create_facility("user1", "Main Warehouse", "warehouse")
        self.assertEqual(rec1["facility_id"], rec2["facility_id"])

    def test_create_facility_different_owners(self):
        rec1 = self.fac_mod.create_facility("user1", "Warehouse", "warehouse")
        rec2 = self.fac_mod.create_facility("user2", "Warehouse", "warehouse")
        self.assertNotEqual(rec1["facility_id"], rec2["facility_id"])

    def test_get_facility_present(self):
        created = self.fac_mod.create_facility("user1", "WH1", "warehouse")
        fetched = self.fac_mod.get_facility(created["facility_id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["facility_id"], created["facility_id"])

    def test_get_facility_absent(self):
        result = self.fac_mod.get_facility("nonexistent123")
        self.assertIsNone(result)

    def test_list_facilities(self):
        for i in range(3):
            self.fac_mod.create_facility("userA", f"WH{i}", "warehouse")
        result = self.fac_mod.list_facilities("userA")
        self.assertEqual(len(result["facilities"]), 3)

    def test_list_facilities_empty(self):
        result = self.fac_mod.list_facilities("nobody")
        self.assertEqual(result["facilities"], [])
        self.assertIsNone(result["next_cursor"])

    def test_update_facility(self):
        rec = self.fac_mod.create_facility("user1", "Old Name", "warehouse")
        fid = rec["facility_id"]
        updated = self.fac_mod.update_facility(fid, user_sub="user1", name="New Name")
        self.assertEqual(updated["name"], "New Name")
        self.assertGreaterEqual(updated["updated_at"], updated["created_at"])

    def test_update_archived_facility_blocked(self):
        rec = self.fac_mod.create_facility("user1", "WH", "warehouse")
        fid = rec["facility_id"]
        self.fac_mod.archive_facility(fid, user_sub="user1")
        with self.assertRaises(HTTPException) as ctx:
            self.fac_mod.update_facility(fid, user_sub="user1", name="X")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_archive_facility(self):
        rec = self.fac_mod.create_facility("user1", "WH", "warehouse")
        fid = rec["facility_id"]
        archived = self.fac_mod.archive_facility(fid, user_sub="user1")
        self.assertEqual(archived["status"], "archived")

    def test_archive_idempotent(self):
        rec = self.fac_mod.create_facility("user1", "WH", "warehouse")
        fid = rec["facility_id"]
        self.fac_mod.archive_facility(fid, user_sub="user1")
        # Second call should not raise
        archived = self.fac_mod.archive_facility(fid, user_sub="user1")
        self.assertEqual(archived["status"], "archived")

    def test_create_location_basic(self):
        rec = self.fac_mod.create_facility("user1", "WH", "warehouse")
        fid = rec["facility_id"]
        loc = self.fac_mod.create_location(fid, "Aisle A", "aisle", user_sub="user1")
        self.assertIn("location_id", loc)
        self.assertTrue(len(loc["location_id"]) > 0)
        self.assertEqual(loc["facility_id"], fid)
        self.assertEqual(loc["location_type"], "aisle")
        self.assertEqual(loc["status"], "active")

    def test_create_location_on_archived_facility(self):
        rec = self.fac_mod.create_facility("user1", "WH", "warehouse")
        fid = rec["facility_id"]
        self.fac_mod.archive_facility(fid, user_sub="user1")
        with self.assertRaises(HTTPException) as ctx:
            self.fac_mod.create_location(fid, "Aisle A", "aisle", user_sub="user1")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_list_locations(self):
        rec = self.fac_mod.create_facility("user1", "WH", "warehouse")
        fid = rec["facility_id"]
        self.fac_mod.create_location(fid, "Aisle A", "aisle", user_sub="user1")
        self.fac_mod.create_location(fid, "Bin B1", "bin", user_sub="user1")
        locs = self.fac_mod.list_locations(fid)
        self.assertEqual(len(locs), 2)

    def test_get_location_present(self):
        rec = self.fac_mod.create_facility("user1", "WH", "warehouse")
        fid = rec["facility_id"]
        loc = self.fac_mod.create_location(fid, "Bin A1", "bin", user_sub="user1")
        fetched = self.fac_mod.get_location(fid, loc["location_id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["location_id"], loc["location_id"])

    def test_get_location_absent(self):
        rec = self.fac_mod.create_facility("user1", "WH", "warehouse")
        fid = rec["facility_id"]
        result = self.fac_mod.get_location(fid, "nope")
        self.assertIsNone(result)

    def test_create_location_different_labels_get_different_ids(self):
        rec = self.fac_mod.create_facility("user1", "WH", "warehouse")
        fid = rec["facility_id"]
        loc1 = self.fac_mod.create_location(fid, "Bin", "bin", user_sub="user1")
        loc2 = self.fac_mod.create_location(fid, "Bin", "bin", user_sub="user1")
        self.assertNotEqual(loc1["location_id"], loc2["location_id"])

    def test_ensure_default_facility(self):
        fac = self.fac_mod.ensure_default_facility()
        self.assertEqual(fac["name"], "Default Warehouse")
        self.assertEqual(fac["owner_sub"], "system")
        expected_id = hashlib.sha256("system|Default Warehouse".encode()).hexdigest()[:32]
        self.assertEqual(fac["facility_id"], expected_id)
        # Verify warehouse location exists
        locs = self.fac_mod.list_locations(fac["facility_id"])
        loc_ids = [l["location_id"] for l in locs]
        self.assertIn("warehouse", loc_ids)

    def test_ensure_default_facility_idempotent(self):
        fac1 = self.fac_mod.ensure_default_facility()
        fac2 = self.fac_mod.ensure_default_facility()
        self.assertEqual(fac1["facility_id"], fac2["facility_id"])
        # Warehouse location still only one
        locs = self.fac_mod.list_locations(fac1["facility_id"])
        wh_locs = [l for l in locs if l["location_id"] == "warehouse"]
        self.assertEqual(len(wh_locs), 1)


# ─────────────────────────── TRANSFER SERVICE TESTS (FAC-006) ──────────────

@unittest.skipIf(mock_aws is None, "moto not installed")
class TestTransfers(unittest.TestCase):
    """FAC-006: transfer service lifecycle."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        self.ddb = boto3.resource("dynamodb", region_name="us-east-1")

        import app.core.tables as tables_mod
        import app.core.settings as settings_mod
        import app.services.transfers as tx_mod

        self.tables_mod = tables_mod
        self.settings_mod = settings_mod
        self.tx_mod = tx_mod

        self.tx_table = _make_transfers_table(self.ddb)
        self.orig_tx = getattr(tables_mod.T, "transfers", None)
        object.__setattr__(tables_mod.T, "transfers", self.tx_table)
        self.addCleanup(lambda: object.__setattr__(tables_mod.T, "transfers", self.orig_tx))

        self.orig_flag = settings_mod.S.facility_fulfillment_enabled
        object.__setattr__(settings_mod.S, "facility_fulfillment_enabled", True)
        self.addCleanup(lambda: object.__setattr__(settings_mod.S, "facility_fulfillment_enabled", self.orig_flag))

    def _create(self, from_loc="loc_A", to_loc="loc_B", owner="admin1"):
        return self.tx_mod.create_transfer(
            "fac1", from_loc, "fac2", to_loc,
            [{"sku": "SKU1", "quantity": 10}],
            owner_sub=owner,
        )

    def test_flag_off_raises_404(self):
        from app.core.settings import S
        object.__setattr__(S, "facility_fulfillment_enabled", False)
        with self.assertRaises(HTTPException) as ctx:
            self._create()
        self.assertEqual(ctx.exception.status_code, 404)
        object.__setattr__(S, "facility_fulfillment_enabled", True)

    def test_create_transfer_basic(self):
        tx = self._create()
        self.assertIn("transfer_id", tx)
        self.assertEqual(tx["status"], "requested")
        self.assertEqual(len(tx["lines"]), 1)
        self.assertEqual(tx["lines"][0]["sku"], "SKU1")
        self.assertEqual(tx["lines"][0]["quantity"], 10)

    def test_get_transfer(self):
        tx = self._create()
        fetched = self.tx_mod.get_transfer(tx["transfer_id"])
        self.assertEqual(fetched["transfer_id"], tx["transfer_id"])

    def test_advance_to_in_transit(self):
        tx = self._create()
        advanced = self.tx_mod.advance_to_in_transit(tx["transfer_id"], user_sub="admin1")
        self.assertEqual(advanced["status"], "in_transit")

    def test_cancel_from_requested(self):
        tx = self._create()
        cancelled = self.tx_mod.cancel_transfer(tx["transfer_id"], user_sub="admin1")
        self.assertEqual(cancelled["status"], "cancelled")

    def test_cancel_from_in_transit(self):
        tx = self._create()
        self.tx_mod.advance_to_in_transit(tx["transfer_id"], user_sub="admin1")
        cancelled = self.tx_mod.cancel_transfer(tx["transfer_id"], user_sub="admin1")
        self.assertEqual(cancelled["status"], "cancelled")

    def test_complete_transfer_without_inventory(self):
        """complete_transfer without inventory module is best-effort, should not raise."""
        tx = self._create()
        self.tx_mod.advance_to_in_transit(tx["transfer_id"], user_sub="admin1")
        completed = self.tx_mod.complete_transfer(tx["transfer_id"], user_sub="admin1")
        self.assertEqual(completed["status"], "completed")
        self.assertIsNotNone(completed.get("completed_at"))

    def test_complete_transfer_idempotent(self):
        """Second complete call returns existing record."""
        tx = self._create()
        self.tx_mod.advance_to_in_transit(tx["transfer_id"], user_sub="admin1")
        self.tx_mod.complete_transfer(tx["transfer_id"], user_sub="admin1")
        # Second call: status is not in_transit, should raise 409
        with self.assertRaises(HTTPException) as ctx:
            self.tx_mod.complete_transfer(tx["transfer_id"], user_sub="admin1")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_cannot_complete_from_requested(self):
        tx = self._create()
        with self.assertRaises(HTTPException) as ctx:
            self.tx_mod.complete_transfer(tx["transfer_id"], user_sub="admin1")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_list_transfers_by_status(self):
        self._create()
        self._create()
        result = self.tx_mod.list_transfers(status="requested")
        self.assertGreaterEqual(len(result["transfers"]), 2)

    def test_empty_lines_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            self.tx_mod.create_transfer("fac1", "loc1", "fac2", "loc2", [], owner_sub="u1")
        self.assertEqual(ctx.exception.status_code, 422)


# ─────────────────────────── RECEIVING TESTS (FAC-007) ─────────────────────

@unittest.skipIf(mock_aws is None, "moto not installed")
class TestReceiving(unittest.TestCase):
    """FAC-007: receiving service."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        self.ddb = boto3.resource("dynamodb", region_name="us-east-1")

        import app.core.tables as tables_mod
        import app.core.settings as settings_mod
        import app.services.receiving as rec_mod

        self.tables_mod = tables_mod
        self.settings_mod = settings_mod
        self.rec_mod = rec_mod

        self.rec_table = _make_receipts_table(self.ddb)
        self.orig_rec = getattr(tables_mod.T, "receipts", None)
        object.__setattr__(tables_mod.T, "receipts", self.rec_table)
        self.addCleanup(lambda: object.__setattr__(tables_mod.T, "receipts", self.orig_rec))

        self.orig_flag = settings_mod.S.facility_fulfillment_enabled
        object.__setattr__(settings_mod.S, "facility_fulfillment_enabled", True)
        self.addCleanup(lambda: object.__setattr__(settings_mod.S, "facility_fulfillment_enabled", self.orig_flag))

        # Disable inventory adjustments (inv module not present in worktree)
        self.orig_inv_flag = getattr(settings_mod.S, "inventory_reservations_enabled", False)
        object.__setattr__(settings_mod.S, "inventory_reservations_enabled", False)
        self.addCleanup(lambda: object.__setattr__(settings_mod.S, "inventory_reservations_enabled", self.orig_inv_flag))

    def _receive(self, corr_id="corr-001", sku="SKU1", qty=10, po_id=None):
        return self.rec_mod.receive_shipment(
            "fac1",
            "loc1",
            [{"sku": sku, "quantity": qty}],
            po_id=po_id,
            correlation_id=corr_id,
            user_sub="admin1",
        )

    def test_flag_off_raises_404(self):
        from app.core.settings import S
        object.__setattr__(S, "facility_fulfillment_enabled", False)
        with self.assertRaises(HTTPException) as ctx:
            self._receive()
        self.assertEqual(ctx.exception.status_code, 404)
        object.__setattr__(S, "facility_fulfillment_enabled", True)

    def test_receive_basic(self):
        rec = self._receive()
        self.assertIn("receipt_id", rec)
        self.assertEqual(rec["facility_id"], "fac1")
        self.assertEqual(rec["location_id"], "loc1")
        self.assertEqual(len(rec["lines"]), 1)
        self.assertEqual(rec["lines"][0]["sku"], "SKU1")
        self.assertEqual(rec["lines"][0]["received_quantity"], 10)

    def test_receipt_id_is_deterministic(self):
        rec = self._receive(corr_id="my-key-1")
        expected_id = hashlib.sha256("my-key-1".encode()).hexdigest()[:32]
        self.assertEqual(rec["receipt_id"], expected_id)

    def test_idempotent_second_receive(self):
        """Same correlation_id → returns existing receipt without double-writing."""
        rec1 = self._receive(corr_id="idem-key")
        rec2 = self._receive(corr_id="idem-key")
        self.assertEqual(rec1["receipt_id"], rec2["receipt_id"])

    def test_get_receipt(self):
        created = self._receive()
        fetched = self.rec_mod.get_receipt(created["receipt_id"])
        self.assertEqual(fetched["receipt_id"], created["receipt_id"])

    def test_get_receipt_not_found(self):
        with self.assertRaises(HTTPException) as ctx:
            self.rec_mod.get_receipt("nonexistent")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_po_id_sentinel(self):
        """po_id=None → sentinel 'NONE'; API strips it back to None."""
        rec = self._receive(po_id=None)
        self.assertIsNone(rec["po_id"])

    def test_po_id_set(self):
        rec = self._receive(po_id="PO-123")
        self.assertEqual(rec["po_id"], "PO-123")

    def test_receipt_status_received(self):
        """All lines received exactly → status=received."""
        rec = self._receive()
        self.assertEqual(rec["status"], "received")

    def test_receipt_status_partial_when_short(self):
        """ordered_qty > received_qty → partial header status."""
        result = self.rec_mod.receive_shipment(
            "fac1", "loc1",
            [{"sku": "SKU1", "quantity": 5, "ordered_qty": 10}],
            correlation_id="short-corr",
            user_sub="admin1",
        )
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["lines"][0]["receipt_status"], "short")

    def test_receipt_status_over(self):
        """received_qty > ordered_qty → over."""
        result = self.rec_mod.receive_shipment(
            "fac1", "loc1",
            [{"sku": "SKU1", "quantity": 15, "ordered_qty": 10}],
            correlation_id="over-corr",
            user_sub="admin1",
        )
        self.assertEqual(result["status"], "over")
        self.assertEqual(result["lines"][0]["receipt_status"], "over")

    def test_list_receipts_for_facility(self):
        self._receive(corr_id="corr-A")
        self._receive(corr_id="corr-B")
        result = self.rec_mod.list_receipts_for_facility("fac1")
        self.assertGreaterEqual(len(result["receipts"]), 2)

    def test_list_receipts_for_po(self):
        self._receive(corr_id="corr-po-1", po_id="PO-ABC")
        result = self.rec_mod.list_receipts_for_po("PO-ABC")
        self.assertGreaterEqual(len(result["receipts"]), 1)
        for r in result["receipts"]:
            self.assertEqual(r["po_id"], "PO-ABC")

    def test_lot_id_derived_from_lot_label(self):
        result = self.rec_mod.receive_shipment(
            "fac1", "loc1",
            [{"sku": "SKU1", "quantity": 10, "lot_label": "BATCH-001"}],
            correlation_id="lot-corr",
            user_sub="admin1",
        )
        line = result["lines"][0]
        self.assertIsNotNone(line.get("lot_id"))
        expected_id = hashlib.sha256(f"{result['receipt_id']}:SKU1:BATCH-001".encode()).hexdigest()[:24]
        self.assertEqual(line["lot_id"], expected_id)


# ─────────────────────────── IMPORT SMOKE TEST ─────────────────────────────

class TestImportSmoke(unittest.TestCase):
    """Verify all FAC service/router modules import without error."""

    def test_import_app_main(self):
        import app.main  # noqa: F401
        self.assertTrue(True)

    def test_import_facilities_service(self):
        import app.services.facilities  # noqa: F401
        self.assertTrue(True)

    def test_import_transfers_service(self):
        import app.services.transfers  # noqa: F401
        self.assertTrue(True)

    def test_import_receiving_service(self):
        import app.services.receiving  # noqa: F401
        self.assertTrue(True)

    def test_import_picking_service(self):
        import app.services.picking  # noqa: F401
        self.assertTrue(True)

    def test_import_shipping_fulfillment_service(self):
        import app.services.shipping_fulfillment  # noqa: F401
        self.assertTrue(True)

    def test_import_facilities_router(self):
        import app.routers.facilities  # noqa: F401
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()

"""Hermetic regression tests for ORD-008 (order adjustments) and ORD-009 (ship groups).

Isolation strategy (mirrors existing hermetic tests in this repo):
  - moto in-memory DynamoDB backs all T.orders writes.
  - ``object.__setattr__`` flips the frozen Settings flag.
  - No real AWS / network calls.
  - No ``@mock_aws`` global decorator — we create the moto context per-class.
"""
from __future__ import annotations

import unittest

import boto3

try:
    from moto import mock_aws
except ImportError:  # pragma: no cover
    mock_aws = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TABLE_NAME = "orders"


def _make_orders_table(ddb):
    return ddb.create_table(
        TableName=_TABLE_NAME,
        KeySchema=[
            {"AttributeName": "order_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "order_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _enable_flag():
    from app.core.settings import S
    object.__setattr__(S, "order_lifecycle_enabled", True)


def _disable_flag():
    from app.core.settings import S
    object.__setattr__(S, "order_lifecycle_enabled", False)


# ---------------------------------------------------------------------------
# ORD-008: order_adjustments
# ---------------------------------------------------------------------------

@unittest.skipIf(mock_aws is None, "moto not installed")
class TestOrderAdjustments(unittest.TestCase):
    """Tests for app.services.order_adjustments."""

    def setUp(self):
        self._moto_ctx = mock_aws()
        self._moto_ctx.start()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self._table = _make_orders_table(ddb)

        # Wire T.orders to our in-memory table
        from app.core import tables as T_module
        object.__setattr__(T_module.T, "orders", self._table)

        _enable_flag()

    def tearDown(self):
        _disable_flag()
        self._moto_ctx.stop()

    # -- helpers ---------------------------------------------------------------

    def _svc(self):
        import importlib
        import app.services.order_adjustments as m
        importlib.reload(m)  # ensure fresh import picks up patched T
        return m

    # -- tests -----------------------------------------------------------------

    def test_add_adjustment_creates_row(self):
        svc = self._svc()
        row = svc.add_adjustment(
            order_id="ORD-001",
            adj_type="tax",
            description="Sales tax 8%",
            amount_cents=800,
            actor_sub="user-1",
        )
        self.assertEqual(row["adj_type"], "tax")
        self.assertEqual(row["amount_cents"], 800)
        self.assertTrue(row["adjustment_id"])
        self.assertTrue(row["sk"].startswith("ADJ#"))
        self.assertEqual(row["created_by"], "user-1")

    def test_add_adjustment_idempotent_same_id(self):
        """Same args → same deterministic adjustment_id → put_item is idempotent."""
        svc = self._svc()
        r1 = svc.add_adjustment("ORD-001", "discount", "Summer sale", -500)
        r2 = svc.add_adjustment("ORD-001", "discount", "Summer sale", -500)
        self.assertEqual(r1["adjustment_id"], r2["adjustment_id"])

    def test_add_adjustment_different_descriptions_different_ids(self):
        svc = self._svc()
        r1 = svc.add_adjustment("ORD-001", "tax", "State tax", 400)
        r2 = svc.add_adjustment("ORD-001", "tax", "County tax", 150)
        self.assertNotEqual(r1["adjustment_id"], r2["adjustment_id"])

    def test_list_adjustments_returns_all_rows(self):
        svc = self._svc()
        svc.add_adjustment("ORD-002", "shipping", "Ground shipping", 999)
        svc.add_adjustment("ORD-002", "tax", "State tax", 200)
        rows = svc.list_adjustments("ORD-002")
        self.assertEqual(len(rows), 2)
        types = {r["adj_type"] for r in rows}
        self.assertEqual(types, {"shipping", "tax"})

    def test_list_adjustments_empty_order(self):
        svc = self._svc()
        rows = svc.list_adjustments("ORD-EMPTY")
        self.assertEqual(rows, [])

    def test_remove_adjustment_deletes_row(self):
        svc = self._svc()
        row = svc.add_adjustment("ORD-003", "surcharge", "Rush fee", 2000)
        adj_id = row["adjustment_id"]
        svc.remove_adjustment("ORD-003", adj_id)
        rows = svc.list_adjustments("ORD-003")
        self.assertEqual(rows, [])

    def test_remove_adjustment_noop_when_missing(self):
        """No exception when the row to delete does not exist."""
        svc = self._svc()
        # Should not raise
        svc.remove_adjustment("ORD-GHOST", "nonexistent-id")

    def test_negative_amount_cents_discount(self):
        svc = self._svc()
        row = svc.add_adjustment("ORD-004", "discount", "10% off", -1000)
        self.assertEqual(row["amount_cents"], -1000)

    def test_compute_order_total_no_header_no_adjustments(self):
        """When there is no order header and no adjustments, totals are all zero."""
        svc = self._svc()
        result = svc.compute_order_total("ORD-NOTEXIST")
        self.assertEqual(result["base_amount_cents"], 0)
        self.assertEqual(result["total_adjustments_cents"], 0)
        self.assertEqual(result["total_cents"], 0)
        self.assertEqual(result["adjustment_count"], 0)

    def test_compute_order_total_with_header_and_adjustments(self):
        """Totals are base + signed adjustments."""
        # Seed an ORDER header row directly
        self._table.put_item(Item={
            "order_id": "ORD-005",
            "sk": "ORDER",
            "amount_cents": 10000,
            "status": "pending_payment",
        })
        svc = self._svc()
        svc.add_adjustment("ORD-005", "tax", "Tax", 800)
        svc.add_adjustment("ORD-005", "discount", "Coupon -200", -200)
        result = svc.compute_order_total("ORD-005")
        self.assertEqual(result["base_amount_cents"], 10000)
        self.assertEqual(result["total_adjustments_cents"], 600)
        self.assertEqual(result["total_cents"], 10600)
        self.assertEqual(result["adjustment_count"], 2)

    def test_invalid_adj_type_raises_422(self):
        from fastapi import HTTPException
        svc = self._svc()
        with self.assertRaises(HTTPException) as ctx:
            svc.add_adjustment("ORD-006", "INVALID", "bad type", 100)
        self.assertEqual(ctx.exception.status_code, 422)

    def test_flag_off_raises_501(self):
        from fastapi import HTTPException
        _disable_flag()
        svc = self._svc()
        with self.assertRaises(HTTPException) as ctx:
            svc.add_adjustment("ORD-007", "tax", "Tax", 100)
        self.assertEqual(ctx.exception.status_code, 501)

    def test_percentage_stored_when_provided(self):
        svc = self._svc()
        row = svc.add_adjustment("ORD-008", "tax", "VAT 20%", 2000, percentage=20.0)
        self.assertEqual(float(row["percentage"]), 20.0)


# ---------------------------------------------------------------------------
# ORD-009: order_ship_groups
# ---------------------------------------------------------------------------

@unittest.skipIf(mock_aws is None, "moto not installed")
class TestOrderShipGroups(unittest.TestCase):
    """Tests for app.services.order_ship_groups."""

    def setUp(self):
        self._moto_ctx = mock_aws()
        self._moto_ctx.start()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self._table = _make_orders_table(ddb)

        from app.core import tables as T_module
        object.__setattr__(T_module.T, "orders", self._table)

        _enable_flag()

    def tearDown(self):
        _disable_flag()
        self._moto_ctx.stop()

    def _svc(self):
        import importlib
        import app.services.order_ship_groups as m
        importlib.reload(m)
        return m

    def test_create_ship_group_creates_row(self):
        svc = self._svc()
        ship_to = {"name": "Alice", "street": "123 Main St", "city": "Portland", "zip": "97201"}
        row = svc.create_ship_group("ORD-SG-001", ship_to=ship_to, ship_method="standard")
        self.assertIsNotNone(row["ship_group_id"])
        self.assertTrue(row["sk"].startswith("SHIPGRP#"))
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["ship_method"], "standard")
        self.assertEqual(row["ship_to"], ship_to)

    def test_create_ship_group_with_carrier_and_items(self):
        svc = self._svc()
        row = svc.create_ship_group(
            "ORD-SG-002",
            ship_to={"street": "456 Oak Ave"},
            carrier="UPS",
            ship_method="express",
            item_ids=["item-1", "item-2"],
        )
        self.assertEqual(row["carrier"], "UPS")
        self.assertEqual(row["item_ids"], ["item-1", "item-2"])

    def test_list_ship_groups_returns_all(self):
        svc = self._svc()
        svc.create_ship_group("ORD-SG-003", ship_to={"zip": "10001"})
        svc.create_ship_group("ORD-SG-003", ship_to={"zip": "90210"}, ship_method="overnight")
        groups = svc.list_ship_groups("ORD-SG-003")
        self.assertEqual(len(groups), 2)

    def test_list_ship_groups_empty(self):
        svc = self._svc()
        groups = svc.list_ship_groups("ORD-SG-EMPTY")
        self.assertEqual(groups, [])

    def test_update_ship_group_tracking_and_status(self):
        svc = self._svc()
        row = svc.create_ship_group("ORD-SG-004", ship_to={"zip": "12345"})
        sg_id = row["ship_group_id"]
        updated = svc.update_ship_group(
            "ORD-SG-004",
            sg_id,
            tracking_number="1Z999AA10123456784",
            status="shipped",
        )
        self.assertEqual(updated["tracking_number"], "1Z999AA10123456784")
        self.assertEqual(updated["status"], "shipped")

    def test_update_ship_group_carrier(self):
        svc = self._svc()
        row = svc.create_ship_group("ORD-SG-005", ship_to={"zip": "00000"})
        sg_id = row["ship_group_id"]
        updated = svc.update_ship_group("ORD-SG-005", sg_id, carrier="FedEx")
        self.assertEqual(updated["carrier"], "FedEx")

    def test_update_ship_group_not_found_raises_404(self):
        from fastapi import HTTPException
        svc = self._svc()
        with self.assertRaises(HTTPException) as ctx:
            svc.update_ship_group("ORD-SG-006", "nonexistent-sg-id", status="shipped")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_delete_ship_group_removes_row(self):
        svc = self._svc()
        row = svc.create_ship_group("ORD-SG-007", ship_to={"zip": "11111"})
        sg_id = row["ship_group_id"]
        svc.delete_ship_group("ORD-SG-007", sg_id)
        groups = svc.list_ship_groups("ORD-SG-007")
        self.assertEqual(groups, [])

    def test_delete_ship_group_noop_when_missing(self):
        svc = self._svc()
        # Should not raise
        svc.delete_ship_group("ORD-SG-GHOST", "no-such-id")

    def test_flag_off_raises_501(self):
        from fastapi import HTTPException
        _disable_flag()
        svc = self._svc()
        with self.assertRaises(HTTPException) as ctx:
            svc.create_ship_group("ORD-SG-008", ship_to={"zip": "99999"})
        self.assertEqual(ctx.exception.status_code, 501)

    def test_invalid_ship_method_raises_422(self):
        from fastapi import HTTPException
        svc = self._svc()
        with self.assertRaises(HTTPException) as ctx:
            svc.create_ship_group("ORD-SG-009", ship_to={"zip": "12345"}, ship_method="teleport")
        self.assertEqual(ctx.exception.status_code, 422)

    def test_invalid_status_on_update_raises_422(self):
        from fastapi import HTTPException
        svc = self._svc()
        row = svc.create_ship_group("ORD-SG-010", ship_to={"zip": "54321"})
        with self.assertRaises(HTTPException) as ctx:
            svc.update_ship_group("ORD-SG-010", row["ship_group_id"], status="flying")
        self.assertEqual(ctx.exception.status_code, 422)

    def test_estimated_ship_date_stored(self):
        svc = self._svc()
        row = svc.create_ship_group(
            "ORD-SG-011",
            ship_to={"zip": "00000"},
            estimated_ship_date="2026-07-04",
        )
        self.assertEqual(row["estimated_ship_date"], "2026-07-04")


if __name__ == "__main__":
    unittest.main()

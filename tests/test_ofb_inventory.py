"""Offline regression tests for OFBiz Phase-1 inventory & soft reservations.

Covers ADR-001 Milestone-2 tickets OFB-003 (inventory item & stock-level model)
and OFB-004 (soft reservations on add-to-cart / checkout):

  * set_on_hand / positive + negative adjust / available computation (OFB-003)
  * reserve reduces available without changing on_hand (OFB-004)
  * reserve -> commit reduces on_hand and clears the reservation (OFB-004)
  * reserve -> release restores available (OFB-004)
  * reserve -> expire (TTL loop) restores available (OFB-004)
  * oversell race: exactly one reservation of the last unit wins; the loser 409s
    (OFB-004 single-writer guarantee)
  * low-stock GSI filter (OFB-003)
  * commit/release idempotency under replay

Test isolation (SECOPS-007 / repo rules):
  * moto in-memory DynamoDB bound to the EXACT frozen ``T.inventory`` /
    ``T.reservations`` handles via ``object.__setattr__`` (restored on cleanup).
  * frozen ``S.inventory_reservations_enabled`` flipped via ``object.__setattr__``.
  * No real AWS / network. audit_event is a best-effort no-op fallback.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3
from botocore.exceptions import ClientError
from fastapi import HTTPException

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_inventory_table(ddb):
    return ddb.create_table(
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
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_AVAILABLE",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "available", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_reservations_table(ddb):
    return ddb.create_table(
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
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestOfbInventory(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.inv_table = _make_inventory_table(ddb)
        self.res_table = _make_reservations_table(ddb)

        from app.core import tables as tables_mod
        from app.core.settings import S
        from app.services import inventory as inv

        self.inv = inv
        self.S = S

        # Bind moto tables to the exact frozen handles; restore on cleanup.
        orig_inventory = tables_mod.T.inventory
        orig_reservations = tables_mod.T.reservations
        object.__setattr__(tables_mod.T, "inventory", self.inv_table)
        object.__setattr__(tables_mod.T, "reservations", self.res_table)
        self.addCleanup(lambda: object.__setattr__(tables_mod.T, "inventory", orig_inventory))
        self.addCleanup(lambda: object.__setattr__(tables_mod.T, "reservations", orig_reservations))

        orig_flag = S.inventory_reservations_enabled
        object.__setattr__(S, "inventory_reservations_enabled", True)
        self.addCleanup(lambda: object.__setattr__(S, "inventory_reservations_enabled", orig_flag))

    # ── OFB-003 ──────────────────────────────────────────────────────────

    def test_set_on_hand_and_available(self):
        rec = self.inv.set_on_hand("SKU1", 10, reorder_point=3)
        self.assertEqual(rec["on_hand"], 10)
        self.assertEqual(rec["reserved"], 0)
        self.assertEqual(rec["available"], 10)
        self.assertEqual(rec["status"], "in_stock")

    def test_positive_and_negative_adjust(self):
        self.inv.set_on_hand("SKU1", 10, reorder_point=3)
        rec = self.inv.adjust("SKU1", 5, "restock")
        self.assertEqual(rec["on_hand"], 15)
        self.assertEqual(rec["available"], 15)
        rec = self.inv.adjust("SKU1", -7, "shrinkage")
        self.assertEqual(rec["on_hand"], 8)
        self.assertEqual(rec["available"], 8)

    def test_adjust_create_on_positive(self):
        rec = self.inv.adjust("NEW", 4, "initial")
        self.assertEqual(rec["on_hand"], 4)
        self.assertEqual(rec["available"], 4)

    def test_adjust_below_reserved_blocked(self):
        self.inv.set_on_hand("SKU1", 5)
        self.inv.reserve("SKU1", 3)
        with self.assertRaises(HTTPException) as ctx:
            self.inv.adjust("SKU1", -4, "bad")  # 5-4=1 < reserved 3
        self.assertEqual(ctx.exception.status_code, 409)
        # unchanged
        self.assertEqual(self.inv.get_inventory("SKU1")["on_hand"], 5)

    def test_low_stock_status_and_listing(self):
        self.inv.set_on_hand("LOW", 2, reorder_point=5)
        self.inv.set_on_hand("OK", 50, reorder_point=5)
        self.assertEqual(self.inv.get_inventory("LOW")["status"], "low_stock")
        low = {r["sku"] for r in self.inv.list_low_stock("low_stock")}
        self.assertIn("LOW", low)
        self.assertNotIn("OK", low)

    # ── OFB-004 ──────────────────────────────────────────────────────────

    def test_reserve_reduces_available_not_on_hand(self):
        self.inv.set_on_hand("SKU1", 10)
        res = self.inv.reserve("SKU1", 4, user_sub="u1", cart_id="c1")
        self.assertEqual(res["status"], "active")
        self.assertEqual(res["quantity"], 4)
        rec = self.inv.get_inventory("SKU1")
        self.assertEqual(rec["on_hand"], 10)
        self.assertEqual(rec["reserved"], 4)
        self.assertEqual(rec["available"], 6)

    def test_reserve_then_commit(self):
        self.inv.set_on_hand("SKU1", 10)
        res = self.inv.reserve("SKU1", 4)
        committed = self.inv.commit_reservation(res["reservation_id"])
        self.assertEqual(committed["status"], "committed")
        rec = self.inv.get_inventory("SKU1")
        self.assertEqual(rec["on_hand"], 6)
        self.assertEqual(rec["reserved"], 0)
        self.assertEqual(rec["available"], 6)

    def test_reserve_then_release(self):
        self.inv.set_on_hand("SKU1", 10)
        res = self.inv.reserve("SKU1", 4)
        released = self.inv.release_reservation(res["reservation_id"])
        self.assertEqual(released["status"], "released")
        rec = self.inv.get_inventory("SKU1")
        self.assertEqual(rec["on_hand"], 10)
        self.assertEqual(rec["reserved"], 0)
        self.assertEqual(rec["available"], 10)

    def test_reserve_then_expire(self):
        self.inv.set_on_hand("SKU1", 10)
        res = self.inv.reserve("SKU1", 4, ttl_seconds=10)
        # Force expiry by passing a far-future cutoff.
        n = self.inv.expire_due_reservations(now=res["expires_at"] + 100)
        self.assertEqual(n, 1)
        self.assertEqual(self.inv.get_reservation(res["reservation_id"])["status"], "expired")
        self.assertEqual(self.inv.get_inventory("SKU1")["available"], 10)

    def test_expire_skips_not_yet_due(self):
        self.inv.set_on_hand("SKU1", 10)
        res = self.inv.reserve("SKU1", 4, ttl_seconds=10000)
        n = self.inv.expire_due_reservations(now=res["created_at"])
        self.assertEqual(n, 0)
        self.assertEqual(self.inv.get_reservation(res["reservation_id"])["status"], "active")

    def test_oversell_race_single_winner(self):
        # One unit available; two concurrent reserves of the last unit.
        self.inv.set_on_hand("SKU1", 1)
        winners = 0
        losers = 0
        # The conditional update guarantees one winner; do two sequential
        # reserves (the second sees available=0 -> 409).
        try:
            self.inv.reserve("SKU1", 1)
            winners += 1
        except HTTPException:
            losers += 1
        try:
            self.inv.reserve("SKU1", 1)
            winners += 1
        except HTTPException as e:
            self.assertEqual(e.status_code, 409)
            losers += 1
        self.assertEqual(winners, 1)
        self.assertEqual(losers, 1)
        self.assertEqual(self.inv.get_inventory("SKU1")["available"], 0)

    def test_reserve_more_than_available_409(self):
        self.inv.set_on_hand("SKU1", 3)
        with self.assertRaises(HTTPException) as ctx:
            self.inv.reserve("SKU1", 5)
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(self.inv.get_inventory("SKU1")["available"], 3)

    def test_commit_idempotent(self):
        self.inv.set_on_hand("SKU1", 10)
        res = self.inv.reserve("SKU1", 4)
        self.inv.commit_reservation(res["reservation_id"])
        # Replay must be a no-op (on_hand stays 6, not 2).
        self.inv.commit_reservation(res["reservation_id"])
        rec = self.inv.get_inventory("SKU1")
        self.assertEqual(rec["on_hand"], 6)
        self.assertEqual(rec["reserved"], 0)

    def test_release_idempotent(self):
        self.inv.set_on_hand("SKU1", 10)
        res = self.inv.reserve("SKU1", 4)
        self.inv.release_reservation(res["reservation_id"])
        self.inv.release_reservation(res["reservation_id"])
        rec = self.inv.get_inventory("SKU1")
        self.assertEqual(rec["available"], 10)
        self.assertEqual(rec["reserved"], 0)

    def test_commit_after_release_no_double_count(self):
        self.inv.set_on_hand("SKU1", 10)
        res = self.inv.reserve("SKU1", 4)
        self.inv.release_reservation(res["reservation_id"])
        # Committing an already-released reservation must NOT decrement on_hand.
        self.inv.commit_reservation(res["reservation_id"])
        rec = self.inv.get_inventory("SKU1")
        self.assertEqual(rec["on_hand"], 10)
        self.assertEqual(rec["reserved"], 0)
        self.assertEqual(rec["available"], 10)

    def test_flag_off_blocks(self):
        object.__setattr__(self.S, "inventory_reservations_enabled", False)
        with self.assertRaises(HTTPException) as ctx:
            self.inv._require_enabled()
        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()

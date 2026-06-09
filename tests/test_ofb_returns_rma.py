"""Offline regression tests for OFBiz Milestone-3 Returns / RMA.

Covers ADR-001 tickets OFB-008 (return-request entity + ownership/qty validation),
OFB-009 (approve/reject/receive + restock), and OFB-010 (refund via the EXISTING
billing ledger path).

  * request_return: ownership (foreign order -> 404), qty bounds, duplicate-open 409
  * approve -> receive -> refund full lifecycle
  * receive restocks via inventory.adjust exactly once (idempotent on replay)
  * refund posts exactly one type=adjustment/reason=refund ledger entry, balance
    delta applied, original ledger row reversed; double-refund prevented (idempotent)
  * reject path + illegal transition -> 409
  * partial-quantity refund prorates the amount

Test isolation (SECOPS-007 / repo rules):
  * moto in-memory DynamoDB bound to the EXACT frozen ``T.returns`` / ``T.orders`` /
    ``T.order_items`` / ``T.billing`` / ``T.inventory`` / ``T.reservations`` handles
    via ``object.__setattr__`` (restored on cleanup).
  * frozen ``S.returns_rma_enabled`` / ``S.inventory_reservations_enabled`` flipped
    via ``object.__setattr__``.
  * No real AWS / network. audit_event/notify are best-effort no-ops.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3
from fastapi import HTTPException

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _t(ddb, name, pk, sk=None, gsi=None, attr_types=None):
    attrs = {pk: "S"}
    schema = [{"AttributeName": pk, "KeyType": "HASH"}]
    if sk:
        attrs[sk] = "S"
        schema.append({"AttributeName": sk, "KeyType": "RANGE"})
    gsis = []
    for g in gsi or []:
        attrs[g["pk"]] = "S"
        ks = [{"AttributeName": g["pk"], "KeyType": "HASH"}]
        if g.get("sk"):
            attrs[g["sk"]] = "S"
            ks.append({"AttributeName": g["sk"], "KeyType": "RANGE"})
        gsis.append({"IndexName": g["name"], "KeySchema": ks, "Projection": {"ProjectionType": "ALL"}})
    for k, v in (attr_types or {}).items():
        attrs[k] = v
    kwargs = dict(
        TableName=name,
        KeySchema=schema,
        AttributeDefinitions=[{"AttributeName": k, "AttributeType": v} for k, v in attrs.items()],
        BillingMode="PAY_PER_REQUEST",
    )
    if gsis:
        kwargs["GlobalSecondaryIndexes"] = gsis
    return ddb.create_table(**kwargs)


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestOfbReturnsRma(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        returns_tbl = _t(
            ddb, "returns", "return_id", "sk",
            gsi=[
                {"name": "GSI_ORDER", "pk": "order_id", "sk": "created_at"},
                {"name": "GSI_STATUS", "pk": "status", "sk": "created_at"},
            ],
            attr_types={"created_at": "N"},
        )
        orders_tbl = _t(ddb, "orders", "order_id")
        order_items_tbl = _t(ddb, "order_items", "order_id", "item_id")
        billing_tbl = _t(
            ddb, "billing", "pk", "sk",
            gsi=[{"name": "GSI_LEDGER_DATE", "pk": "ledger_date", "sk": "sk"}],
        )
        inventory_tbl = _t(
            ddb, "inventory", "sku", "location_sk",
            gsi=[{"name": "GSI_AVAILABLE", "pk": "status", "sk": "available"}],
            attr_types={"available": "N"},
        )
        reservations_tbl = _t(
            ddb, "reservations", "reservation_pk", "sk",
            gsi=[
                {"name": "GSI_SKU", "pk": "sku", "sk": "created_at"},
                {"name": "GSI_EXPIRY", "pk": "gsi_expiry_pk", "sk": "expires_at"},
            ],
            attr_types={"created_at": "N", "expires_at": "N"},
        )

        from app.core import tables as tables_mod
        from app.core.settings import S
        from app.services import returns_rma as rma
        from app.services import inventory as inv

        self.rma = rma
        self.inv = inv
        self.S = S
        self.billing_tbl = billing_tbl

        binds = {
            "returns": returns_tbl,
            "orders": orders_tbl,
            "order_items": order_items_tbl,
            "billing": billing_tbl,
            "inventory": inventory_tbl,
            "reservations": reservations_tbl,
        }
        for name, tbl in binds.items():
            orig = getattr(tables_mod.T, name)
            object.__setattr__(tables_mod.T, name, tbl)
            self.addCleanup(lambda n=name, o=orig: object.__setattr__(tables_mod.T, n, o))

        for flag in ("returns_rma_enabled", "inventory_reservations_enabled"):
            orig = getattr(S, flag)
            object.__setattr__(S, flag, True)
            self.addCleanup(lambda f=flag, o=orig: object.__setattr__(S, f, o))

    # ── fixtures ──────────────────────────────────────────────────────────

    def _seed_order(self, order_id="ord1", user="alice", *, sku="SKU1", qty=4, unit=250):
        from app.core import tables as tables_mod

        tables_mod.T.orders.put_item(Item={
            "order_id": order_id,
            "user_id": user,
            "status": "pending_payment",
            "currency": "usd",
            "amount_cents": unit * qty,
            "created_at": "2026-01-01T00:00:00+00:00",
            "ledger_sk": "LEDGER#100#orig1",
        })
        tables_mod.T.order_items.put_item(Item={
            "order_id": order_id,
            "item_id": "1",
            "sku": sku,
            "quantity": qty,
            "amount_cents": unit * qty,
        })
        # seed the original settled charge ledger row
        self.billing_tbl.put_item(Item={
            "pk": f"USER#{user}",
            "sk": "LEDGER#100#orig1",
            "type": "charge",
            "amount_cents": unit * qty,
            "state": "settled",
            "reason": "purchase",
        })

    def _ledger_refunds(self, user="alice"):
        r = self.billing_tbl.query(
            KeyConditionExpression="pk = :p",
            ExpressionAttributeValues={":p": f"USER#{user}"},
        )
        return [i for i in r.get("Items", []) if i.get("reason") == "refund"]

    # ── OFB-008: request flow ────────────────────────────────────────────

    def test_request_return_happy(self):
        self._seed_order()
        rec = self.rma.request_return(user_sub="alice", order_id="ord1", reason="defective",
                                      lines=[{"item_id": "1", "quantity": 2}])
        self.assertEqual(rec["status"], "requested")
        self.assertEqual(rec["lines"][0]["quantity"], 2)
        self.assertEqual(rec["lines"][0]["amount_cents"], 500)  # unit 250 * 2

    def test_foreign_order_404(self):
        self._seed_order(user="alice")
        with self.assertRaises(HTTPException) as ctx:
            self.rma.request_return(user_sub="bob", order_id="ord1", reason="x",
                                    lines=[{"item_id": "1", "quantity": 1}])
        self.assertEqual(ctx.exception.status_code, 404)

    def test_unknown_order_404(self):
        with self.assertRaises(HTTPException) as ctx:
            self.rma.request_return(user_sub="alice", order_id="nope", reason="x",
                                    lines=[{"item_id": "1", "quantity": 1}])
        self.assertEqual(ctx.exception.status_code, 404)

    def test_over_quantity_422(self):
        self._seed_order(qty=4)
        with self.assertRaises(HTTPException) as ctx:
            self.rma.request_return(user_sub="alice", order_id="ord1", reason="x",
                                    lines=[{"item_id": "1", "quantity": 5}])
        self.assertEqual(ctx.exception.status_code, 422)

    def test_unknown_line_422(self):
        self._seed_order()
        with self.assertRaises(HTTPException) as ctx:
            self.rma.request_return(user_sub="alice", order_id="ord1", reason="x",
                                    lines=[{"item_id": "99", "quantity": 1}])
        self.assertEqual(ctx.exception.status_code, 422)

    def test_duplicate_open_return_409(self):
        self._seed_order()
        self.rma.request_return(user_sub="alice", order_id="ord1", reason="x",
                                lines=[{"item_id": "1", "quantity": 1}])
        with self.assertRaises(HTTPException) as ctx:
            self.rma.request_return(user_sub="alice", order_id="ord1", reason="y",
                                    lines=[{"item_id": "1", "quantity": 1}])
        self.assertEqual(ctx.exception.status_code, 409)

    # ── OFB-009: approve / receive / restock ─────────────────────────────

    def test_lifecycle_approve_receive_restock(self):
        self._seed_order(sku="SKU1", qty=4, unit=250)
        self.inv.set_on_hand("SKU1", 10, reorder_point=2)
        rec = self.rma.request_return(user_sub="alice", order_id="ord1", reason="x",
                                      lines=[{"item_id": "1", "quantity": 3}])
        rid = rec["return_id"]
        self.assertEqual(self.rma.approve_return(rid, actor_sub="admin")["status"], "approved")
        recv = self.rma.receive_return(rid, actor_sub="admin")
        self.assertEqual(recv["status"], "received")
        # restocked +3
        self.assertEqual(self.inv.get_inventory("SKU1")["on_hand"], 13)

    def test_receive_restock_idempotent(self):
        self._seed_order(sku="SKU1", qty=4, unit=250)
        self.inv.set_on_hand("SKU1", 10)
        rec = self.rma.request_return(user_sub="alice", order_id="ord1", reason="x",
                                      lines=[{"item_id": "1", "quantity": 3}])
        rid = rec["return_id"]
        self.rma.approve_return(rid, actor_sub="admin")
        self.rma.receive_return(rid, actor_sub="admin")
        # replay receive: no second restock
        self.rma.receive_return(rid, actor_sub="admin")
        self.assertEqual(self.inv.get_inventory("SKU1")["on_hand"], 13)

    def test_restock_skipped_when_inventory_flag_off(self):
        from app.core.settings import S
        self._seed_order(sku="SKU1", qty=4, unit=250)
        self.inv.set_on_hand("SKU1", 10)
        object.__setattr__(S, "inventory_reservations_enabled", False)
        rec = self.rma.request_return(user_sub="alice", order_id="ord1", reason="x",
                                      lines=[{"item_id": "1", "quantity": 3}])
        rid = rec["return_id"]
        self.rma.approve_return(rid, actor_sub="admin")
        recv = self.rma.receive_return(rid, actor_sub="admin")
        self.assertEqual(recv["status"], "received")
        # RMA still functions; no restock happened
        self.assertEqual(self.inv.get_inventory("SKU1")["on_hand"], 10)

    def test_reject_path(self):
        self._seed_order()
        rec = self.rma.request_return(user_sub="alice", order_id="ord1", reason="x",
                                      lines=[{"item_id": "1", "quantity": 1}])
        rid = rec["return_id"]
        out = self.rma.reject_return(rid, actor_sub="admin", note="not eligible")
        self.assertEqual(out["status"], "rejected")
        self.assertEqual(out["decision_note"], "not eligible")

    def test_illegal_transition_409(self):
        self._seed_order()
        rec = self.rma.request_return(user_sub="alice", order_id="ord1", reason="x",
                                      lines=[{"item_id": "1", "quantity": 1}])
        rid = rec["return_id"]
        # can't receive a still-requested return
        with self.assertRaises(HTTPException) as ctx:
            self.rma.receive_return(rid, actor_sub="admin")
        self.assertEqual(ctx.exception.status_code, 409)

    # ── OFB-010: refund via existing billing ─────────────────────────────

    def test_refund_full_lifecycle(self):
        self._seed_order(sku="SKU1", qty=4, unit=250)
        self.inv.set_on_hand("SKU1", 10)
        rec = self.rma.request_return(user_sub="alice", order_id="ord1", reason="x",
                                      lines=[{"item_id": "1", "quantity": 2}])
        rid = rec["return_id"]
        self.rma.approve_return(rid, actor_sub="admin")
        self.rma.receive_return(rid, actor_sub="admin")
        out = self.rma.refund_return(rid, actor_sub="admin")
        self.assertEqual(out["status"], "refunded")
        self.assertEqual(out["refund_amount_cents"], 500)  # 250 * 2
        self.assertEqual(out["provider"], "stripe")
        self.assertTrue(out["refund_ledger_sk"])

        # exactly one refund ledger entry, correct shape
        refunds = self._ledger_refunds()
        self.assertEqual(len(refunds), 1)
        self.assertEqual(refunds[0]["type"], "adjustment")
        self.assertEqual(int(refunds[0]["amount_cents"]), 500)
        self.assertEqual(refunds[0]["state"], "settled")

        # balance delta applied (payments_settled reduced)
        bal = self.billing_tbl.get_item(Key={"pk": "USER#alice", "sk": "BALANCE"}).get("Item")
        self.assertEqual(int(bal["payments_settled_cents"]), -500)

        # original ledger row reversed
        orig = self.billing_tbl.get_item(Key={"pk": "USER#alice", "sk": "LEDGER#100#orig1"}).get("Item")
        self.assertEqual(orig["state"], "reversed")

    def test_double_refund_prevented(self):
        self._seed_order(sku="SKU1", qty=4, unit=250)
        self.inv.set_on_hand("SKU1", 10)
        rec = self.rma.request_return(user_sub="alice", order_id="ord1", reason="x",
                                      lines=[{"item_id": "1", "quantity": 2}])
        rid = rec["return_id"]
        self.rma.approve_return(rid, actor_sub="admin")
        self.rma.receive_return(rid, actor_sub="admin")
        self.rma.refund_return(rid, actor_sub="admin")
        # replay: status already refunded -> idempotent no-op (no second ledger post)
        out = self.rma.refund_return(rid, actor_sub="admin")
        self.assertEqual(out["status"], "refunded")
        self.assertEqual(len(self._ledger_refunds()), 1)

    def test_partial_quantity_prorate(self):
        # 4 units @ 1000 total => unit 250; return 1 => refund 250
        self._seed_order(sku="SKU1", qty=4, unit=250)
        self.inv.set_on_hand("SKU1", 10)
        rec = self.rma.request_return(user_sub="alice", order_id="ord1", reason="x",
                                      lines=[{"item_id": "1", "quantity": 1}])
        rid = rec["return_id"]
        self.rma.approve_return(rid, actor_sub="admin")
        self.rma.receive_return(rid, actor_sub="admin")
        out = self.rma.refund_return(rid, actor_sub="admin")
        self.assertEqual(out["refund_amount_cents"], 250)

    def test_flag_off_404(self):
        from app.core.settings import S
        object.__setattr__(S, "returns_rma_enabled", False)
        with self.assertRaises(HTTPException) as ctx:
            self.rma.request_return(user_sub="alice", order_id="ord1", reason="x",
                                    lines=[{"item_id": "1", "quantity": 1}])
        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

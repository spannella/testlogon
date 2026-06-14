"""Hermetic offline tests for the OFBiz ORDER-LIFECYCLE (ORD) backend core.

Covers ORD-004 (models), ORD-005 (state machine + CAS + idempotency),
ORD-006 (history + audit), ORD-007 (creation hook), ORD-011 (lifecycle read +
allowed_transitions + line_items + router). No TestClient, no real AWS:
moto in-memory tables bound to the frozen T handles via object.__setattr__,
frozen S flags toggled the same way, route coroutines run on a fresh loop.
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack

import boto3
import pytest
from boto3.dynamodb.conditions import Key
from moto import mock_aws

from app.core.settings import S
from app.core.tables import T
from app.models import (
    OrderAdjustment,
    OrderAdjustmentType,
    OrderLifecycleStatus,
    OrderStatusHistoryEntry,
    OrderTransitionRequest,
)
from pydantic import ValidationError


def _make_orders_table(ddb, name="orders"):
    return ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "order_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "order_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "lifecycle_status", "AttributeType": "S"},
            {"AttributeName": "updated_ts", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_ORDER_STATUS",
                "KeySchema": [
                    {"AttributeName": "lifecycle_status", "KeyType": "HASH"},
                    {"AttributeName": "updated_ts", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_order_items_table(ddb, name="order_items"):
    return ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "order_id", "KeyType": "HASH"},
            {"AttributeName": "item_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "order_id", "AttributeType": "S"},
            {"AttributeName": "item_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


# ── Pure model tests (no AWS) ─────────────────────────────────────────────────
class TestOrderModels(unittest.TestCase):
    def test_eleven_status_members(self):
        members = {s.value for s in OrderLifecycleStatus}
        self.assertEqual(
            members,
            {
                "created", "approved", "allocated", "picking", "packed",
                "shipped", "completed", "held", "backorder", "cancelled", "returned",
            },
        )

    def test_unknown_lifecycle_status_rejected(self):
        with pytest.raises(ValueError):
            OrderLifecycleStatus("pending_payment")

    def test_history_entry_initial_event(self):
        e = OrderStatusHistoryEntry(event_id="abc", to_status="created", actor="sys", ts=1700000000)
        self.assertIsNone(e.from_status)

    def test_history_negative_ts_rejected(self):
        with pytest.raises(ValidationError):
            OrderStatusHistoryEntry(event_id="abc", to_status="created", actor="u", ts=-1)

    def test_adjustment_negative_rejected(self):
        with pytest.raises(ValidationError):
            OrderAdjustment(adjustment_id="a", adj_type=OrderAdjustmentType.DISCOUNT, amount_cents=-1)

    def test_transition_request_invalid_target(self):
        with pytest.raises(ValidationError):
            OrderTransitionRequest(target_status="pending_payment")


# ── State machine / history / read / router (moto) ───────────────────────────
class TestOrderLifecycle(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.orders = _make_orders_table(ddb)
        self.order_items = _make_order_items_table(ddb)

        import app.services.order_lifecycle as svc

        self.svc = svc

        orig_orders = T.orders
        orig_items = T.order_items
        object.__setattr__(T, "orders", self.orders)
        object.__setattr__(T, "order_items", self.order_items)
        self.addCleanup(lambda: object.__setattr__(T, "orders", orig_orders))
        self.addCleanup(lambda: object.__setattr__(T, "order_items", orig_items))

        orig_flag = S.order_lifecycle_enabled
        object.__setattr__(S, "order_lifecycle_enabled", True)
        self.addCleanup(lambda: object.__setattr__(S, "order_lifecycle_enabled", orig_flag))

        orig_bo = S.order_backorder_enabled
        object.__setattr__(S, "order_backorder_enabled", False)
        self.addCleanup(lambda: object.__setattr__(S, "order_backorder_enabled", orig_bo))

    def _seed(self, order_id, lifecycle_status="created", **extra):
        item = {
            "order_id": order_id,
            "sk": "ORDER",
            "user_id": "alice",
            "lifecycle_status": lifecycle_status,
            "status": "pending_payment",
            "created_at": "2026-06-09T00:00:00+00:00",
            "updated_at": "2026-06-09T00:00:00+00:00",
            "updated_ts": 1749427200,
            "amount_cents": 1000,
            "currency": "USD",
            "source_system": "shopping_cart",
            "correlation_id": "corr1",
            "line_item_count": 0,
        }
        item.update(extra)
        self.orders.put_item(Item=item)

    # ORD-005
    def test_transition_graph_completeness(self):
        for s in OrderLifecycleStatus:
            self.assertIn(s.value, self.svc.TRANSITIONS)
        self.assertEqual(self.svc.TRANSITIONS["cancelled"], set())
        self.assertEqual(self.svc.TRANSITIONS["returned"], set())

    def test_legal_transition_mirrors_legacy(self):
        self._seed("o1", "created")
        result = self.svc.transition_order("o1", "approved", actor="admin", reason="ok")
        self.assertEqual(result.to_status, "approved")
        self.assertEqual(result.from_status, "created")
        self.assertEqual(len(result.event_id), 16)
        item = self.orders.get_item(Key={"order_id": "o1", "sk": "ORDER"})["Item"]
        self.assertEqual(item["lifecycle_status"], "approved")
        self.assertEqual(item["status"], "approved")  # legacy mirror

    def test_illegal_transition_raises_and_no_write(self):
        self._seed("o2", "packed")
        with pytest.raises(self.svc.OrderTransitionError):
            self.svc.transition_order("o2", "created", actor="admin")
        item = self.orders.get_item(Key={"order_id": "o2", "sk": "ORDER"})["Item"]
        self.assertEqual(item["lifecycle_status"], "packed")

    def test_order_not_found(self):
        with pytest.raises(self.svc.OrderNotFoundError):
            self.svc.transition_order("missing", "approved", actor="admin")

    def test_order_without_lifecycle_status_not_found(self):
        self.orders.put_item(Item={"order_id": "o3", "sk": "ORDER", "user_id": "alice"})
        with pytest.raises(self.svc.OrderNotFoundError):
            self.svc.transition_order("o3", "approved", actor="admin")

    def test_terminal_states_cannot_transition(self):
        self._seed("o4", "cancelled")
        with pytest.raises(self.svc.OrderTransitionError):
            self.svc.transition_order("o4", "approved", actor="admin")
        self._seed("o5", "returned")
        with pytest.raises(self.svc.OrderTransitionError):
            self.svc.transition_order("o5", "completed", actor="admin")

    def test_held_pre_hold_roundtrip(self):
        self._seed("o6", "picking")
        self.svc.transition_order("o6", "held", actor="admin")
        item = self.orders.get_item(Key={"order_id": "o6", "sk": "ORDER"})["Item"]
        self.assertEqual(item["pre_hold_status"], "picking")
        self.svc.transition_order("o6", "picking", actor="admin")
        item = self.orders.get_item(Key={"order_id": "o6", "sk": "ORDER"})["Item"]
        self.assertNotIn("pre_hold_status", item)

    def test_backorder_subflag_gate(self):
        self._seed("o7", "approved")
        with pytest.raises(self.svc.OrderTransitionError):
            self.svc.transition_order("o7", "backorder", actor="wh")
        object.__setattr__(S, "order_backorder_enabled", True)
        result = self.svc.transition_order("o7", "backorder", actor="wh")
        self.assertEqual(result.to_status, "backorder")

    def test_event_id_deterministic(self):
        a = self.svc._derive_event_id("o", "created", "approved", "k1")
        b = self.svc._derive_event_id("o", "created", "approved", "k1")
        self.assertEqual(a, b)
        self.assertEqual(
            self.svc._derive_event_id("o", "c", "a", None),
            self.svc._derive_event_id("o", "c", "a", ""),
        )

    def test_conflict_on_cas_failure(self):
        self._seed("o8", "approved")
        from unittest.mock import patch
        from botocore.exceptions import ClientError

        err = ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem")
        with patch.object(self.orders, "update_item", side_effect=err):
            with pytest.raises(self.svc.OrderConflictError):
                self.svc.transition_order("o8", "allocated", actor="admin")

    def test_idempotent_replay_no_second_hist(self):
        self._seed("o9", "created")
        self.svc.transition_order("o9", "approved", actor="admin", idempotency_key="k1")
        # header is now "approved"; replay with same key + same target → no-op success.
        r2 = self.svc.transition_order("o9", "approved", actor="admin", idempotency_key="k1")
        self.assertEqual(r2.to_status, "approved")
        # The replay must NOT append a second HIST row.
        resp = self.orders.query(
            KeyConditionExpression=Key("order_id").eq("o9") & Key("sk").begins_with("HIST#")
        )
        self.assertEqual(len(resp["Items"]), 1)

    # ORD-006
    def test_history_written_and_newest_first(self):
        self._seed("h1", "shipped")
        for ts, frm, to, eid in [
            (100, None, "created", "e1"),
            (200, "created", "approved", "e2"),
            (300, "approved", "shipped", "e3"),
        ]:
            self.svc._append_history_row(
                "h1", from_status=frm, to_status=to, actor="u", reason="", event_id=eid, ts=ts
            )
        hist = self.svc.list_status_history("h1")
        self.assertEqual([h["to_status"] for h in hist], ["shipped", "approved", "created"])
        self.assertIsNone(hist[-1]["from_status"])

    def test_append_history_swallows_exceptions(self):
        from unittest.mock import MagicMock

        bad = MagicMock()
        bad.put_item.side_effect = Exception("boom")
        orig = T.orders
        try:
            object.__setattr__(T, "orders", bad)
            self.svc._append_history_row(
                "x", from_status="created", to_status="approved", actor="u",
                reason="", event_id="e", ts=1,
            )
        finally:
            object.__setattr__(T, "orders", orig)

    def test_transition_writes_hist_and_audit(self):
        from unittest.mock import patch

        self._seed("full", "created")
        calls = []
        with patch.object(self.svc, "_audit_safe", side_effect=lambda *a, **kw: calls.append((a, kw))):
            self.svc.transition_order("full", "approved", actor="admin", reason="go")
        resp = self.orders.query(
            KeyConditionExpression=Key("order_id").eq("full") & Key("sk").begins_with("HIST#")
        )
        self.assertEqual(len(resp["Items"]), 1)
        self.assertEqual(resp["Items"][0]["from_status"], "created")
        self.assertEqual(calls[-1][0][0], "order_status_changed")

    # ORD-011 read
    def test_get_order_lifecycle_allowed_transitions_and_items(self):
        self._seed("read1", "approved", line_item_count=1)
        self.order_items.put_item(Item={
            "order_id": "read1", "item_id": "1", "sku": "SKU1",
            "quantity": 2, "product_type": "good",
            "pricing_ref": {"unit_price_cents": 500, "currency": "usd"},
        })
        out = self.svc.get_order_lifecycle("read1", include={"history"})
        self.assertEqual(out.lifecycle_status, OrderLifecycleStatus.APPROVED)
        # The graph is permissive (backorder is a legal edge); the sub-flag gate
        # is enforced only at transition time, not in the read.
        self.assertEqual(
            set(out.allowed_transitions),
            {"allocated", "held", "backorder", "cancelled"},
        )
        self.assertEqual(len(out.line_items), 1)
        self.assertEqual(out.line_items[0].unit_price_cents, 500)
        self.assertEqual(out.line_items[0].currency, "USD")
        self.assertIsNotNone(out.status_history)

    def test_get_order_lifecycle_not_found(self):
        with pytest.raises(self.svc.OrderNotFoundError):
            self.svc.get_order_lifecycle("nope")

    # ORD-010 cancel
    def test_cancel_order_transitions_no_refund(self):
        self._seed("c1", "created")
        out = self.svc.cancel_order("c1", reason="changed mind", refund=False, actor="alice")
        self.assertEqual(out.lifecycle_status, OrderLifecycleStatus.CANCELLED)


class TestOrderLifecycleRouter(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.orders = _make_orders_table(ddb)
        self.order_items = _make_order_items_table(ddb)

        orig_orders = T.orders
        orig_items = T.order_items
        object.__setattr__(T, "orders", self.orders)
        object.__setattr__(T, "order_items", self.order_items)
        self.addCleanup(lambda: object.__setattr__(T, "orders", orig_orders))
        self.addCleanup(lambda: object.__setattr__(T, "order_items", orig_items))

    def _seed(self, order_id, lifecycle_status="created", user_id="alice"):
        self.orders.put_item(Item={
            "order_id": order_id, "sk": "ORDER", "user_id": user_id,
            "lifecycle_status": lifecycle_status, "status": "pending_payment",
            "created_at": "2026-06-09T00:00:00+00:00", "updated_at": "2026-06-09T00:00:00+00:00",
            "updated_ts": 1749427200, "amount_cents": 1000, "currency": "USD",
            "source_system": "shopping_cart", "correlation_id": "c", "line_item_count": 0,
        })

    def _run(self, coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_flag_off_returns_503(self):
        from fastapi import HTTPException
        import app.routers.order_lifecycle as rt

        orig = S.order_lifecycle_enabled
        object.__setattr__(S, "order_lifecycle_enabled", False)
        try:
            with pytest.raises(HTTPException) as ei:
                self._run(rt.get_order_history("o1", ctx={"user_sub": "alice", "role": "USER"}))
            self.assertEqual(ei.value.status_code, 503)
        finally:
            object.__setattr__(S, "order_lifecycle_enabled", orig)

    def test_foreign_order_404(self):
        from fastapi import HTTPException
        import app.routers.order_lifecycle as rt

        orig = S.order_lifecycle_enabled
        object.__setattr__(S, "order_lifecycle_enabled", True)
        try:
            self._seed("o2", user_id="bob")
            with pytest.raises(HTTPException) as ei:
                self._run(rt.get_order_history("o2", ctx={"user_sub": "alice", "role": "USER"}))
            self.assertEqual(ei.value.status_code, 404)
        finally:
            object.__setattr__(S, "order_lifecycle_enabled", orig)

    def test_owner_can_read_lifecycle(self):
        import app.routers.order_lifecycle as rt

        orig = S.order_lifecycle_enabled
        object.__setattr__(S, "order_lifecycle_enabled", True)
        try:
            self._seed("o3", "approved", user_id="alice")
            out = self._run(rt.get_order_lifecycle_endpoint(
                "o3", include="", ctx={"user_sub": "alice", "role": "USER"}
            ))
            self.assertEqual(out.order_id, "o3")
            self.assertEqual(out.lifecycle_status, OrderLifecycleStatus.APPROVED)
        finally:
            object.__setattr__(S, "order_lifecycle_enabled", orig)

    def test_owner_cancel_blocked_on_packed(self):
        from fastapi import HTTPException
        import app.routers.order_lifecycle as rt
        from app.models import OrderCancelIn

        orig = S.order_lifecycle_enabled
        object.__setattr__(S, "order_lifecycle_enabled", True)
        try:
            self._seed("o4", "packed", user_id="alice")
            with pytest.raises(HTTPException) as ei:
                self._run(rt.cancel_order_endpoint(
                    "o4", OrderCancelIn(reason="late"), request=None,
                    ctx={"user_sub": "alice", "role": "USER"},
                ))
            self.assertEqual(ei.value.status_code, 409)
        finally:
            object.__setattr__(S, "order_lifecycle_enabled", orig)

    def test_owner_cancel_created(self):
        import app.routers.order_lifecycle as rt
        from app.models import OrderCancelIn

        orig = S.order_lifecycle_enabled
        object.__setattr__(S, "order_lifecycle_enabled", True)
        try:
            self._seed("o5", "created", user_id="alice")
            out = self._run(rt.cancel_order_endpoint(
                "o5", OrderCancelIn(reason="oops", refund=False), request=None,
                ctx={"user_sub": "alice", "role": "USER"},
            ))
            self.assertEqual(out.lifecycle_status, OrderLifecycleStatus.CANCELLED)
        finally:
            object.__setattr__(S, "order_lifecycle_enabled", orig)


class TestOrderCreationHook(unittest.TestCase):
    """ORD-007: create_order stamps lifecycle on flag-on, byte-identical on flag-off."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.orders = _make_orders_table(ddb)
        self.order_items = _make_order_items_table(ddb)

        import app.services.commerce_order_service as cos

        # Bind the singleton's table handles to moto + frozen T.
        self.cos = cos
        orig_orders = T.orders
        orig_items = T.order_items
        object.__setattr__(T, "orders", self.orders)
        object.__setattr__(T, "order_items", self.order_items)
        cos.commerce_order_service.orders = self.orders
        cos.commerce_order_service.order_items = self.order_items
        self.addCleanup(lambda: object.__setattr__(T, "orders", orig_orders))
        self.addCleanup(lambda: object.__setattr__(T, "order_items", orig_items))

    def _line_items(self):
        return [{
            "sku": "SKU1", "product_type": "file_bundle", "billing_model": "one_time",
            "source_system": "shopping_cart", "quantity": 1,
            "pricing_ref": {"unit_price_cents": 1000, "currency": "USD"},
        }]

    def test_flag_off_no_lifecycle_status(self):
        orig = S.order_lifecycle_enabled
        object.__setattr__(S, "order_lifecycle_enabled", False)
        try:
            res = self.cos.commerce_order_service.create_order(
                user_id="alice", source_system="shopping_cart", line_items=self._line_items(),
            )
            item = self.orders.get_item(Key={"order_id": res["order_id"], "sk": "ORDER"})["Item"]
            self.assertEqual(item["status"], "pending_payment")
            self.assertNotIn("lifecycle_status", item)
            self.assertNotIn("updated_ts", item)
            self.assertEqual(item["sk"], "ORDER")
        finally:
            object.__setattr__(S, "order_lifecycle_enabled", orig)

    def test_flag_on_stamps_created_and_hist(self):
        orig = S.order_lifecycle_enabled
        object.__setattr__(S, "order_lifecycle_enabled", True)
        try:
            res = self.cos.commerce_order_service.create_order(
                user_id="alice", source_system="shopping_cart", line_items=self._line_items(),
            )
            oid = res["order_id"]
            item = self.orders.get_item(Key={"order_id": oid, "sk": "ORDER"})["Item"]
            self.assertEqual(item["lifecycle_status"], "created")
            self.assertIn("updated_ts", item)
            resp = self.orders.query(
                KeyConditionExpression=Key("order_id").eq(oid) & Key("sk").begins_with("HIST#")
            )
            self.assertEqual(len(resp["Items"]), 1)
            self.assertEqual(resp["Items"][0]["to_status"], "created")
            self.assertNotIn("from_status", resp["Items"][0])
        finally:
            object.__setattr__(S, "order_lifecycle_enabled", orig)


if __name__ == "__main__":
    unittest.main()

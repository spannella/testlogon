"""Offline regression tests for the ORD server-side order list (GET /ui/orders).

Follow-up 1: ``app/routers/order_lifecycle.py`` previously exposed no list
endpoint, forcing the frontend onto a lookup-by-id + localStorage stopgap.
This adds ``order_store.list_orders(...)`` (GSI query, never a scan) + a
``GET /ui/orders`` route gated by ``S.order_lifecycle_enabled``.

Test isolation (SECOPS-007 / repo rules):
  * Real in-memory moto DynamoDB ``orders`` table (with GSI_USER / GSI_STATUS)
    bound to the frozen ``T.orders`` handle via ``object.__setattr__`` + restore.
  * Frozen ``Settings`` flag flipped with ``object.__setattr__``.
  * NO TestClient — the route coroutine and service fn are called directly.
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None


def _make_orders_table(ddb):
    return ddb.create_table(
        TableName="orders",
        KeySchema=[
            {"AttributeName": "order_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "order_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "user_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_USER",
                "KeySchema": [
                    {"AttributeName": "user_id", "KeyType": "HASH"},
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


def _seed_order(table, order_id, user_id, status, created_at, amount=1000):
    table.put_item(
        Item={
            "order_id": order_id,
            "sk": "ORDER",
            "user_id": user_id,
            "status": status,
            "created_at": created_at,
            "updated_at": created_at,
            "source_system": "shopping_cart",
            "correlation_id": f"corr:{order_id}",
            "currency": "USD",
            "amount_cents": amount,
            "line_item_count": 1,
            "lifecycle_status": "created",
        }
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestOrderListEndpoint(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_orders_table(ddb)

        from app.core.tables import T
        from app.routers import order_lifecycle as router
        from app.services import order_store

        self.T = T
        self.router = router
        self.order_store = order_store
        self.S = router.S

        self._orig_orders = T.orders
        object.__setattr__(T, "orders", self.table)
        self.addCleanup(lambda: object.__setattr__(T, "orders", self._orig_orders))

        self._orig_flag = self.S.order_lifecycle_enabled
        object.__setattr__(self.S, "order_lifecycle_enabled", True)
        self.addCleanup(
            lambda: object.__setattr__(self.S, "order_lifecycle_enabled", self._orig_flag)
        )

        # Seed: alice has 3 orders, bob has 1.
        _seed_order(self.table, "o1", "alice", "pending_payment", "2026-01-01T00:00:00")
        _seed_order(self.table, "o2", "alice", "completed", "2026-01-02T00:00:00")
        _seed_order(self.table, "o3", "alice", "pending_payment", "2026-01-03T00:00:00")
        _seed_order(self.table, "o4", "bob", "pending_payment", "2026-01-01T12:00:00")

    def _ctx(self, sub="alice", role="user"):
        return {"user_sub": sub, "role": role}

    def _call(self, **kwargs):
        kwargs.setdefault("user_id", None)
        kwargs.setdefault("status", None)
        kwargs.setdefault("limit", 50)
        kwargs.setdefault("cursor", None)
        ctx = kwargs.pop("ctx", self._ctx())
        return asyncio.run(self.router.list_orders_endpoint(ctx=ctx, **kwargs))

    # -- service-level --------------------------------------------------------

    def test_service_lists_user_orders(self):
        headers, cursor = self.order_store.list_orders(user_id="alice")
        ids = {h["order_id"] for h in headers}
        self.assertEqual(ids, {"o1", "o2", "o3"})
        self.assertIsNone(cursor)

    def test_service_newest_first(self):
        headers, _ = self.order_store.list_orders(user_id="alice")
        self.assertEqual([h["order_id"] for h in headers], ["o3", "o2", "o1"])

    def test_service_status_filter(self):
        headers, _ = self.order_store.list_orders(status="pending_payment")
        ids = {h["order_id"] for h in headers}
        self.assertEqual(ids, {"o1", "o3", "o4"})

    def test_service_status_plus_user(self):
        headers, _ = self.order_store.list_orders(user_id="alice", status="pending_payment")
        ids = {h["order_id"] for h in headers}
        self.assertEqual(ids, {"o1", "o3"})

    def test_service_requires_scope(self):
        with self.assertRaises(ValueError):
            self.order_store.list_orders()

    def test_service_pagination_cursor(self):
        page1, cursor = self.order_store.list_orders(user_id="alice", limit=2)
        self.assertEqual(len(page1), 2)
        self.assertIsNotNone(cursor)
        page2, cursor2 = self.order_store.list_orders(user_id="alice", limit=2, cursor=cursor)
        self.assertEqual(len(page2), 1)
        all_ids = {h["order_id"] for h in page1} | {h["order_id"] for h in page2}
        self.assertEqual(all_ids, {"o1", "o2", "o3"})

    # -- route-level ----------------------------------------------------------

    def test_route_user_lists_own(self):
        out = self._call(ctx=self._ctx("alice"))
        self.assertEqual({o.order_id for o in out.orders}, {"o1", "o2", "o3"})

    def test_route_user_id_param_ignored_for_non_admin(self):
        # Non-admin passing user_id=bob still only sees alice's orders.
        out = self._call(ctx=self._ctx("alice"), user_id="bob")
        self.assertEqual({o.order_id for o in out.orders}, {"o1", "o2", "o3"})

    def test_route_admin_cross_user(self):
        out = self._call(ctx=self._ctx("root", "root"), user_id="bob")
        self.assertEqual({o.order_id for o in out.orders}, {"o4"})

    def test_route_admin_status_only(self):
        out = self._call(ctx=self._ctx("root", "root"), status="completed")
        self.assertEqual({o.order_id for o in out.orders}, {"o2"})

    def test_route_admin_unscoped_400(self):
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as cm:
            self._call(ctx=self._ctx("root", "root"))
        self.assertEqual(cm.exception.status_code, 400)

    def test_route_pagination(self):
        out1 = self._call(ctx=self._ctx("alice"), limit=2)
        self.assertEqual(len(out1.orders), 2)
        self.assertIsNotNone(out1.next_cursor)
        out2 = self._call(ctx=self._ctx("alice"), limit=2, cursor=out1.next_cursor)
        self.assertEqual(len(out2.orders), 1)

    def test_route_flag_off_503(self):
        from fastapi import HTTPException

        object.__setattr__(self.S, "order_lifecycle_enabled", False)
        with self.assertRaises(HTTPException) as cm:
            self._call(ctx=self._ctx("alice"))
        self.assertEqual(cm.exception.status_code, 503)


if __name__ == "__main__":
    unittest.main()

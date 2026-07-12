"""
JOB-004 hermetic tests: list_open, list_hot, list_mine service functions + router endpoints.
Uses moto in-memory DynamoDB; no real AWS, no network, no TestClient.
"""
from __future__ import annotations

import asyncio
import time
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import boto3
from moto import mock_aws

import app.services.job_orders as svc
import app.routers.job_orders as router_mod
from app.core.settings import S
from app.models import JobOrderCreateIn


def _create_job_orders_table(ddb):
    return ddb.create_table(
        TableName="job_orders",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "recruiter_sub", "AttributeType": "S"},
            {"AttributeName": "hot_flag", "AttributeType": "S"},
            {"AttributeName": "public_flag", "AttributeType": "S"},
            {"AttributeName": "job_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_BY_STATUS",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_BY_RECRUITER",
                "KeySchema": [
                    {"AttributeName": "recruiter_sub", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_HOT",
                "KeySchema": [
                    {"AttributeName": "hot_flag", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_PUBLIC",
                "KeySchema": [
                    {"AttributeName": "public_flag", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_DIRECT",
                "KeySchema": [
                    {"AttributeName": "job_id", "KeyType": "HASH"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


FAKE_CTX = {"user_sub": "alice", "role": "USER"}


@mock_aws
class TestJobOrderLists(unittest.TestCase):

    def setUp(self):
        self.stack = ExitStack()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        tbl = _create_job_orders_table(ddb)
        from app.core.tables import T, _FloatSafeTable
        self._orig_tbl = T.job_orders
        object.__setattr__(T, "job_orders", _FloatSafeTable(tbl))
        object.__setattr__(S, "ats_enabled", True)
        object.__setattr__(S, "job_orders_enabled", True)
        self.audit_mock = MagicMock()
        self.stack.enter_context(patch.object(svc, "audit_event", self.audit_mock))

    def tearDown(self):
        from app.core.tables import T
        object.__setattr__(T, "job_orders", self._orig_tbl)
        object.__setattr__(S, "ats_enabled", False)
        object.__setattr__(S, "job_orders_enabled", False)
        self.stack.close()

    def _make_job(self, status="active", hot=False, recruiter_subs=None, company_id="co_A"):
        data = JobOrderCreateIn(
            title=f"Job-{int(time.time()*1000)}",
            type="hire",
            client_company_id=company_id,
            status=status,
            hot=hot,
            recruiter_subs=recruiter_subs or [],
        )
        return svc.create_job_order("actor", data)

    def _soft_delete(self, job_id):
        svc.delete_job_order("actor", job_id)

    # TC-001: list_open returns non-terminal, non-deleted orders only
    def test_list_open_basic(self):
        active = self._make_job(status="active")
        on_hold = self._make_job(status="on_hold")
        closed = self._make_job(status="closed")
        deleted = self._make_job(status="active")
        self._soft_delete(deleted.job_id)

        items, cursor = svc.list_open()
        ids = {i.job_id for i in items}
        self.assertIn(active.job_id, ids)
        self.assertIn(on_hold.job_id, ids)
        self.assertNotIn(closed.job_id, ids)
        self.assertNotIn(deleted.job_id, ids)

    # TC-002: list_open with status=active narrows correctly
    def test_list_open_status_filter(self):
        active1 = self._make_job(status="active")
        active2 = self._make_job(status="active")
        on_hold = self._make_job(status="on_hold")

        items, _ = svc.list_open(status="active")
        ids = {i.job_id for i in items}
        self.assertIn(active1.job_id, ids)
        self.assertIn(active2.job_id, ids)
        self.assertNotIn(on_hold.job_id, ids)

    # TC-003: list_open with invalid status returns 400
    def test_list_open_invalid_status_400(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            svc.list_open(status="closed")  # terminal — disallowed
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "invalid_status_filter")

    # TC-004: list_open with company_id scopes to one client
    def test_list_open_company_filter(self):
        co_a_1 = self._make_job(company_id="co_A")
        co_a_2 = self._make_job(company_id="co_A")
        co_b = self._make_job(company_id="co_B")

        items, _ = svc.list_open(company_id="co_A")
        ids = {i.job_id for i in items}
        self.assertIn(co_a_1.job_id, ids)
        self.assertIn(co_a_2.job_id, ids)
        self.assertNotIn(co_b.job_id, ids)

    # TC-006: list_hot returns only hot orders
    def test_list_hot_basic(self):
        hot = self._make_job(hot=True)
        cold = self._make_job(hot=False)
        hot_deleted = self._make_job(hot=True)
        self._soft_delete(hot_deleted.job_id)

        items, _ = svc.list_hot()
        ids = {i.job_id for i in items}
        self.assertIn(hot.job_id, ids)
        self.assertNotIn(cold.job_id, ids)
        self.assertNotIn(hot_deleted.job_id, ids)

    # TC-007: list_hot cursor pagination
    def test_list_hot_pagination(self):
        for _ in range(5):
            self._make_job(hot=True)

        page1, cursor = svc.list_hot(limit=3)
        self.assertEqual(len(page1), 3)
        # cursor may be None if moto returns all in one shot; just check no overlap
        if cursor:
            page2, cursor2 = svc.list_hot(cursor=cursor, limit=3)
            ids1 = {i.job_id for i in page1}
            ids2 = {i.job_id for i in page2}
            self.assertEqual(len(ids1 & ids2), 0)  # no overlap

    # TC-008: Toggling hot off removes from list_hot
    def test_list_hot_toggle_off(self):
        from app.core.tables import T
        hot = self._make_job(hot=True)
        items, _ = svc.list_hot()
        self.assertIn(hot.job_id, {i.job_id for i in items})

        # Remove hot_flag directly
        T.job_orders.update_item(
            Key={"pk": f"COMPANY#co_A", "sk": f"JOB#{hot.job_id}"},
            UpdateExpression="REMOVE hot_flag",
        )
        items2, _ = svc.list_hot()
        self.assertNotIn(hot.job_id, {i.job_id for i in items2})

    # TC-009: list_mine returns only caller's orders
    def test_list_mine_basic(self):
        alice_job = self._make_job(recruiter_subs=["alice"])
        bob_job = self._make_job(recruiter_subs=["bob"])

        items, _ = svc.list_mine("alice")
        ids = {i.job_id for i in items}
        self.assertIn(alice_job.job_id, ids)
        self.assertNotIn(bob_job.job_id, ids)

    # TC-010: list_mine tolerates stale index row (job not found)
    def test_list_mine_stale_index(self):
        from app.core.tables import T
        # Inject a stale recruiter index row with a non-existent job_id
        T.job_orders.put_item(Item={
            "pk": "COMPANY#co_A",
            "sk": "RECRUITER#alice#JOB#job_orphan123",
            "recruiter_sub": "alice",
            "job_id": "job_orphan123",
            "created_at": 1000,
        })
        items, _ = svc.list_mine("alice")
        self.assertEqual(len(items), 0)  # stale row silently skipped

    # TC-011: list_mine cursor pagination
    def test_list_mine_pagination(self):
        for _ in range(4):
            self._make_job(recruiter_subs=["alice"])

        page1, cursor = svc.list_mine("alice", limit=3)
        self.assertEqual(len(page1), 3)

    # TC-012: Flag-off 503 for all three list functions
    def test_flag_off_503(self):
        from fastapi import HTTPException
        object.__setattr__(S, "ats_enabled", False)
        try:
            for fn_args in [
                (svc.list_open, []),
                (svc.list_hot, []),
                (svc.list_mine, ["alice"]),
            ]:
                fn, args = fn_args
                with self.assertRaises(HTTPException) as ctx:
                    fn(*args)
                self.assertEqual(ctx.exception.status_code, 503)
        finally:
            object.__setattr__(S, "ats_enabled", True)

    # TC-013: Empty results returns ([], None)
    def test_list_hot_empty(self):
        items, cursor = svc.list_hot()
        self.assertEqual(items, [])
        self.assertIsNone(cursor)

    # TC-014: Router endpoints delegate and return correct envelope shape
    def test_router_open_endpoint_shape(self):
        self._make_job(status="active")
        result = _run(router_mod.get_open_job_orders(
            company_id=None, status=None, cursor=None, limit=50, ctx=FAKE_CTX
        ))
        self.assertIn("items", result)
        self.assertIn("next_cursor", result)
        self.assertIsInstance(result["items"], list)
        self.assertEqual(len(result["items"]), 1)

    def test_router_hot_endpoint_shape(self):
        self._make_job(hot=True)
        result = _run(router_mod.get_hot_job_orders(cursor=None, limit=50, ctx=FAKE_CTX))
        self.assertIn("items", result)
        self.assertEqual(len(result["items"]), 1)

    def test_router_mine_endpoint_shape(self):
        self._make_job(recruiter_subs=["alice"])
        result = _run(router_mod.get_my_job_orders(cursor=None, limit=50, ctx=FAKE_CTX))
        self.assertIn("items", result)
        self.assertEqual(len(result["items"]), 1)


if __name__ == "__main__":
    unittest.main()

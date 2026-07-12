"""
JOB-005 hermetic tests: adjust_placed_count, get_openings_summary, openings endpoint.
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


FAKE_CTX = {"user_sub": "test_user", "role": "USER"}


@mock_aws
class TestJobOrderCounter(unittest.TestCase):

    def setUp(self):
        self.stack = ExitStack()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        tbl = _create_job_orders_table(ddb)
        from app.core.tables import T, _FloatSafeTable
        self._orig_tbl = T.job_orders
        object.__setattr__(T, "job_orders", _FloatSafeTable(tbl))
        object.__setattr__(S, "ats_enabled", True)
        object.__setattr__(S, "job_orders_enabled", True)
        object.__setattr__(S, "job_order_allow_reopen", True)
        self.audit_mock = MagicMock()
        self.stack.enter_context(patch.object(svc, "audit_event", self.audit_mock))

    def tearDown(self):
        from app.core.tables import T
        object.__setattr__(T, "job_orders", self._orig_tbl)
        object.__setattr__(S, "ats_enabled", False)
        object.__setattr__(S, "job_orders_enabled", False)
        self.stack.close()

    def _create_job(self, openings=3, status="active"):
        data = JobOrderCreateIn(
            title=f"Job-{int(time.time()*1000)}",
            type="hire",
            client_company_id="co_A",
            openings=openings,
            status=status,
        )
        out = svc.create_job_order("actor", data)
        return out.job_id, out

    def test_new_job_counter_zero(self):
        jid, out = self._create_job(openings=3)
        self.assertEqual(out.placed_count, 0)
        self.assertEqual(out.openings_remaining, 3)

    def test_adjust_increment_basic(self):
        jid, _ = self._create_job(openings=3)
        self.audit_mock.reset_mock()
        out = svc.adjust_placed_count(jid, +1, actor_sub="actor")
        self.assertEqual(out.placed_count, 1)
        self.assertEqual(out.openings_remaining, 2)
        # Audit emitted
        adjust_calls = [c for c in self.audit_mock.call_args_list if c[0][0] == "job_order.placement_adjusted"]
        self.assertEqual(len(adjust_calls), 1)
        self.assertEqual(adjust_calls[0][1]["delta"], 1)

    def test_adjust_decrement_basic(self):
        jid, _ = self._create_job(openings=3)
        svc.adjust_placed_count(jid, +1, actor_sub="actor")
        out = svc.adjust_placed_count(jid, -1, actor_sub="actor")
        self.assertEqual(out.placed_count, 0)
        self.assertEqual(out.openings_remaining, 3)

    def test_adjust_underflow_pre_flight(self):
        from fastapi import HTTPException
        jid, _ = self._create_job(openings=3)
        with self.assertRaises(HTTPException) as ctx:
            svc.adjust_placed_count(jid, -1, actor_sub="actor")
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "placed_count_underflow")

    def test_auto_full_on_last_placement(self):
        jid, _ = self._create_job(openings=2)
        svc.adjust_placed_count(jid, +1, actor_sub="actor")
        self.audit_mock.reset_mock()
        out = svc.adjust_placed_count(jid, +1, actor_sub="actor")
        self.assertEqual(out.placed_count, 2)
        self.assertEqual(out.status, "full")
        # status_changed audit emitted
        status_calls = [c for c in self.audit_mock.call_args_list if c[0][0] == "job_order.status_changed"]
        self.assertTrue(len(status_calls) >= 1)

    def test_auto_full_not_on_hold(self):
        jid, _ = self._create_job(openings=1, status="on_hold")
        out = svc.adjust_placed_count(jid, +1, actor_sub="actor")
        self.assertEqual(out.placed_count, 1)
        # status must NOT have changed to full
        self.assertEqual(out.status, "on_hold")

    def test_auto_full_openings_zero(self):
        jid, _ = self._create_job(openings=0, status="active")
        out = svc.adjust_placed_count(jid, +1, actor_sub="actor")
        self.assertEqual(out.placed_count, 1)
        self.assertEqual(out.status, "active")  # no auto-full

    def test_decrement_does_not_revert_full(self):
        jid, _ = self._create_job(openings=2)
        svc.adjust_placed_count(jid, +2, actor_sub="actor")
        out_before = svc.get_job_order(jid)
        self.assertEqual(out_before.status, "full")

        out = svc.adjust_placed_count(jid, -1, actor_sub="actor")
        self.assertEqual(out.placed_count, 1)
        self.assertEqual(out.openings_remaining, 1)
        self.assertEqual(out.status, "full")  # still full

    def test_summary_endpoint_values(self):
        jid, _ = self._create_job(openings=5)
        svc.adjust_placed_count(jid, +2, actor_sub="actor")
        summary = svc.get_openings_summary(jid)
        self.assertEqual(summary["openings"], 5)
        self.assertEqual(summary["placed_count"], 2)
        self.assertEqual(summary["openings_remaining"], 3)

    def test_summary_not_found(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            svc.get_openings_summary("job_nonexistent")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_openings_endpoint_status_200(self):
        jid, _ = self._create_job(openings=5)
        result = _run(router_mod.get_openings_summary_endpoint(
            job_id=jid, ctx=FAKE_CTX
        ))
        self.assertIn("openings", result)
        self.assertIn("placed_count", result)
        self.assertIn("openings_remaining", result)
        self.assertEqual(result["openings"], 5)

    def test_openings_endpoint_flag_off(self):
        from fastapi import HTTPException
        jid, _ = self._create_job()
        object.__setattr__(S, "ats_enabled", False)
        try:
            with self.assertRaises(HTTPException) as ctx:
                _run(router_mod.get_openings_summary_endpoint(job_id=jid, ctx=FAKE_CTX))
            self.assertEqual(ctx.exception.status_code, 503)
        finally:
            object.__setattr__(S, "ats_enabled", True)

    def test_adjust_candidate_ref_in_audit(self):
        jid, _ = self._create_job()
        self.audit_mock.reset_mock()
        svc.adjust_placed_count(jid, +1, actor_sub="actor", candidate_ref="cnd_abc123")
        adjust_calls = [c for c in self.audit_mock.call_args_list if c[0][0] == "job_order.placement_adjusted"]
        self.assertEqual(len(adjust_calls), 1)
        self.assertEqual(adjust_calls[0][1]["candidate_ref"], "cnd_abc123")

    def test_adjust_large_delta(self):
        jid, _ = self._create_job(openings=10)
        out = svc.adjust_placed_count(jid, +5, actor_sub="actor")
        self.assertEqual(out.placed_count, 5)
        self.assertEqual(out.openings_remaining, 5)

    def test_adjust_large_delta_auto_full(self):
        jid, _ = self._create_job(openings=3)
        out = svc.adjust_placed_count(jid, +3, actor_sub="actor")
        self.assertEqual(out.status, "full")

    def test_adjust_on_deleted_job(self):
        from fastapi import HTTPException
        jid, _ = self._create_job()
        svc.delete_job_order("actor", jid)
        with self.assertRaises(HTTPException) as ctx:
            svc.adjust_placed_count(jid, +1, actor_sub="actor")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_placed_count_projected_on_get(self):
        jid, _ = self._create_job(openings=5)
        svc.adjust_placed_count(jid, +2, actor_sub="actor")
        out = svc.get_job_order(jid)
        self.assertEqual(out.placed_count, 2)
        self.assertEqual(out.openings_remaining, 3)

    def test_flag_off_adjust(self):
        from fastapi import HTTPException
        jid, _ = self._create_job()
        object.__setattr__(S, "job_orders_enabled", False)
        try:
            with self.assertRaises(HTTPException) as ctx:
                svc.adjust_placed_count(jid, +1, actor_sub="actor")
            self.assertEqual(ctx.exception.status_code, 503)
        finally:
            object.__setattr__(S, "job_orders_enabled", True)

    def test_flag_off_summary(self):
        from fastapi import HTTPException
        jid, _ = self._create_job()
        object.__setattr__(S, "ats_enabled", False)
        try:
            with self.assertRaises(HTTPException) as ctx:
                svc.get_openings_summary(jid)
            self.assertEqual(ctx.exception.status_code, 503)
        finally:
            object.__setattr__(S, "ats_enabled", True)


if __name__ == "__main__":
    unittest.main()

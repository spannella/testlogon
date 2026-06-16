"""
JOB-002 hermetic tests: Job Order CRUD service + status state-machine.
Uses moto in-memory DynamoDB; no real AWS, no network, no TestClient.
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3
from moto import mock_aws

import app.services.job_orders as svc
from app.core import tables as tables_mod
from app.core.settings import S
from app.models import JobOrderCreateIn, JobOrderUpdateIn


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _safe_table_from_moto(table):
    from app.core.tables import _safe_table as _st
    from app.core.tables import _FloatSafeTable
    return _FloatSafeTable(table)


@mock_aws
class TestJobOrdersService(unittest.TestCase):

    def setUp(self):
        self.stack = ExitStack()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        tbl = _create_job_orders_table(ddb)
        from app.core.tables import T, _FloatSafeTable
        self._orig_tbl = T.job_orders
        object.__setattr__(T, "job_orders", _FloatSafeTable(tbl))

        # Enable flags
        object.__setattr__(S, "ats_enabled", True)
        object.__setattr__(S, "job_orders_enabled", True)
        object.__setattr__(S, "job_order_allow_reopen", True)

        # Patch audit_event
        self.audit_mock = MagicMock()
        self.stack.enter_context(
            patch.object(svc, "audit_event", self.audit_mock)
        )

    def tearDown(self):
        from app.core.tables import T
        object.__setattr__(T, "job_orders", self._orig_tbl)
        object.__setattr__(S, "ats_enabled", False)
        object.__setattr__(S, "job_orders_enabled", False)
        self.stack.close()

    def _make_job(self, **kwargs):
        defaults = dict(title="SRE", type="hire", client_company_id="co_A")
        defaults.update(kwargs)
        data = JobOrderCreateIn(**defaults)
        return svc.create_job_order("actor_sub", data)

    # --- create tests ---

    def test_create_basic(self):
        out = self._make_job()
        self.assertIsNotNone(out.job_id)
        self.assertTrue(out.job_id.startswith("job_"))
        self.assertEqual(out.placed_count, 0)
        self.assertEqual(out.openings_remaining, out.openings)
        self.assertEqual(out.status, "active")
        self.audit_mock.assert_called_once()
        call_args = self.audit_mock.call_args
        self.assertEqual(call_args[0][0], "job_order.created")

    def test_create_no_recruiter(self):
        out = self._make_job(recruiter_subs=[])
        self.assertEqual(out.recruiter_subs, [])
        self.assertEqual(out.openings_remaining, out.openings)

    def test_create_hot_sparse(self):
        from app.core.tables import T
        out_hot = self._make_job(hot=True)
        item = T.job_orders.query(
            IndexName="GSI_DIRECT",
            KeyConditionExpression=boto3.dynamodb.conditions.Key("job_id").eq(out_hot.job_id),
            Limit=1,
        )["Items"][0]
        self.assertEqual(item.get("hot_flag"), "1")
        self.assertTrue(out_hot.hot)

        out_cold = self._make_job(hot=False)
        item2 = T.job_orders.query(
            IndexName="GSI_DIRECT",
            KeyConditionExpression=boto3.dynamodb.conditions.Key("job_id").eq(out_cold.job_id),
            Limit=1,
        )["Items"][0]
        self.assertNotIn("hot_flag", item2)

    def test_create_public_sparse(self):
        from app.core.tables import T
        out_pub = self._make_job(public=True)
        item = T.job_orders.query(
            IndexName="GSI_DIRECT",
            KeyConditionExpression=boto3.dynamodb.conditions.Key("job_id").eq(out_pub.job_id),
            Limit=1,
        )["Items"][0]
        self.assertEqual(item.get("public_flag"), "1")

        out_priv = self._make_job(public=False)
        item2 = T.job_orders.query(
            IndexName="GSI_DIRECT",
            KeyConditionExpression=boto3.dynamodb.conditions.Key("job_id").eq(out_priv.job_id),
            Limit=1,
        )["Items"][0]
        self.assertNotIn("public_flag", item2)

    def test_create_invalid_type(self):
        from fastapi import HTTPException
        data = JobOrderCreateIn.__new__(JobOrderCreateIn)
        # Bypass validator by directly constructing model_fields
        # Use a valid model then check service-level guard
        # The Pydantic validator already blocks bad types, so test it
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            JobOrderCreateIn(title="T", type="bad_type", client_company_id="c1")

    def test_create_invalid_status(self):
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            JobOrderCreateIn(title="T", type="hire", client_company_id="c1", status="bad_status")

    # --- get tests ---

    def test_get_by_job_id(self):
        out = self._make_job()
        fetched = svc.get_job_order(out.job_id)
        self.assertEqual(fetched.job_id, out.job_id)
        self.assertEqual(fetched.title, "SRE")

    def test_get_not_found(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            svc.get_job_order("job_doesnotexist")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_get_soft_deleted(self):
        from fastapi import HTTPException
        out = self._make_job()
        svc.delete_job_order("actor_sub", out.job_id)
        with self.assertRaises(HTTPException) as ctx:
            svc.get_job_order(out.job_id)
        self.assertEqual(ctx.exception.status_code, 404)

    # --- update tests ---

    def test_update_title_only(self):
        out = self._make_job()
        old_updated_at = out.updated_at
        self.audit_mock.reset_mock()
        updated = svc.update_job_order("actor_sub", out.job_id, JobOrderUpdateIn(title="New Title"))
        self.assertEqual(updated.title, "New Title")
        self.assertGreaterEqual(updated.updated_at, old_updated_at)
        # audit for update
        audit_events = [c[0][0] for c in self.audit_mock.call_args_list]
        self.assertIn("job_order.updated", audit_events)

    def test_update_hot_toggle(self):
        from app.core.tables import T
        out = self._make_job(hot=False)
        svc.update_job_order("actor_sub", out.job_id, JobOrderUpdateIn(hot=True))
        item = T.job_orders.query(
            IndexName="GSI_DIRECT",
            KeyConditionExpression=boto3.dynamodb.conditions.Key("job_id").eq(out.job_id),
            Limit=1,
        )["Items"][0]
        self.assertEqual(item.get("hot_flag"), "1")

        # Now toggle off
        svc.update_job_order("actor_sub", out.job_id, JobOrderUpdateIn(hot=False))
        item2 = T.job_orders.query(
            IndexName="GSI_DIRECT",
            KeyConditionExpression=boto3.dynamodb.conditions.Key("job_id").eq(out.job_id),
            Limit=1,
        )["Items"][0]
        self.assertNotIn("hot_flag", item2)

    def test_update_recruiter_add(self):
        from app.core.tables import T
        out = self._make_job(recruiter_subs=["alice"])
        svc.update_job_order("actor_sub", out.job_id, JobOrderUpdateIn(recruiter_subs=["alice", "bob"]))
        # Check index row for bob exists
        cid = out.client_company_id
        resp = T.job_orders.get_item(Key={
            "pk": f"COMPANY#{cid}",
            "sk": f"RECRUITER#bob#JOB#{out.job_id}",
        })
        self.assertIn("Item", resp)

    def test_update_recruiter_remove(self):
        from app.core.tables import T
        out = self._make_job(recruiter_subs=["alice", "bob"])
        svc.update_job_order("actor_sub", out.job_id, JobOrderUpdateIn(recruiter_subs=["alice"]))
        cid = out.client_company_id
        resp = T.job_orders.get_item(Key={
            "pk": f"COMPANY#{cid}",
            "sk": f"RECRUITER#bob#JOB#{out.job_id}",
        })
        self.assertNotIn("Item", resp)

    def test_update_recruiter_swap(self):
        from app.core.tables import T
        out = self._make_job(recruiter_subs=["alice"])
        svc.update_job_order("actor_sub", out.job_id, JobOrderUpdateIn(recruiter_subs=["carol"]))
        cid = out.client_company_id
        # alice removed
        resp_alice = T.job_orders.get_item(Key={
            "pk": f"COMPANY#{cid}",
            "sk": f"RECRUITER#alice#JOB#{out.job_id}",
        })
        self.assertNotIn("Item", resp_alice)
        # carol added
        resp_carol = T.job_orders.get_item(Key={
            "pk": f"COMPANY#{cid}",
            "sk": f"RECRUITER#carol#JOB#{out.job_id}",
        })
        self.assertIn("Item", resp_carol)

    def test_update_status_delegates(self):
        out = self._make_job()
        self.assertEqual(out.status, "active")
        updated = svc.update_job_order("actor_sub", out.job_id, JobOrderUpdateIn(status="on_hold"))
        self.assertEqual(updated.status, "on_hold")

    # --- set_status tests ---

    def test_set_status_lead_to_active(self):
        out = self._make_job(status="lead")
        result = svc.set_status("actor_sub", out.job_id, "active")
        self.assertEqual(result.status, "active")

    def test_set_status_upcoming_to_active(self):
        out = self._make_job(status="upcoming")
        result = svc.set_status("actor_sub", out.job_id, "active")
        self.assertEqual(result.status, "active")

    def test_set_status_active_on_hold_active(self):
        out = self._make_job()
        r1 = svc.set_status("actor_sub", out.job_id, "on_hold")
        self.assertEqual(r1.status, "on_hold")
        r2 = svc.set_status("actor_sub", out.job_id, "active")
        self.assertEqual(r2.status, "active")

    def test_set_status_active_to_full(self):
        out = self._make_job()
        r = svc.set_status("actor_sub", out.job_id, "full")
        self.assertEqual(r.status, "full")

    def test_set_status_active_to_closed(self):
        out = self._make_job()
        r = svc.set_status("actor_sub", out.job_id, "closed")
        self.assertEqual(r.status, "closed")

    def test_set_status_active_to_canceled(self):
        out = self._make_job()
        r = svc.set_status("actor_sub", out.job_id, "canceled")
        self.assertEqual(r.status, "canceled")

    def test_set_status_on_hold_to_closed(self):
        out = self._make_job()
        svc.set_status("actor_sub", out.job_id, "on_hold")
        r = svc.set_status("actor_sub", out.job_id, "closed")
        self.assertEqual(r.status, "closed")

    def test_set_status_full_to_canceled(self):
        out = self._make_job()
        svc.set_status("actor_sub", out.job_id, "full")
        r = svc.set_status("actor_sub", out.job_id, "canceled")
        self.assertEqual(r.status, "canceled")

    def test_set_status_same_noop(self):
        out = self._make_job()
        self.audit_mock.reset_mock()
        r = svc.set_status("actor_sub", out.job_id, "active")
        self.assertEqual(r.status, "active")
        # No audit event for no-op
        status_change_calls = [
            c for c in self.audit_mock.call_args_list
            if c[0][0] == "job_order.status_changed"
        ]
        self.assertEqual(len(status_change_calls), 0)

    def test_set_status_lead_to_full_rejected(self):
        from fastapi import HTTPException
        out = self._make_job(status="lead")
        with self.assertRaises(HTTPException) as ctx:
            svc.set_status("actor_sub", out.job_id, "full")
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "invalid_status_transition")

    def test_set_status_closed_to_active_reopen(self):
        out = self._make_job()
        svc.set_status("actor_sub", out.job_id, "closed")
        object.__setattr__(S, "job_order_allow_reopen", True)
        r = svc.set_status("actor_sub", out.job_id, "active")
        self.assertEqual(r.status, "active")

    def test_set_status_closed_to_active_reopen_disabled(self):
        from fastapi import HTTPException
        out = self._make_job()
        svc.set_status("actor_sub", out.job_id, "closed")
        object.__setattr__(S, "job_order_allow_reopen", False)
        try:
            with self.assertRaises(HTTPException) as ctx:
                svc.set_status("actor_sub", out.job_id, "active")
            self.assertEqual(ctx.exception.status_code, 409)
            self.assertEqual(ctx.exception.detail["code"], "reopen_not_allowed")
        finally:
            object.__setattr__(S, "job_order_allow_reopen", True)

    def test_set_status_closed_to_on_hold_rejected(self):
        from fastapi import HTTPException
        out = self._make_job()
        svc.set_status("actor_sub", out.job_id, "closed")
        with self.assertRaises(HTTPException) as ctx:
            svc.set_status("actor_sub", out.job_id, "on_hold")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_set_status_canceled_any_rejected(self):
        from fastapi import HTTPException
        out = self._make_job()
        svc.set_status("actor_sub", out.job_id, "canceled")
        for target in ("active", "closed", "on_hold"):
            with self.assertRaises(HTTPException) as ctx:
                svc.set_status("actor_sub", out.job_id, target)
            self.assertEqual(ctx.exception.status_code, 409)
            self.assertEqual(ctx.exception.detail["code"], "invalid_status_transition")

    def test_set_status_unknown_value(self):
        from fastapi import HTTPException
        out = self._make_job()
        with self.assertRaises(HTTPException) as ctx:
            svc.set_status("actor_sub", out.job_id, "nonexistent_status")
        self.assertEqual(ctx.exception.status_code, 422)

    # --- delete tests ---

    def test_delete_soft(self):
        from app.core.tables import T
        from fastapi import HTTPException
        out = self._make_job(recruiter_subs=["alice"])
        self.audit_mock.reset_mock()
        svc.delete_job_order("actor_sub", out.job_id)

        # get_job_order should now 404
        with self.assertRaises(HTTPException) as ctx:
            svc.get_job_order(out.job_id)
        self.assertEqual(ctx.exception.status_code, 404)

        # META row still exists with deleted_at
        item = T.job_orders.query(
            IndexName="GSI_DIRECT",
            KeyConditionExpression=boto3.dynamodb.conditions.Key("job_id").eq(out.job_id),
            Limit=1,
        )["Items"][0]
        self.assertIn("deleted_at", item)

        # Recruiter index row deleted
        cid = out.client_company_id
        resp = T.job_orders.get_item(Key={
            "pk": f"COMPANY#{cid}",
            "sk": f"RECRUITER#alice#JOB#{out.job_id}",
        })
        self.assertNotIn("Item", resp)

        # Audit emitted
        audit_events = [c[0][0] for c in self.audit_mock.call_args_list]
        self.assertIn("job_order.deleted", audit_events)

    def test_delete_twice(self):
        from fastapi import HTTPException
        out = self._make_job()
        svc.delete_job_order("actor_sub", out.job_id)
        with self.assertRaises(HTTPException) as ctx:
            svc.delete_job_order("actor_sub", out.job_id)
        self.assertEqual(ctx.exception.status_code, 404)

    # --- flag-off tests ---

    def test_flag_off_ats(self):
        from fastapi import HTTPException
        object.__setattr__(S, "ats_enabled", False)
        try:
            data = JobOrderCreateIn(title="T", type="hire", client_company_id="c1")
            with self.assertRaises(HTTPException) as ctx:
                svc.create_job_order("actor_sub", data)
            self.assertEqual(ctx.exception.status_code, 503)
        finally:
            object.__setattr__(S, "ats_enabled", True)

    def test_flag_off_job_orders(self):
        from fastapi import HTTPException
        object.__setattr__(S, "job_orders_enabled", False)
        try:
            data = JobOrderCreateIn(title="T", type="hire", client_company_id="c1")
            for fn, args in [
                (svc.create_job_order, ("a", data)),
                (svc.get_job_order, ("job_fake",)),
                (svc.delete_job_order, ("a", "job_fake")),
                (svc.set_status, ("a", "job_fake", "active")),
                (svc.get_openings_summary, ("job_fake",)),
            ]:
                with self.assertRaises(HTTPException) as ctx:
                    fn(*args)
                self.assertEqual(ctx.exception.status_code, 503)
        finally:
            object.__setattr__(S, "job_orders_enabled", True)

    def test_audit_events(self):
        out = self._make_job()
        # create audit
        create_calls = [c for c in self.audit_mock.call_args_list if c[0][0] == "job_order.created"]
        self.assertEqual(len(create_calls), 1)
        self.assertEqual(create_calls[0][1]["job_id"], out.job_id)

        self.audit_mock.reset_mock()
        svc.update_job_order("actor_sub", out.job_id, JobOrderUpdateIn(title="X"))
        update_calls = [c for c in self.audit_mock.call_args_list if c[0][0] == "job_order.updated"]
        self.assertEqual(len(update_calls), 1)

        self.audit_mock.reset_mock()
        svc.set_status("actor_sub", out.job_id, "on_hold")
        status_calls = [c for c in self.audit_mock.call_args_list if c[0][0] == "job_order.status_changed"]
        self.assertEqual(len(status_calls), 1)
        self.assertEqual(status_calls[0][1]["from_status"], "active")
        self.assertEqual(status_calls[0][1]["to_status"], "on_hold")

        self.audit_mock.reset_mock()
        svc.delete_job_order("actor_sub", out.job_id)
        del_calls = [c for c in self.audit_mock.call_args_list if c[0][0] == "job_order.deleted"]
        self.assertEqual(len(del_calls), 1)


if __name__ == "__main__":
    unittest.main()

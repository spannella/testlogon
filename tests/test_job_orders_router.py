"""
JOB-003 hermetic tests: Job Order router handlers called directly (no TestClient).
Uses moto in-memory DynamoDB; no real AWS, no network.
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import boto3
from moto import mock_aws

import app.services.job_orders as svc
import app.routers.job_orders as router_mod
from app.core import tables as tables_mod
from app.core.settings import S
from app.models import JobOrderCreateIn, JobOrderUpdateIn


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


FAKE_SESSION = {"user_sub": "test_user", "role": "USER"}


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


@mock_aws
class TestJobOrdersRouter(unittest.TestCase):

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

    def _create(self, **kwargs):
        defaults = dict(title="SRE", type="hire", client_company_id="co_A")
        defaults.update(kwargs)
        body = JobOrderCreateIn(**defaults)
        return _run(router_mod.create_job_order(body=body, session=FAKE_SESSION))

    # 1. create returns JobOrderOut with expected fields
    def test_create_returns_job_out(self):
        out = self._create()
        self.assertIsNotNone(out.job_id)
        self.assertEqual(out.status, "active")
        self.assertEqual(out.placed_count, 0)
        self.assertEqual(out.openings_remaining, out.openings)

    # 2. get returns 200
    def test_get_returns_200(self):
        created = self._create()
        fetched = _run(router_mod.get_job_order(job_id=created.job_id, session=FAKE_SESSION))
        self.assertEqual(fetched.job_id, created.job_id)
        self.assertEqual(fetched.title, "SRE")

    # 3. get unknown → 404
    def test_get_unknown_raises_404(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            _run(router_mod.get_job_order(job_id="job_notfound", session=FAKE_SESSION))
        self.assertEqual(ctx.exception.status_code, 404)

    # 4. patch updates field
    def test_patch_updates_field(self):
        created = self._create()
        body = JobOrderUpdateIn(title="Updated Title")
        updated = _run(router_mod.update_job_order(
            job_id=created.job_id, body=body, session=FAKE_SESSION
        ))
        self.assertEqual(updated.title, "Updated Title")

    # 5. patch unknown → 404
    def test_patch_unknown_raises_404(self):
        from fastapi import HTTPException
        body = JobOrderUpdateIn(title="X")
        with self.assertRaises(HTTPException) as ctx:
            _run(router_mod.update_job_order(job_id="job_fake", body=body, session=FAKE_SESSION))
        self.assertEqual(ctx.exception.status_code, 404)

    # 6. set_status legal transition
    def test_set_status_legal_transition(self):
        created = self._create()
        from app.routers.job_orders import SetStatusIn
        body = SetStatusIn(status="on_hold")
        result = _run(router_mod.set_job_order_status(
            job_id=created.job_id, body=body, session=FAKE_SESSION
        ))
        self.assertEqual(result.status, "on_hold")

    # 7. set_status illegal transition → 409
    def test_set_status_illegal_transition_returns_409(self):
        from fastapi import HTTPException
        from app.routers.job_orders import SetStatusIn
        created = self._create()
        _run(router_mod.set_job_order_status(
            job_id=created.job_id, body=SetStatusIn(status="closed"), session=FAKE_SESSION
        ))
        with self.assertRaises(HTTPException) as ctx:
            _run(router_mod.set_job_order_status(
                job_id=created.job_id, body=SetStatusIn(status="full"), session=FAKE_SESSION
            ))
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "invalid_status_transition")

    # 8. delete returns 204 then GET → 404
    def test_delete_returns_204(self):
        from fastapi import HTTPException
        created = self._create()
        resp = _run(router_mod.delete_job_order(job_id=created.job_id, session=FAKE_SESSION))
        self.assertEqual(resp.status_code, 204)
        with self.assertRaises(HTTPException) as ctx:
            _run(router_mod.get_job_order(job_id=created.job_id, session=FAKE_SESSION))
        self.assertEqual(ctx.exception.status_code, 404)

    # 9. flag off → 503 on all endpoints
    def test_flag_off_all_endpoints_503(self):
        from fastapi import HTTPException
        object.__setattr__(S, "ats_enabled", False)
        try:
            created_job_id = "job_fake"
            from app.models import JobOrderCreateIn, JobOrderUpdateIn
            from app.routers.job_orders import SetStatusIn

            endpoints = [
                (router_mod.create_job_order, {"body": JobOrderCreateIn(title="T", type="hire", client_company_id="c1"), "session": FAKE_SESSION}),
                (router_mod.get_job_order, {"job_id": created_job_id, "session": FAKE_SESSION}),
                (router_mod.update_job_order, {"job_id": created_job_id, "body": JobOrderUpdateIn(), "session": FAKE_SESSION}),
                (router_mod.set_job_order_status, {"job_id": created_job_id, "body": SetStatusIn(status="active"), "session": FAKE_SESSION}),
                (router_mod.delete_job_order, {"job_id": created_job_id, "session": FAKE_SESSION}),
            ]
            for fn, kwargs in endpoints:
                with self.assertRaises(HTTPException) as ctx:
                    _run(fn(**kwargs))
                self.assertEqual(ctx.exception.status_code, 503, f"Expected 503 from {fn.__name__}")
                self.assertEqual(ctx.exception.detail["code"], "job_orders_disabled")
        finally:
            object.__setattr__(S, "ats_enabled", True)

    # 10. feature_status always returns regardless of flags
    def test_feature_status_always_returns(self):
        # flags on
        result = _run(router_mod.feature_status())
        self.assertIn("ats_enabled", result)
        self.assertIn("job_orders_enabled", result)
        self.assertTrue(result["ats_enabled"])

        # flags off
        object.__setattr__(S, "ats_enabled", False)
        object.__setattr__(S, "job_orders_enabled", False)
        try:
            result2 = _run(router_mod.feature_status())
            self.assertFalse(result2["ats_enabled"])
            self.assertFalse(result2["job_orders_enabled"])
        finally:
            object.__setattr__(S, "ats_enabled", True)
            object.__setattr__(S, "job_orders_enabled", True)

    # 11. audit emitted on create
    def test_audit_event_emitted_on_create(self):
        self._create()
        create_calls = [c for c in self.audit_mock.call_args_list if c[0][0] == "job_order.created"]
        self.assertEqual(len(create_calls), 1)

    # 12. audit emitted on delete
    def test_audit_event_emitted_on_delete(self):
        created = self._create()
        self.audit_mock.reset_mock()
        _run(router_mod.delete_job_order(job_id=created.job_id, session=FAKE_SESSION))
        del_calls = [c for c in self.audit_mock.call_args_list if c[0][0] == "job_order.deleted"]
        self.assertEqual(len(del_calls), 1)


if __name__ == "__main__":
    unittest.main()

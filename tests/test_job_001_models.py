"""
JOB-001 hermetic tests: Pydantic models, constants, settings defaults.
No DynamoDB, no AWS, no network — pure model instantiation.
"""
from __future__ import annotations

import os
import unittest

import boto3
from moto import mock_aws
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestJobOrderModels(unittest.TestCase):

    def _import_models(self):
        from app.models import (
            JOB_ORDER_STATUSES,
            JOB_ORDER_TERMINAL,
            JOB_ORDER_TYPES,
            JobOrderCreateIn,
            JobOrderListOut,
            JobOrderOut,
            JobOrderUpdateIn,
        )
        return (
            JOB_ORDER_TYPES, JOB_ORDER_STATUSES, JOB_ORDER_TERMINAL,
            JobOrderCreateIn, JobOrderUpdateIn, JobOrderOut, JobOrderListOut,
        )

    def test_create_in_valid_hire(self):
        _, _, _, JobOrderCreateIn, _, _, _ = self._import_models()
        obj = JobOrderCreateIn(title="SRE", type="hire", client_company_id="c1")
        self.assertEqual(obj.status, "active")
        self.assertEqual(obj.openings, 1)
        self.assertFalse(obj.hot)
        self.assertFalse(obj.public)
        self.assertEqual(obj.recruiter_subs, [])

    def test_create_in_valid_all_types(self):
        JOB_ORDER_TYPES, _, _, JobOrderCreateIn, _, _, _ = self._import_models()
        for t in JOB_ORDER_TYPES:
            obj = JobOrderCreateIn(title="T", type=t, client_company_id="c1")
            self.assertEqual(obj.type, t)

    def test_create_in_invalid_type(self):
        _, _, _, JobOrderCreateIn, _, _, _ = self._import_models()
        with self.assertRaises(ValidationError) as ctx:
            JobOrderCreateIn(title="T", type="freelance", client_company_id="c1")
        self.assertIn("type must be one of", str(ctx.exception))

    def test_create_in_valid_statuses(self):
        _, JOB_ORDER_STATUSES, _, JobOrderCreateIn, _, _, _ = self._import_models()
        for s in JOB_ORDER_STATUSES:
            obj = JobOrderCreateIn(title="T", type="hire", client_company_id="c1", status=s)
            self.assertEqual(obj.status, s)

    def test_create_in_invalid_status(self):
        _, _, _, JobOrderCreateIn, _, _, _ = self._import_models()
        with self.assertRaises(ValidationError) as ctx:
            JobOrderCreateIn(title="T", type="hire", client_company_id="c1", status="fired")
        self.assertIn("status must be one of", str(ctx.exception))

    def test_create_in_title_too_long(self):
        _, _, _, JobOrderCreateIn, _, _, _ = self._import_models()
        with self.assertRaises(ValidationError):
            JobOrderCreateIn(title="x" * 256, type="hire", client_company_id="c1")

    def test_create_in_openings_negative(self):
        _, _, _, JobOrderCreateIn, _, _, _ = self._import_models()
        with self.assertRaises(ValidationError):
            JobOrderCreateIn(title="T", type="hire", client_company_id="c1", openings=-1)

    def test_create_in_openings_exceeds_max(self):
        _, _, _, JobOrderCreateIn, _, _, _ = self._import_models()
        with self.assertRaises(ValidationError):
            JobOrderCreateIn(title="T", type="hire", client_company_id="c1", openings=10001)

    def test_create_in_pay_rate_negative(self):
        _, _, _, JobOrderCreateIn, _, _, _ = self._import_models()
        with self.assertRaises(ValidationError):
            JobOrderCreateIn(title="T", type="hire", client_company_id="c1", pay_rate_cents=-100)

    def test_create_in_recruiter_subs_too_many(self):
        _, _, _, JobOrderCreateIn, _, _, _ = self._import_models()
        with self.assertRaises(ValidationError):
            JobOrderCreateIn(
                title="T", type="hire", client_company_id="c1",
                recruiter_subs=["s"] * 26,
            )

    def test_update_in_all_none(self):
        _, _, _, _, JobOrderUpdateIn, _, _ = self._import_models()
        obj = JobOrderUpdateIn()
        self.assertIsNone(obj.title)
        self.assertIsNone(obj.type)
        self.assertIsNone(obj.status)

    def test_update_in_invalid_type(self):
        _, _, _, _, JobOrderUpdateIn, _, _ = self._import_models()
        with self.assertRaises(ValidationError) as ctx:
            JobOrderUpdateIn(type="bad")
        self.assertIn("type must be one of", str(ctx.exception))

    def test_update_in_none_type_ok(self):
        _, _, _, _, JobOrderUpdateIn, _, _ = self._import_models()
        obj = JobOrderUpdateIn(type=None)
        self.assertIsNone(obj.type)

    def test_job_order_out_openings_remaining_field_exists(self):
        _, _, _, _, _, JobOrderOut, _ = self._import_models()
        self.assertIn("openings_remaining", JobOrderOut.model_fields)
        self.assertIn("placed_count", JobOrderOut.model_fields)

    def test_settings_defaults_false(self):
        # Must be tested in a clean environment (no ATS_ENABLED set)
        env_bak = os.environ.pop("ATS_ENABLED", None)
        env_bak2 = os.environ.pop("JOB_ORDERS_ENABLED", None)
        try:
            from app.core.settings import S
            self.assertFalse(S.ats_enabled)
            self.assertFalse(S.job_orders_enabled)
        finally:
            if env_bak is not None:
                os.environ["ATS_ENABLED"] = env_bak
            if env_bak2 is not None:
                os.environ["JOB_ORDERS_ENABLED"] = env_bak2

    def test_settings_table_name_default(self):
        from app.core.settings import S
        self.assertEqual(S.job_orders_table_name, "job_orders")

    def test_job_order_terminal_constant(self):
        _, _, JOB_ORDER_TERMINAL, _, _, _, _ = self._import_models()
        self.assertIn("closed", JOB_ORDER_TERMINAL)
        self.assertIn("canceled", JOB_ORDER_TERMINAL)
        self.assertNotIn("active", JOB_ORDER_TERMINAL)

    def test_job_order_list_out(self):
        _, _, _, _, _, JobOrderOut, JobOrderListOut = self._import_models()
        lo = JobOrderListOut(items=[], next_cursor=None)
        self.assertEqual(lo.items, [])
        self.assertIsNone(lo.next_cursor)


@mock_aws
class TestJobOrderDDBTable(unittest.TestCase):
    """Test the DDB table can be created with the right GSIs and attr_types."""

    def setUp(self):
        import boto3
        self.ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = self.ddb.create_table(
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

    def test_table_created_with_gsi_count(self):
        desc = self.ddb.meta.client.describe_table(TableName="job_orders")
        gsis = desc["Table"].get("GlobalSecondaryIndexes", [])
        self.assertEqual(len(gsis), 5)

    def test_table_created_with_numeric_created_at(self):
        desc = self.ddb.meta.client.describe_table(TableName="job_orders")
        attrs = {a["AttributeName"]: a["AttributeType"] for a in desc["Table"]["AttributeDefinitions"]}
        self.assertEqual(attrs.get("created_at"), "N")

    def test_t_job_orders_handle_importable(self):
        from app.core.tables import T
        self.assertTrue(hasattr(T, "job_orders"))
        self.assertIsNotNone(T.job_orders)


if __name__ == "__main__":
    unittest.main()

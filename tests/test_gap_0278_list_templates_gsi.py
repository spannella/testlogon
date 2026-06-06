"""Offline regression test for GAP-0278 (KYC-017).

``KycDocumentTemplateService.list_templates`` used a full-table ``scan()`` with a
``FilterExpression`` on ``sk == VERSION#0`` and applied the status filter in
Python afterwards. The ``status-updated-index`` GSI (PK=status, SK=updated_at N)
was designed for exactly this query but was bypassed (only
``get_required_templates_for_tier`` used it).

The fix rewrites ``list_templates`` to ``query()`` the GSI:
  * when a status is supplied, one GSI partition is read;
  * when no status is supplied, every known status partition is queried and
    merged;
  * both paths paginate via ``LastEvaluatedKey`` and keep the same return shape
    (list of VERSION#0 metadata rows, newest ``updated_at`` first, capped by
    ``limit``).

This test is fully hermetic. We create a real in-memory moto table WITH the
``status-updated-index`` GSI and patch the exact ``T.kyc_document_templates``
handle (``T`` is a frozen dataclass, so we use ``object.__setattr__`` and
restore afterwards). A spy wraps ``.query`` / ``.scan`` so we can assert the GSI
path is taken and the scan path is never used.

FAILS BEFORE FIX: ``list_templates`` calls ``scan()`` (no ``query`` recorded),
so the GSI assertions fail.
PASSES AFTER FIX: the GSI query path is used and returns exactly the right
VERSION#0 metadata rows in newest-updated-first order.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_kyc_document_templates_table(ddb):
    """Mirror scripts/local-ddb-init.py kyc_document_templates TableDef."""
    return ddb.create_table(
        TableName="kyc_document_templates",
        KeySchema=[
            {"AttributeName": "template_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "template_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "slug", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "updated_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "slug-status-index",
                "KeySchema": [
                    {"AttributeName": "slug", "KeyType": "HASH"},
                    {"AttributeName": "status", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "status-updated-index",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "updated_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


class _OpSpy:
    """Wraps a moto table, recording every .query / .scan call (with kwargs)."""

    def __init__(self, table):
        self._table = table
        self.query_calls = []
        self.scan_calls = []

    def query(self, **kwargs):
        self.query_calls.append(kwargs)
        return self._table.query(**kwargs)

    def scan(self, **kwargs):
        self.scan_calls.append(kwargs)
        return self._table.scan(**kwargs)

    def __getattr__(self, name):
        return getattr(self._table, name)


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestListTemplatesStatusGsi(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        self.spy = _OpSpy(_make_kyc_document_templates_table(ddb))

        from app.core.tables import T

        self.T = T
        # T is a frozen dataclass — patch the handle via object.__setattr__ and
        # restore the original on cleanup.
        self._orig = T.kyc_document_templates
        object.__setattr__(T, "kyc_document_templates", self.spy)
        self.addCleanup(
            lambda: object.__setattr__(T, "kyc_document_templates", self._orig)
        )

        from app.services.kyc_document_templates import KycDocumentTemplateService

        # The service reads T.kyc_document_templates at __init__ — instantiate
        # AFTER the patch so it picks up the spy.
        self.svc = KycDocumentTemplateService()

    # -- seeding helpers ----------------------------------------------------

    def _seed_meta(self, template_id, slug, status, updated_at):
        """Seed a VERSION#0 metadata placeholder row."""
        self.spy.put_item(
            Item={
                "template_id": template_id,
                "sk": "VERSION#0",
                "version": 0,
                "slug": slug,
                "display_name": slug,
                "description": "",
                "status": status,
                "required_tier": "tier_1",
                "s3_key": "",
                "placeholder_fields": [],
                "latest_version": 0,
                "created_by": "admin",
                "created_at": updated_at,
                "updated_at": updated_at,
            }
        )

    def _seed_version(self, template_id, slug, status, updated_at, version):
        """Seed a non-metadata VERSION#n (n > 0) row (an uploaded PDF version)."""
        self.spy.put_item(
            Item={
                "template_id": template_id,
                "sk": f"VERSION#{version}",
                "version": version,
                "slug": slug,
                "display_name": slug,
                "status": status,
                "required_tier": "tier_1",
                "s3_key": f"templates/{template_id}/v{version}.pdf",
                "created_at": updated_at,
                "updated_at": updated_at,
            }
        )

    # -- status-filtered listing -------------------------------------------

    def test_list_templates_by_status_uses_status_gsi_not_scan(self):
        """FAILS BEFORE FIX: list_templates scans the table. PASSES AFTER FIX:
        it queries the status-updated-index GSI and returns only active metas."""
        self._seed_meta("kdt_a", "alpha", "active", 1000)
        self._seed_meta("kdt_b", "bravo", "active", 2000)
        self._seed_meta("kdt_c", "charlie", "inactive", 1500)
        self._seed_meta("kdt_d", "delta", "archived", 1700)

        result = self.svc.list_templates(status="active")

        self.assertTrue(
            self.spy.query_calls,
            "list_templates(status=...) must query the status-updated-index GSI",
        )
        self.assertEqual(
            self.spy.query_calls[0].get("IndexName"), "status-updated-index"
        )
        self.assertEqual(
            self.spy.scan_calls, [],
            "status-filtered listing must not fall back to a full-table scan",
        )

        ids = {i["template_id"] for i in result}
        self.assertEqual(ids, {"kdt_a", "kdt_b"})
        for meta in result:
            self.assertEqual(meta["status"], "active")
            self.assertEqual(int(meta["version"]), 0)

    def test_list_templates_newest_updated_first(self):
        """Result ordering is updated_at descending (newest first)."""
        self._seed_meta("kdt_old", "old", "active", 1000)
        self._seed_meta("kdt_new", "new", "active", 5000)
        self._seed_meta("kdt_mid", "mid", "active", 3000)

        result = self.svc.list_templates(status="active")

        order = [i["template_id"] for i in result]
        self.assertEqual(order, ["kdt_new", "kdt_mid", "kdt_old"])

    def test_list_templates_excludes_non_metadata_version_rows(self):
        """Only VERSION#0 metadata rows are returned, never uploaded versions."""
        self._seed_meta("kdt_a", "alpha", "active", 1000)
        self._seed_version("kdt_a", "alpha", "active", 1100, version=1)
        self._seed_version("kdt_a", "alpha", "active", 1200, version=2)

        result = self.svc.list_templates(status="active")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["template_id"], "kdt_a")
        self.assertEqual(int(result[0]["version"]), 0)
        self.assertEqual(self.spy.scan_calls, [])

    # -- all-status listing -------------------------------------------------

    def test_list_templates_all_statuses_queries_each_partition_no_scan(self):
        """status=None must query every status partition via the GSI, not scan."""
        self._seed_meta("kdt_a", "alpha", "active", 1000)
        self._seed_meta("kdt_c", "charlie", "inactive", 1500)
        self._seed_meta("kdt_d", "delta", "archived", 1700)

        result = self.svc.list_templates()

        self.assertEqual(
            self.spy.scan_calls, [],
            "no-status listing must not scan the full table",
        )
        # One query per known status partition (active, inactive, archived).
        self.assertGreaterEqual(len(self.spy.query_calls), 3)
        for kw in self.spy.query_calls:
            self.assertEqual(kw.get("IndexName"), "status-updated-index")

        ids = {i["template_id"] for i in result}
        self.assertEqual(ids, {"kdt_a", "kdt_c", "kdt_d"})

    def test_list_templates_respects_limit(self):
        """The limit cap is honoured after merge + sort."""
        for n in range(5):
            self._seed_meta(f"kdt_{n}", f"slug{n}", "active", 1000 + n)

        result = self.svc.list_templates(status="active", limit=2)

        self.assertEqual(len(result), 2)
        # Newest two by updated_at.
        self.assertEqual([i["template_id"] for i in result], ["kdt_4", "kdt_3"])
        self.assertEqual(self.spy.scan_calls, [])


if __name__ == "__main__":
    unittest.main()

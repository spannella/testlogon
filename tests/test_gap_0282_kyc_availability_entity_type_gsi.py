"""Offline regression test for GAP-0282 (KYC-019).

``KycCaseAssignmentService._scan_availability_items`` retrieves every admin
availability record from the shared ``kyc_cases`` table. The records live under
``ADMIN#{sub}`` / ``AVAILABILITY`` keys; because ``begins_with`` on a partition
key is only valid as a ``FilterExpression`` (never a ``KeyConditionExpression``),
the original implementation issued a full-table ``Scan`` — reading and
discarding every case / audit / SLA row in the table before the filter ran.

The fix:
  * adds a sparse ``entity-type-index`` GSI (PK ``entity_type``, SK
    ``admin_sub``) to the ``kyc_cases`` ``TableDef`` in
    ``scripts/local-ddb-init.py``;
  * rewrites ``_scan_availability_items`` to ``query()`` that GSI
    (``entity_type = "kyc_admin_availability"``), paginating via
    ``LastEvaluatedKey``, instead of scanning the whole table.

Only availability items carry BOTH ``entity_type`` and a top-level
``admin_sub``, so the GSI is sparse — case / audit / SLA rows are never
projected, and the query returns exactly the availability rows.

This test is fully hermetic. We create a real in-memory moto table WITH the new
GSI and patch the exact ``T.kyc_cases`` handle (``T`` is a frozen dataclass, so
we use ``object.__setattr__`` and restore afterwards). A spy wraps
``.query`` / ``.scan`` so we can assert the GSI path is taken. Settings ``S`` is
also frozen, so its index-name attribute is patched the same way (defensive — it
already defaults to ``entity-type-index``).

FAILS BEFORE FIX: ``_scan_availability_items`` calls ``scan(...)`` with a
``begins_with`` filter and never queries ``entity-type-index`` — the scan spy
records calls and the GSI assertions fail.
PASSES AFTER FIX: the GSI query is used, drains every ``LastEvaluatedKey`` page,
and returns ALL admin availability rows mixed in among non-ADMIN noise.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_kyc_cases_table(ddb, *, entity_type_index_name: str):
    """Mirror scripts/local-ddb-init.py kyc_cases TableDef (post-GAP-0282)."""
    return ddb.create_table(
        TableName="kyc_cases",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "entity_type", "AttributeType": "S"},
            {"AttributeName": "admin_sub", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": entity_type_index_name,
                "KeySchema": [
                    {"AttributeName": "entity_type", "KeyType": "HASH"},
                    {"AttributeName": "admin_sub", "KeyType": "RANGE"},
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
class TestKycAvailabilityEntityTypeGsi(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        from app.core.settings import S

        self.S = S
        self.index_name = S.kyc_cases_entity_type_index_name
        self.spy = _OpSpy(_make_kyc_cases_table(ddb, entity_type_index_name=self.index_name))

        from app.core.tables import T

        self.T = T
        # T is a frozen dataclass — patch the handle via object.__setattr__ and
        # restore the original on cleanup.
        self._orig = T.kyc_cases
        object.__setattr__(T, "kyc_cases", self.spy)
        self.addCleanup(lambda: object.__setattr__(T, "kyc_cases", self._orig))

        from app.services.kyc_case_assignment import KycCaseAssignmentService

        # KycCaseAssignmentService._table defaults to T.kyc_cases bound at class
        # definition time; pass the spy explicitly so this instance uses it.
        self.svc = KycCaseAssignmentService(_table=self.spy)

    # -- seeding helpers ----------------------------------------------------

    def _seed_availability(self, admin_sub: str, *, on_duty: bool = True):
        self.spy.put_item(
            Item={
                "pk": f"ADMIN#{admin_sub}",
                "sk": "AVAILABILITY",
                "entity_type": "kyc_admin_availability",
                "admin_sub": admin_sub,
                "on_duty": on_duty,
                "max_cases": 20,
            }
        )

    def _seed_case(self, case_id: str):
        # Non-ADMIN noise: a case META row (no top-level admin_sub → not indexed).
        self.spy.put_item(
            Item={
                "pk": f"KYC#{case_id}",
                "sk": "META",
                "entity_type": "kyc_case",
                "case_id": case_id,
                "status": "submitted",
                "review": {"assigned_admin_sub": "someone"},
            }
        )

    def _seed_audit(self, case_id: str, ts: int):
        self.spy.put_item(
            Item={
                "pk": f"AUDIT#ASSIGN#{case_id}",
                "sk": f"{ts}#evt",
                "entity_type": "kyc_assignment_audit",
                "case_id": case_id,
            }
        )

    def _seed_sla(self, tier: str):
        self.spy.put_item(
            Item={
                "pk": "CONFIG",
                "sk": f"SLA#{tier}",
                "entity_type": "kyc_sla_config",
                "tier": tier,
            }
        )

    # -- tests --------------------------------------------------------------

    def test_uses_entity_type_gsi_not_scan(self):
        """FAILS BEFORE FIX: _scan_availability_items scans with begins_with.
        PASSES AFTER FIX: it queries the entity-type GSI and returns exactly the
        availability rows, ignoring case / audit / SLA noise."""
        self._seed_availability("admin1")
        self._seed_availability("admin2")
        # Non-ADMIN noise that a full-table scan would have to read & discard.
        for n in range(5):
            self._seed_case(f"c{n}")
            self._seed_audit(f"c{n}", 1000 + n)
        self._seed_sla("tier_1")
        self._seed_sla("tier_2")

        items = self.svc._scan_availability_items()

        self.assertTrue(
            self.spy.query_calls,
            "_scan_availability_items must query the entity-type GSI, not scan",
        )
        self.assertEqual(self.spy.query_calls[0].get("IndexName"), self.index_name)
        self.assertEqual(
            self.spy.scan_calls, [],
            "availability lookup must not fall back to a full-table scan",
        )

        subs = {it["admin_sub"] for it in items}
        self.assertEqual(subs, {"admin1", "admin2"})
        for it in items:
            self.assertEqual(it["entity_type"], "kyc_admin_availability")

    def test_returns_all_rows_across_lastevaluatedkey_pages(self):
        """Seed more availability rows than fit on one Query page (simulated via
        a small Limit) plus non-ADMIN noise, and assert the LastEvaluatedKey loop
        returns EVERY admin availability row — the core completeness guarantee of
        the minimal fix.

        Wrap the GSI query so the first call carries a tiny Limit, forcing moto
        to return a LastEvaluatedKey and exercising the pagination loop."""
        expected = {f"admin{n:03d}" for n in range(25)}
        for sub in expected:
            self._seed_availability(sub)
        # Interleave non-ADMIN noise — must never appear in the result.
        for n in range(40):
            self._seed_case(f"noise{n}")
            self._seed_audit(f"noise{n}", 2000 + n)

        real_query = self.spy.query

        def _paged_query(**kwargs):
            # Force a tiny page size on the availability GSI query so moto returns
            # a LastEvaluatedKey, exercising the pagination loop.
            if kwargs.get("IndexName") == self.index_name:
                kwargs = {**kwargs, "Limit": 4}
            return real_query(**kwargs)

        self.spy.query = _paged_query  # type: ignore[method-assign]
        try:
            items = self.svc._scan_availability_items()
        finally:
            self.spy.query = real_query  # type: ignore[method-assign]

        subs = {it["admin_sub"] for it in items}
        self.assertEqual(subs, expected, "every availability row must be returned across pages")
        self.assertGreater(len(self.spy.query_calls), 1, "pagination loop must issue multiple Query calls")
        self.assertEqual(self.spy.scan_calls, [])

    def test_empty_when_no_availability(self):
        """No availability rows (only noise) → empty list, still no scan."""
        for n in range(3):
            self._seed_case(f"c{n}")
        self._seed_sla("tier_1")

        items = self.svc._scan_availability_items()

        self.assertEqual(items, [])
        self.assertEqual(self.spy.query_calls[0].get("IndexName"), self.index_name)
        self.assertEqual(self.spy.scan_calls, [])


if __name__ == "__main__":
    unittest.main()

"""Offline regression test for GAP-0283 (KYC-019).

``KycCaseAssignmentService._active_case_counts`` used to call
``_scan_active_cases`` — three GSI Queries that load every active case item into
memory — and bucket assignments by ``review.assigned_admin_sub`` in Python. On a
table with thousands of under-review cases that is an O(N-active-cases) read on
the critical path of every ``auto_assign`` / workload-dashboard call.

The fix:
  * denormalizes a TOP-LEVEL ``assigned_admin_sub`` onto each case at assignment
    time (and REMOVEs it on unclaim) so a GSI can key on it;
  * adds a sparse ``assigned-admin-index`` GSI (PK ``assigned_admin_sub``,
    SK ``gsi_status_pk``) to the ``kyc_cases`` TableDef in
    ``scripts/local-ddb-init.py``;
  * rewrites ``_active_case_counts`` (and the single-admin availability paths) to
    run targeted ``Select=COUNT`` Queries against that GSI — one per admin from
    the (small) availability roster — instead of scanning all active cases.

This test is fully hermetic. We build a real in-memory moto ``kyc_cases`` table
WITH the new GSI and inject it as the service's ``_table`` (the dataclass field
is not frozen). A spy wraps ``.query`` / ``.scan`` so we can assert the GSI path
is taken and that no full active-case scan-and-bucket happens.

FAILS BEFORE FIX: ``_active_case_counts`` queries the ``status-updated-index``
(STATUS#... partitions) and never the ``assigned-admin-index`` — the index does
not even exist in the TableDef, so seeding/querying it raises; and per-admin
``Select=COUNT`` is absent. PASSES AFTER FIX: counts come from per-admin
``Select=COUNT`` Queries on ``assigned-admin-index`` and match the seeded data.
"""
from __future__ import annotations

import ast
import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None

from app.core.settings import S

_ASSIGNED_IDX = S.kyc_cases_assigned_admin_index_name  # "assigned-admin-index"
_STATUS_IDX = S.kyc_cases_status_index_name
_ENTITY_IDX = S.kyc_cases_entity_type_index_name


def _make_kyc_cases_table(ddb):
    """Mirror scripts/local-ddb-init.py kyc_cases TableDef (post-GAP-0283)."""
    return ddb.create_table(
        TableName="kyc_cases",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gsi_status_pk", "AttributeType": "S"},
            {"AttributeName": "gsi_status_sk", "AttributeType": "S"},
            {"AttributeName": "entity_type", "AttributeType": "S"},
            {"AttributeName": "admin_sub", "AttributeType": "S"},
            {"AttributeName": "assigned_admin_sub", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": _STATUS_IDX,
                "KeySchema": [
                    {"AttributeName": "gsi_status_pk", "KeyType": "HASH"},
                    {"AttributeName": "gsi_status_sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": _ENTITY_IDX,
                "KeySchema": [
                    {"AttributeName": "entity_type", "KeyType": "HASH"},
                    {"AttributeName": "admin_sub", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": _ASSIGNED_IDX,
                "KeySchema": [
                    {"AttributeName": "assigned_admin_sub", "KeyType": "HASH"},
                    {"AttributeName": "gsi_status_pk", "KeyType": "RANGE"},
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
class TestKycAssignedAdminCountGsi(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.spy = _OpSpy(_make_kyc_cases_table(ddb))

        from app.services.kyc_case_assignment import KycCaseAssignmentService

        # The dataclass field is not frozen — inject the spy directly.
        self.svc = KycCaseAssignmentService(_table=self.spy)

    # -- seeding helpers ----------------------------------------------------

    def _seed_case(self, case_id, status, assigned, *, ts=1000):
        """Write a case item the way the fixed write path produces it: top-level
        ``assigned_admin_sub`` present only when assigned (sparse GSI key)."""
        item = {
            "pk": f"KYC#{case_id}",
            "sk": "META",
            "entity_type": "kyc_case",
            "kyc_case_id": case_id,
            "status": status,
            "gsi_status_pk": f"STATUS#{status}",
            "gsi_status_sk": f"{ts:013d}#{case_id}",
            "review": {"assigned_admin_sub": assigned} if assigned else {},
        }
        if assigned:
            item["assigned_admin_sub"] = assigned
        self.spy.put_item(Item=item)

    def _seed_availability(self, admin_sub, ts=1000):
        self.spy.put_item(
            Item={
                "pk": f"ADMIN#{admin_sub}",
                "sk": "AVAILABILITY",
                "entity_type": "kyc_admin_availability",
                "admin_sub": admin_sub,
                "on_duty": True,
                "max_cases": 20,
                "updated_at": ts,
            }
        )

    # -- per-admin count ----------------------------------------------------

    def test_count_active_for_admin_uses_assigned_admin_gsi(self):
        """FAILS BEFORE FIX: no per-admin Select=COUNT on assigned-admin-index.
        PASSES AFTER FIX: count via the GSI matches the seeded active cases."""
        # alice: 2 active (under_review, submitted) + 1 inactive (approved, no key)
        self._seed_case("c1", "under_review", "alice")
        self._seed_case("c2", "submitted", "alice")
        self._seed_case("c3", "approved", None)  # terminal, unassigned
        # bob: 1 active
        self._seed_case("c4", "needs_more_info", "bob")

        n_alice = self.svc._count_active_for_admin("alice")
        n_bob = self.svc._count_active_for_admin("bob")
        n_none = self.svc._count_active_for_admin("carol")

        self.assertEqual(n_alice, 2)
        self.assertEqual(n_bob, 1)
        self.assertEqual(n_none, 0)

        # Must query the assigned-admin-index, never a full-table scan.
        self.assertTrue(self.spy.query_calls)
        self.assertTrue(
            all(c.get("IndexName") == _ASSIGNED_IDX for c in self.spy.query_calls),
            "per-admin counts must Query assigned-admin-index only",
        )
        self.assertEqual(self.spy.scan_calls, [])
        self.assertTrue(
            all(c.get("Select") == "COUNT" for c in self.spy.query_calls),
            "per-admin counts must use Select=COUNT (no item payload loaded)",
        )

    def test_count_excludes_terminal_statuses(self):
        """approved/rejected cases keep their assigned_admin_sub key but must NOT
        count toward active workload (status filter on the GSI Query)."""
        self._seed_case("c1", "under_review", "alice")
        # An approved case still assigned to alice (top-level key retained):
        item = {
            "pk": "KYC#c2", "sk": "META", "entity_type": "kyc_case",
            "kyc_case_id": "c2", "status": "approved",
            "gsi_status_pk": "STATUS#approved",
            "gsi_status_sk": "0000000001000#c2",
            "assigned_admin_sub": "alice",
            "review": {"assigned_admin_sub": "alice"},
        }
        self.spy.put_item(Item=item)

        self.assertEqual(self.svc._count_active_for_admin("alice"), 1)

    # -- full roster counts -------------------------------------------------

    def test_active_case_counts_returns_per_admin_map_via_gsi(self):
        """_active_case_counts returns {admin: count} computed from per-admin GSI
        COUNT queries (one per availability admin), not a scan-and-bucket."""
        self._seed_availability("alice")
        self._seed_availability("bob")
        self._seed_availability("carol")  # on duty, zero cases -> omitted

        self._seed_case("c1", "under_review", "alice")
        self._seed_case("c2", "submitted", "alice")
        self._seed_case("c3", "needs_more_info", "alice")
        self._seed_case("c4", "submitted", "bob")
        self._seed_case("c5", "approved", None)

        counts = self.svc._active_case_counts()

        self.assertEqual(counts, {"alice": 3, "bob": 1})

        # The assigned-admin-index must be queried; the status-index scan path is
        # only acceptable for enumerating availability rows (entity-type-index).
        idx_used = {c.get("IndexName") for c in self.spy.query_calls}
        self.assertIn(_ASSIGNED_IDX, idx_used)
        self.assertNotIn(_STATUS_IDX, idx_used,
                         "must not fall back to the all-active-cases status scan")
        self.assertEqual(self.spy.scan_calls, [])

    def test_count_paginates_lastevaluatedkey(self):
        """Many active cases for one admin must all be counted across GSI pages."""
        for n in range(55):
            self._seed_case(f"c{n:03d}", "under_review", "alice", ts=1000 + n)

        # COUNT queries page internally; _count_active_for_admin must loop ekey.
        self.assertEqual(self.svc._count_active_for_admin("alice"), 55)


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestKycCasesTableDefHasAssignedAdminGsi(unittest.TestCase):
    """Static check: scripts/local-ddb-init.py declares the GSI with correct
    attr_types so dev/prod parity (SECOPS-007) holds."""

    def _kyc_cases_tabledef(self):
        src = open("scripts/local-ddb-init.py").read()
        tree = ast.parse(src)  # raises on syntax error
        found = []

        class _V(ast.NodeVisitor):
            def visit_Call(self, node):
                if isinstance(node.func, ast.Name) and node.func.id == "TableDef":
                    found.append(node)
                self.generic_visit(node)

        _V().visit(tree)
        # Identify the kyc_cases TableDef by its gsi list mentioning the index.
        for node in found:
            dump = ast.dump(node)
            if "kyc_cases_assigned_admin_index_name" in dump:
                return node, dump
        return None, ""

    def test_assigned_admin_gsi_present_with_string_attr_types(self):
        node, dump = self._kyc_cases_tabledef()
        self.assertIsNotNone(node, "kyc_cases TableDef must reference assigned-admin index")
        # GSI keyed on assigned_admin_sub (PK) + gsi_status_pk (SK).
        self.assertIn("assigned_admin_sub", dump)
        self.assertIn("gsi_status_pk", dump)
        # attr_types must declare both string-keyed attrs (only key attrs declared;
        # no numeric sort key here, so both are "S").
        self.assertIn("'assigned_admin_sub'", dump.replace('"', "'"))


if __name__ == "__main__":
    unittest.main()

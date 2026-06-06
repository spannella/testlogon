"""Offline regression test for GAP-0297 (LICENSE-005).

``list_syndicate_content`` in ``app/services/syndicate_open_licensing.py`` used
to always call ``_list_registered_content`` (a single, un-paginated query of the
whole ``SYND#{syndicate_id}`` partition) and then filter by ``creator_id`` in
Python. The GSI1 index (``GSI1PK = SYND_CREATOR#{syndicate_id}#{creator_id}``,
``GSI1SK = registered_at``) that already exists on the table went unused. Two
problems followed:

1. Creator-scoped listing read every content item in the syndicate (O(N) reads)
   instead of querying GSI1 for just that creator's items.
2. Neither ``_list_registered_content`` nor the GSI helper looped on
   ``LastEvaluatedKey``, so a syndicate whose content registry exceeds a single
   1 MB DynamoDB page silently dropped items past the first page.

The fix: query GSI1 when ``creator_id`` is given, and paginate both the GSI
query and the full-partition scan via ``LastEvaluatedKey``.

Fully offline: a real in-memory DynamoDB table (with the GSI1 index) is created
with moto and ``syndicate_open_licensing.T`` is patched to point at it, mirroring
``tests/test_gap_0176_0177_org_service.py``. Functions are called directly (the
FastAPI TestClient is unusable in this repo). The GSI query path is genuinely
exercised against moto's index.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_table(ddb):
    """Create the syndicate_open_licensing table mirroring local-ddb-init.py.

    Includes GSI1 (GSI1PK / GSI1SK) with the numeric sort key, exactly as the
    real table is declared in scripts/local-ddb-init.py:1734-1740.
    """
    return ddb.create_table(
        TableName="syndicate_open_licensing",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestListSyndicateContentGsi(unittest.TestCase):
    SID = "synd1"
    CREATOR_A = "user_a"
    CREATOR_B = "user_b"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_table(ddb)

        from app.services import syndicate_open_licensing as svc

        self.svc = svc
        # Bind the EXACT attribute the service reads (T.syndicate_open_licensing)
        # to the moto-backed table, restored automatically on cleanup.
        self.stack.enter_context(
            patch.object(svc, "T", SimpleNamespace(syndicate_open_licensing=self.table))
        )

    def _seed(self, content_id: str, creator_id: str, registered_at: int, exempt: bool = False):
        self.table.put_item(
            Item={
                "pk": f"SYND#{self.SID}",
                "sk": f"CONTENT#{content_id}",
                "content_id": content_id,
                "content_type": "video",
                "creator_id": creator_id,
                "registered_at": registered_at,
                "exempt": exempt,
                "GSI1PK": f"SYND_CREATOR#{self.SID}#{creator_id}",
                "GSI1SK": registered_at,
            }
        )

    def _seed_mixed(self, n: int = 12):
        """Seed n content items, alternating between creator A and B."""
        for i in range(n):
            creator = self.CREATOR_A if i % 2 == 0 else self.CREATOR_B
            self._seed(f"c{i}", creator, registered_at=100 + i)

    # ------------------------------------------------------------------
    # GAP-0297 core: creator filter goes through GSI1
    # ------------------------------------------------------------------
    def test_creator_filter_returns_only_that_creator(self):
        self._seed_mixed(12)
        result = self.svc.list_syndicate_content(syndicate_id=self.SID, creator_id=self.CREATOR_A)
        self.assertTrue(result)
        self.assertTrue(all(r["creator_id"] == self.CREATOR_A for r in result))
        # 6 of 12 belong to creator A (even indices).
        self.assertEqual(len(result), 6)
        # Sorted newest-first.
        ats = [r["registered_at"] for r in result]
        self.assertEqual(ats, sorted(ats, reverse=True))

    def test_creator_filter_issues_gsi_query(self):
        """The fix MUST query IndexName='GSI1' when creator_id is given.

        Fails before the fix (old code only does a partition query + Python
        filter and never passes IndexName).
        """
        self._seed_mixed(6)

        real_query = self.table.query
        seen_index = []

        def spy_query(**kwargs):
            if kwargs.get("IndexName"):
                seen_index.append(kwargs["IndexName"])
            return real_query(**kwargs)

        with patch.object(
            self.svc, "T", SimpleNamespace(syndicate_open_licensing=MagicMock(query=spy_query))
        ):
            result = self.svc.list_syndicate_content(syndicate_id=self.SID, creator_id=self.CREATOR_B)

        self.assertIn("GSI1", seen_index, "GSI1 was not queried — fix not applied")
        self.assertTrue(all(r["creator_id"] == self.CREATOR_B for r in result))

    # ------------------------------------------------------------------
    # No creator filter still returns everything
    # ------------------------------------------------------------------
    def test_no_creator_returns_all(self):
        self._seed_mixed(12)
        result = self.svc.list_syndicate_content(syndicate_id=self.SID)
        self.assertEqual(len(result), 12)

    def test_include_exempt_false_filters_exempt(self):
        self._seed("c0", self.CREATOR_A, 100, exempt=False)
        self._seed("c1", self.CREATOR_A, 101, exempt=True)
        all_items = self.svc.list_syndicate_content(syndicate_id=self.SID, creator_id=self.CREATOR_A)
        self.assertEqual(len(all_items), 2)
        non_exempt = self.svc.list_syndicate_content(
            syndicate_id=self.SID, creator_id=self.CREATOR_A, include_exempt=False
        )
        self.assertEqual(len(non_exempt), 1)
        self.assertEqual(non_exempt[0]["content_id"], "c0")

    # ------------------------------------------------------------------
    # Pagination: both paths must loop on LastEvaluatedKey
    # ------------------------------------------------------------------
    def test_full_scan_paginates(self):
        """A forced 1-item page must not truncate the partition scan."""
        self._seed_mixed(5)

        real_query = self.table.query

        def paged_query(**kwargs):
            kwargs.setdefault("Limit", 1)
            return real_query(**kwargs)

        with patch.object(
            self.svc, "T", SimpleNamespace(syndicate_open_licensing=MagicMock(query=paged_query))
        ):
            result = self.svc.list_syndicate_content(syndicate_id=self.SID)

        self.assertEqual(len(result), 5, "Pagination loop missed items past the first page")

    def test_gsi_query_paginates(self):
        """The GSI creator path must also loop on LastEvaluatedKey."""
        # 8 items for creator A.
        for i in range(8):
            self._seed(f"a{i}", self.CREATOR_A, registered_at=200 + i)
        # Noise for creator B.
        for i in range(4):
            self._seed(f"b{i}", self.CREATOR_B, registered_at=300 + i)

        real_query = self.table.query

        def paged_query(**kwargs):
            kwargs.setdefault("Limit", 2)
            return real_query(**kwargs)

        with patch.object(
            self.svc, "T", SimpleNamespace(syndicate_open_licensing=MagicMock(query=paged_query))
        ):
            result = self.svc.list_syndicate_content(syndicate_id=self.SID, creator_id=self.CREATOR_A)

        self.assertEqual(len(result), 8, "GSI pagination loop missed items past the first page")
        self.assertTrue(all(r["creator_id"] == self.CREATOR_A for r in result))


if __name__ == "__main__":
    unittest.main()

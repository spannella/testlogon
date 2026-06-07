"""Offline regression tests for GAP-0347 and GAP-0348 (SHOP-001).

Both gaps live in ``app/routers/catalog.py`` and touch the ``shopping_catalog``
DynamoDB table:

GAP-0348 — ``_find_item_by_id`` did a full-table ``scan`` (filtered on
``item_id``) to resolve an item from a bare item_id. The fix adds a ``ByItemId``
GSI (partition key ``item_id``) to ``shopping_catalog`` and rewrites
``_find_item_by_id`` to ``query`` that GSI (O(1)) instead of scanning. The
signature/return are unchanged, so all four call sites keep working.

GAP-0347 — ``_check_low_stock_alert`` fired ``write_alert`` unconditionally on
every stock decrement at/below the low-stock threshold → an alert storm on
high-velocity items. The fix writes a sparse, conditional sentinel row
(``LOWSTOCK_ALERT_SENTINEL#{creator}`` / ``LOWSTOCK#{item}``) with a 1-hour
``ttl_epoch`` before alerting; a ``ConditionalCheckFailedException`` on the
sentinel put means a recent alert already fired in the window → suppress. This
yields per-item once-per-hour dedup.

Fully offline: a real in-memory DynamoDB ``shopping_catalog`` table (with the new
``ByItemId`` GSI) is created via moto and bound to the EXACT frozen ``T.catalog``
handle via ``object.__setattr__`` (restored on cleanup). ``write_alert`` is
patched to a spy. No real AWS / network.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_catalog_table(ddb):
    """Create shopping_catalog mirroring scripts/local-ddb-init.py (incl. ByItemId)."""
    return ddb.create_table(
        TableName="shopping_catalog",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "S"},
            {"AttributeName": "item_id", "AttributeType": "S"},
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
            {
                "IndexName": "ByItemId",
                "KeySchema": [
                    {"AttributeName": "item_id", "KeyType": "HASH"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class _CatalogTestBase(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_catalog_table(ddb)

        from app.routers import catalog
        from app.core.tables import T

        self.catalog = catalog

        # Bind the EXACT frozen T.catalog handle to the moto table; restore after.
        orig = T.catalog
        object.__setattr__(T, "catalog", self.table)
        self.addCleanup(lambda: object.__setattr__(T, "catalog", orig))

    def _seed_item(self, item_id: str, category_id: str, creator_id: str = "creator-1"):
        self.table.put_item(
            Item={
                "PK": f"CAT#{category_id}",
                "SK": f"ITEM#{item_id}",
                "entity": "item",
                "category_id": category_id,
                "item_id": item_id,
                "creator_id": creator_id,
                "name": f"Item {item_id}",
            }
        )


class TestFindItemByIdGap0348(_CatalogTestBase):
    def test_find_item_by_id_resolves_via_gsi(self):
        """GAP-0348: _find_item_by_id returns the right item across many items.

        Seeds several items and looks each up by bare item_id. The new GSI query
        path resolves each correctly. (The old code would scan; this asserts
        correctness across multiple distinct items.)
        """
        for i in range(10):
            self._seed_item(item_id=f"item-{i:03d}", category_id=f"cat-{i:03d}")

        for i in range(10):
            found = self.catalog._find_item_by_id(f"item-{i:03d}")
            self.assertIsNotNone(found, f"item-{i:03d} not found")
            self.assertEqual(found["item_id"], f"item-{i:03d}")
            self.assertEqual(found["category_id"], f"cat-{i:03d}")
            self.assertEqual(found["SK"], f"ITEM#item-{i:03d}")

    def test_find_item_by_id_missing_returns_none(self):
        self._seed_item(item_id="present", category_id="cat-x")
        self.assertIsNone(self.catalog._find_item_by_id("absent"))

    def test_find_item_by_id_ignores_non_item_rows(self):
        """A review row also carries item_id but entity != item → filtered out."""
        self.table.put_item(
            Item={
                "PK": "ITEM#rev-item",
                "SK": "REVIEW#r1",
                "entity": "review",
                "item_id": "rev-item",
                "review_id": "r1",
            }
        )
        # No actual item row with that item_id → must not match the review.
        self.assertIsNone(self.catalog._find_item_by_id("rev-item"))

    def test_find_item_by_id_does_not_scan(self):
        """The lookup must use the GSI query, not a full-table scan."""
        self._seed_item(item_id="no-scan", category_id="cat-ns")
        with patch.object(self.table, "scan", side_effect=AssertionError("scan called")):
            found = self.catalog._find_item_by_id("no-scan")
        self.assertIsNotNone(found)
        self.assertEqual(found["item_id"], "no-scan")


class TestLowStockAlertDedupGap0347(_CatalogTestBase):
    def setUp(self):
        super().setUp()
        from app.core.settings import S

        # Enable alerts + a known threshold on the frozen settings; restore after.
        orig_enabled = S.catalog_stock_alerts_enabled
        orig_thresh = S.catalog_default_low_stock_threshold
        object.__setattr__(S, "catalog_stock_alerts_enabled", True)
        object.__setattr__(S, "catalog_default_low_stock_threshold", 5)
        self.addCleanup(lambda: object.__setattr__(S, "catalog_stock_alerts_enabled", orig_enabled))
        self.addCleanup(lambda: object.__setattr__(S, "catalog_default_low_stock_threshold", orig_thresh))

    def _item(self, item_id="item-1", creator_id="creator-1"):
        return {
            "PK": f"CAT#cat-1",
            "SK": f"ITEM#{item_id}",
            "entity": "item",
            "item_id": item_id,
            "creator_id": creator_id,
            "name": f"Item {item_id}",
        }

    def test_alert_fires_once_per_window(self):
        """GAP-0347: repeated below-threshold calls for the same item alert once."""
        item = self._item(item_id="hot", creator_id="c1")
        calls = []
        with patch("app.services.alerts.write_alert", side_effect=lambda *a, **k: calls.append((a, k))):
            for _ in range(10):
                self.catalog._check_low_stock_alert(item, new_stock=3)
        self.assertEqual(len(calls), 1, f"expected 1 alert, got {len(calls)}")
        # Sentinel row was written (sparse: no item_id / GSI1 keys).
        resp = self.table.get_item(
            Key={"PK": "LOWSTOCK_ALERT_SENTINEL#c1", "SK": "LOWSTOCK#hot"}
        )
        sentinel = resp.get("Item")
        self.assertIsNotNone(sentinel)
        self.assertIn("ttl_epoch", sentinel)
        self.assertNotIn("item_id", sentinel)
        self.assertNotIn("GSI1PK", sentinel)

    def test_different_items_each_alert(self):
        """A different item still alerts (dedup is per-item)."""
        calls = []
        with patch("app.services.alerts.write_alert", side_effect=lambda *a, **k: calls.append((a, k))):
            self.catalog._check_low_stock_alert(self._item(item_id="a", creator_id="c1"), new_stock=2)
            self.catalog._check_low_stock_alert(self._item(item_id="b", creator_id="c1"), new_stock=2)
        self.assertEqual(len(calls), 2)

    def test_alert_fires_again_after_sentinel_cleared(self):
        """After the sentinel expires (simulated by deletion), a new alert fires."""
        item = self._item(item_id="reappear", creator_id="c2")
        calls = []
        with patch("app.services.alerts.write_alert", side_effect=lambda *a, **k: calls.append(1)):
            self.catalog._check_low_stock_alert(item, new_stock=3)
            # Simulate TTL expiry by deleting the sentinel row.
            self.table.delete_item(
                Key={"PK": "LOWSTOCK_ALERT_SENTINEL#c2", "SK": "LOWSTOCK#reappear"}
            )
            self.catalog._check_low_stock_alert(item, new_stock=2)
        self.assertEqual(len(calls), 2)

    def test_above_threshold_no_alert(self):
        item = self._item(item_id="plenty", creator_id="c3")
        calls = []
        with patch("app.services.alerts.write_alert", side_effect=lambda *a, **k: calls.append(1)):
            self.catalog._check_low_stock_alert(item, new_stock=99)
        self.assertEqual(len(calls), 0)

    def test_disabled_flag_no_alert(self):
        from app.core.settings import S

        object.__setattr__(S, "catalog_stock_alerts_enabled", False)
        item = self._item(item_id="off", creator_id="c4")
        calls = []
        with patch("app.services.alerts.write_alert", side_effect=lambda *a, **k: calls.append(1)):
            self.catalog._check_low_stock_alert(item, new_stock=1)
        self.assertEqual(len(calls), 0)


if __name__ == "__main__":
    unittest.main()

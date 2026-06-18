"""
Hermetic offline pytest for PRD-004 (product_categories service) and
PRD-005 (category tree router endpoints).

Covers:
  - add_child creates a tree row with correct path, position, GSI keys
  - get_ancestry returns ancestor ids from materialized path
  - list_children queries the ByParent GSI and returns rows in order
  - cycle detection raises ValueError (not HTTPException) on direct cycle
  - cycle detection raises ValueError on indirect/transitive cycle
  - move_category updates the path of the moved category
  - move_category 404s when node not found
  - product_depth_enabled=False → 501 from all service functions
  - get_breadcrumb returns [{category_id, name}] chain
  - list_descendants collects all recursive children

Pattern:
  - moto @mock_aws for in-memory DynamoDB
  - T.product_depth patched via object.__setattr__ on the frozen T singleton
  - S.product_depth_enabled patched via object.__setattr__ on the frozen S singleton
  - Service functions called directly (no FastAPI TestClient)
"""

from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

try:
    import boto3
    from moto import mock_aws
    HAS_MOTO = True
except ImportError:
    HAS_MOTO = False


# ---------------------------------------------------------------------------
# Table construction helper (mirrors test_prd_catalog_depth.py)
# ---------------------------------------------------------------------------

def _make_product_depth_table(ddb):
    """Create product_depth table with all GSIs needed by PRD-004."""
    return ddb.create_table(
        TableName="product_depth",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK",            "AttributeType": "S"},
            {"AttributeName": "SK",            "AttributeType": "S"},
            {"AttributeName": "GSI_FTCAT_PK",  "AttributeType": "S"},
            {"AttributeName": "GSI_FTCAT_SK",  "AttributeType": "N"},
            {"AttributeName": "GSI_VIRT_PK",   "AttributeType": "S"},
            {"AttributeName": "GSI_VIRT_SK",   "AttributeType": "N"},
            {"AttributeName": "GSI_PRICE_PK",  "AttributeType": "S"},
            {"AttributeName": "GSI_PRICE_SK",  "AttributeType": "N"},
            {"AttributeName": "GSI_PARENT_PK", "AttributeType": "S"},
            {"AttributeName": "GSI_PARENT_SK", "AttributeType": "N"},
            {"AttributeName": "GSI_ASSOC_PK",  "AttributeType": "S"},
            {"AttributeName": "GSI_ASSOC_SK",  "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByFeatureCategory",
                "KeySchema": [
                    {"AttributeName": "GSI_FTCAT_PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI_FTCAT_SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByVirtualParent",
                "KeySchema": [
                    {"AttributeName": "GSI_VIRT_PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI_VIRT_SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByItemPrice",
                "KeySchema": [
                    {"AttributeName": "GSI_PRICE_PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI_PRICE_SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByParent",
                "KeySchema": [
                    {"AttributeName": "GSI_PARENT_PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI_PARENT_SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByAssocSource",
                "KeySchema": [
                    {"AttributeName": "GSI_ASSOC_PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI_ASSOC_SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


# ---------------------------------------------------------------------------
# Base test class
# ---------------------------------------------------------------------------

@unittest.skipUnless(HAS_MOTO, "moto not installed")
class CategoryTreeTestCase(unittest.TestCase):
    """Base: starts moto, creates table, patches T + S."""

    def setUp(self):
        self._moto = mock_aws()
        self._moto.start()

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self._table = _make_product_depth_table(ddb)

        # Patch T.product_depth to the moto table
        from app.core import tables as _tables_mod
        self._orig_pd = _tables_mod.T.product_depth
        object.__setattr__(_tables_mod.T, "product_depth", self._table)

        # Enable the feature flag
        from app.core import settings as _settings_mod
        self._orig_enabled = _settings_mod.S.product_depth_enabled
        object.__setattr__(_settings_mod.S, "product_depth_enabled", True)

        self._tables_mod = _tables_mod
        self._settings_mod = _settings_mod

    def tearDown(self):
        object.__setattr__(self._tables_mod.T, "product_depth", self._orig_pd)
        object.__setattr__(self._settings_mod.S, "product_depth_enabled", self._orig_enabled)
        self._moto.stop()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAddChild(CategoryTreeTestCase):
    """PRD-004: add_child creates tree row with correct fields."""

    def test_add_child_creates_row(self):
        from app.services.product_categories import add_child
        row = add_child(
            parent_category_id="parent1",
            category_id="child1",
            owner_sub="user_a",
            name="Child One",
            position=0,
        )
        self.assertEqual(row["category_id"], "child1")
        self.assertEqual(row["parent_category_id"], "parent1")
        self.assertEqual(row["path"], "parent1/child1")
        self.assertEqual(row["name"], "Child One")
        self.assertEqual(row["owner_sub"], "user_a")
        self.assertEqual(row["GSI_PARENT_PK"], "PARENT#parent1")
        self.assertEqual(int(row["GSI_PARENT_SK"]), 0)

    def test_add_child_persists_to_ddb(self):
        from app.services.product_categories import add_child, _get_tree_row
        add_child("p", "c", "user_a", "Child", position=2)
        fetched = _get_tree_row("c")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["path"], "p/c")
        self.assertEqual(int(fetched["position"]), 2)

    def test_add_child_nested_path(self):
        from app.services.product_categories import add_child
        # grandparent → parent → child
        add_child("gp", "p", "user_a", "Parent")
        row = add_child("p", "c", "user_a", "Child")
        self.assertEqual(row["path"], "gp/p/c")


class TestGetAncestry(CategoryTreeTestCase):
    """PRD-004: get_ancestry derives correct ancestor list from path."""

    def test_get_ancestry_two_levels(self):
        from app.services.product_categories import add_child, get_ancestry
        add_child("root", "mid", "user_a", "Mid")
        add_child("mid", "leaf", "user_a", "Leaf")
        ancestors = get_ancestry("leaf")
        self.assertEqual(ancestors, ["root", "mid"])

    def test_get_ancestry_root_node(self):
        from app.services.product_categories import add_child, get_ancestry
        add_child("root", "child", "user_a", "Child")
        # root itself has no tree row → ancestry of child is just ["root"]
        ancestors = get_ancestry("child")
        self.assertEqual(ancestors, ["root"])

    def test_get_ancestry_missing_node_returns_empty(self):
        from app.services.product_categories import get_ancestry
        self.assertEqual(get_ancestry("nonexistent"), [])


class TestListChildren(CategoryTreeTestCase):
    """PRD-004: list_children queries ByParent GSI."""

    def test_list_children_returns_direct_children(self):
        from app.services.product_categories import add_child, list_children
        add_child("root", "a", "user_a", "A", position=0)
        add_child("root", "b", "user_a", "B", position=1)
        add_child("root", "c", "user_a", "C", position=2)
        # Add a grandchild — should NOT appear
        add_child("a", "a1", "user_a", "A1", position=0)

        children, lek = list_children("root")
        child_ids = [ch["category_id"] for ch in children]
        self.assertIn("a", child_ids)
        self.assertIn("b", child_ids)
        self.assertIn("c", child_ids)
        self.assertNotIn("a1", child_ids)
        self.assertIsNone(lek)

    def test_list_children_empty_parent(self):
        from app.services.product_categories import list_children
        children, lek = list_children("nobody")
        self.assertEqual(children, [])
        self.assertIsNone(lek)


class TestCycleDetection(CategoryTreeTestCase):
    """PRD-004: cycle detection raises ValueError."""

    def test_direct_cycle_raises(self):
        from app.services.product_categories import add_child
        # A → B, then try B → A (direct cycle)
        add_child("A", "B", "user_a", "B")
        with self.assertRaises(ValueError) as ctx:
            add_child("B", "A", "user_a", "A")
        self.assertIn("Cycle", str(ctx.exception))

    def test_transitive_cycle_raises(self):
        from app.services.product_categories import add_child
        # A → B → C, then try C → A (transitive)
        add_child("A", "B", "user_a", "B")
        add_child("B", "C", "user_a", "C")
        with self.assertRaises(ValueError):
            add_child("C", "A", "user_a", "A")


class TestMoveCategory(CategoryTreeTestCase):
    """PRD-004: move_category re-parents and updates path."""

    def test_move_updates_path(self):
        from app.services.product_categories import add_child, move_category, _get_tree_row
        # old_root → child, new_root exists (no tree row)
        add_child("old_root", "child", "user_a", "Child")
        result = move_category("child", "new_root", "user_a")
        self.assertEqual(result["parent_category_id"], "new_root")
        self.assertEqual(result["path"], "new_root/child")

    def test_move_404_for_missing_node(self):
        from fastapi import HTTPException
        from app.services.product_categories import move_category
        with self.assertRaises(HTTPException) as ctx:
            move_category("ghost", "somewhere", "user_a")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_move_cycle_detection(self):
        from app.services.product_categories import add_child, move_category
        # root → A → B → C; try to move A under C (would create cycle)
        add_child("root", "A", "user_a", "A")
        add_child("A", "B", "user_a", "B")
        add_child("B", "C", "user_a", "C")
        with self.assertRaises(ValueError):
            move_category("A", "C", "user_a")


class TestFlagOff(CategoryTreeTestCase):
    """PRD-004: all public functions raise 501 when flag is off."""

    def setUp(self):
        super().setUp()
        object.__setattr__(self._settings_mod.S, "product_depth_enabled", False)

    def test_add_child_501_when_flag_off(self):
        from fastapi import HTTPException
        from app.services.product_categories import add_child
        with self.assertRaises(HTTPException) as ctx:
            add_child("p", "c", "user_a", "C")
        self.assertEqual(ctx.exception.status_code, 501)
        self.assertEqual(ctx.exception.detail, "product_depth_not_enabled")

    def test_list_children_501_when_flag_off(self):
        from fastapi import HTTPException
        from app.services.product_categories import list_children
        with self.assertRaises(HTTPException) as ctx:
            list_children("p")
        self.assertEqual(ctx.exception.status_code, 501)

    def test_get_ancestry_501_when_flag_off(self):
        from fastapi import HTTPException
        from app.services.product_categories import get_ancestry
        with self.assertRaises(HTTPException) as ctx:
            get_ancestry("c")
        self.assertEqual(ctx.exception.status_code, 501)

    def test_move_category_501_when_flag_off(self):
        from fastapi import HTTPException
        from app.services.product_categories import move_category
        with self.assertRaises(HTTPException) as ctx:
            move_category("c", "p", "user_a")
        self.assertEqual(ctx.exception.status_code, 501)

    def test_list_descendants_501_when_flag_off(self):
        from fastapi import HTTPException
        from app.services.product_categories import list_descendants
        with self.assertRaises(HTTPException) as ctx:
            list_descendants("c")
        self.assertEqual(ctx.exception.status_code, 501)

    def test_get_breadcrumb_501_when_flag_off(self):
        from fastapi import HTTPException
        from app.services.product_categories import get_breadcrumb
        with self.assertRaises(HTTPException) as ctx:
            get_breadcrumb("c")
        self.assertEqual(ctx.exception.status_code, 501)


class TestGetBreadcrumb(CategoryTreeTestCase):
    """PRD-004: get_breadcrumb returns [{category_id, name}] chain."""

    def test_breadcrumb_three_levels(self):
        from app.services.product_categories import add_child, get_breadcrumb
        add_child("root", "mid", "user_a", "Mid Category")
        add_child("mid", "leaf", "user_a", "Leaf Category")
        crumbs = get_breadcrumb("leaf")
        self.assertEqual(len(crumbs), 3)
        self.assertEqual(crumbs[0]["category_id"], "root")
        self.assertEqual(crumbs[1]["category_id"], "mid")
        self.assertEqual(crumbs[1]["name"], "Mid Category")
        self.assertEqual(crumbs[2]["category_id"], "leaf")
        self.assertEqual(crumbs[2]["name"], "Leaf Category")

    def test_breadcrumb_missing_node_returns_fallback(self):
        from app.services.product_categories import get_breadcrumb
        # No tree row → returns single-element list with id as name
        crumbs = get_breadcrumb("orphan")
        self.assertEqual(len(crumbs), 1)
        self.assertEqual(crumbs[0]["category_id"], "orphan")


class TestListDescendants(CategoryTreeTestCase):
    """PRD-004: list_descendants collects all recursive children."""

    def test_list_descendants_flat(self):
        from app.services.product_categories import add_child, list_descendants
        add_child("root", "a", "user_a", "A")
        add_child("root", "b", "user_a", "B")
        desc = list_descendants("root")
        desc_ids = {d["category_id"] for d in desc}
        self.assertIn("a", desc_ids)
        self.assertIn("b", desc_ids)

    def test_list_descendants_recursive(self):
        from app.services.product_categories import add_child, list_descendants
        add_child("root", "child", "user_a", "Child")
        add_child("child", "grandchild", "user_a", "GrandChild")
        desc = list_descendants("root")
        desc_ids = {d["category_id"] for d in desc}
        self.assertIn("child", desc_ids)
        self.assertIn("grandchild", desc_ids)

    def test_list_descendants_empty(self):
        from app.services.product_categories import list_descendants
        # No children
        desc = list_descendants("lonely")
        self.assertEqual(desc, [])


if __name__ == "__main__":
    unittest.main()

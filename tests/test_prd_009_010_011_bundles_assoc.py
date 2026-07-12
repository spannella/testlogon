"""Regression tests for PRD-009, PRD-010, PRD-011.

PRD-009: expand_bundle + compute_bundle_price (app/services/product_variants.py)
PRD-010: product associations CRUD (app/services/product_associations.py)
PRD-011: bundle expand + association router endpoints (app/routers/catalog.py)

Test isolation (SECOPS-007):
  * Real in-memory moto DynamoDB ``shopping_catalog`` + ``product_depth`` tables
    bound to the frozen ``T`` handles via ``object.__setattr__`` + restore.
  * Frozen ``Settings`` flags flipped with ``object.__setattr__``.
  * Route coroutines called directly — no TestClient, no real network.
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None


# ---------------------------------------------------------------------------
# DynamoDB table helpers
# ---------------------------------------------------------------------------

def _make_catalog_table(ddb):
    return ddb.create_table(
        TableName="shopping_catalog",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
            {"AttributeName": "item_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByItemId",
                "KeySchema": [{"AttributeName": "item_id", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_product_depth_table(ddb):
    return ddb.create_table(
        TableName="product_depth",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


# ---------------------------------------------------------------------------
# Base test class — shared setUp / tearDown
# ---------------------------------------------------------------------------

@unittest.skipIf(mock_aws is None, "moto is not installed")
class _Base(unittest.TestCase):
    OWNER = "alice"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.catalog = _make_catalog_table(ddb)
        self.depth = _make_product_depth_table(ddb)

        from app.core.tables import T
        from app.services import product_variants as svc_variants
        from app.services import product_associations as svc_assoc
        from app.routers import catalog as router_mod

        self.T = T
        self.svc_variants = svc_variants
        self.svc_assoc = svc_assoc
        self.router_mod = router_mod
        self.S = svc_variants.S

        self._orig_catalog = T.catalog
        self._orig_depth = T.product_depth
        object.__setattr__(T, "catalog", self.catalog)
        object.__setattr__(T, "product_depth", self.depth)
        self.addCleanup(lambda: object.__setattr__(T, "catalog", self._orig_catalog))
        self.addCleanup(lambda: object.__setattr__(T, "product_depth", self._orig_depth))

        self._orig_flags = {
            "product_depth_enabled": self.S.product_depth_enabled,
            "product_depth_bundles_enabled": getattr(self.S, "product_depth_bundles_enabled", True),
        }
        object.__setattr__(self.S, "product_depth_enabled", True)
        object.__setattr__(self.S, "product_depth_bundles_enabled", True)
        self.addCleanup(self._restore_flags)

    def _restore_flags(self):
        for k, v in self._orig_flags.items():
            object.__setattr__(self.S, k, v)

    def _seed_item(self, item_id: str, price: int = 1000):
        """Write a minimal catalog row for item_id."""
        self.catalog.put_item(
            Item={
                "PK": "CAT#default",
                "SK": f"ITEM#{item_id}",
                "entity": "item",
                "item_id": item_id,
                "sku": f"sku-{item_id}",
                "name": f"Item {item_id}",
                "price_cents": price,
                "creator_id": self.OWNER,
            }
        )

    def _set_product_type(self, item_id: str, product_type: str):
        """Write a TYPE marker row on product_depth."""
        self.depth.put_item(
            Item={
                "PK": f"ITEM#{item_id}",
                "SK": "TYPE",
                "entity": "product_type",
                "product_type": product_type,
                "creator_id": self.OWNER,
                "created_at": 1,
                "updated_at": 1,
            }
        )

    def _add_component(self, parent_id: str, comp_id: str, qty: int = 1):
        """Write a BUNDLE# component row directly."""
        self.depth.put_item(
            Item={
                "PK": f"ITEM#{parent_id}",
                "SK": f"BUNDLE#{comp_id}",
                "entity": "bundle_component",
                "parent_item_id": parent_id,
                "component_item_id": comp_id,
                "quantity": qty,
                "creator_id": self.OWNER,
                "created_at": 1,
                "updated_at": 1,
            }
        )

    def _ctx(self, sub: str | None = None):
        return {"user_sub": sub or self.OWNER, "role": "user"}


# ---------------------------------------------------------------------------
# PRD-009: compute_bundle_price
# ---------------------------------------------------------------------------

class TestComputeBundlePrice(_Base):

    def test_kit_price_is_sum_of_components(self):
        """Kit price = Σ(component price × qty)."""
        self._seed_item("kit-1", price=0)     # parent — price irrelevant for kit
        self._seed_item("part-a", price=500)
        self._seed_item("part-b", price=300)
        self._set_product_type("kit-1", "kit")
        self._add_component("kit-1", "part-a", qty=2)   # 2 × 500 = 1000
        self._add_component("kit-1", "part-b", qty=1)   # 1 × 300 =  300

        price = self.svc_variants.compute_bundle_price("kit-1")
        self.assertEqual(price, 1300)

    def test_bundle_price_uses_parent_catalog_price(self):
        """Bundle price = parent's fixed price_cents from catalog."""
        self._seed_item("bundle-1", price=9999)
        self._seed_item("comp-x", price=100)
        self._set_product_type("bundle-1", "bundle")
        self._add_component("bundle-1", "comp-x", qty=3)

        price = self.svc_variants.compute_bundle_price("bundle-1")
        self.assertEqual(price, 9999)

    def test_flag_off_raises_501(self):
        """compute_bundle_price raises 501 when product_depth_enabled=False."""
        from fastapi import HTTPException
        object.__setattr__(self.S, "product_depth_enabled", False)
        self._seed_item("bundle-1")
        with self.assertRaises(HTTPException) as cm:
            self.svc_variants.compute_bundle_price("bundle-1")
        self.assertEqual(cm.exception.status_code, 501)


# ---------------------------------------------------------------------------
# PRD-009: expand_bundle
# ---------------------------------------------------------------------------

class TestExpandBundle(_Base):

    def _setup_simple_bundle(self):
        """Create bundle-1 with two scalar components."""
        self._seed_item("bundle-1", price=5000)
        self._seed_item("comp-a", price=1000)
        self._seed_item("comp-b", price=2000)
        self._set_product_type("bundle-1", "bundle")
        self._add_component("bundle-1", "comp-a", qty=1)
        self._add_component("bundle-1", "comp-b", qty=2)

    def test_expand_returns_correct_lines(self):
        """expand_bundle returns item/qty/lines dict with correct component lines."""
        self._setup_simple_bundle()
        result = self.svc_variants.expand_bundle("bundle-1", qty=1)

        self.assertEqual(result["item_id"], "bundle-1")
        self.assertEqual(result["qty"], 1)
        self.assertEqual(result["bundle_price_cents"], 5000)

        lines = {line["item_id"]: line for line in result["lines"]}
        self.assertIn("comp-a", lines)
        self.assertIn("comp-b", lines)
        self.assertEqual(lines["comp-a"]["qty"], 1)
        self.assertEqual(lines["comp-a"]["price_cents"], 1000)
        self.assertEqual(lines["comp-a"]["line_total_cents"], 1000)
        self.assertEqual(lines["comp-b"]["qty"], 2)
        self.assertEqual(lines["comp-b"]["line_total_cents"], 4000)

    def test_expand_with_qty_multiplier(self):
        """qty parameter multiplies all component quantities."""
        self._setup_simple_bundle()
        result = self.svc_variants.expand_bundle("bundle-1", qty=3)

        self.assertEqual(result["qty"], 3)
        lines = {line["item_id"]: line for line in result["lines"]}
        self.assertEqual(lines["comp-a"]["qty"], 3)
        self.assertEqual(lines["comp-b"]["qty"], 6)

    def test_expand_nested_bundle(self):
        """Nested bundle: inner bundle components are flattened into parent lines."""
        # outer bundle contains inner bundle and a scalar.
        self._seed_item("outer", price=10000)
        self._seed_item("inner", price=3000)
        self._seed_item("leaf-x", price=500)
        self._seed_item("leaf-y", price=750)

        self._set_product_type("outer", "bundle")
        self._set_product_type("inner", "bundle")

        # outer → inner (qty=1) + leaf-x (qty=2)
        self._add_component("outer", "inner", qty=1)
        self._add_component("outer", "leaf-x", qty=2)
        # inner → leaf-y (qty=3)
        self._add_component("inner", "leaf-y", qty=3)

        result = self.svc_variants.expand_bundle("outer", qty=1)
        lines = {line["item_id"]: line for line in result["lines"]}

        # leaf-x comes from outer directly
        self.assertIn("leaf-x", lines)
        self.assertEqual(lines["leaf-x"]["qty"], 2)
        # leaf-y comes through inner expansion
        self.assertIn("leaf-y", lines)
        self.assertEqual(lines["leaf-y"]["qty"], 3)
        # inner itself should NOT be a leaf line
        self.assertNotIn("inner", lines)

    def test_cycle_detection_raises_value_error(self):
        """Cycle detection raises ValueError('circular_bundle')."""
        self._seed_item("a", price=100)
        self._seed_item("b", price=200)
        self._set_product_type("a", "bundle")
        self._set_product_type("b", "bundle")
        self._add_component("a", "b", qty=1)
        self._add_component("b", "a", qty=1)  # creates a→b→a cycle

        with self.assertRaises(ValueError) as cm:
            self.svc_variants.expand_bundle("a", qty=1)
        self.assertIn("circular_bundle", str(cm.exception))

    def test_max_depth_exceeded_raises_422(self):
        """Depth > 5 raises HTTPException 422."""
        from fastapi import HTTPException

        # Build a 7-level deep chain: d0 → d1 → ... → d6
        for i in range(7):
            self._seed_item(f"d{i}", price=100)
            self._set_product_type(f"d{i}", "bundle")
            if i < 6:
                self._add_component(f"d{i}", f"d{i+1}", qty=1)
        # d6 has no components — leaf

        with self.assertRaises(HTTPException) as cm:
            self.svc_variants.expand_bundle("d0", qty=1)
        self.assertEqual(cm.exception.status_code, 422)

    def test_flag_off_raises_501(self):
        """expand_bundle raises 501 when product_depth_enabled=False."""
        from fastapi import HTTPException
        object.__setattr__(self.S, "product_depth_enabled", False)
        self._seed_item("bundle-1")
        with self.assertRaises(HTTPException) as cm:
            self.svc_variants.expand_bundle("bundle-1")
        self.assertEqual(cm.exception.status_code, 501)


# ---------------------------------------------------------------------------
# PRD-010: product associations service
# ---------------------------------------------------------------------------

class TestProductAssociations(_Base):

    def test_add_association_returns_row(self):
        """add_association returns a row with expected fields."""
        row = self.svc_assoc.add_association("item-a", "substitute", "item-b")
        self.assertEqual(row["from_item_id"], "item-a")
        self.assertEqual(row["to_item_id"], "item-b")
        self.assertEqual(row["assoc_type"], "substitute")
        self.assertIn("assoc_id", row)
        self.assertEqual(len(row["assoc_id"]), 16)

    def test_add_association_idempotent_same_assoc_id(self):
        """Same triple always produces the same assoc_id."""
        r1 = self.svc_assoc.add_association("item-a", "complement", "item-b")
        r2 = self.svc_assoc.add_association("item-a", "complement", "item-b")
        self.assertEqual(r1["assoc_id"], r2["assoc_id"])

    def test_list_associations_returns_all(self):
        """list_associations without filter returns all types."""
        self.svc_assoc.add_association("src", "substitute", "tgt-1")
        self.svc_assoc.add_association("src", "complement", "tgt-2")
        self.svc_assoc.add_association("src", "upgrade", "tgt-3")

        rows = self.svc_assoc.list_associations("src")
        self.assertEqual(len(rows), 3)

    def test_list_associations_with_type_filter(self):
        """list_associations(assoc_type=X) returns only rows of that type."""
        self.svc_assoc.add_association("src", "substitute", "tgt-1")
        self.svc_assoc.add_association("src", "complement", "tgt-2")
        self.svc_assoc.add_association("src", "substitute", "tgt-3")

        rows = self.svc_assoc.list_associations("src", assoc_type="substitute")
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["assoc_type"], "substitute")

    def test_remove_association(self):
        """remove_association deletes the row; subsequent list returns empty."""
        self.svc_assoc.add_association("src", "upgrade", "tgt")
        rows_before = self.svc_assoc.list_associations("src")
        self.assertEqual(len(rows_before), 1)

        self.svc_assoc.remove_association("src", "upgrade", "tgt")
        rows_after = self.svc_assoc.list_associations("src")
        self.assertEqual(len(rows_after), 0)

    def test_remove_association_noop_when_missing(self):
        """remove_association is a no-op when the row does not exist."""
        # Should not raise any exception.
        self.svc_assoc.remove_association("nonexistent", "substitute", "other")

    def test_invalid_assoc_type_raises_422(self):
        """add_association raises 422 for unknown assoc_type."""
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            self.svc_assoc.add_association("a", "badtype", "b")
        self.assertEqual(cm.exception.status_code, 422)

    def test_flag_off_raises_501(self):
        """Service functions raise 501 when product_depth_enabled=False."""
        from fastapi import HTTPException
        object.__setattr__(self.S, "product_depth_enabled", False)
        with self.assertRaises(HTTPException) as cm:
            self.svc_assoc.add_association("a", "substitute", "b")
        self.assertEqual(cm.exception.status_code, 501)

        with self.assertRaises(HTTPException) as cm2:
            self.svc_assoc.list_associations("a")
        self.assertEqual(cm2.exception.status_code, 501)


# ---------------------------------------------------------------------------
# PRD-011: router endpoints
# ---------------------------------------------------------------------------

class TestRouterEndpoints(_Base):

    def _expand(self, item_id: str, qty: int = 1):
        return asyncio.run(
            self.router_mod.expand_bundle_endpoint(item_id=item_id, qty=qty)
        )

    def _add_assoc(self, item_id: str, assoc_type: str, to_item_id: str, ctx=None):
        from app.routers.catalog import _AssociationIn
        body = _AssociationIn(assoc_type=assoc_type, to_item_id=to_item_id)
        return asyncio.run(
            self.router_mod.add_association_endpoint(
                item_id=item_id, body=body, ctx=ctx or self._ctx()
            )
        )

    def _list_assoc(self, item_id: str, assoc_type: str | None = None):
        return asyncio.run(
            self.router_mod.list_associations_endpoint(
                item_id=item_id, assoc_type=assoc_type
            )
        )

    def _del_assoc(self, item_id: str, to_item_id: str, assoc_type: str, ctx=None):
        return asyncio.run(
            self.router_mod.remove_association_endpoint(
                item_id=item_id,
                to_item_id=to_item_id,
                assoc_type=assoc_type,
                ctx=ctx or self._ctx(),
            )
        )

    def test_expand_bundle_endpoint(self):
        """GET /items/{id}/expand returns correct expand result."""
        self._seed_item("bndl", price=8000)
        self._seed_item("prt", price=400)
        self._set_product_type("bndl", "bundle")
        self._add_component("bndl", "prt", qty=3)

        result = self._expand("bndl", qty=2)
        self.assertEqual(result["item_id"], "bndl")
        self.assertEqual(result["qty"], 2)
        lines = result["lines"]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["item_id"], "prt")
        self.assertEqual(lines[0]["qty"], 6)   # 3 * 2

    def test_expand_endpoint_501_when_flag_off(self):
        """GET /items/{id}/expand returns 501 when product_depth_enabled=False."""
        from fastapi import HTTPException
        object.__setattr__(self.S, "product_depth_enabled", False)
        self._seed_item("bndl")
        with self.assertRaises(HTTPException) as cm:
            self._expand("bndl")
        self.assertEqual(cm.exception.status_code, 501)

    def test_add_list_remove_association_via_router(self):
        """Full CRUD cycle for associations through router endpoints."""
        self._seed_item("src-item", price=100)
        self._seed_item("tgt-item", price=200)

        row = self._add_assoc("src-item", "substitute", "tgt-item")
        self.assertEqual(row["from_item_id"], "src-item")
        self.assertEqual(row["to_item_id"], "tgt-item")

        listed = self._list_assoc("src-item")
        self.assertEqual(listed["item_id"], "src-item")
        self.assertEqual(listed["count"], 1)

        del_result = self._del_assoc("src-item", "tgt-item", "substitute")
        self.assertTrue(del_result["ok"])

        listed_after = self._list_assoc("src-item")
        self.assertEqual(listed_after["count"], 0)

    def test_association_owner_check_403(self):
        """add_association raises 403 for non-owner."""
        from fastapi import HTTPException
        self._seed_item("src-item", price=100)
        with self.assertRaises(HTTPException) as cm:
            self._add_assoc("src-item", "complement", "other", ctx=self._ctx("mallory"))
        self.assertEqual(cm.exception.status_code, 403)

    def test_association_endpoint_501_when_flag_off(self):
        """Association endpoints return 501 when product_depth_enabled=False."""
        from fastapi import HTTPException
        object.__setattr__(self.S, "product_depth_enabled", False)
        self._seed_item("src-item")
        with self.assertRaises(HTTPException) as cm:
            self._add_assoc("src-item", "substitute", "other")
        self.assertEqual(cm.exception.status_code, 501)

        with self.assertRaises(HTTPException) as cm2:
            self._list_assoc("src-item")
        self.assertEqual(cm2.exception.status_code, 501)


if __name__ == "__main__":
    unittest.main()

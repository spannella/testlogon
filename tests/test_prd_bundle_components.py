"""Offline regression tests for PRD product-bundle membership API.

Follow-up 3: catalog had ProductTypeEnum 'bundle'/'kit' but no component API.
This adds add/list/delete bundle-component endpoints on the product-depth
surface (``app/routers/catalog.py``) + backing service fns in
``app/services/product_variants.py``, gated by
``S.product_depth_enabled`` + ``S.product_depth_bundles_enabled``.

Test isolation (SECOPS-007 / repo rules):
  * Real in-memory moto DynamoDB ``shopping_catalog`` (ByItemId GSI) +
    ``product_depth`` tables bound to the frozen ``T`` handles via
    ``object.__setattr__`` + restore.
  * Frozen ``Settings`` flags flipped with ``object.__setattr__``.
  * NO TestClient — route coroutines / service fns called directly.
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


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestBundleComponents(unittest.TestCase):
    OWNER = "alice"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.catalog = _make_catalog_table(ddb)
        self.depth = _make_product_depth_table(ddb)

        from app.core.tables import T
        from app.routers import catalog as router
        from app.services import product_variants as svc

        self.T = T
        self.router = router
        self.svc = svc
        self.S = svc.S

        self._orig_catalog = T.catalog
        self._orig_depth = T.product_depth
        object.__setattr__(T, "catalog", self.catalog)
        object.__setattr__(T, "product_depth", self.depth)
        self.addCleanup(lambda: object.__setattr__(T, "catalog", self._orig_catalog))
        self.addCleanup(lambda: object.__setattr__(T, "product_depth", self._orig_depth))

        self._orig_flags = {
            "product_depth_enabled": self.S.product_depth_enabled,
            "product_depth_bundles_enabled": self.S.product_depth_bundles_enabled,
        }
        object.__setattr__(self.S, "product_depth_enabled", True)
        object.__setattr__(self.S, "product_depth_bundles_enabled", True)
        self.addCleanup(self._restore_flags)

        # Seed catalog items.
        self._seed_item("bundle-1", price=5000)
        self._seed_item("comp-a", price=1000)
        self._seed_item("comp-b", price=2000)
        self._seed_item("standalone-1", price=999)
        # Mark bundle-1 as a bundle (TYPE marker row on product_depth).
        self.depth.put_item(
            Item={
                "PK": "ITEM#bundle-1",
                "SK": "TYPE",
                "entity": "product_type",
                "product_type": "bundle",
                "creator_id": self.OWNER,
                "created_at": 1,
                "updated_at": 1,
            }
        )

    def _restore_flags(self):
        for k, v in self._orig_flags.items():
            object.__setattr__(self.S, k, v)

    def _seed_item(self, item_id, price=1000):
        self.catalog.put_item(
            Item={
                "PK": f"CAT#c1",
                "SK": f"ITEM#{item_id}",
                "entity": "item",
                "item_id": item_id,
                "sku": f"sku-{item_id}",
                "name": f"Item {item_id}",
                "price_cents": price,
                "creator_id": self.OWNER,
            }
        )

    def _ctx(self, sub=None):
        return {"user_sub": sub or self.OWNER, "role": "user"}

    def _add(self, parent, component, qty=1, ctx=None):
        from app import models

        body = models.BundleComponentIn(component_item_id=component, quantity=qty)
        return asyncio.run(
            self.router.add_bundle_component_endpoint(
                item_id=parent, body=body, ctx=ctx or self._ctx()
            )
        )

    def _list(self, parent, ctx=None):
        return asyncio.run(
            self.router.list_bundle_components_endpoint(item_id=parent, ctx=ctx or self._ctx())
        )

    def _delete(self, parent, component, ctx=None):
        return asyncio.run(
            self.router.remove_bundle_component_endpoint(
                item_id=parent, component_item_id=component, ctx=ctx or self._ctx()
            )
        )

    # -- happy path -----------------------------------------------------------

    def test_add_list_delete(self):
        out = self._add("bundle-1", "comp-a", qty=2)
        self.assertEqual(out.component_item_id, "comp-a")
        self.assertEqual(out.quantity, 2)

        self._add("bundle-1", "comp-b", qty=1)
        listed = self._list("bundle-1")
        self.assertEqual(listed.count, 2)
        comps = {c.component_item_id: c for c in listed.components}
        self.assertEqual(comps["comp-a"].quantity, 2)
        self.assertEqual(comps["comp-a"].component_sku, "sku-comp-a")
        self.assertEqual(comps["comp-a"].component_name, "Item comp-a")
        self.assertEqual(comps["comp-a"].component_price_cents, 1000)
        self.assertEqual(comps["comp-b"].component_price_cents, 2000)

        # delete one
        self._delete("bundle-1", "comp-a")
        listed2 = self._list("bundle-1")
        self.assertEqual(listed2.count, 1)
        self.assertEqual(listed2.components[0].component_item_id, "comp-b")

    def test_add_is_idempotent_quantity_update(self):
        self._add("bundle-1", "comp-a", qty=1)
        self._add("bundle-1", "comp-a", qty=5)
        listed = self._list("bundle-1")
        self.assertEqual(listed.count, 1)
        self.assertEqual(listed.components[0].quantity, 5)

    # -- error paths ----------------------------------------------------------

    def test_non_bundle_parent_422(self):
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as cm:
            self._add("standalone-1", "comp-a")
        self.assertEqual(cm.exception.status_code, 422)

    def test_unknown_component_404(self):
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as cm:
            self._add("bundle-1", "ghost-item")
        # _find_catalog_item raises 404 for an unknown component.
        self.assertIn(cm.exception.status_code, (404, 422))

    def test_self_reference_rejected(self):
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as cm:
            self._add("bundle-1", "bundle-1")
        self.assertEqual(cm.exception.status_code, 422)

    def test_cycle_rejected(self):
        # Make comp-a a bundle that contains bundle-1, then try to add comp-a to bundle-1.
        self.depth.put_item(
            Item={
                "PK": "ITEM#comp-a",
                "SK": "TYPE",
                "entity": "product_type",
                "product_type": "bundle",
                "creator_id": self.OWNER,
                "created_at": 1,
                "updated_at": 1,
            }
        )
        self._add("comp-a", "bundle-1")  # comp-a now contains bundle-1
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as cm:
            self._add("bundle-1", "comp-a")
        self.assertEqual(cm.exception.status_code, 422)

    def test_delete_unknown_404(self):
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as cm:
            self._delete("bundle-1", "comp-a")
        self.assertEqual(cm.exception.status_code, 404)

    def test_non_owner_403(self):
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as cm:
            self._add("bundle-1", "comp-a", ctx=self._ctx("mallory"))
        self.assertEqual(cm.exception.status_code, 403)

    def test_flag_off_404(self):
        from fastapi import HTTPException

        object.__setattr__(self.S, "product_depth_enabled", False)
        with self.assertRaises(HTTPException) as cm:
            self._add("bundle-1", "comp-a")
        self.assertEqual(cm.exception.status_code, 404)
        with self.assertRaises(HTTPException) as cm2:
            self._list("bundle-1")
        self.assertEqual(cm2.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()

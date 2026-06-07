"""Offline regression test for GAP-0349 (SHOP-002).

``app/services/shoppingcart.py``: ``add_catalog_item`` fetched the catalog item
but only copied ``sku``/``name``/``quantity``/``unit_price_cents`` into the cart
item, dropping the catalog item's ``creator_id``. Consequently
``_resolve_cart_creator`` returned ``None`` for catalog-backed cart items, and
``purchase_cart`` fell back to the *buyer*'s ``user_sub`` as the
``creator_user_id`` for promo validation, so creator-scoped promos always failed
with "not valid for this creator".

The two-part fix:
  (a) ``add_catalog_item`` puts ``creator_user_id`` (from the catalog item's
      ``creator_id`` field) into the payload it hands to ``add_item``.
  (b) ``add_item``'s NEW-ITEM path (which builds the DDB item from an explicit
      named field set, not the whole payload) passes ``creator_user_id`` through.

Without BOTH parts the stored cart item lacks ``creator_user_id`` and
``_resolve_cart_creator`` returns ``None``.

Fully offline: a real in-memory DynamoDB (moto) is created with the same
keyschema as ``scripts/local-ddb-init.py`` for the ``shopping_catalog`` and
``shopping_cart`` tables, and the FROZEN ``T`` handles are rebound via
``object.__setattr__`` then restored on teardown.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_catalog_table(ddb):
    """Mirror scripts/local-ddb-init.py shopping_catalog (PK/SK + GSIs)."""
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
                "KeySchema": [{"AttributeName": "item_id", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_cart_table(ddb):
    """Mirror scripts/local-ddb-init.py shopping_cart (PK/SK + ByStatusActivity)."""
    return ddb.create_table(
        TableName="shopping_cart",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "last_activity_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByStatusActivity",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "last_activity_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto not installed")
class TestGap0349CartCreatorId(unittest.TestCase):
    def setUp(self):
        from app.core.tables import T

        self._stack = ExitStack()
        self._stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self._catalog = _make_catalog_table(ddb)
        self._cart = _make_cart_table(ddb)

        # Rebind the FROZEN table handles, restore on teardown.
        self._orig_catalog = T.catalog
        self._orig_cart = T.shopping_cart
        object.__setattr__(T, "catalog", self._catalog)
        object.__setattr__(T, "shopping_cart", self._cart)
        self._T = T

    def tearDown(self):
        object.__setattr__(self._T, "catalog", self._orig_catalog)
        object.__setattr__(self._T, "shopping_cart", self._orig_cart)
        self._stack.close()

    def test_catalog_item_carries_creator_user_id(self):
        import app.services.shoppingcart as sc

        buyer = "buyer-sub-1"
        creator = "creator-sub-99"  # deliberately != buyer
        category_id = "cat1"
        item_id = "itemABC"

        # Seed a catalog item with creator_id set to the creator (not the buyer).
        self._catalog.put_item(
            Item={
                **sc._catalog_item_key(category_id, item_id),
                "entity": "item",
                "name": "Widget",
                "price_cents": 500,
                "currency": "USD",
                "item_id": item_id,
                "creator_id": creator,
            }
        )

        cart = sc.start_cart(buyer)
        cart_id = cart["cart_id"]

        sc.add_catalog_item(
            buyer, cart_id, category_id=category_id, item_id=item_id, quantity=2
        )

        # Raw stored cart item must now carry creator_user_id == catalog creator_id.
        sku = f"catalog:{item_id}"
        stored = self._cart.get_item(
            Key={"PK": sc._user_pk(buyer), "SK": sc._item_sk(cart_id, sku)}
        ).get("Item")
        self.assertIsNotNone(stored, "cart item should have been written")
        self.assertEqual(
            stored.get("creator_user_id"),
            creator,
            "stored cart item must carry the catalog item's creator_id as creator_user_id",
        )

        # _resolve_cart_creator must resolve to the creator (not None, not buyer).
        items = sc.list_items(buyer, cart_id)
        resolved = sc._resolve_cart_creator(items)
        self.assertEqual(resolved, creator)
        self.assertNotEqual(resolved, buyer)
        self.assertIsNotNone(resolved)


if __name__ == "__main__":
    unittest.main()

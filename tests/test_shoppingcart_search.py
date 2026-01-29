import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app.routers import shoppingcart as shoppingcart_router
from app.services import shoppingcart


class TestShoppingCartSearch(unittest.TestCase):
    def test_search_items_matches_tokens(self):
        items = [
            {
                "PK": "USER#user",
                "SK": "CART#c1#ITEM#sku-1",
                "type": "item",
                "cart_id": "c1",
                "sku": "sku-1",
                "name": "Blue Widget",
                "quantity": 2,
                "unit_price_cents": 125,
                "updated_at": "t1",
            },
            {
                "PK": "USER#user",
                "SK": "CART#c2#ITEM#sku-2",
                "type": "item",
                "cart_id": "c2",
                "sku": "sku-2",
                "name": "Red Gadget",
                "quantity": 1,
                "unit_price_cents": 300,
                "updated_at": "t2",
            },
        ]
        fake_tables = SimpleNamespace(shopping_cart=Mock())
        fake_tables.shopping_cart.query.return_value = {"Items": items}
        with patch.object(shoppingcart, "T", fake_tables):
            resp = shoppingcart.search_items("user", "blue", 10)
        self.assertEqual(len(resp), 1)
        self.assertEqual(resp[0]["sku"], "sku-1")
        self.assertEqual(resp[0]["cart_id"], "c1")

    def test_search_items_returns_empty_when_no_match(self):
        items = [
            {
                "PK": "USER#user",
                "SK": "CART#c1#ITEM#sku-1",
                "type": "item",
                "cart_id": "c1",
                "sku": "sku-1",
                "name": "Blue Widget",
                "quantity": 2,
                "unit_price_cents": 125,
                "updated_at": "t1",
            }
        ]
        fake_tables = SimpleNamespace(shopping_cart=Mock())
        fake_tables.shopping_cart.query.return_value = {"Items": items}
        with patch.object(shoppingcart, "T", fake_tables):
            resp = shoppingcart.search_items("user", "green", 10)
        self.assertEqual(resp, [])

    def test_search_items_route_returns_items(self):
        with patch.object(shoppingcart_router, "search_items", return_value=[{"sku": "sku-1"}]):
            resp = asyncio.run(shoppingcart_router.ui_search_items(q="sku", limit=10, ctx={"user_sub": "user"}))
        self.assertEqual(resp["count"], 1)
        self.assertEqual(resp["items"][0]["sku"], "sku-1")

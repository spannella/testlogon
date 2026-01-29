import asyncio
import unittest
from unittest.mock import Mock, patch

from app.routers import catalog


class TestCatalogSearch(unittest.TestCase):
    def test_search_items_matches_name_tokens(self):
        table = Mock()
        table.scan.return_value = {
            "Items": [
                {
                    "entity": "item",
                    "category_id": "c1",
                    "item_id": "i1",
                    "name": "Red Chair",
                    "description": "Soft seat",
                    "price_cents": 1000,
                    "currency": "USD",
                    "image_urls": [],
                    "attributes": {},
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-01T00:00:00Z",
                }
            ],
            "LastEvaluatedKey": None,
        }
        with patch.object(catalog, "T", Mock(catalog=table)):
            resp = asyncio.run(catalog.search_items(q="chair", page_size=10, next_token=None))
        self.assertEqual(len(resp.items), 1)
        self.assertEqual(resp.items[0].item_id, "i1")

    def test_search_items_filters_non_matches(self):
        table = Mock()
        table.scan.return_value = {
            "Items": [
                {
                    "entity": "item",
                    "category_id": "c1",
                    "item_id": "i2",
                    "name": "Blue Sofa",
                    "description": "Large cushions",
                    "price_cents": 2000,
                    "currency": "USD",
                    "image_urls": [],
                    "attributes": {},
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-01T00:00:00Z",
                }
            ],
            "LastEvaluatedKey": None,
        }
        with patch.object(catalog, "T", Mock(catalog=table)):
            resp = asyncio.run(catalog.search_items(q="chair", page_size=10, next_token=None))
        self.assertEqual(resp.items, [])

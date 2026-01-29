import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app.services import purchase_history


class TestPurchaseHistorySearch(unittest.TestCase):
    def test_search_transactions_matches_text(self):
        items = [
            {
                "txn_id": "t1",
                "created_at": 1,
                "updated_at": 2,
                "status": "COMPLETED",
                "amount": "12.50",
                "currency": "USD",
                "merchant_id": "billing",
                "external_ref": "INV-100",
                "description": "Monthly plan renewal",
                "metadata": {"note": "priority"},
            },
            {
                "txn_id": "t2",
                "created_at": 3,
                "updated_at": 4,
                "status": "PENDING",
                "amount": "9.99",
                "currency": "USD",
                "merchant_id": "shopping_cart",
                "external_ref": "ORDER-200",
                "description": "Cart checkout",
            },
        ]
        fake_tables = SimpleNamespace(purchase_transactions=Mock())
        fake_tables.purchase_transactions.query.return_value = {"Items": items}
        with patch.object(purchase_history, "T", fake_tables):
            resp = purchase_history.search_transactions("user", "renewal", 25)
        self.assertEqual(len(resp), 1)
        self.assertEqual(resp[0]["txn_id"], "t1")

    def test_search_transactions_returns_empty_when_no_match(self):
        items = [
            {
                "txn_id": "t1",
                "created_at": 1,
                "updated_at": 2,
                "status": "COMPLETED",
                "amount": "12.50",
                "currency": "USD",
                "merchant_id": "billing",
                "external_ref": "INV-100",
                "description": "Monthly plan renewal",
            }
        ]
        fake_tables = SimpleNamespace(purchase_transactions=Mock())
        fake_tables.purchase_transactions.query.return_value = {"Items": items}
        with patch.object(purchase_history, "T", fake_tables):
            resp = purchase_history.search_transactions("user", "gadget", 25)
        self.assertEqual(resp, [])

    def test_search_transactions_matches_metadata_and_shipping(self):
        items = [
            {
                "txn_id": "t9",
                "created_at": 1,
                "updated_at": 2,
                "status": "COMPLETED",
                "amount": "12.50",
                "currency": "USD",
                "merchant_id": "billing",
                "external_ref": "INV-200",
                "description": "Monthly plan renewal",
                "metadata": {"note": "priority", "tags": ["vip", "q1"]},
                "shipping": {"carrier": "UPS", "tracking_number": "1Z999"},
            }
        ]
        fake_tables = SimpleNamespace(purchase_transactions=Mock())
        fake_tables.purchase_transactions.query.return_value = {"Items": items}
        with patch.object(purchase_history, "T", fake_tables):
            resp = purchase_history.search_transactions("user", "ups", 25)
        self.assertEqual(len(resp), 1)
        self.assertEqual(resp[0]["txn_id"], "t9")

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app.services import purchase_history, receipts


class TestReceiptsService(unittest.TestCase):
    def test_get_or_create_receipt_returns_existing(self):
        txn_item = {
            "user_sub": "user-1",
            "txn_id": "txn-1",
            "receipt_path": "/billing/receipts/txn-1.pdf",
            "receipt_generated_at": 123,
            "status": "COMPLETED",
            "amount": "10.00",
            "currency": "usd",
            "created_at": 10,
            "completed_at": 11,
        }
        with (
            patch.object(receipts, "get_transaction_item", return_value=txn_item),
            patch.object(receipts, "get_profile", return_value={"display_name": "Ada"}),
            patch.object(receipts, "_find_payment_record", return_value=None),
            patch.object(receipts, "upload_billing_receipt", return_value={"path": "/billing/receipts/txn-1.pdf"}),
            patch.object(receipts, "set_receipt_info") as set_mock,
            patch.object(receipts, "build_download_url", return_value="https://example/receipt.pdf"),
            patch.object(receipts, "now_ts", return_value=123),
        ):
            result = receipts.get_or_create_receipt("user-1", "txn-1")

        self.assertEqual(result["receipt_path"], "/billing/receipts/txn-1.pdf")
        self.assertEqual(result["receipt_url"], "https://example/receipt.pdf")
        self.assertEqual(result["generated_at"], 123)
        set_mock.assert_called_once()

    def test_get_or_create_receipt_creates_pdf(self):
        txn_item = {
            "user_sub": "user-2",
            "txn_id": "txn-2",
            "status": "COMPLETED",
            "amount": "10.00",
            "currency": "usd",
            "created_at": 10,
            "completed_at": 11,
        }
        with (
            patch.object(receipts, "get_transaction_item", return_value=txn_item),
            patch.object(receipts, "get_profile", return_value={"display_name": "Ada"}),
            patch.object(receipts, "_find_payment_record", return_value={"external_id": "pay_1", "kind": "paypal"}),
            patch.object(receipts, "upload_billing_receipt", return_value={"path": "/billing/receipts/txn-2.pdf"}),
            patch.object(receipts, "set_receipt_info") as set_mock,
            patch.object(receipts, "build_download_url", return_value="https://example/txn-2.pdf"),
            patch.object(receipts, "now_ts", return_value=456),
        ):
            result = receipts.get_or_create_receipt("user-2", "txn-2")

        self.assertEqual(result["receipt_path"], "/billing/receipts/txn-2.pdf")
        self.assertEqual(result["receipt_url"], "https://example/txn-2.pdf")
        self.assertEqual(result["generated_at"], 456)
        set_mock.assert_called_once_with("user-2", "txn-2", "/billing/receipts/txn-2.pdf", 456)


class TestPurchaseHistoryReceiptInfo(unittest.TestCase):
    def test_set_receipt_info_records_event(self):
        txn_item = {"user_sub": "user-3", "sk": "TXN#1#abc", "version": 2}
        fake_tables = SimpleNamespace(purchase_transactions=Mock())
        with (
            patch.object(purchase_history, "_fetch_txn", return_value=txn_item),
            patch.object(purchase_history, "T", fake_tables),
            patch.object(purchase_history, "now_ts", return_value=999),
            patch.object(purchase_history, "_record_event") as event_mock,
        ):
            purchase_history.set_receipt_info("user-3", "txn-3", "/billing/receipts/txn-3.pdf", 321)

        fake_tables.purchase_transactions.update_item.assert_called_once()
        event_mock.assert_called_once_with(
            "txn-3",
            "user-3",
            "receipt_generated",
            {"receipt_path": "/billing/receipts/txn-3.pdf", "receipt_generated_at": 321},
        )

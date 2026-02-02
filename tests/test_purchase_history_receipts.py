import unittest
from unittest.mock import patch

from app.services import purchase_history


class TestPurchaseHistoryReceipts(unittest.TestCase):
    def test_record_receipt_download_emits_event(self):
        with patch.object(purchase_history, "_record_event") as event_mock:
            purchase_history.record_receipt_download(
                "user-1",
                "txn-1",
                "/billing/receipts/txn-1.pdf",
            )

        event_mock.assert_called_once_with(
            "txn-1",
            "user-1",
            "receipt_downloaded",
            {"receipt_path": "/billing/receipts/txn-1.pdf"},
        )

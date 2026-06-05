"""GAP-0049: platform 30% revenue share must be written to a ledger.

Offline unit tests for `app.services.ad_billing._split_revenue`. No real AWS:
DynamoDB table handles are replaced with MagicMocks.
"""
from unittest.mock import patch, MagicMock


class TestSplitRevenuePlatformEntry:
    def _run_split(self, charge_cents=100, creator_id="creator_001", meta=None):
        from app.services.ad_billing import _split_revenue
        mock_billing = MagicMock()
        mock_ad_billing = MagicMock()
        with patch("app.services.ad_billing.T") as mock_t, \
             patch("app.services.ad_billing.new_ledger_entry") as mock_nle:
            mock_t.billing = mock_billing
            mock_t.ad_billing = mock_ad_billing
            mock_nle.return_value = ("sk_123", {"pk": f"USER#{creator_id}", "sk": "sk_123"})
            _split_revenue(
                charge_cents=charge_cents,
                creator_id=creator_id,
                meta=meta if meta is not None else {"campaign_id": "camp_001"},
                ts=1748000000,
            )
        return mock_ad_billing

    def test_platform_revenue_entry_written(self):
        """_split_revenue must write a platform_revenue_credit to T.ad_billing."""
        mock_ad_billing = self._run_split(charge_cents=100)
        # FAILS BEFORE FIX: put_item never called on ad_billing in _split_revenue
        mock_ad_billing.put_item.assert_called_once()
        item = mock_ad_billing.put_item.call_args[1]["Item"]
        assert item["pk"] == "PLATFORM#revenue"
        assert item["sk"].startswith("LEDGER#1748000000#")
        assert item["entry_type"] == "platform_revenue_credit"
        assert item["amount_cents"] == 30  # 30% of 100 cents
        assert item["state"] == "settled"

    def test_platform_share_calculation(self):
        """Platform gets exactly 30% (integer division, rounded down)."""
        mock_ad_billing = self._run_split(charge_cents=333)
        item = mock_ad_billing.put_item.call_args[1]["Item"]
        assert item["amount_cents"] == 99  # 333 * 30 // 100 = 99

    def test_creator_share_correct(self):
        """Creator gets charge_cents minus platform_share."""
        from app.services.ad_billing import _split_revenue
        mock_billing = MagicMock()
        with patch("app.services.ad_billing.T") as mock_t, \
             patch("app.services.ad_billing.new_ledger_entry") as mock_nle:
            mock_t.billing = mock_billing
            mock_t.ad_billing = MagicMock()
            mock_nle.return_value = ("sk", {"pk": "USER#c", "sk": "sk"})
            _split_revenue(charge_cents=100, creator_id="c", meta={}, ts=1748000000)
        _, kwargs = mock_nle.call_args
        assert kwargs["amount_cents"] == 70  # 100 - 30

    def test_platform_entry_has_month_key(self):
        """Platform revenue entry includes month_key for ByMonth GSI."""
        mock_ad_billing = self._run_split(charge_cents=200)
        item = mock_ad_billing.put_item.call_args[1]["Item"]
        assert "month_key" in item
        assert len(item["month_key"]) == 7  # "YYYY-MM"

    def test_platform_entry_meta_carries_split_context(self):
        """Platform entry meta records creator + split context for reconciliation."""
        mock_ad_billing = self._run_split(charge_cents=100, creator_id="creator_001")
        item = mock_ad_billing.put_item.call_args[1]["Item"]
        assert item["meta"]["creator_id"] == "creator_001"
        assert item["meta"]["creator_share_cents"] == 70
        assert item["meta"]["charge_cents"] == 100
        assert item["meta"]["platform_share_pct"] == 30

    def test_no_platform_entry_when_share_zero(self):
        """Tiny charges where 30% rounds to 0 write no platform entry."""
        mock_ad_billing = self._run_split(charge_cents=1)  # 1 * 30 // 100 == 0
        mock_ad_billing.put_item.assert_not_called()

    def test_platform_entry_failure_does_not_raise(self):
        """A DynamoDB error on platform write is swallowed (warning logged)."""
        from app.services.ad_billing import _split_revenue
        mock_ad_billing = MagicMock()
        mock_ad_billing.put_item.side_effect = Exception("DDB error")
        with patch("app.services.ad_billing.T") as mock_t, \
             patch("app.services.ad_billing.new_ledger_entry") as mock_nle:
            mock_t.billing = MagicMock()
            mock_t.ad_billing = mock_ad_billing
            mock_nle.return_value = ("sk", {"pk": "USER#c", "sk": "sk"})
            # Must not raise
            _split_revenue(charge_cents=100, creator_id="c", meta={}, ts=1748000000)

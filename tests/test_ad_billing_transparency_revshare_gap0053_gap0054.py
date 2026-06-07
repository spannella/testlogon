"""GAP-0053 + GAP-0054: advertiser transparency + per-creator revenue share.

Offline unit tests for `app.services.ad_billing._split_revenue`. No real AWS:
DynamoDB table handles and cross-module lookups are replaced with MagicMocks.

GAP-0053: a charge must call record_transparency so the per-advertiser
transparency log (read by get_advertiser_transparency) is populated.

GAP-0054: the creator credit must reflect the creator's negotiated
revenue_share_bps, not a hardcoded 30% platform share.
"""
from unittest.mock import patch, MagicMock


def _split(*, charge_cents, creator_id="creator_001", account_id="acct_001",
           meta=None, bps=7000, bps_side_effect=None, company_name="Acme Corp"):
    """Fire _split_revenue with mocked tables + cross-module lookups.

    Returns (mock_new_ledger_entry, mock_record_transparency, mock_ad_billing).
    """
    from app.services.ad_billing import _split_revenue

    rt = MagicMock()
    gaa = MagicMock(return_value={"company_name": company_name, "account_id": account_id})
    gbps = MagicMock(return_value=bps)
    if bps_side_effect is not None:
        gbps.side_effect = bps_side_effect

    mock_ad_billing = MagicMock()
    with patch("app.services.ad_billing.T") as mock_t, \
         patch("app.services.ad_billing.new_ledger_entry") as mock_nle, \
         patch("app.services.content_ad_controls.get_creator_revenue_share_bps", gbps), \
         patch("app.services.content_ad_controls.record_transparency", rt), \
         patch("app.services.ad_accounts.get_ad_account", gaa):
        mock_t.billing = MagicMock()
        mock_t.ad_billing = mock_ad_billing
        mock_nle.return_value = ("sk_123", {"pk": f"USER#{creator_id}", "sk": "sk_123"})
        _split_revenue(
            charge_cents=charge_cents,
            creator_id=creator_id,
            account_id=account_id,
            meta=meta if meta is not None else {"model": "cpm", "campaign_id": "camp_001"},
            ts=1748000000,
        )
    return mock_nle, rt, mock_ad_billing


# ── GAP-0053: transparency ──────────────────────────────────────────────────


class TestTransparencyRecorded:
    def test_record_transparency_called_on_charge(self):
        """FAILS BEFORE FIX: record_transparency has no call site."""
        _, rt, _ = _split(charge_cents=10000, account_id="acct_001")
        rt.assert_called_once()
        kwargs = rt.call_args.kwargs
        assert kwargs["creator_sub"] == "creator_001"
        assert kwargs["account_id"] == "acct_001"
        assert kwargs["company_name"] == "Acme Corp"
        assert kwargs["month"] == "2025-05"  # 1748000000 -> 2025-05 UTC

    def test_impression_model_records_one_impression(self):
        _, rt, _ = _split(charge_cents=10000, meta={"model": "cpm"})
        kwargs = rt.call_args.kwargs
        assert kwargs["impressions"] == 1
        assert kwargs["clicks"] == 0

    def test_click_model_records_one_click(self):
        _, rt, _ = _split(charge_cents=10000, meta={"model": "cpc"})
        kwargs = rt.call_args.kwargs
        assert kwargs["clicks"] == 1
        assert kwargs["impressions"] == 0

    def test_transparency_revenue_is_creator_share(self):
        # 10000 cents * 7000 bps // 10000 = 7000 to creator
        _, rt, _ = _split(charge_cents=10000, bps=7000)
        assert rt.call_args.kwargs["revenue_cents"] == 7000

    def test_no_transparency_without_account_id(self):
        _, rt, _ = _split(charge_cents=10000, account_id="")
        rt.assert_not_called()

    def test_transparency_failure_does_not_break_billing(self):
        """Transparency is best-effort; a raise must not propagate or block the
        platform-revenue ledger write."""
        from app.services.ad_billing import _split_revenue
        mock_ad_billing = MagicMock()
        with patch("app.services.ad_billing.T") as mock_t, \
             patch("app.services.ad_billing.new_ledger_entry") as mock_nle, \
             patch("app.services.content_ad_controls.get_creator_revenue_share_bps",
                   return_value=7000), \
             patch("app.services.content_ad_controls.record_transparency",
                   side_effect=Exception("boom")), \
             patch("app.services.ad_accounts.get_ad_account",
                   return_value={"company_name": "Acme"}):
            mock_t.billing = MagicMock()
            mock_t.ad_billing = mock_ad_billing
            mock_nle.return_value = ("sk", {"pk": "USER#c", "sk": "sk"})
            # Must not raise
            _split_revenue(charge_cents=10000, creator_id="c",
                           account_id="a", meta={"model": "cpm"}, ts=1748000000)
        # platform revenue ledger write still happened
        mock_ad_billing.put_item.assert_called_once()


# ── GAP-0054: per-creator revenue share ─────────────────────────────────────


class TestPerCreatorRevenueShare:
    def test_default_bps_matches_legacy_70_30(self):
        mock_nle, _, _ = _split(charge_cents=10000, bps=7000)
        assert mock_nle.call_args.kwargs["amount_cents"] == 7000

    def test_custom_90_percent_share(self):
        """FAILS BEFORE FIX: hardcoded 30% gives creator 7000, not 9000."""
        mock_nle, _, _ = _split(charge_cents=10000, bps=9000)
        assert mock_nle.call_args.kwargs["amount_cents"] == 9000

    def test_custom_50_percent_share(self):
        mock_nle, _, _ = _split(charge_cents=10000, bps=5000)
        assert mock_nle.call_args.kwargs["amount_cents"] == 5000

    def test_zero_creator_share_writes_no_credit(self):
        mock_nle, _, _ = _split(charge_cents=10000, bps=0)
        mock_nle.assert_not_called()

    def test_bps_recorded_in_creator_ledger_meta(self):
        mock_nle, _, _ = _split(charge_cents=10000, bps=9000)
        meta = mock_nle.call_args.kwargs["meta"]
        assert meta["revenue_share_bps"] == 9000
        # platform share % derived: (10000 - 9000)*100//10000 = 10
        assert meta["platform_share_pct"] == 10

    def test_platform_ledger_uses_dynamic_share(self):
        """GAP-0049 platform ledger preserved + uses dynamic split (GAP-0054)."""
        _, _, mock_ad_billing = _split(charge_cents=10000, bps=9000)
        item = mock_ad_billing.put_item.call_args[1]["Item"]
        assert item["entry_type"] == "platform_revenue_credit"
        assert item["amount_cents"] == 1000  # 10000 - 9000
        assert item["meta"]["revenue_share_bps"] == 9000
        assert item["meta"]["platform_share_pct"] == 10
        assert item["meta"]["creator_share_cents"] == 9000

    def test_bps_lookup_failure_falls_back_to_default(self):
        """If the BPS lookup raises, fall back to default (7000) and keep billing."""
        mock_nle, _, _ = _split(charge_cents=10000,
                                bps_side_effect=Exception("DDB timeout"))
        assert mock_nle.call_args.kwargs["amount_cents"] == 7000

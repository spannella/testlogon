"""Offline regression tests for GAP-0197 (FIN-010).

GAP-0197 — Four creator-level affiliate analytics aggregations were absent from
``app/services/affiliate_links.py``: ``get_creator_summary``,
``get_click_timeseries``, ``get_earnings_breakdown`` and ``get_top_products``.
Only the per-link ``get_link_stats`` existed. As a result the creator dashboard
had no cross-link summary, click time-series, earnings breakdown, or
top-products leaderboard.

These tests call the service functions directly (the FastAPI TestClient is
unusable in this repo) against real in-memory DynamoDB tables created with moto.

TEST ISOLATION (critical): we do NOT rely on global ``@mock_aws`` interception
of the app's pre-bound boto3 clients — that leaks to real AWS when another test
module imported the app first. Instead we monkeypatch the *exact* handle the
code uses: the frozen ``T`` table-handle container on ``affiliate_links``. ``T``
is frozen, so we swap the attribute with ``object.__setattr__`` and restore the
original afterwards. The ``affiliate_links`` table is created with the same GSIs
as ``scripts/local-ddb-init.py`` (including the new ``ByCreator`` GSI on the
clicks table) so creator-scoped queries behave exactly as in prod.

FAILS BEFORE FIX: the four functions don't exist → ``AttributeError`` on import
/ call. PASSES AFTER FIX.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_links_table(ddb):
    """Mirror the AffiliateLinks TableDef from scripts/local-ddb-init.py."""
    return ddb.create_table(
        TableName="AffiliateLinks",
        KeySchema=[{"AttributeName": "link_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "link_id", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByAffiliate",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_clicks_table(ddb):
    """Mirror the AffiliateClicks TableDef incl. the new ByCreator GSI."""
    return ddb.create_table(
        TableName="AffiliateClicks",
        KeySchema=[
            {"AttributeName": "link_id", "KeyType": "HASH"},
            {"AttributeName": "click_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "link_id", "AttributeType": "S"},
            {"AttributeName": "click_id", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
            {"AttributeName": "GSI2PK", "AttributeType": "S"},
            {"AttributeName": "GSI2SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByVisitor",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByCreator",
                "KeySchema": [
                    {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestAffiliateAnalyticsGap0197(unittest.TestCase):
    DAY = 86400

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.links = _make_links_table(ddb)
        self.clicks = _make_clicks_table(ddb)

        from app.services import affiliate_links as svc
        from app.core.tables import T as real_T

        self.svc = svc

        # Swap the EXACT handle the code uses. T is frozen -> object.__setattr__.
        self._orig_links = real_T.affiliate_links
        self._orig_clicks = real_T.affiliate_clicks
        object.__setattr__(real_T, "affiliate_links", self.links)
        object.__setattr__(real_T, "affiliate_clicks", self.clicks)

        def _restore():
            object.__setattr__(real_T, "affiliate_links", self._orig_links)
            object.__setattr__(real_T, "affiliate_clicks", self._orig_clicks)

        self.addCleanup(_restore)

    # -- seed helpers --------------------------------------------------

    def _seed_link(
        self,
        creator_id: str,
        link_id: str,
        *,
        clicks: int = 0,
        unique: int = 0,
        conversions: int = 0,
        revenue: int = 0,
        commission: int = 0,
        status: str = "active",
        created_at: int = 1000,
        target_name: str = "",
        target_id: str = "",
        target_type: str = "catalog_item",
    ):
        self.links.put_item(
            Item={
                "link_id": link_id,
                "affiliate_user_id": creator_id,
                "target_type": target_type,
                "target_id": target_id or link_id,
                "target_name": target_name or link_id,
                "status": status,
                "click_count": clicks,
                "unique_click_count": unique,
                "conversion_count": conversions,
                "revenue_cents": revenue,
                "commission_earned_cents": commission,
                "created_at": created_at,
                "GSI1PK": f"AFFILIATE#{creator_id}",
                "GSI1SK": created_at,
            }
        )

    def _seed_click(self, creator_id: str, link_id: str, ts: int):
        cid = f"clk_{ts}_{link_id}"
        self.clicks.put_item(
            Item={
                "link_id": link_id,
                "click_id": cid,
                "clicked_at": ts,
                "creator_id": creator_id,
                "GSI2PK": f"CREATOR#{creator_id}",
                "GSI2SK": ts,
            }
        )

    # -- summary -------------------------------------------------------

    def test_summary_empty(self):
        out = self.svc.get_creator_summary("creator_none")
        self.assertEqual(out["total_links"], 0)
        self.assertEqual(out["total_clicks"], 0)
        self.assertEqual(out["total_commission_cents"], 0)
        self.assertEqual(out["overall_conversion_rate_pct"], 0.0)

    def test_summary_aggregates_across_links(self):
        c = "creator_summary"
        self._seed_link(c, "afl_a", clicks=5, unique=4, conversions=2,
                        revenue=1000, commission=100, status="active")
        self._seed_link(c, "afl_b", clicks=5, unique=6, conversions=2,
                        revenue=500, commission=50, status="revoked")
        out = self.svc.get_creator_summary(c)
        self.assertEqual(out["total_links"], 2)
        self.assertEqual(out["active_links"], 1)
        self.assertEqual(out["total_clicks"], 10)
        self.assertEqual(out["unique_clicks"], 10)
        self.assertEqual(out["total_conversions"], 4)
        self.assertEqual(out["total_revenue_cents"], 1500)
        self.assertEqual(out["total_commission_cents"], 150)
        # 4 conversions / 10 unique = 40%
        self.assertEqual(out["overall_conversion_rate_pct"], 40.0)

    def test_summary_isolated_per_creator(self):
        self._seed_link("creator_x", "afl_x", clicks=99)
        self._seed_link("creator_y", "afl_y", clicks=1)
        self.assertEqual(self.svc.get_creator_summary("creator_y")["total_clicks"], 1)

    # -- timeseries ----------------------------------------------------

    def test_timeseries_buckets_by_day(self):
        c = "creator_ts"
        base = 7 * self.DAY  # aligned to a day boundary
        # 3 clicks on day 0, 1 on day 1, 2 on day 2
        for i in range(3):
            self._seed_click(c, "afl_ts", base + i * 10)
        self._seed_click(c, "afl_ts", base + self.DAY + 5)
        self._seed_click(c, "afl_ts", base + 2 * self.DAY + 1)
        self._seed_click(c, "afl_ts", base + 2 * self.DAY + 2)

        out = self.svc.get_click_timeseries(c, interval="day")
        self.assertEqual(len(out), 3)
        # chronologically sorted
        self.assertEqual([b["clicks"] for b in out], [3, 1, 2])
        self.assertEqual(out[0]["bucket"], str(base))

    def test_timeseries_creator_scoped(self):
        self._seed_click("creator_a", "afl_a", 10 * self.DAY)
        self._seed_click("creator_b", "afl_b", 10 * self.DAY)
        out = self.svc.get_click_timeseries("creator_a", interval="day")
        self.assertEqual(sum(b["clicks"] for b in out), 1)

    def test_timeseries_time_range_filter(self):
        c = "creator_range"
        for d in range(5):
            self._seed_click(c, "afl_r", d * self.DAY + 100)
        # only days 1..3 inclusive
        out = self.svc.get_click_timeseries(
            c, interval="day", from_ts=1 * self.DAY, to_ts=3 * self.DAY + self.DAY - 1
        )
        self.assertEqual(sum(b["clicks"] for b in out), 3)

    # -- earnings breakdown -------------------------------------------

    def test_earnings_breakdown_sorted_desc(self):
        c = "creator_earn"
        self._seed_link(c, "afl_lo", commission=10, revenue=100, conversions=1,
                        target_name="Low")
        self._seed_link(c, "afl_hi", commission=500, revenue=5000, conversions=5,
                        target_name="High")
        out = self.svc.get_earnings_breakdown(c)
        self.assertEqual(out["total_commission_cents"], 510)
        self.assertEqual(out["items"][0]["link_id"], "afl_hi")
        self.assertGreaterEqual(
            out["items"][0]["commission_earned_cents"],
            out["items"][1]["commission_earned_cents"],
        )
        self.assertEqual(out["items"][0]["target_name"], "High")

    # -- top products --------------------------------------------------

    def test_top_products_ranked_and_limited(self):
        c = "creator_top"
        for i in range(6):
            self._seed_link(c, f"afl_{i}", clicks=i * 10)
        out = self.svc.get_top_products(c, limit=3)
        self.assertEqual(len(out), 3)
        clicks = [p["click_count"] for p in out]
        self.assertEqual(clicks, sorted(clicks, reverse=True))
        self.assertEqual(out[0]["link_id"], "afl_5")  # highest clicks

    # -- record_click now indexes by creator --------------------------

    def test_record_click_indexes_by_creator(self):
        """A click recorded with creator_id is surfaced by the time-series."""
        c = "creator_rc"
        self._seed_link(c, "afl_rc")
        self.svc.record_click(
            link_id="afl_rc",
            tracking_code="ABCDE",
            ip_address="1.2.3.4",
            user_agent="Mozilla/5.0",
            creator_id=c,
        )
        out = self.svc.get_click_timeseries(c, interval="day")
        self.assertEqual(sum(b["clicks"] for b in out), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

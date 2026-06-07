"""Offline regression tests for GAP-0201 (FIN-012).

GAP-0201 — the platform engagement-benchmarks feature was wholly absent: no
``compute_platform_benchmarks`` / ``get_platform_benchmarks`` service functions,
no ``GET /ui/analytics/engagement/benchmarks`` endpoint, no
``POST /internal/analytics/engagement/compute-benchmarks`` endpoint, and no
``EngagementBenchmarksOut`` model. A creator therefore had no way to compare
their engagement rate against the platform distribution.

The fix adds:
  - ``compute_platform_benchmarks(date_str)`` — scans every creator's
    ``DAILY#<date>`` rollup row, aggregates ``engagement_rate_bps`` into
    avg/median/p25/p75 + sample_size, and persists a ``PLATFORM#BENCHMARKS``
    snapshot row.
  - ``get_platform_benchmarks(date_str)`` / ``get_benchmarks_with_percentile``.
  - the GET endpoint (503 until computed) + the internal compute endpoint.

TEST ISOLATION: this test does NOT rely on global moto interception of the
app's pre-bound clients (that leaks to real AWS when another test file imported
the app first). Instead a real in-memory moto table is created and the exact
handle the code uses — ``T.analytics_rollups`` — is swapped via
``object.__setattr__`` (``T`` is a frozen dataclass), restored afterward. The
router handlers are called directly (the FastAPI TestClient is unusable here).
Mirrors ``tests/test_gap_0176_0177_org_service.py``.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_analytics_rollups_table(ddb):
    """Mirror the AnalyticsRollups table from scripts/local-ddb-init.py."""
    return ddb.create_table(
        TableName="AnalyticsRollups",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestEngagementBenchmarksGap0201(unittest.TestCase):
    DATE = "2026-01-01"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_analytics_rollups_table(ddb)

        from app.core.tables import T
        from app.services import engagement_rate

        self.engagement_rate = engagement_rate
        # Swap the EXACT handle the service uses (T frozen → object.__setattr__).
        self._orig_handle = T.analytics_rollups
        object.__setattr__(T, "analytics_rollups", self.table)
        self.addCleanup(
            lambda: object.__setattr__(T, "analytics_rollups", self._orig_handle)
        )

    # ── seed helpers ──────────────────────────────────────────────

    def _seed_creator_daily(self, user_id: str, bps: int, date: str | None = None):
        date = date or self.DATE
        self.table.put_item(
            Item={
                "pk": f"CREATOR#{user_id}",
                "sk": f"DAILY#{date}",
                "engagement_rate_bps": bps,
                "engagement_likes": bps,  # arbitrary; not used by benchmark math
                "post_count": 1,
                "follower_snapshot": 100,
            }
        )

    # ── compute_platform_benchmarks ───────────────────────────────

    def test_compute_no_data_returns_zero_sample(self):
        """No creator rows → sample_size 0, all percentiles 0, snapshot stored."""
        result = self.engagement_rate.compute_platform_benchmarks(self.DATE)
        self.assertEqual(result["sample_size"], 0)
        self.assertEqual(result["average_rate_bps"], 0)
        self.assertEqual(result["median_rate_bps"], 0)
        # Snapshot persisted under the reserved benchmark key.
        stored = self.table.get_item(
            Key={"pk": "PLATFORM#BENCHMARKS", "sk": self.DATE}
        ).get("Item")
        self.assertIsNotNone(stored)
        self.assertEqual(int(stored["sample_size"]), 0)

    def test_compute_aggregates_percentiles(self):
        """Four creators (200/400/600/800 bps) → correct avg/median/p25/p75.

        avg = (200+400+600+800)/4 = 500
        nearest-rank over sorted [200,400,600,800]:
          p25 = rank ceil(.25*4)=1 → 200
          p50 = rank ceil(.50*4)=2 → 400
          p75 = rank ceil(.75*4)=3 → 600
        FAILS BEFORE FIX: compute_platform_benchmarks does not exist (ImportError).
        """
        for i, bps in enumerate((200, 400, 600, 800), start=1):
            self._seed_creator_daily(f"u{i}", bps)

        result = self.engagement_rate.compute_platform_benchmarks(self.DATE)
        self.assertEqual(result["sample_size"], 4)
        self.assertEqual(result["average_rate_bps"], 500)
        self.assertEqual(result["median_rate_bps"], 400)
        self.assertEqual(result["p25_rate_bps"], 200)
        self.assertEqual(result["p75_rate_bps"], 600)

    def test_compute_excludes_zero_and_non_creator_rows(self):
        """Zero-rate creators and non-CREATOR rows are excluded from the sample."""
        self._seed_creator_daily("active", 400)
        self._seed_creator_daily("idle", 0)  # excluded (rate <= 0)
        # A non-creator row on the same SK must be ignored.
        self.table.put_item(
            Item={"pk": "PLATFORM#OTHER", "sk": f"DAILY#{self.DATE}", "engagement_rate_bps": 9999}
        )
        result = self.engagement_rate.compute_platform_benchmarks(self.DATE)
        self.assertEqual(result["sample_size"], 1)
        self.assertEqual(result["average_rate_bps"], 400)

    def test_compute_ignores_other_dates(self):
        """Only the target date's rows are aggregated."""
        self._seed_creator_daily("u1", 400, date=self.DATE)
        self._seed_creator_daily("u2", 1000, date="2026-02-02")
        result = self.engagement_rate.compute_platform_benchmarks(self.DATE)
        self.assertEqual(result["sample_size"], 1)
        self.assertEqual(result["average_rate_bps"], 400)

    # ── get_platform_benchmarks ───────────────────────────────────

    def test_get_returns_none_before_compute(self):
        self.assertIsNone(self.engagement_rate.get_platform_benchmarks(self.DATE))

    def test_get_returns_snapshot_after_compute(self):
        self._seed_creator_daily("u1", 400)
        self.engagement_rate.compute_platform_benchmarks(self.DATE)
        bench = self.engagement_rate.get_platform_benchmarks(self.DATE)
        self.assertIsNotNone(bench)
        self.assertEqual(int(bench["average_rate_bps"]), 400)

    # ── percentile math ───────────────────────────────────────────

    def test_percentile_for_rate(self):
        """Percentile = fraction of creators at-or-below the caller's rate."""
        for i, bps in enumerate((200, 400, 600, 800), start=1):
            self._seed_creator_daily(f"u{i}", bps)
        # 600 is >= three of four samples (200,400,600) → 75.0
        self.assertEqual(
            self.engagement_rate.percentile_for_rate(self.DATE, 600), 75.0
        )
        # 800 is >= all four → 100.0
        self.assertEqual(
            self.engagement_rate.percentile_for_rate(self.DATE, 800), 100.0
        )
        # below the minimum sample → only itself? no: at-or-below counts samples,
        # 100 is below all four → 0.0
        self.assertEqual(
            self.engagement_rate.percentile_for_rate(self.DATE, 100), 0.0
        )
        # zero / negative caller rate → None (no rate)
        self.assertIsNone(self.engagement_rate.percentile_for_rate(self.DATE, 0))


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestEngagementBenchmarksEndpointGap0201(unittest.TestCase):
    """Exercise the router handlers directly (TestClient is unusable here)."""

    DATE = "2026-03-03"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_analytics_rollups_table(ddb)

        from app.core.tables import T

        self._orig_handle = T.analytics_rollups
        object.__setattr__(T, "analytics_rollups", self.table)
        self.addCleanup(
            lambda: object.__setattr__(T, "analytics_rollups", self._orig_handle)
        )

        import app.routers.creator_analytics as router_mod
        from app.models import EngagementBenchmarksOut

        self.router_mod = router_mod
        self.EngagementBenchmarksOut = EngagementBenchmarksOut
        self.session = {"user_sub": "viewer1"}

    def _seed_creator_daily(self, user_id: str, bps: int):
        self.table.put_item(
            Item={
                "pk": f"CREATOR#{user_id}",
                "sk": f"DAILY#{self.DATE}",
                "engagement_rate_bps": bps,
                "post_count": 1,
                "follower_snapshot": 100,
            }
        )

    def test_get_endpoint_503_before_compute(self):
        """GET handler raises 503 when no benchmark snapshot exists.

        FAILS BEFORE FIX: analytics_engagement_benchmarks does not exist.
        """
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as ctx:
            self.router_mod.analytics_engagement_benchmarks(
                date=self.DATE, session=self.session
            )
        self.assertEqual(ctx.exception.status_code, 503)

    def test_internal_compute_then_get_returns_shape(self):
        """Internal compute endpoint populates a snapshot; GET returns full shape.

        Seed three creators (200/400/600). viewer1 has 400 bps → percentile 66.7
        (>= two of three samples = 200,400). All EngagementBenchmarksOut fields
        present and percent-valued.
        """
        self._seed_creator_daily("u1", 200)
        self._seed_creator_daily("u2", 400)
        self._seed_creator_daily("u3", 600)

        # Internal compute endpoint.
        comp = self.router_mod.trigger_compute_benchmarks(date=self.DATE)
        self.assertTrue(comp["ok"])
        self.assertEqual(comp["sample_size"], 3)

        # Patch the viewer's own summary (computed from the viewer's OWN rollups,
        # which we don't seed here) so my_percentile is deterministic. The
        # percentile itself is still derived from the real seeded distribution.
        # Patch at the service module where get_benchmarks_with_percentile reads it.
        from app.services import engagement_rate as svc

        with patch.object(
            svc,
            "get_engagement_summary",
            return_value={"engagement_rate_bps": 400},
        ):
            out = self.router_mod.analytics_engagement_benchmarks(
                date=self.DATE, session=self.session
            )

        self.assertIsInstance(out, self.EngagementBenchmarksOut)
        # avg = (200+400+600)/3 = 400 bps = 4.0%
        self.assertEqual(out.average_rate, 4.0)
        self.assertEqual(out.median_rate, 4.0)   # nearest-rank p50 of 3 → rank 2 → 400
        self.assertEqual(out.p25_rate, 2.0)      # rank ceil(.25*3)=1 → 200 → 2.0%
        self.assertEqual(out.p75_rate, 6.0)      # rank ceil(.75*3)=3 → 600 → 6.0%
        self.assertEqual(out.sample_size, 3)
        # viewer 400 bps >= two of three (200,400) → 2/3 = 66.7%
        self.assertEqual(out.my_percentile, 66.7)
        self.assertEqual(out.date, self.DATE)
        self.assertGreater(out.computed_at, 0)
        # All required fields present.
        for key in ("average_rate", "median_rate", "p25_rate", "p75_rate",
                    "sample_size", "my_percentile", "computed_at", "date"):
            self.assertIn(key, out.model_dump())

    def test_get_endpoint_invalid_date_400(self):
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as ctx:
            self.router_mod.analytics_engagement_benchmarks(
                date="not-a-date", session=self.session
            )
        self.assertEqual(ctx.exception.status_code, 400)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

"""Offline hermetic tests for KYC Analytics service (KYC-024).

Covers:
  - compute_funnel() with seeded cases in various statuses
  - conversion_rate() derived from funnel output
  - compute_snapshot() combining all sub-metrics
  - get_rejection_reasons() with reason_codes lists
  - get_geographic_distribution() grouped by country
  - _tier_breakdown_from_cases() grouped by intake_profile
  - get_processing_time_histogram() bucketing
  - get_volume_trends() daily/weekly granularities
  - get_screening_hit_trends()
  - get_drop_off_analysis()
  - store_daily_snapshot() / get_daily_snapshot() round-trip
  - precompute_daily_snapshot() convenience helper
  - compare_periods()
  - Empty table → zero metrics, no crash

Hermetic / offline (TEST ISOLATION):
* Real in-memory DynamoDB ``kyc_cases`` table via moto, bound to the exact
  frozen ``ANALYTICS_SERVICE._table`` handle via ``object.__setattr__``
  (restored in tearDown).
* Frozen ``Settings`` singleton ``S`` mutated via ``object.__setattr__`` for
  settings overrides; restored in tearDown.
* The service is called directly (sync); no real AWS / network is touched.
* Cases are seeded by writing items directly to the moto table rather than
  going through the full KycCaseStore to avoid circular imports.
"""
from __future__ import annotations

import time
import unittest
from contextlib import ExitStack
from datetime import datetime, timezone

import boto3

try:
    from moto import mock_aws
except ImportError:  # pragma: no cover
    mock_aws = None

from app.core.settings import S
import app.services.kyc_analytics as analytics_mod
from app.services.kyc_analytics import ANALYTICS_SERVICE, _ANALYTICS_PK


# ── helpers ───────────────────────────────────────────────────────────────────

# A stable "today" reference so tests are deterministic regardless of wall-clock.
# We pick a fixed timestamp well in the past so it falls inside any reasonable
# test window.
_NOW = int(datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc).timestamp())
_DAY = 86400  # seconds per day


def _ts_offset(days: int) -> int:
    """Return _NOW shifted by ``days`` days (negative = in the past)."""
    return _NOW + days * _DAY


def _period(days_back: int = 30) -> tuple[int, int]:
    """Return (start, end) spanning the last ``days_back`` days from _NOW."""
    return _NOW - days_back * _DAY, _NOW


def _make_kyc_cases_table(ddb):
    """Create an in-memory moto kyc_cases table with the status GSI."""
    return ddb.create_table(
        TableName="kyc_cases",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gsi_status_pk", "AttributeType": "S"},
            {"AttributeName": "gsi_status_sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "status-updated-index",
                "KeySchema": [
                    {"AttributeName": "gsi_status_pk", "KeyType": "HASH"},
                    {"AttributeName": "gsi_status_sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )


def _seed_case(
    table,
    *,
    user_sub: str,
    status: str,
    created_at: int,
    intake_profile: str = "standard",
    country: str = "US",
    rejection_reason_codes: list[str] | None = None,
    submitted_at: int | None = None,
    decided_at: int | None = None,
) -> None:
    """Write a minimal kyc_case META row directly to the moto table."""
    review: dict = {}
    if rejection_reason_codes:
        review["reason_codes"] = rejection_reason_codes
    if decided_at:
        review["decided_at"] = decided_at

    submission: dict = {}
    if submitted_at:
        submission["submitted_at"] = submitted_at

    item: dict = {
        "pk": f"USER#{user_sub}",
        "sk": "META",
        "user_sub": user_sub,
        "entity_type": "kyc_case",
        "status": status,
        "created_at": created_at,
        "country_code": country,
        "intake_profile": intake_profile,
        # GSI keys
        "gsi_status_pk": f"STATUS#{status}",
        "gsi_status_sk": str(created_at),
    }
    if review:
        item["review"] = review
    if submission:
        item["submission"] = submission
    table.put_item(Item=item)


# ── test class ────────────────────────────────────────────────────────────────


class KycAnalyticsServiceTests(unittest.TestCase):
    def setUp(self):
        if mock_aws is None:
            self.skipTest("moto not available")

        self._stack = ExitStack()
        self._stack.enter_context(mock_aws())

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_kyc_cases_table(ddb)

        # Bind the service's _table to our moto table.
        self._orig_table = ANALYTICS_SERVICE._table
        object.__setattr__(ANALYTICS_SERVICE, "_table", self.table)

        # Cap scan items to a small number so tests run fast.
        self._orig_max_scan = S.kyc_analytics_max_scan_items
        self._orig_trend_max = S.kyc_analytics_trend_max_periods
        object.__setattr__(S, "kyc_analytics_max_scan_items", 1000)
        object.__setattr__(S, "kyc_analytics_trend_max_periods", 90)
        # Use the fixed index name from settings.
        self._orig_status_index = S.kyc_cases_status_index_name
        object.__setattr__(S, "kyc_cases_status_index_name", "status-updated-index")

    def tearDown(self):
        object.__setattr__(ANALYTICS_SERVICE, "_table", self._orig_table)
        object.__setattr__(S, "kyc_analytics_max_scan_items", self._orig_max_scan)
        object.__setattr__(S, "kyc_analytics_trend_max_periods", self._orig_trend_max)
        object.__setattr__(S, "kyc_cases_status_index_name", self._orig_status_index)
        self._stack.close()

    # ── seed helpers ──────────────────────────────────────────────────────────

    def _seed_typical_cases(self) -> None:
        """Seed a representative set of cases for funnel/snapshot tests."""
        t0 = _NOW - 10 * _DAY  # within a 30-day window
        _seed_case(self.table, user_sub="u_draft",      status="draft",        created_at=t0)
        _seed_case(self.table, user_sub="u_sub1",       status="submitted",    created_at=t0 + 100)
        _seed_case(self.table, user_sub="u_review1",    status="under_review", created_at=t0 + 200)
        _seed_case(self.table, user_sub="u_needs_info", status="needs_more_info", created_at=t0 + 300)
        _seed_case(self.table, user_sub="u_approved1",  status="approved",     created_at=t0 + 400, country="GB",
                   intake_profile="enhanced",
                   submitted_at=t0 + 401, decided_at=t0 + 401 + 7200)  # 2h processing
        _seed_case(self.table, user_sub="u_approved2",  status="approved",     created_at=t0 + 500, country="US",
                   submitted_at=t0 + 501, decided_at=t0 + 501 + 18000)  # 5h processing
        _seed_case(self.table, user_sub="u_rejected1",  status="rejected",     created_at=t0 + 600, country="US",
                   rejection_reason_codes=["doc_mismatch", "expired_id"],
                   submitted_at=t0 + 601, decided_at=t0 + 601 + 3600)  # 1h processing
        _seed_case(self.table, user_sub="u_rejected2",  status="rejected",     created_at=t0 + 700, country="DE",
                   rejection_reason_codes=["doc_mismatch"],
                   intake_profile="high_risk",
                   submitted_at=t0 + 701, decided_at=t0 + 701 + 86400)  # 24h processing
        _seed_case(self.table, user_sub="u_expired",    status="expired",      created_at=t0 + 800)

    # ── 1. compute_funnel ─────────────────────────────────────────────────────

    def test_compute_funnel_step_names(self):
        """Funnel must return exactly the 5 expected step names in order."""
        self._seed_typical_cases()
        start, end = _period(30)
        funnel = ANALYTICS_SERVICE.compute_funnel(period_start=start, period_end=end)
        names = [f.step for f in funnel]
        self.assertEqual(names, ["started", "docs_uploaded", "submitted", "under_review", "approved"])

    def test_compute_funnel_counts_monotone_decreasing(self):
        """Each step must have count <= the previous step's count (funnel narrows)."""
        self._seed_typical_cases()
        start, end = _period(30)
        funnel = ANALYTICS_SERVICE.compute_funnel(period_start=start, period_end=end)
        counts = [f.count for f in funnel]
        for i in range(1, len(counts)):
            self.assertLessEqual(counts[i], counts[i - 1], f"step {i} count {counts[i]} > step {i-1} count {counts[i-1]}")

    def test_compute_funnel_started_count(self):
        """All 9 seeded cases should appear at 'started'."""
        self._seed_typical_cases()
        start, end = _period(30)
        funnel = ANALYTICS_SERVICE.compute_funnel(period_start=start, period_end=end)
        started = funnel[0]
        self.assertEqual(started.step, "started")
        self.assertEqual(started.count, 9)

    def test_compute_funnel_approved_count(self):
        """Only approved cases contribute to the 'approved' step."""
        self._seed_typical_cases()
        start, end = _period(30)
        funnel = ANALYTICS_SERVICE.compute_funnel(period_start=start, period_end=end)
        approved_step = funnel[-1]
        self.assertEqual(approved_step.step, "approved")
        self.assertEqual(approved_step.count, 2)

    def test_compute_funnel_first_step_drop_off_is_zero(self):
        """The first funnel step has zero drop_off_count and drop_off_pct."""
        self._seed_typical_cases()
        start, end = _period(30)
        funnel = ANALYTICS_SERVICE.compute_funnel(period_start=start, period_end=end)
        self.assertEqual(funnel[0].drop_off_count, 0)
        self.assertEqual(funnel[0].drop_off_pct, 0.0)

    def test_compute_funnel_percentage_of_started(self):
        """percentage on each step = count / started * 100, rounded to 2dp."""
        self._seed_typical_cases()
        start, end = _period(30)
        funnel = ANALYTICS_SERVICE.compute_funnel(period_start=start, period_end=end)
        started_count = funnel[0].count
        for step in funnel:
            expected_pct = round(100.0 * step.count / started_count, 2)
            self.assertAlmostEqual(step.percentage, expected_pct, places=2,
                                   msg=f"step={step.step}")

    def test_compute_funnel_period_filter_excludes_old_cases(self):
        """Cases created before the period window are excluded."""
        old_t = _NOW - 100 * _DAY
        _seed_case(self.table, user_sub="u_old_draft", status="draft", created_at=old_t)
        _seed_case(self.table, user_sub="u_new_draft", status="draft",
                   created_at=_NOW - 5 * _DAY)
        start, end = _period(30)
        funnel = ANALYTICS_SERVICE.compute_funnel(period_start=start, period_end=end)
        self.assertEqual(funnel[0].count, 1)  # only u_new_draft

    def test_compute_funnel_empty_table(self):
        """Empty table returns funnel with all zeros; no crash."""
        start, end = _period(30)
        funnel = ANALYTICS_SERVICE.compute_funnel(period_start=start, period_end=end)
        for step in funnel:
            self.assertEqual(step.count, 0)
            self.assertEqual(step.percentage, 0.0)
            self.assertEqual(step.drop_off_count, 0)

    # ── 2. conversion_rate ────────────────────────────────────────────────────

    def test_conversion_rate_is_approved_over_started(self):
        """conversion_rate = approved_count / started_count."""
        self._seed_typical_cases()
        start, end = _period(30)
        funnel = ANALYTICS_SERVICE.compute_funnel(period_start=start, period_end=end)
        rate = ANALYTICS_SERVICE.conversion_rate(funnel)
        started = funnel[0].count   # 9
        approved = funnel[-1].count  # 2
        expected = round(approved / started, 2)
        self.assertAlmostEqual(rate, expected, places=5)

    def test_conversion_rate_empty_funnel(self):
        """Empty funnel returns 0.0 without error."""
        self.assertEqual(ANALYTICS_SERVICE.conversion_rate([]), 0.0)

    def test_conversion_rate_zero_started(self):
        """Zero started count returns 0.0."""
        start, end = _period(30)
        funnel = ANALYTICS_SERVICE.compute_funnel(period_start=start, period_end=end)
        # empty table → all counts=0
        self.assertEqual(ANALYTICS_SERVICE.conversion_rate(funnel), 0.0)

    # ── 3. compute_snapshot ───────────────────────────────────────────────────

    def test_compute_snapshot_returns_analytics_snapshot(self):
        """compute_snapshot returns an AnalyticsSnapshot dataclass."""
        from app.services.kyc_analytics import AnalyticsSnapshot
        self._seed_typical_cases()
        start, end = _period(30)
        snap = ANALYTICS_SERVICE.compute_snapshot(period_start=start, period_end=end)
        self.assertIsInstance(snap, AnalyticsSnapshot)

    def test_compute_snapshot_totals(self):
        """Snapshot counts match the seeded data."""
        self._seed_typical_cases()
        start, end = _period(30)
        snap = ANALYTICS_SERVICE.compute_snapshot(period_start=start, period_end=end)
        self.assertEqual(snap.total_applications, 9)
        self.assertEqual(snap.approved_count, 2)
        self.assertEqual(snap.rejected_count, 2)
        # submitted + under_review + needs_more_info = 3
        self.assertEqual(snap.pending_count, 3)

    def test_compute_snapshot_avg_processing_hours(self):
        """Average processing hours is positive and computed over decided cases."""
        self._seed_typical_cases()
        start, end = _period(30)
        snap = ANALYTICS_SERVICE.compute_snapshot(period_start=start, period_end=end)
        # 4 decided cases: 2h, 5h, 1h, 24h → avg = 8h
        self.assertAlmostEqual(snap.avg_processing_hours, 8.0, places=1)

    def test_compute_snapshot_processing_time_distribution_keys(self):
        """Processing time distribution has p50/p75/p90/p99 keys."""
        self._seed_typical_cases()
        start, end = _period(30)
        snap = ANALYTICS_SERVICE.compute_snapshot(period_start=start, period_end=end)
        self.assertSetEqual(set(snap.processing_time_distribution.keys()), {"p50", "p75", "p90", "p99"})

    def test_compute_snapshot_empty_table(self):
        """Empty table → zero counts, no crash."""
        start, end = _period(30)
        snap = ANALYTICS_SERVICE.compute_snapshot(period_start=start, period_end=end)
        self.assertEqual(snap.total_applications, 0)
        self.assertEqual(snap.approved_count, 0)
        self.assertEqual(snap.avg_processing_hours, 0.0)

    # ── 4. get_rejection_reasons ──────────────────────────────────────────────

    def test_rejection_reasons_counts_codes(self):
        """Each rejection reason code is counted correctly."""
        self._seed_typical_cases()
        start, end = _period(30)
        reasons = ANALYTICS_SERVICE.get_rejection_reasons(period_start=start, period_end=end)
        # u_rejected1: doc_mismatch + expired_id; u_rejected2: doc_mismatch
        self.assertEqual(reasons.get("doc_mismatch"), 2)
        self.assertEqual(reasons.get("expired_id"), 1)

    def test_rejection_reasons_excludes_non_rejected(self):
        """Non-rejected cases do not contribute to the breakdown."""
        self._seed_typical_cases()
        start, end = _period(30)
        reasons = ANALYTICS_SERVICE.get_rejection_reasons(period_start=start, period_end=end)
        # Only rejected cases should appear
        total_from_reasons = sum(reasons.values())
        # 3 reason codes total: doc_mismatch×2, expired_id×1
        self.assertEqual(total_from_reasons, 3)

    def test_rejection_reasons_unspecified_when_no_codes(self):
        """Rejected cases without reason_codes fall into 'unspecified'."""
        t0 = _NOW - 5 * _DAY
        _seed_case(self.table, user_sub="u_no_reason", status="rejected", created_at=t0)
        start, end = _period(30)
        reasons = ANALYTICS_SERVICE.get_rejection_reasons(period_start=start, period_end=end)
        self.assertIn("unspecified", reasons)
        self.assertEqual(reasons["unspecified"], 1)

    def test_rejection_reasons_empty_table(self):
        """Empty table returns empty dict."""
        start, end = _period(30)
        reasons = ANALYTICS_SERVICE.get_rejection_reasons(period_start=start, period_end=end)
        self.assertEqual(reasons, {})

    def test_rejection_reasons_top10_limit(self):
        """At most 10 reason codes are returned."""
        t0 = _NOW - 5 * _DAY
        for i in range(15):
            _seed_case(
                self.table,
                user_sub=f"u_rej_{i}",
                status="rejected",
                created_at=t0 + i,
                rejection_reason_codes=[f"code_{i}"],
            )
        start, end = _period(30)
        reasons = ANALYTICS_SERVICE.get_rejection_reasons(period_start=start, period_end=end)
        self.assertLessEqual(len(reasons), 10)

    # ── 5. get_geographic_distribution ───────────────────────────────────────

    def test_geo_distribution_groups_by_country(self):
        """Returns one entry per distinct country."""
        self._seed_typical_cases()
        start, end = _period(30)
        geo = ANALYTICS_SERVICE.get_geographic_distribution(period_start=start, period_end=end)
        countries = {g["country"] for g in geo}
        # US, GB, DE seeded; plus "unknown" for cases without explicit country
        self.assertIn("US", countries)
        self.assertIn("GB", countries)
        self.assertIn("DE", countries)

    def test_geo_distribution_counts(self):
        """Country count in the geo distribution matches seeded cases."""
        self._seed_typical_cases()
        start, end = _period(30)
        geo = ANALYTICS_SERVICE.get_geographic_distribution(period_start=start, period_end=end)
        by_country = {g["country"]: g for g in geo}
        # GB: 1 approved
        self.assertEqual(by_country["GB"]["count"], 1)
        self.assertEqual(by_country["GB"]["approved"], 1)
        self.assertEqual(by_country["GB"]["rejected"], 0)

    def test_geo_distribution_approval_rate(self):
        """approval_rate is percentage of decided cases that are approved."""
        t0 = _NOW - 5 * _DAY
        _seed_case(self.table, user_sub="u1", status="approved", created_at=t0, country="FR")
        _seed_case(self.table, user_sub="u2", status="rejected", created_at=t0 + 1, country="FR")
        _seed_case(self.table, user_sub="u3", status="rejected", created_at=t0 + 2, country="FR")
        start, end = _period(30)
        geo = ANALYTICS_SERVICE.get_geographic_distribution(period_start=start, period_end=end)
        by_country = {g["country"]: g for g in geo}
        # 1/3 approved of decided (3 decided) → 33.33%
        self.assertAlmostEqual(by_country["FR"]["approval_rate"], 33.33, places=1)

    def test_geo_distribution_sorted_by_count_desc(self):
        """Countries are sorted by count descending."""
        t0 = _NOW - 5 * _DAY
        for i in range(5):
            _seed_case(self.table, user_sub=f"u_us_{i}", status="draft", created_at=t0 + i, country="US")
        _seed_case(self.table, user_sub="u_au", status="draft", created_at=t0 + 10, country="AU")
        start, end = _period(30)
        geo = ANALYTICS_SERVICE.get_geographic_distribution(period_start=start, period_end=end)
        counts = [g["count"] for g in geo]
        self.assertEqual(counts, sorted(counts, reverse=True))

    def test_geo_distribution_empty_table(self):
        """Empty table returns empty list."""
        start, end = _period(30)
        geo = ANALYTICS_SERVICE.get_geographic_distribution(period_start=start, period_end=end)
        self.assertEqual(geo, [])

    # ── 6. tier segmentation via _tier_breakdown_from_cases ──────────────────

    def test_tier_breakdown_standard_is_tier_2(self):
        """intake_profile='standard' maps to tier_2."""
        t0 = _NOW - 5 * _DAY
        _seed_case(self.table, user_sub="u_std", status="approved", created_at=t0,
                   intake_profile="standard")
        start, end = _period(30)
        snap = ANALYTICS_SERVICE.compute_snapshot(period_start=start, period_end=end)
        self.assertIn("tier_2", snap.tier_breakdown)
        self.assertEqual(snap.tier_breakdown["tier_2"]["approved"], 1)

    def test_tier_breakdown_enhanced_is_tier_3(self):
        """intake_profile='enhanced' maps to tier_3."""
        t0 = _NOW - 5 * _DAY
        _seed_case(self.table, user_sub="u_enh", status="rejected", created_at=t0,
                   intake_profile="enhanced")
        start, end = _period(30)
        snap = ANALYTICS_SERVICE.compute_snapshot(period_start=start, period_end=end)
        self.assertIn("tier_3", snap.tier_breakdown)
        self.assertEqual(snap.tier_breakdown["tier_3"]["rejected"], 1)

    def test_tier_breakdown_default_is_tier_1(self):
        """Unrecognized intake_profile falls back to tier_1."""
        t0 = _NOW - 5 * _DAY
        _seed_case(self.table, user_sub="u_basic", status="draft", created_at=t0,
                   intake_profile="")
        start, end = _period(30)
        snap = ANALYTICS_SERVICE.compute_snapshot(period_start=start, period_end=end)
        self.assertIn("tier_1", snap.tier_breakdown)

    def test_tier_breakdown_counts_started(self):
        """tier_breakdown 'started' counts all cases for that tier."""
        t0 = _NOW - 5 * _DAY
        for i in range(3):
            _seed_case(self.table, user_sub=f"u_med_{i}", status="submitted",
                       created_at=t0 + i, intake_profile="medium_risk")
        start, end = _period(30)
        snap = ANALYTICS_SERVICE.compute_snapshot(period_start=start, period_end=end)
        self.assertEqual(snap.tier_breakdown["tier_2"]["started"], 3)

    # ── 7. get_processing_time_histogram ─────────────────────────────────────

    def test_histogram_returns_histogram_and_percentiles_keys(self):
        """Return value has 'histogram' list and 'percentiles' dict."""
        self._seed_typical_cases()
        start, end = _period(30)
        result = ANALYTICS_SERVICE.get_processing_time_histogram(
            period_start=start, period_end=end, bucket_hours=4
        )
        self.assertIn("histogram", result)
        self.assertIn("percentiles", result)

    def test_histogram_bucket_labels_format(self):
        """Histogram bucket labels follow the 'X-Yh' format."""
        self._seed_typical_cases()
        start, end = _period(30)
        result = ANALYTICS_SERVICE.get_processing_time_histogram(
            period_start=start, period_end=end, bucket_hours=4
        )
        for bucket in result["histogram"][:-1]:  # all except last overflow bucket
            self.assertRegex(bucket["bucket_label"], r"^\d+-\d+h$")
        # last bucket is overflow
        self.assertTrue(result["histogram"][-1]["bucket_label"].endswith("h+"))

    def test_histogram_total_count_matches_decided_cases(self):
        """Sum of histogram bucket counts equals the number of decided cases."""
        self._seed_typical_cases()
        start, end = _period(30)
        result = ANALYTICS_SERVICE.get_processing_time_histogram(
            period_start=start, period_end=end, bucket_hours=4
        )
        total = sum(b["count"] for b in result["histogram"])
        # 4 cases have both submitted_at and decided_at
        self.assertEqual(total, 4)

    def test_histogram_percentiles_keys(self):
        """Percentiles dict has p50/p75/p90/p99."""
        self._seed_typical_cases()
        start, end = _period(30)
        result = ANALYTICS_SERVICE.get_processing_time_histogram(
            period_start=start, period_end=end
        )
        self.assertSetEqual(set(result["percentiles"].keys()), {"p50", "p75", "p90", "p99"})

    def test_histogram_empty_table(self):
        """Empty table returns histogram with all zero counts."""
        start, end = _period(30)
        result = ANALYTICS_SERVICE.get_processing_time_histogram(
            period_start=start, period_end=end, bucket_hours=4
        )
        total = sum(b["count"] for b in result["histogram"])
        self.assertEqual(total, 0)
        self.assertEqual(result["percentiles"]["p50"], 0.0)

    # ── 8. get_volume_trends ──────────────────────────────────────────────────

    def test_volume_trends_daily_returns_correct_period_count(self):
        """Daily granularity for N periods returns N entries."""
        self._seed_typical_cases()
        result = ANALYTICS_SERVICE.get_volume_trends(
            granularity="daily", periods=7, end_date=_NOW
        )
        self.assertEqual(len(result), 7)

    def test_volume_trends_period_labels_daily(self):
        """Daily period labels follow 'YYYY-MM-DD' format."""
        self._seed_typical_cases()
        result = ANALYTICS_SERVICE.get_volume_trends(
            granularity="daily", periods=3, end_date=_NOW
        )
        for entry in result:
            self.assertRegex(entry["period"], r"^\d{4}-\d{2}-\d{2}$")

    def test_volume_trends_weekly_labels(self):
        """Weekly period labels follow 'YYYY-MM-DD' format."""
        result = ANALYTICS_SERVICE.get_volume_trends(
            granularity="weekly", periods=4, end_date=_NOW
        )
        self.assertEqual(len(result), 4)
        for entry in result:
            self.assertRegex(entry["period"], r"^\d{4}-\d{2}-\d{2}$")

    def test_volume_trends_keys(self):
        """Each trend entry has the expected keys."""
        self._seed_typical_cases()
        result = ANALYTICS_SERVICE.get_volume_trends(
            granularity="daily", periods=5, end_date=_NOW
        )
        expected_keys = {"period", "started", "submitted", "approved", "rejected"}
        for entry in result:
            self.assertSetEqual(set(entry.keys()), expected_keys)

    def test_volume_trends_approved_count(self):
        """Approved counts in trends must be non-negative integers."""
        self._seed_typical_cases()
        result = ANALYTICS_SERVICE.get_volume_trends(
            granularity="daily", periods=14, end_date=_NOW
        )
        for entry in result:
            self.assertGreaterEqual(entry["approved"], 0)
            self.assertIsInstance(entry["approved"], int)

    def test_volume_trends_monthly_granularity(self):
        """Monthly granularity returns entries with 'YYYY-MM' labels."""
        result = ANALYTICS_SERVICE.get_volume_trends(
            granularity="monthly", periods=3, end_date=_NOW
        )
        self.assertEqual(len(result), 3)
        for entry in result:
            self.assertRegex(entry["period"], r"^\d{4}-\d{2}$")

    def test_volume_trends_empty_table(self):
        """Empty table returns entries with all-zero counts."""
        result = ANALYTICS_SERVICE.get_volume_trends(
            granularity="daily", periods=5, end_date=_NOW
        )
        for entry in result:
            self.assertEqual(entry["started"], 0)
            self.assertEqual(entry["approved"], 0)

    # ── 9. get_screening_hit_trends ───────────────────────────────────────────

    def test_screening_hit_trends_keys(self):
        """Each entry has period/total_screened/hits/hit_rate keys."""
        result = ANALYTICS_SERVICE.get_screening_hit_trends(
            granularity="daily", periods=3, end_date=_NOW
        )
        self.assertEqual(len(result), 3)
        for entry in result:
            self.assertIn("period", entry)
            self.assertIn("total_screened", entry)
            self.assertIn("hits", entry)
            self.assertIn("hit_rate", entry)

    def test_screening_hit_trends_detects_hit_codes(self):
        """Cases with sanctions hit codes are counted as hits."""
        t0 = _NOW - 5 * _DAY  # within 7-day window
        _seed_case(self.table, user_sub="u_hit", status="submitted", created_at=t0,
                   rejection_reason_codes=["sanctions_hit"])
        _seed_case(self.table, user_sub="u_clean", status="submitted", created_at=t0 + 1)
        result = ANALYTICS_SERVICE.get_screening_hit_trends(
            granularity="daily", periods=7, end_date=_NOW
        )
        total_hits = sum(e["hits"] for e in result)
        total_screened = sum(e["total_screened"] for e in result)
        self.assertEqual(total_screened, 2)
        self.assertEqual(total_hits, 1)

    def test_screening_hit_trends_hit_rate_zero_when_no_hits(self):
        """hit_rate is 0.0 when there are no hits."""
        t0 = _NOW - 2 * _DAY
        _seed_case(self.table, user_sub="u_clean2", status="submitted", created_at=t0)
        result = ANALYTICS_SERVICE.get_screening_hit_trends(
            granularity="daily", periods=7, end_date=_NOW
        )
        # All hit_rates in entries with screened=0 should be 0.0
        for entry in result:
            if entry["total_screened"] == 0:
                self.assertEqual(entry["hit_rate"], 0.0)

    # ── 10. get_drop_off_analysis ─────────────────────────────────────────────

    def test_drop_off_analysis_step_count(self):
        """Drop-off analysis returns len(funnel)-1 transition entries."""
        self._seed_typical_cases()
        start, end = _period(30)
        steps = ANALYTICS_SERVICE.get_drop_off_analysis(period_start=start, period_end=end)
        self.assertEqual(len(steps), 4)  # 5 funnel steps → 4 transitions

    def test_drop_off_analysis_keys(self):
        """Each step has the expected keys."""
        self._seed_typical_cases()
        start, end = _period(30)
        steps = ANALYTICS_SERVICE.get_drop_off_analysis(period_start=start, period_end=end)
        expected = {"from_step", "to_step", "continued", "dropped", "drop_rate", "avg_time_in_step_hours"}
        for step in steps:
            self.assertSetEqual(set(step.keys()), expected)

    def test_drop_off_analysis_from_to_sequence(self):
        """from_step/to_step pairs follow funnel step order."""
        self._seed_typical_cases()
        start, end = _period(30)
        steps = ANALYTICS_SERVICE.get_drop_off_analysis(period_start=start, period_end=end)
        from_steps = [s["from_step"] for s in steps]
        to_steps = [s["to_step"] for s in steps]
        self.assertEqual(from_steps, ["started", "docs_uploaded", "submitted", "under_review"])
        self.assertEqual(to_steps, ["docs_uploaded", "submitted", "under_review", "approved"])

    def test_drop_off_analysis_dropped_non_negative(self):
        """dropped count is never negative."""
        self._seed_typical_cases()
        start, end = _period(30)
        steps = ANALYTICS_SERVICE.get_drop_off_analysis(period_start=start, period_end=end)
        for s in steps:
            self.assertGreaterEqual(s["dropped"], 0)

    def test_drop_off_analysis_empty_table(self):
        """Empty table returns 4 steps all with zeros."""
        start, end = _period(30)
        steps = ANALYTICS_SERVICE.get_drop_off_analysis(period_start=start, period_end=end)
        self.assertEqual(len(steps), 4)
        for s in steps:
            self.assertEqual(s["dropped"], 0)
            self.assertEqual(s["drop_rate"], 0.0)

    # ── 11. store_daily_snapshot / get_daily_snapshot ─────────────────────────

    def test_store_and_retrieve_daily_snapshot(self):
        """store_daily_snapshot writes to DDB; get_daily_snapshot reads it back."""
        from app.services.kyc_analytics import AnalyticsSnapshot, FunnelStep
        snap = AnalyticsSnapshot(
            period_start=1000,
            period_end=2000,
            total_applications=5,
            approved_count=3,
            rejected_count=1,
            pending_count=1,
            conversion_rate=0.6,
            avg_processing_hours=4.5,
        )
        ANALYTICS_SERVICE.store_daily_snapshot(date_iso="2025-06-01", snapshot=snap)
        item = ANALYTICS_SERVICE.get_daily_snapshot(date_iso="2025-06-01")
        self.assertIsNotNone(item)
        self.assertEqual(item["pk"], _ANALYTICS_PK)
        self.assertEqual(item["sk"], "DAILY#2025-06-01")
        self.assertEqual(item["date_iso"], "2025-06-01")
        self.assertEqual(item["entity_type"], "kyc_analytics_snapshot")

    def test_store_daily_snapshot_contents(self):
        """Stored snapshot item carries the core metrics."""
        from app.services.kyc_analytics import AnalyticsSnapshot
        snap = AnalyticsSnapshot(
            period_start=100,
            period_end=200,
            total_applications=10,
            approved_count=7,
            rejected_count=2,
            pending_count=1,
            conversion_rate=0.7,
            avg_processing_hours=3.0,
            rejection_reasons={"doc_mismatch": 2},
            geographic_distribution=[{"country": "US", "count": 10}],
            tier_breakdown={"tier_1": {"started": 10, "approved": 7, "rejected": 2}},
        )
        ANALYTICS_SERVICE.store_daily_snapshot(date_iso="2025-06-02", snapshot=snap)
        item = ANALYTICS_SERVICE.get_daily_snapshot(date_iso="2025-06-02")
        embedded = item["snapshot"]
        self.assertEqual(int(embedded["total_applications"]), 10)
        self.assertEqual(int(embedded["approved_count"]), 7)

    def test_get_daily_snapshot_missing_returns_none(self):
        """get_daily_snapshot returns None for a date that has no row."""
        result = ANALYTICS_SERVICE.get_daily_snapshot(date_iso="1999-01-01")
        self.assertIsNone(result)

    def test_store_daily_snapshot_overwrites(self):
        """Storing twice for the same date overwrites the previous entry."""
        from app.services.kyc_analytics import AnalyticsSnapshot
        snap1 = AnalyticsSnapshot(period_start=0, period_end=1, total_applications=1,
                                  approved_count=0, rejected_count=0, pending_count=1,
                                  conversion_rate=0.0, avg_processing_hours=0.0)
        snap2 = AnalyticsSnapshot(period_start=0, period_end=1, total_applications=99,
                                  approved_count=50, rejected_count=10, pending_count=39,
                                  conversion_rate=0.5, avg_processing_hours=8.0)
        ANALYTICS_SERVICE.store_daily_snapshot(date_iso="2025-06-03", snapshot=snap1)
        ANALYTICS_SERVICE.store_daily_snapshot(date_iso="2025-06-03", snapshot=snap2)
        item = ANALYTICS_SERVICE.get_daily_snapshot(date_iso="2025-06-03")
        self.assertEqual(int(item["snapshot"]["total_applications"]), 99)

    # ── 12. precompute_daily_snapshot ─────────────────────────────────────────

    def test_precompute_daily_snapshot_returns_summary(self):
        """precompute_daily_snapshot returns a dict with date_iso + counts."""
        result = ANALYTICS_SERVICE.precompute_daily_snapshot(date_iso="2025-06-10")
        self.assertIn("date_iso", result)
        self.assertEqual(result["date_iso"], "2025-06-10")
        self.assertIn("total_applications", result)
        self.assertIn("approved_count", result)

    def test_precompute_daily_snapshot_writes_to_ddb(self):
        """precompute_daily_snapshot stores a retrievable row in the table."""
        ANALYTICS_SERVICE.precompute_daily_snapshot(date_iso="2025-06-11")
        item = ANALYTICS_SERVICE.get_daily_snapshot(date_iso="2025-06-11")
        self.assertIsNotNone(item)
        self.assertEqual(item["date_iso"], "2025-06-11")

    def test_precompute_daily_snapshot_defaults_to_yesterday(self):
        """Calling without date_iso uses yesterday's date."""
        from datetime import datetime, timezone, timedelta
        yesterday = (datetime.now(tz=timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        result = ANALYTICS_SERVICE.precompute_daily_snapshot()
        self.assertEqual(result["date_iso"], yesterday)
        item = ANALYTICS_SERVICE.get_daily_snapshot(date_iso=yesterday)
        self.assertIsNotNone(item)

    # ── 13. compare_periods ───────────────────────────────────────────────────

    def test_compare_periods_returns_current_previous_deltas(self):
        """compare_periods returns a dict with 'current', 'previous', 'deltas'."""
        self._seed_typical_cases()
        now = _NOW
        # current = last 10 days; previous = 10 days before that
        result = ANALYTICS_SERVICE.compare_periods(
            current_start=now - 10 * _DAY,
            current_end=now,
            previous_start=now - 20 * _DAY,
            previous_end=now - 10 * _DAY - 1,
        )
        self.assertIn("current", result)
        self.assertIn("previous", result)
        self.assertIn("deltas", result)

    def test_compare_periods_delta_keys(self):
        """deltas dict has the expected keys."""
        start, end = _period(30)
        result = ANALYTICS_SERVICE.compare_periods(
            current_start=start,
            current_end=end,
            previous_start=start - 30 * _DAY,
            previous_end=start - 1,
        )
        expected_delta_keys = {
            "conversion_rate_delta",
            "volume_delta",
            "volume_delta_pct",
            "approved_delta",
            "rejected_delta",
            "avg_processing_hours_delta",
        }
        self.assertSetEqual(set(result["deltas"].keys()), expected_delta_keys)

    def test_compare_periods_empty_previous(self):
        """Empty previous period → zero previous counts, no crash."""
        self._seed_typical_cases()
        now = _NOW
        result = ANALYTICS_SERVICE.compare_periods(
            current_start=now - 10 * _DAY,
            current_end=now,
            # previous window contains no data
            previous_start=now - 1000 * _DAY,
            previous_end=now - 999 * _DAY,
        )
        self.assertEqual(result["previous"].total_applications, 0)
        self.assertEqual(result["deltas"]["volume_delta_pct"], 0.0)

    # ── 14. _case_country fallback logic ─────────────────────────────────────

    def test_case_country_falls_back_to_submission_snapshot(self):
        """_case_country reads from submission.evidence_snapshot if top-level missing."""
        from app.services.kyc_analytics import _case_country
        case = {
            "submission": {
                "evidence_snapshot": {
                    "country_code": "JP"
                }
            }
        }
        self.assertEqual(_case_country(case), "JP")

    def test_case_country_unknown_when_no_field(self):
        """_case_country returns 'unknown' for empty case."""
        from app.services.kyc_analytics import _case_country
        self.assertEqual(_case_country({}), "unknown")

    def test_case_country_prefers_top_level_country_key(self):
        """Top-level 'country' takes precedence over submission snapshot."""
        from app.services.kyc_analytics import _case_country
        case = {
            "country": "BR",
            "submission": {
                "evidence_snapshot": {"country": "US"}
            }
        }
        self.assertEqual(_case_country(case), "BR")

    # ── 15. _case_tier logic ──────────────────────────────────────────────────

    def test_case_tier_high_risk_is_tier3(self):
        from app.services.kyc_analytics import _case_tier
        self.assertEqual(_case_tier({"intake_profile": "high_risk"}), "tier_3")

    def test_case_tier_medium_risk_is_tier2(self):
        from app.services.kyc_analytics import _case_tier
        self.assertEqual(_case_tier({"intake_profile": "medium_risk"}), "tier_2")

    def test_case_tier_unknown_is_tier1(self):
        from app.services.kyc_analytics import _case_tier
        self.assertEqual(_case_tier({"intake_profile": "unknown_profile"}), "tier_1")

    def test_case_tier_missing_profile_is_tier1(self):
        from app.services.kyc_analytics import _case_tier
        self.assertEqual(_case_tier({}), "tier_1")

    # ── 16. _decimalize helper ────────────────────────────────────────────────

    def test_decimalize_converts_float(self):
        from decimal import Decimal
        from app.services.kyc_analytics import _decimalize
        result = _decimalize(3.14)
        self.assertIsInstance(result, Decimal)
        self.assertEqual(result, Decimal("3.14"))

    def test_decimalize_nested_dict(self):
        from decimal import Decimal
        from app.services.kyc_analytics import _decimalize
        result = _decimalize({"a": 1.5, "b": {"c": 2.5}})
        self.assertIsInstance(result["a"], Decimal)
        self.assertIsInstance(result["b"]["c"], Decimal)

    def test_decimalize_leaves_int_unchanged(self):
        from app.services.kyc_analytics import _decimalize
        self.assertEqual(_decimalize(42), 42)
        self.assertIsInstance(_decimalize(42), int)

    def test_decimalize_list(self):
        from decimal import Decimal
        from app.services.kyc_analytics import _decimalize
        result = _decimalize([1.0, 2.0])
        self.assertTrue(all(isinstance(v, Decimal) for v in result))

    # ── 17. _pct_of / _percentile helpers ────────────────────────────────────

    def test_pct_of_zero_denominator(self):
        from app.services.kyc_analytics import _pct_of
        self.assertEqual(_pct_of(5, 0), 0.0)

    def test_pct_of_basic(self):
        from app.services.kyc_analytics import _pct_of
        self.assertAlmostEqual(_pct_of(1, 4), 25.0, places=5)

    def test_percentile_empty(self):
        from app.services.kyc_analytics import _percentile
        self.assertEqual(_percentile([], 0.5), 0.0)

    def test_percentile_single_value(self):
        from app.services.kyc_analytics import _percentile
        self.assertAlmostEqual(_percentile([10.0], 0.99), 10.0, places=5)

    def test_percentile_median(self):
        from app.services.kyc_analytics import _percentile
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        self.assertAlmostEqual(_percentile(values, 0.5), 3.0, places=5)

    # ── 18. _processing_hours helper ─────────────────────────────────────────

    def test_processing_hours_correct(self):
        from app.services.kyc_analytics import _processing_hours
        case = {
            "submission": {"submitted_at": 1000},
            "review": {"decided_at": 4600},  # 3600 seconds = 1 hour
        }
        result = _processing_hours(case)
        self.assertIsNotNone(result)
        self.assertAlmostEqual(result, 1.0, places=5)

    def test_processing_hours_none_when_no_submitted_at(self):
        from app.services.kyc_analytics import _processing_hours
        case = {"review": {"decided_at": 5000}}
        self.assertIsNone(_processing_hours(case))

    def test_processing_hours_none_when_decided_before_submitted(self):
        from app.services.kyc_analytics import _processing_hours
        case = {
            "submission": {"submitted_at": 5000},
            "review": {"decided_at": 3000},
        }
        self.assertIsNone(_processing_hours(case))

    def test_processing_hours_none_for_empty_case(self):
        from app.services.kyc_analytics import _processing_hours
        self.assertIsNone(_processing_hours({}))

    # ── 19. Country in geo via country_code top-level field ───────────────────

    def test_geo_uses_country_code_field(self):
        """Top-level 'country_code' is recognized by _case_country."""
        t0 = _NOW - 5 * _DAY
        _seed_case(self.table, user_sub="u_ca", status="approved",
                   created_at=t0, country="CA")  # seeder writes country_code
        start, end = _period(30)
        geo = ANALYTICS_SERVICE.get_geographic_distribution(period_start=start, period_end=end)
        countries = {g["country"] for g in geo}
        self.assertIn("CA", countries)

    # ── 20. Snapshot funnel list serialised correctly ─────────────────────────

    def test_store_snapshot_with_funnel_steps(self):
        """Stored snapshot funnel is a list of step dicts."""
        self._seed_typical_cases()
        start, end = _period(30)
        snap = ANALYTICS_SERVICE.compute_snapshot(period_start=start, period_end=end)
        ANALYTICS_SERVICE.store_daily_snapshot(date_iso="2025-07-01", snapshot=snap)
        item = ANALYTICS_SERVICE.get_daily_snapshot(date_iso="2025-07-01")
        self.assertIsInstance(item["funnel"], list)
        self.assertEqual(len(item["funnel"]), 5)
        step_names = [s["step"] for s in item["funnel"]]
        self.assertEqual(step_names, ["started", "docs_uploaded", "submitted", "under_review", "approved"])

    # ── 21. ANALYTICS_SERVICE is the module-level singleton ──────────────────

    def test_analytics_service_singleton_is_service_class(self):
        """ANALYTICS_SERVICE is an instance of KycAnalyticsService."""
        self.assertIsInstance(ANALYTICS_SERVICE, analytics_mod.KycAnalyticsService)

    def test_module_singleton_is_reachable(self):
        """The module exports ANALYTICS_SERVICE."""
        self.assertIs(analytics_mod.ANALYTICS_SERVICE, ANALYTICS_SERVICE)


if __name__ == "__main__":
    unittest.main()

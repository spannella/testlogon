"""KYC Analytics & Funnel Dashboard service (KYC-024).

Aggregates data from the ``kyc_cases`` DynamoDB table to compute funnel
conversion, time-series volume trends, processing-time histograms, rejection
reason breakdowns, geographic distribution, tier segmentation, and period
comparisons. Daily snapshots are pre-computed by a background task and stored
in the same table under PK=``ANALYTICS`` (single-table pattern) to avoid
expensive real-time scans for historical data.

All numeric values written to DynamoDB use ``int``; ``app/core/tables.py``
wraps tables to coerce stray floats to ``Decimal`` on writes, so percentages
are stored as ints (rounded) or pre-rounded floats are coerced automatically.
Computation results returned to callers use plain Python ``float``/``int``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import logging
from typing import Any

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts


def _decimalize(obj: Any) -> Any:
    """Recursively convert Python floats to Decimal for DynamoDB writes.

    DynamoDB's boto3 serializer rejects ``float``. Snapshot items carry
    percentages/rates as floats, so we coerce just before writing.
    """
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _decimalize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_decimalize(v) for v in obj]
    return obj

logger = logging.getLogger(__name__)

# Ordered funnel steps. Each step maps to a set of statuses that count as
# "reached this step or beyond" — a case that is ``approved`` has, by
# definition, also passed ``submitted`` and ``under_review``.
_FUNNEL_STEPS: list[str] = [
    "started",
    "docs_uploaded",
    "submitted",
    "under_review",
    "approved",
]

# Statuses that represent a case having reached at least the given funnel step.
# Cases are bucketed by their *current* status; we expand to "reached" using the
# natural progression of the KYC workflow.
_STATUS_REACHED: dict[str, set[str]] = {
    # current status -> set of funnel steps it has reached
    "draft": {"started"},
    "submitted": {"started", "docs_uploaded", "submitted"},
    "under_review": {"started", "docs_uploaded", "submitted", "under_review"},
    "needs_more_info": {"started", "docs_uploaded", "submitted", "under_review"},
    "approved": {"started", "docs_uploaded", "submitted", "under_review", "approved"},
    "rejected": {"started", "docs_uploaded", "submitted", "under_review"},
    "expired": {"started"},
}

_ALL_STATUSES = ["draft", "submitted", "under_review", "needs_more_info", "approved", "rejected", "expired"]

_ANALYTICS_PK = "ANALYTICS"


@dataclass
class FunnelStep:
    step: str
    count: int = 0
    percentage: float = 0.0
    drop_off_count: int = 0
    drop_off_pct: float = 0.0


@dataclass
class AnalyticsSnapshot:
    period_start: int = 0
    period_end: int = 0
    funnel: list[FunnelStep] = field(default_factory=list)
    conversion_rate: float = 0.0
    total_applications: int = 0
    approved_count: int = 0
    rejected_count: int = 0
    pending_count: int = 0
    avg_processing_hours: float = 0.0
    processing_time_distribution: dict[str, float] = field(default_factory=dict)
    rejection_reasons: dict[str, int] = field(default_factory=dict)
    geographic_distribution: list[dict[str, Any]] = field(default_factory=list)
    tier_breakdown: dict[str, dict[str, int]] = field(default_factory=dict)


def _round2(value: float) -> float:
    return round(float(value), 2)


def _pct_of(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return _round2(100.0 * numerator / denominator)


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(round((len(ordered) - 1) * q))
    idx = max(0, min(idx, len(ordered) - 1))
    return _round2(ordered[idx])


def _case_tier(case: dict[str, Any]) -> str:
    """Derive a tier label from the case intake profile.

    Mirrors the risk derivation in ``KycCaseStore.list_admin_queue`` so the
    analytics segmentation lines up with the operational queue view.
    """
    intake = str(case.get("intake_profile") or "").strip().lower()
    if intake in {"enhanced", "high_risk"}:
        return "tier_3"
    if intake in {"standard", "medium_risk"}:
        return "tier_2"
    return "tier_1"


def _case_country(case: dict[str, Any]) -> str:
    """Best-effort country extraction.

    The case META item does not store a top-level country, so we look at a few
    likely locations. Falls back to ``"unknown"``.
    """
    for key in ("country", "country_code", "residency_country"):
        val = str(case.get(key) or "").strip().upper()
        if val:
            return val
    submission = case.get("submission") or {}
    snapshot = submission.get("evidence_snapshot") or {}
    for key in ("country", "country_code"):
        val = str(snapshot.get(key) or "").strip().upper()
        if val:
            return val
    return "unknown"


def _case_in_period(case: dict[str, Any], period_start: int, period_end: int) -> bool:
    created = int(case.get("created_at") or 0)
    return period_start <= created <= period_end


def _processing_hours(case: dict[str, Any]) -> float | None:
    submission = dict(case.get("submission") or {})
    submitted_at = int(submission.get("submitted_at") or 0)
    decided_at = int((case.get("review") or {}).get("decided_at") or 0)
    if submitted_at > 0 and decided_at >= submitted_at:
        return _round2((decided_at - submitted_at) / 3600.0)
    return None


@dataclass
class KycAnalyticsService:
    _table: Any = field(default=T.kyc_cases)

    # ── Low-level case loading ────────────────────────────────────────────

    def _load_cases_by_status(self, status: str, *, max_items: int) -> list[dict[str, Any]]:
        """Query all cases for a status via the status GSI, paginating.

        DynamoDB applies the 1MB page limit before any filter, so we loop with
        ``LastEvaluatedKey`` until exhausted or the scan cap is hit.
        """
        rows: list[dict[str, Any]] = []
        last_key: dict[str, Any] | None = None
        while True:
            kwargs: dict[str, Any] = {
                "IndexName": S.kyc_cases_status_index_name,
                "KeyConditionExpression": "gsi_status_pk = :pk",
                "ExpressionAttributeValues": {":pk": f"STATUS#{status}"},
                "ScanIndexForward": False,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = self._table.query(**kwargs)
            for row in resp.get("Items", []):
                if row.get("entity_type") == "kyc_case":
                    rows.append(row)
            if len(rows) >= max_items:
                rows = rows[:max_items]
                break
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        return rows

    def _load_all_cases(
        self,
        *,
        period_start: int,
        period_end: int,
        country: str | None = None,
        tier: str | None = None,
    ) -> list[dict[str, Any]]:
        max_items = max(100, int(S.kyc_analytics_max_scan_items))
        cases: list[dict[str, Any]] = []
        per_status_cap = max_items
        for status in _ALL_STATUSES:
            try:
                rows = self._load_cases_by_status(status, max_items=per_status_cap)
            except Exception:  # pragma: no cover - defensive (bad status etc.)
                logger.exception("kyc.analytics.load_status_failed status=%s", status)
                rows = []
            cases.extend(rows)
            if len(cases) >= max_items:
                cases = cases[:max_items]
                break

        country_norm = (country or "").strip().upper() or None
        tier_norm = (tier or "").strip().lower() or None
        out: list[dict[str, Any]] = []
        for case in cases:
            if not _case_in_period(case, period_start, period_end):
                continue
            if country_norm and _case_country(case) != country_norm:
                continue
            if tier_norm and _case_tier(case) != tier_norm:
                continue
            out.append(case)
        return out

    # ── Funnel ────────────────────────────────────────────────────────────

    def compute_funnel(
        self,
        *,
        period_start: int,
        period_end: int,
        country: str | None = None,
        tier: str | None = None,
        cases: list[dict[str, Any]] | None = None,
    ) -> list[FunnelStep]:
        if cases is None:
            cases = self._load_all_cases(
                period_start=period_start, period_end=period_end, country=country, tier=tier
            )
        step_counts: dict[str, int] = {step: 0 for step in _FUNNEL_STEPS}
        for case in cases:
            status = str(case.get("status") or "")
            reached = _STATUS_REACHED.get(status, {"started"})
            for step in reached:
                if step in step_counts:
                    step_counts[step] += 1

        first_count = step_counts.get(_FUNNEL_STEPS[0], 0)
        out: list[FunnelStep] = []
        prev_count = first_count
        for i, step in enumerate(_FUNNEL_STEPS):
            count = step_counts.get(step, 0)
            percentage = _pct_of(count, first_count) if first_count else 0.0
            if i == 0:
                drop_off_count = 0
                drop_off_pct = 0.0
            else:
                drop_off_count = max(0, prev_count - count)
                drop_off_pct = _pct_of(drop_off_count, prev_count) if prev_count else 0.0
            out.append(
                FunnelStep(
                    step=step,
                    count=count,
                    percentage=percentage,
                    drop_off_count=drop_off_count,
                    drop_off_pct=drop_off_pct,
                )
            )
            prev_count = count
        return out

    def conversion_rate(self, funnel: list[FunnelStep]) -> float:
        if not funnel:
            return 0.0
        started = funnel[0].count
        approved = funnel[-1].count
        if started <= 0:
            return 0.0
        return _round2(approved / started)

    # ── Full snapshot ─────────────────────────────────────────────────────

    def compute_snapshot(
        self,
        *,
        period_start: int,
        period_end: int,
        country: str | None = None,
        tier: str | None = None,
    ) -> AnalyticsSnapshot:
        cases = self._load_all_cases(
            period_start=period_start, period_end=period_end, country=country, tier=tier
        )
        funnel = self.compute_funnel(
            period_start=period_start, period_end=period_end, cases=cases
        )

        approved = sum(1 for c in cases if str(c.get("status")) == "approved")
        rejected = sum(1 for c in cases if str(c.get("status")) == "rejected")
        pending = sum(
            1
            for c in cases
            if str(c.get("status")) in {"submitted", "under_review", "needs_more_info"}
        )
        total = len(cases)

        hours = [h for c in cases if (h := _processing_hours(c)) is not None]
        avg_hours = _round2(sum(hours) / len(hours)) if hours else 0.0
        distribution = {
            "p50": _percentile(hours, 0.50),
            "p75": _percentile(hours, 0.75),
            "p90": _percentile(hours, 0.90),
            "p99": _percentile(hours, 0.99),
        }

        rejection_reasons = self._rejection_reasons_from_cases(cases)
        geographic = self._geographic_from_cases(cases)
        tier_breakdown = self._tier_breakdown_from_cases(cases)

        return AnalyticsSnapshot(
            period_start=period_start,
            period_end=period_end,
            funnel=funnel,
            conversion_rate=self.conversion_rate(funnel),
            total_applications=total,
            approved_count=approved,
            rejected_count=rejected,
            pending_count=pending,
            avg_processing_hours=avg_hours,
            processing_time_distribution=distribution,
            rejection_reasons=rejection_reasons,
            geographic_distribution=geographic,
            tier_breakdown=tier_breakdown,
        )

    # ── Rejection reasons ─────────────────────────────────────────────────

    def _rejection_reasons_from_cases(self, cases: list[dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for case in cases:
            if str(case.get("status")) != "rejected":
                continue
            review = case.get("review") or {}
            codes = review.get("reason_codes") or []
            if not codes:
                counts["unspecified"] = counts.get("unspecified", 0) + 1
                continue
            for code in codes:
                key = str(code).strip() or "unspecified"
                counts[key] = counts.get(key, 0) + 1
        # Top 10 by count.
        top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
        return dict(top)

    def get_rejection_reasons(
        self, *, period_start: int, period_end: int
    ) -> dict[str, int]:
        cases = self._load_all_cases(period_start=period_start, period_end=period_end)
        return self._rejection_reasons_from_cases(cases)

    # ── Geographic ────────────────────────────────────────────────────────

    def _geographic_from_cases(self, cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_country: dict[str, dict[str, int]] = {}
        for case in cases:
            country = _case_country(case)
            bucket = by_country.setdefault(country, {"count": 0, "approved": 0, "rejected": 0})
            bucket["count"] += 1
            status = str(case.get("status"))
            if status == "approved":
                bucket["approved"] += 1
            elif status == "rejected":
                bucket["rejected"] += 1
        out: list[dict[str, Any]] = []
        for country, bucket in by_country.items():
            decided = bucket["approved"] + bucket["rejected"]
            out.append(
                {
                    "country": country,
                    "count": bucket["count"],
                    "approved": bucket["approved"],
                    "rejected": bucket["rejected"],
                    "approval_rate": _pct_of(bucket["approved"], decided) if decided else 0.0,
                }
            )
        out.sort(key=lambda r: (-r["count"], r["country"]))
        return out

    def get_geographic_distribution(
        self, *, period_start: int, period_end: int
    ) -> list[dict[str, Any]]:
        cases = self._load_all_cases(period_start=period_start, period_end=period_end)
        return self._geographic_from_cases(cases)

    # ── Tier breakdown ────────────────────────────────────────────────────

    def _tier_breakdown_from_cases(
        self, cases: list[dict[str, Any]]
    ) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for case in cases:
            tier = _case_tier(case)
            bucket = out.setdefault(tier, {"started": 0, "approved": 0, "rejected": 0})
            bucket["started"] += 1
            status = str(case.get("status"))
            if status == "approved":
                bucket["approved"] += 1
            elif status == "rejected":
                bucket["rejected"] += 1
        return out

    # ── Processing-time histogram ─────────────────────────────────────────

    def get_processing_time_histogram(
        self,
        *,
        period_start: int,
        period_end: int,
        bucket_hours: int = 4,
    ) -> dict[str, Any]:
        bucket_hours = max(1, int(bucket_hours))
        cases = self._load_all_cases(period_start=period_start, period_end=period_end)
        hours = [h for c in cases if (h := _processing_hours(c)) is not None]

        # Fixed bucket ranges up to 48h, then an overflow bucket.
        edges = list(range(0, 48 + bucket_hours, bucket_hours))
        labels: list[str] = []
        counts: list[int] = []
        for i in range(len(edges) - 1):
            lo, hi = edges[i], edges[i + 1]
            labels.append(f"{lo}-{hi}h")
            counts.append(0)
        overflow_label = f"{edges[-1]}h+"
        labels.append(overflow_label)
        counts.append(0)

        for h in hours:
            placed = False
            for i in range(len(edges) - 1):
                if edges[i] <= h < edges[i + 1]:
                    counts[i] += 1
                    placed = True
                    break
            if not placed:
                counts[-1] += 1

        histogram = [
            {"bucket_label": label, "count": cnt} for label, cnt in zip(labels, counts)
        ]
        percentiles = {
            "p50": _percentile(hours, 0.50),
            "p75": _percentile(hours, 0.75),
            "p90": _percentile(hours, 0.90),
            "p99": _percentile(hours, 0.99),
        }
        return {"histogram": histogram, "percentiles": percentiles}

    # ── Volume trends ─────────────────────────────────────────────────────

    def _period_bounds(self, granularity: str, periods: int, end_date: int) -> list[tuple[int, int, str]]:
        """Return a list of (start_ts, end_ts, label) oldest→newest."""
        end_dt = datetime.fromtimestamp(end_date, tz=timezone.utc)
        bounds: list[tuple[int, int, str]] = []
        if granularity == "monthly":
            # Anchor to first-of-month boundaries.
            cur = end_dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            for _ in range(periods):
                start = cur
                # next month
                if start.month == 12:
                    nxt = start.replace(year=start.year + 1, month=1)
                else:
                    nxt = start.replace(month=start.month + 1)
                bounds.append(
                    (int(start.timestamp()), int(nxt.timestamp()) - 1, start.strftime("%Y-%m"))
                )
                # step back one month
                if cur.month == 1:
                    cur = cur.replace(year=cur.year - 1, month=12)
                else:
                    cur = cur.replace(month=cur.month - 1)
        else:
            step_days = 7 if granularity == "weekly" else 1
            day = end_dt.replace(hour=0, minute=0, second=0, microsecond=0)
            for _ in range(periods):
                start = day - timedelta(days=step_days - 1)
                end = day.replace(hour=23, minute=59, second=59)
                bounds.append(
                    (int(start.timestamp()), int(end.timestamp()), start.strftime("%Y-%m-%d"))
                )
                day = day - timedelta(days=step_days)
        bounds.reverse()
        return bounds

    def get_volume_trends(
        self,
        *,
        granularity: str,
        periods: int,
        end_date: int | None = None,
    ) -> list[dict[str, Any]]:
        granularity = granularity if granularity in {"daily", "weekly", "monthly"} else "daily"
        periods = max(1, min(int(periods), int(S.kyc_analytics_trend_max_periods)))
        end_date = int(end_date) if end_date else now_ts()
        bounds = self._period_bounds(granularity, periods, end_date)
        if not bounds:
            return []

        # Load all cases spanning the full window once, then bucket.
        window_start = bounds[0][0]
        window_end = bounds[-1][1]
        cases = self._load_all_cases(period_start=window_start, period_end=window_end)

        trends: list[dict[str, Any]] = []
        for start, end, label in bounds:
            started = submitted = approved = rejected = 0
            for case in cases:
                created = int(case.get("created_at") or 0)
                if not (start <= created <= end):
                    continue
                started += 1
                status = str(case.get("status"))
                if status in _STATUS_REACHED and "submitted" in _STATUS_REACHED[status]:
                    submitted += 1
                if status == "approved":
                    approved += 1
                elif status == "rejected":
                    rejected += 1
            trends.append(
                {
                    "period": label,
                    "started": started,
                    "submitted": submitted,
                    "approved": approved,
                    "rejected": rejected,
                }
            )
        return trends

    # ── Screening hit trends ──────────────────────────────────────────────

    def get_screening_hit_trends(
        self, *, granularity: str, periods: int, end_date: int | None = None
    ) -> list[dict[str, Any]]:
        """Sanctions/PEP screening hit rate over time.

        Derives "screened" from cases that reached submission within the period
        and "hits" from cases whose review reason codes indicate a screening
        flag. This avoids a dependency on the screening-results table while
        still providing a meaningful trend.
        """
        granularity = granularity if granularity in {"daily", "weekly", "monthly"} else "daily"
        periods = max(1, min(int(periods), int(S.kyc_analytics_trend_max_periods)))
        end_date = int(end_date) if end_date else now_ts()
        bounds = self._period_bounds(granularity, periods, end_date)
        if not bounds:
            return []
        window_start = bounds[0][0]
        window_end = bounds[-1][1]
        cases = self._load_all_cases(period_start=window_start, period_end=window_end)

        hit_codes = {"sanctions_hit", "pep_match", "screening_hit", "adverse_media", "suspicious_identity"}
        trends: list[dict[str, Any]] = []
        for start, end, label in bounds:
            screened = hits = 0
            for case in cases:
                created = int(case.get("created_at") or 0)
                if not (start <= created <= end):
                    continue
                status = str(case.get("status"))
                if status in _STATUS_REACHED and "submitted" in _STATUS_REACHED[status]:
                    screened += 1
                    codes = {str(c).strip() for c in (case.get("review") or {}).get("reason_codes") or []}
                    if codes & hit_codes:
                        hits += 1
            trends.append(
                {
                    "period": label,
                    "total_screened": screened,
                    "hits": hits,
                    "hit_rate": _pct_of(hits, screened) if screened else 0.0,
                }
            )
        return trends

    # ── Drop-off analysis ─────────────────────────────────────────────────

    def get_drop_off_analysis(
        self, *, period_start: int, period_end: int
    ) -> list[dict[str, Any]]:
        funnel = self.compute_funnel(period_start=period_start, period_end=period_end)
        steps: list[dict[str, Any]] = []
        for i in range(len(funnel) - 1):
            cur = funnel[i]
            nxt = funnel[i + 1]
            continued = nxt.count
            dropped = max(0, cur.count - nxt.count)
            steps.append(
                {
                    "from_step": cur.step,
                    "to_step": nxt.step,
                    "continued": continued,
                    "dropped": dropped,
                    "drop_rate": _pct_of(dropped, cur.count) if cur.count else 0.0,
                    "avg_time_in_step_hours": 0.0,
                }
            )
        return steps

    # ── Period comparison ─────────────────────────────────────────────────

    def compare_periods(
        self,
        *,
        current_start: int,
        current_end: int,
        previous_start: int,
        previous_end: int,
    ) -> dict[str, Any]:
        current = self.compute_snapshot(period_start=current_start, period_end=current_end)
        previous = self.compute_snapshot(period_start=previous_start, period_end=previous_end)
        vol_delta = current.total_applications - previous.total_applications
        deltas = {
            "conversion_rate_delta": _round2(current.conversion_rate - previous.conversion_rate),
            "volume_delta": vol_delta,
            "volume_delta_pct": _pct_of(vol_delta, previous.total_applications)
            if previous.total_applications
            else 0.0,
            "approved_delta": current.approved_count - previous.approved_count,
            "rejected_delta": current.rejected_count - previous.rejected_count,
            "avg_processing_hours_delta": _round2(
                current.avg_processing_hours - previous.avg_processing_hours
            ),
        }
        return {"current": current, "previous": previous, "deltas": deltas}

    # ── Pre-computed snapshots ────────────────────────────────────────────

    def _snapshot_to_item(self, date_iso: str, snapshot: AnalyticsSnapshot) -> dict[str, Any]:
        return {
            "pk": _ANALYTICS_PK,
            "sk": f"DAILY#{date_iso}",
            "entity_type": "kyc_analytics_snapshot",
            "date_iso": date_iso,
            "snapshot": {
                "period_start": snapshot.period_start,
                "period_end": snapshot.period_end,
                "total_applications": snapshot.total_applications,
                "approved_count": snapshot.approved_count,
                "rejected_count": snapshot.rejected_count,
                "pending_count": snapshot.pending_count,
                "conversion_rate": snapshot.conversion_rate,
                "avg_processing_hours": snapshot.avg_processing_hours,
            },
            "funnel": [
                {
                    "step": s.step,
                    "count": s.count,
                    "percentage": s.percentage,
                    "drop_off_count": s.drop_off_count,
                    "drop_off_pct": s.drop_off_pct,
                }
                for s in snapshot.funnel
            ],
            "processing_time_distribution": snapshot.processing_time_distribution,
            "rejection_reasons": snapshot.rejection_reasons,
            "geographic_distribution": snapshot.geographic_distribution,
            "tier_breakdown": snapshot.tier_breakdown,
            "computed_at": now_ts(),
        }

    def store_daily_snapshot(self, *, date_iso: str, snapshot: AnalyticsSnapshot) -> None:
        item = _decimalize(self._snapshot_to_item(date_iso, snapshot))
        self._table.put_item(Item=item)

    def get_daily_snapshot(self, *, date_iso: str) -> dict[str, Any] | None:
        resp = self._table.get_item(Key={"pk": _ANALYTICS_PK, "sk": f"DAILY#{date_iso}"})
        return resp.get("Item")

    def _day_bounds(self, date_iso: str) -> tuple[int, int]:
        day = datetime.strptime(date_iso, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        start = int(day.timestamp())
        end = int((day + timedelta(days=1)).timestamp()) - 1
        return start, end

    def precompute_daily_snapshot(self, *, date_iso: str | None = None) -> dict[str, Any]:
        """Compute and store a daily snapshot. Defaults to yesterday (UTC).

        Returns a small summary describing what was computed.
        """
        if date_iso is None:
            yesterday = datetime.now(tz=timezone.utc) - timedelta(days=1)
            date_iso = yesterday.strftime("%Y-%m-%d")
        start, end = self._day_bounds(date_iso)
        snapshot = self.compute_snapshot(period_start=start, period_end=end)
        self.store_daily_snapshot(date_iso=date_iso, snapshot=snapshot)
        return {
            "date_iso": date_iso,
            "total_applications": snapshot.total_applications,
            "approved_count": snapshot.approved_count,
        }


# Module-level singleton for router + background task reuse.
ANALYTICS_SERVICE = KycAnalyticsService()


# ── Background pre-computation loop (registered from app/main.py) ──────────


async def kyc_analytics_precompute_loop(interval_seconds: int = 3600) -> None:
    """Every ``interval_seconds`` (1h default): recompute yesterday's and
    today's daily snapshot. Never raises out of the loop."""
    import asyncio

    while True:
        try:
            today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
            ANALYTICS_SERVICE.precompute_daily_snapshot()  # yesterday
            ANALYTICS_SERVICE.precompute_daily_snapshot(date_iso=today)  # running today
        except Exception:  # pragma: no cover - defensive
            logger.exception("kyc.analytics.precompute_error")
        await asyncio.sleep(max(60, int(interval_seconds)))


def start_kyc_analytics_precompute_task() -> None:
    """Register the KYC analytics pre-computation background task at startup."""
    import asyncio

    if S.kyc_analytics_precompute_enabled:
        asyncio.ensure_future(kyc_analytics_precompute_loop())
        logger.info("KYC analytics precompute task started")

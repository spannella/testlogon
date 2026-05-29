# KYC-024: KYC Analytics & Funnel Dashboard

**Ticket**: KYC-024
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 7-9 days
**Depends on**: KYC-001 (Admin Review Dashboard), KYC-008 (Risk Scoring Engine), KYC-012 (Compliance Reporting & Export)

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The existing KYC metrics endpoint (`get_admin_kyc_metrics` in `app/routers/kyc_cases.py`, line 947) provides a basic snapshot: `funnel_counts` (count per status), `review_latency_seconds` (p50/p90/p99), `stale_queue_count`, and `submit_guard_failures_by_reason`. This is useful for operational monitoring but insufficient for strategic decision-making. Platform operators need:

1. **Funnel visualization**: Where exactly do users abandon the KYC process? Is the drop-off at document upload, questionnaire completion, or signature? What is the overall conversion rate from "started" to "approved"?
2. **Time-series trends**: Are application volumes increasing? Is approval rate improving or declining? Are rejection reasons changing over time?
3. **Segmentation**: How do completion rates differ by country, document type, verification tier? Which user segments have the highest rejection rates?
4. **Comparative analysis**: How does this week compare to last week? This month vs. previous month?
5. **Processing efficiency**: What is the distribution of processing times? Are there outlier cases taking disproportionately long?

Without this visibility, compliance teams operate reactively rather than proactively, and product teams cannot measure the impact of KYC flow improvements.

### 1.2 How It Works

1. The analytics service aggregates data from the `kyc_cases` DDB table, computing metrics over configurable time windows.
2. A background task runs hourly to pre-compute aggregate metrics and store snapshots, avoiding expensive real-time scans on every dashboard load.
3. The admin dashboard renders the data using charts: funnel bar chart, time-series line charts, pie charts for rejection reasons, and a tabular geographic distribution view.
4. Admins can filter by date range, tier, country, and compare current period with a previous period.
5. All chart data is returned as structured JSON from the API; the frontend renders using lightweight charting components.

### 1.3 Dashboard Sections

| Section | Visualization | Description |
|---------|--------------|-------------|
| KYC Funnel | Horizontal bar chart | started -> docs_uploaded -> submitted -> under_review -> approved |
| Drop-off Analysis | Funnel with drop-off percentages | Shows where users abandon at each step |
| Conversion Rate | Single metric cards | Overall, by tier, by country |
| Processing Time | Histogram | Distribution of time from submission to decision |
| Rejection Reasons | Pie/donut chart | Breakdown of rejection reason codes |
| Screening Hit Rate | Line chart | Sanctions/PEP screening hits over time (KYC-006) |
| Geographic Distribution | Table with country flags | Application count and approval rate by country |
| Volume Trends | Line chart | Daily/weekly/monthly application volume with comparison overlay |
| Period Comparison | Comparison cards | This period vs. previous period for key metrics |

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Manager | See funnel conversion from started to approved | Funnel chart with absolute counts and percentages at each step |
| Manager | Identify where users drop off in the KYC flow | Drop-off percentages between each funnel step |
| Manager | View rejection reasons breakdown | Pie chart showing top 10 rejection reason codes |
| Manager | Compare this week to last week | Side-by-side metrics with delta indicators (up/down arrows) |
| Manager | Filter analytics by country and tier | Dropdown filters update all charts |
| Manager | See processing time distribution | Histogram with p50, p75, p90, p99 markers |
| Manager | View geographic distribution of applications | Table with country, count, approval rate columns |

---

## 2. Current State Analysis

### 2.1 Existing Metrics (`app/routers/kyc_cases.py`, line 947)

The `get_admin_kyc_metrics` endpoint delegates to `KycCaseStore.get_metrics_snapshot` (line 701 in `app/services/kyc_cases.py`). This method:

1. Queries each status from the `status-updated-index` GSI to count cases per status (`funnel_counts`).
2. Collects `review_latency_seconds` from cases that have a decision timestamp minus submission timestamp.
3. Computes `stale_queue_count` -- cases under review for longer than `stale_after_seconds` (default 48h).
4. Aggregates `submit_guard_failures_by_reason` from cases with `missing_requirements`.

This is a real-time scan that becomes expensive as the case count grows. It provides no time-series data, no segmentation, no comparison capability, and no geographic breakdown.

### 2.2 KYC Case Data Model

The `kyc_cases` table contains:
- `status` — Current case status (indexed by `gsi_status_pk`)
- `created_at` — Case creation timestamp (N)
- `updated_at` — Last update timestamp (N)
- `intake_profile` — Profile name
- User-facing metadata (linked via `user_sub`)

The table does not store country or document type as top-level indexed attributes. These must be extracted from the case's file attachments or user profile.

### 2.3 Admin Dashboard Patterns

The platform has several admin dashboards:
- `frontend/src/pages/admin/ModerationBoardPage.tsx` — Moderation queue
- `frontend/src/pages/admin/RateLimitDashboard.tsx` — Rate limit metrics
- `frontend/src/pages/admin/AuditExportPage.tsx` — Audit log export

These follow a common pattern: a React page with `useQuery` hooks fetching JSON data from admin API endpoints, rendered with Card/Table components. The analytics dashboard will follow the same pattern, using simple HTML/CSS chart components (bar, line, pie) rather than a heavy charting library.

---

## 3. Technical Design

### 3.1 New Service: `app/services/kyc_analytics.py`

```python
@dataclass
class FunnelStep:
    step: str                      # e.g., "started", "docs_uploaded", "submitted"
    count: int
    percentage: float              # Relative to first step
    drop_off_count: int            # Lost from previous step
    drop_off_pct: float

@dataclass
class AnalyticsSnapshot:
    period_start: int              # Unix timestamp
    period_end: int
    funnel: list[FunnelStep]
    conversion_rate: float         # approved / started
    total_applications: int
    approved_count: int
    rejected_count: int
    pending_count: int
    avg_processing_hours: float
    processing_time_distribution: dict[str, float]  # p50, p75, p90, p99
    rejection_reasons: dict[str, int]               # reason_code -> count
    geographic_distribution: list[dict[str, Any]]   # [{country, count, approved, rejected, rate}]
    tier_breakdown: dict[str, dict[str, int]]       # tier -> {started, approved, rejected}

class KycAnalyticsService:
    def compute_funnel(self, *, period_start: int, period_end: int,
                       country: str | None = None,
                       tier: str | None = None) -> list[FunnelStep]:
        """Compute KYC funnel for the given time period.
        Steps: started, profile_complete, docs_uploaded, questionnaire_done,
               signature_done, submitted, under_review, approved.
        Uses status transition timestamps from case records."""

    def compute_snapshot(self, *, period_start: int, period_end: int,
                         country: str | None = None,
                         tier: str | None = None) -> AnalyticsSnapshot:
        """Compute full analytics snapshot for a time period."""

    def get_volume_trends(self, *, granularity: str, periods: int,
                          end_date: int | None = None) -> list[dict[str, Any]]:
        """Time-series of application volume.
        granularity: "daily" | "weekly" | "monthly"
        Returns: [{ period, started, submitted, approved, rejected }]"""

    def get_processing_time_histogram(self, *, period_start: int,
                                       period_end: int,
                                       bucket_hours: int = 4) -> list[dict[str, Any]]:
        """Processing time distribution in buckets.
        Returns: [{ bucket_label: "0-4h", count: 15 }, ...]"""

    def get_screening_hit_trends(self, *, granularity: str,
                                  periods: int) -> list[dict[str, Any]]:
        """Sanctions/PEP screening hit rate over time.
        Returns: [{ period, total_screened, hits, hit_rate }]"""

    def compare_periods(self, *, current_start: int, current_end: int,
                        previous_start: int, previous_end: int) -> dict[str, Any]:
        """Side-by-side comparison of two periods.
        Returns: { current: AnalyticsSnapshot, previous: AnalyticsSnapshot,
                   deltas: { conversion_rate_delta, volume_delta, ... } }"""

    def get_drop_off_analysis(self, *, period_start: int,
                               period_end: int) -> list[dict[str, Any]]:
        """Detailed drop-off analysis between each funnel step.
        Returns: [{ from_step, to_step, continued, dropped, drop_rate, avg_time_in_step }]"""

    def precompute_daily_snapshot(self) -> None:
        """Background job: compute and store yesterday's snapshot.
        Stored in kyc_cases table with PK=ANALYTICS, SK=DAILY#{date_iso}."""
```

### 3.2 Pre-computed Snapshots

To avoid expensive real-time table scans, daily snapshots are pre-computed by a background task:

```
# Stored in kyc_cases table (single-table pattern)
PK: ANALYTICS
SK: DAILY#{date_iso}          — e.g., "DAILY#2026-05-28"

Attributes:
  snapshot (M)                — Serialized AnalyticsSnapshot
  computed_at (N)
  tier_breakdown (M)
  geographic_distribution (L)
  rejection_reasons (M)
```

GSI for time-range queries on snapshots:

```
# Re-use existing status-updated-index GSI
# Query: PK="ANALYTICS", SK between "DAILY#2026-05-01" and "DAILY#2026-05-31"
```

The background task runs hourly (registered in `app/main.py`):

```python
async def kyc_analytics_precompute_loop():
    """Run every hour. Compute snapshot for yesterday if not already computed.
    Also refresh today's running snapshot."""
    while True:
        try:
            svc = KycAnalyticsService()
            svc.precompute_daily_snapshot()
        except Exception:
            logger.exception("KYC analytics precompute error")
        await asyncio.sleep(3600)  # 1 hour
```

### 3.3 Router Endpoints

Add to a new router `app/routers/kyc_analytics.py`:

```python
router = APIRouter(prefix="/v1/kyc/analytics", tags=["kyc-analytics"])

# All endpoints require admin session
GET /funnel?from={ts}&to={ts}&country={cc}&tier={tier}
  — KYC funnel with optional filters
  — Response: { "funnel": [FunnelStep], "conversion_rate": float }

GET /snapshot?from={ts}&to={ts}&country={cc}&tier={tier}
  — Full analytics snapshot
  — Response: { "snapshot": AnalyticsSnapshot }

GET /trends?granularity={daily|weekly|monthly}&periods={N}
  — Volume trends time series
  — Response: { "trends": [{ period, started, submitted, approved, rejected }] }

GET /processing-times?from={ts}&to={ts}&bucket_hours={N}
  — Processing time histogram
  — Response: { "histogram": [{ bucket_label, count }], "percentiles": { p50, p75, p90, p99 } }

GET /rejection-reasons?from={ts}&to={ts}
  — Rejection reason breakdown
  — Response: { "reasons": { reason_code: count } }

GET /screening-hits?granularity={daily|weekly}&periods={N}
  — Screening hit rate trends
  — Response: { "trends": [{ period, total_screened, hits, hit_rate }] }

GET /geographic?from={ts}&to={ts}
  — Geographic distribution
  — Response: { "countries": [{ country, count, approved, rejected, approval_rate }] }

GET /compare?current_from={ts}&current_to={ts}&previous_from={ts}&previous_to={ts}
  — Period comparison
  — Response: { "current": Snapshot, "previous": Snapshot, "deltas": {...} }

GET /drop-off?from={ts}&to={ts}
  — Drop-off analysis between funnel steps
  — Response: { "steps": [{ from_step, to_step, continued, dropped, drop_rate }] }
```

Register in `app/main.py`:

```python
from app.routers.kyc_analytics import router as kyc_analytics_router
app.include_router(kyc_analytics_router)
```

### 3.4 Frontend: `frontend/src/pages/admin/KycAnalyticsDashboard.tsx`

**Route in `App.tsx`:**

```tsx
const KycAnalyticsDashboard = lazy(() => import("@/pages/admin/KycAnalyticsDashboard"));
<Route path="admin/kyc/analytics" element={<KycAnalyticsDashboard />} />
```

**Components:**

- `KycAnalyticsDashboard` — Main page with date range picker, country/tier filters
- `FunnelChart` — Horizontal bar chart showing funnel steps with counts and percentages
- `DropOffChart` — Funnel visualization with red drop-off indicators between steps
- `VolumeChart` — Line chart with daily/weekly/monthly volume, optional comparison overlay
- `ProcessingTimeHistogram` — Bar chart with time buckets and percentile markers
- `RejectionReasonsPie` — Donut chart showing top rejection reasons
- `GeographicTable` — Table with country flag emoji, count, approval rate, sortable columns
- `PeriodComparisonCards` — Side-by-side metric cards with delta arrows (green up, red down)
- `ConversionRateCard` — Large metric card showing overall conversion rate

**Chart implementation**: Charts are built with simple HTML/CSS (colored `<div>` bars for bar charts, CSS grid for pie approximation, `<table>` for data tables) rather than importing a charting library. This keeps the bundle size small and avoids dependency on D3/Chart.js.

**API endpoints in `frontend/src/api/endpoints/kyc-analytics.ts`:**

```typescript
export const getFunnel = (params: { from: number; to: number; country?: string; tier?: string }) =>
  client.get<{ funnel: FunnelStep[]; conversion_rate: number }>("/v1/kyc/analytics/funnel", { params });

export const getSnapshot = (params: { from: number; to: number }) =>
  client.get<{ snapshot: AnalyticsSnapshot }>("/v1/kyc/analytics/snapshot", { params });

export const getTrends = (params: { granularity: string; periods: number }) =>
  client.get<{ trends: TrendPoint[] }>("/v1/kyc/analytics/trends", { params });

export const getProcessingTimes = (params: { from: number; to: number; bucket_hours?: number }) =>
  client.get<{ histogram: HistogramBucket[]; percentiles: Percentiles }>(
    "/v1/kyc/analytics/processing-times", { params }
  );

export const getRejectionReasons = (params: { from: number; to: number }) =>
  client.get<{ reasons: Record<string, number> }>("/v1/kyc/analytics/rejection-reasons", { params });

export const getGeographic = (params: { from: number; to: number }) =>
  client.get<{ countries: CountryStats[] }>("/v1/kyc/analytics/geographic", { params });

export const comparePeriods = (params: {
  current_from: number; current_to: number;
  previous_from: number; previous_to: number;
}) => client.get<{ current: AnalyticsSnapshot; previous: AnalyticsSnapshot; deltas: Deltas }>(
  "/v1/kyc/analytics/compare", { params }
);

export const getDropOff = (params: { from: number; to: number }) =>
  client.get<{ steps: DropOffStep[] }>("/v1/kyc/analytics/drop-off", { params });
```

**Types in `frontend/src/api/types.ts`:**

```typescript
interface FunnelStep {
  step: string;
  count: number;
  percentage: number;
  drop_off_count: number;
  drop_off_pct: number;
}

interface TrendPoint {
  period: string;
  started: number;
  submitted: number;
  approved: number;
  rejected: number;
}

interface HistogramBucket {
  bucket_label: string;
  count: number;
}

interface CountryStats {
  country: string;
  count: number;
  approved: number;
  rejected: number;
  approval_rate: number;
}

interface DropOffStep {
  from_step: string;
  to_step: string;
  continued: number;
  dropped: number;
  drop_rate: number;
  avg_time_in_step_hours: number;
}
```

---

## 4. E2E Test Plan

**Test file**: `frontend/e2e/kyc-analytics.spec.ts`
**Total**: ~15 tests across 3 sections (237-239)

### Section 237: Analytics API (6 tests)

```typescript
test("237.1 Get funnel returns steps with counts", async ({ page }) => {
  // Seed several KYC cases in various statuses
  // GET /v1/kyc/analytics/funnel?from=0&to=9999999999
  // Expect funnel array with step, count, percentage for each step
});

test("237.2 Funnel filtered by tier", async ({ page }) => {
  // GET funnel with tier=tier_2
  // Expect only tier_2 cases counted
});

test("237.3 Volume trends returns time series", async ({ page }) => {
  // GET /v1/kyc/analytics/trends?granularity=daily&periods=7
  // Expect array with 7 entries, each with period and counts
});

test("237.4 Processing time histogram returns buckets", async ({ page }) => {
  // GET /v1/kyc/analytics/processing-times?from=0&to=9999999999
  // Expect histogram array with bucket_label and count
  // Expect percentiles object with p50, p75, p90, p99
});

test("237.5 Rejection reasons returns reason code counts", async ({ page }) => {
  // Seed rejected cases with reason codes
  // GET /v1/kyc/analytics/rejection-reasons
  // Expect reasons map with at least one entry
});

test("237.6 Non-admin cannot access analytics", async ({ page }) => {
  // Alice (USER) GET funnel -> 403
});
```

### Section 238: Comparison & Geographic API (5 tests)

```typescript
test("238.1 Compare periods returns current, previous, and deltas", async ({ page }) => {
  // GET /v1/kyc/analytics/compare with current and previous time ranges
  // Expect current.total_applications, previous.total_applications, deltas object
});

test("238.2 Geographic distribution returns country breakdown", async ({ page }) => {
  // Seed cases with different countries
  // GET /v1/kyc/analytics/geographic
  // Expect countries array with country, count, approval_rate
});

test("238.3 Drop-off analysis shows loss between steps", async ({ page }) => {
  // GET /v1/kyc/analytics/drop-off
  // Expect steps array with from_step, to_step, continued, dropped, drop_rate
});

test("238.4 Snapshot returns full analytics summary", async ({ page }) => {
  // GET /v1/kyc/analytics/snapshot
  // Expect all fields: funnel, conversion_rate, processing_time_distribution, etc.
});

test("238.5 Empty date range returns zero counts", async ({ page }) => {
  // GET funnel with from/to in the far future
  // Expect all counts = 0, conversion_rate = 0
});
```

### Section 239: Analytics Dashboard UI (4 tests)

```typescript
test("239.1 Dashboard page loads with funnel chart", async ({ page }) => {
  // Navigate to /admin/kyc/analytics
  // Expect heading "KYC Analytics"
  // Expect funnel chart section with step labels
});

test("239.2 Date range filter updates chart data", async ({ page }) => {
  // Select "Last 7 days" from date range picker
  // Expect funnel data to refresh (verify via network response)
});

test("239.3 Country filter narrows results", async ({ page }) => {
  // Select a specific country from dropdown
  // Expect funnel counts to change
});

test("239.4 Comparison mode shows previous period overlay", async ({ page }) => {
  // Toggle "Compare with previous period"
  // Expect comparison cards with delta indicators
});
```

---

## 5. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/kyc_analytics.py` | **New** | Funnel computation, trends, histograms, geographic, comparisons |
| `app/routers/kyc_analytics.py` | **New** | 9 analytics API endpoints |
| `app/main.py` | Modify | Register `kyc_analytics_router`, add precompute background task |
| `app/core/settings.py` | Modify | Add `kyc_analytics_precompute_enabled`, `kyc_analytics_cache_ttl` |
| `app/core/tables.py` | Modify | No new table needed (uses kyc_cases single-table) |
| `frontend/src/api/endpoints/kyc-analytics.ts` | **New** | API client functions for all analytics endpoints |
| `frontend/src/api/types.ts` | Modify | Add `FunnelStep`, `TrendPoint`, `HistogramBucket`, `CountryStats`, etc. |
| `frontend/src/pages/admin/KycAnalyticsDashboard.tsx` | **New** | Main analytics dashboard page |
| `frontend/src/components/shared/FunnelChart.tsx` | **New** | Horizontal bar funnel chart |
| `frontend/src/components/shared/VolumeChart.tsx` | **New** | Time-series line chart |
| `frontend/src/components/shared/ProcessingTimeHistogram.tsx` | **New** | Histogram bar chart |
| `frontend/src/components/shared/RejectionReasonsPie.tsx` | **New** | Donut chart component |
| `frontend/src/components/shared/PeriodComparisonCards.tsx` | **New** | Comparison metric cards |
| `frontend/src/App.tsx` | Modify | Add `/admin/kyc/analytics` route |
| `frontend/e2e/kyc-analytics.spec.ts` | **New** | 15 E2E tests across sections 237-239 |

---

## 6. Configuration Reference

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `KYC_ANALYTICS_PRECOMPUTE_ENABLED` | `true` | Enable/disable hourly snapshot precomputation |
| `KYC_ANALYTICS_CACHE_TTL` | `300` | Cache TTL in seconds for real-time analytics queries |
| `KYC_ANALYTICS_MAX_SCAN_ITEMS` | `10000` | Maximum items to scan for real-time computation |
| `KYC_ANALYTICS_TREND_MAX_PERIODS` | `90` | Maximum periods for trend queries |

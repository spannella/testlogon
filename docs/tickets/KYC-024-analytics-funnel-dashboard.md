# KYC-024: KYC Analytics & Funnel Dashboard

**Ticket**: KYC-024
**Author**: Engineering
**Status**: Implemented
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

### 2.1 Existing Metrics (`app/routers/kyc_cases.py`, line 946)

The `get_admin_kyc_metrics` endpoint (see `app/routers/kyc_cases.py:946-959`) delegates to `KycCaseStore.get_metrics_snapshot` (see `app/services/kyc_cases.py:701`). This method:

1. Queries each status via `list_cases_by_status` (see `app/services/kyc_cases.py:617`) from the `status-updated-index` GSI (see `app/core/settings.py:1067`) to count cases per status (`funnel_counts`).
2. Collects `review_latency_seconds` from cases that have a decision timestamp minus submission timestamp.
3. Computes `stale_queue_count` -- cases under review for longer than `stale_after_seconds` (default 48h).
4. Aggregates `submit_guard_failures_by_reason` from cases with `missing_requirements`.

The auth pattern uses `require_ui_session` + manual admin/root role check (see `app/routers/kyc_cases.py:950-953`), consistent with all other KYC admin endpoints.

This is a real-time scan that becomes expensive as the case count grows. It provides no time-series data, no segmentation, no comparison capability, and no geographic breakdown.

### 2.2 KYC Case Data Model

The `kyc_cases` table contains:
- `status` -- Current case status (indexed by `gsi_status_pk`)
- `created_at` -- Case creation timestamp (N)
- `updated_at` -- Last update timestamp (N)
- `intake_profile` -- Profile name
- User-facing metadata (linked via `user_sub`)

The table does not store country or document type as top-level indexed attributes. These must be extracted from the case's file attachments or user profile.

### 2.3 Admin Dashboard Patterns

The platform has several admin dashboards (all confirmed to exist):
- `frontend/src/pages/admin/ModerationBoardPage.tsx` (301 lines) -- Moderation queue
- `frontend/src/pages/admin/RateLimitDashboard.tsx` (544 lines) -- Rate limit metrics
- `frontend/src/pages/admin/AuditExportPage.tsx` (168 lines) -- Audit log export

These follow a common pattern: a React page with `useQuery` hooks fetching JSON data from admin API endpoints, rendered with Card/Table components. The analytics dashboard will follow the same pattern, using simple HTML/CSS chart components (bar, line, pie) rather than a heavy charting library.

---

## 3. Technical Design

### 3.1 Architecture Diagram

```
+-------------------+      +--------------------+      +-------------------+
|   React Frontend  |      |   FastAPI Backend   |      |   DynamoDB        |
|                   |      |                    |      |                   |
|  KycAnalytics     |      |  kyc_analytics.py  |      |  kyc_cases table  |
|  Dashboard        |      |  (router)          |      |    Case items     |
|                   |      |                    |      |    ANALYTICS PK   |
|  FunnelChart      | ---> | GET /funnel        | ---> |  status-updated   |
|  VolumeChart      | ---> | GET /trends        |      |  -index GSI       |
|  ProcessingTime   | ---> | GET /processing    |      |                   |
|  RejectionPie     | ---> | GET /rejection     |      |                   |
|  GeographicTable  | ---> | GET /geographic    |      |                   |
|  ComparisonCards  | ---> | GET /compare       |      |                   |
|                   |      |                    |      |                   |
|  DateRangePicker  |      |  kyc_analytics.py  |      |  Pre-computed     |
|  CountryFilter    |      |  (service)         |      |  ANALYTICS/       |
|  TierFilter       |      |                    |      |  DAILY#date       |
+-------------------+      +--------------------+      +-------------------+
                                    |
                                    | Background task (hourly)
                                    v
                           +--------------------+
                           |  precompute_daily   |
                           |  _snapshot()        |
                           |  - Scans kyc_cases  |
                           |  - Computes funnel  |
                           |  - Stores snapshot  |
                           |    in DDB           |
                           +--------------------+

Request Flow:

  Admin -> KycAnalyticsDashboard
    |
    +-> useQuery(["kyc-analytics", "funnel", filters])
    |     -> GET /v1/kyc/analytics/funnel?from=...&to=...&country=SE
    |     -> Backend: check for pre-computed snapshot
    |     -> If snapshot exists + covers range: return cached
    |     -> Else: compute real-time from kyc_cases table
    |     <- { funnel: [...], conversion_rate: 0.65 }
    |
    +-> useQuery(["kyc-analytics", "trends", granularity])
    |     -> GET /v1/kyc/analytics/trends?granularity=daily&periods=30
    |     -> Backend: query ANALYTICS/DAILY#... items for each period
    |     <- { trends: [{ period: "2026-05-01", started: 45, ... }, ...] }
    |
    +-> useQuery(["kyc-analytics", "processing-times", filters])
          -> GET /v1/kyc/analytics/processing-times?from=...&to=...
          -> Backend: scan cases with decision timestamps, bucket by hours
          <- { histogram: [...], percentiles: { p50: 4.2, p75: 8.1, ... } }
```

### 3.2 New Service: `app/services/kyc_analytics.py`

<!-- NOTE: app/services/kyc_analytics.py does not exist yet — new implementation required -->

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

### 3.3 DynamoDB Access Patterns

| Access Pattern | PK | SK / Index | Operation | Notes |
|---|---|---|---|---|
| Store daily snapshot | `ANALYTICS` | `DAILY#{date_iso}` | PutItem | Hourly background task |
| Get daily snapshot | `ANALYTICS` | `DAILY#{date_iso}` | GetItem | Cached per-day lookup |
| Query snapshot range | `ANALYTICS` | Between `DAILY#start` and `DAILY#end` | Query | For trends over date range |
| Count cases by status (funnel) | `gsi_status_pk` GSI (see `app/core/settings.py:1067` — `status-updated-index`) | SK=status, filter by created_at | Query | Real-time funnel computation |
| Get case processing times | `gsi_status_pk` GSI | SK=approved/rejected, filter by timestamps | Query | Histogram computation |
| Count by country | Full table scan with FilterExpression | -- | Scan | Expensive; prefer pre-computed |
| Count by tier | Full table scan with FilterExpression | -- | Scan | Expensive; prefer pre-computed |

**Example DynamoDB Items:**

Pre-computed daily snapshot:
```json
{
  "pk": "ANALYTICS",
  "sk": "DAILY#2026-05-28",
  "snapshot": {
    "period_start": 1748390400,
    "period_end": 1748476800,
    "total_applications": 45,
    "approved_count": 28,
    "rejected_count": 7,
    "pending_count": 10,
    "conversion_rate": 0.622,
    "avg_processing_hours": 6.3
  },
  "funnel": [
    {"step": "started", "count": 45, "percentage": 100.0, "drop_off_count": 0, "drop_off_pct": 0.0},
    {"step": "docs_uploaded", "count": 38, "percentage": 84.4, "drop_off_count": 7, "drop_off_pct": 15.6},
    {"step": "submitted", "count": 35, "percentage": 77.8, "drop_off_count": 3, "drop_off_pct": 7.9},
    {"step": "approved", "count": 28, "percentage": 62.2, "drop_off_count": 7, "drop_off_pct": 20.0}
  ],
  "rejection_reasons": {"incomplete_documents": 3, "suspicious_identity": 2, "expired_id": 2},
  "geographic_distribution": [
    {"country": "SE", "count": 15, "approved": 12, "rejected": 1, "approval_rate": 80.0},
    {"country": "DE", "count": 10, "approved": 7, "rejected": 2, "approval_rate": 70.0}
  ],
  "tier_breakdown": {
    "tier_1": {"started": 30, "approved": 20, "rejected": 5},
    "tier_2": {"started": 15, "approved": 8, "rejected": 2}
  },
  "computed_at": 1748480400
}
```

### 3.4 Pre-computed Snapshots

To avoid expensive real-time table scans, daily snapshots are pre-computed by a background task:

```
# Stored in kyc_cases table (single-table pattern)
PK: ANALYTICS
SK: DAILY#{date_iso}          -- e.g., "DAILY#2026-05-28"

Attributes:
  snapshot (M)                -- Serialized AnalyticsSnapshot
  computed_at (N)
  tier_breakdown (M)
  geographic_distribution (L)
  rejection_reasons (M)
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

### 3.5 Pydantic Models

```python
# -- KYC Analytics (KYC-024) -- Add to app/models.py

class FunnelStepOut(BaseModel):
    step: str
    count: int = 0
    percentage: float = 0.0
    drop_off_count: int = 0
    drop_off_pct: float = 0.0

class FunnelResponse(BaseModel):
    funnel: list[FunnelStepOut] = Field(default_factory=list)
    conversion_rate: float = 0.0

class TrendPointOut(BaseModel):
    period: str  # ISO date or date range
    started: int = 0
    submitted: int = 0
    approved: int = 0
    rejected: int = 0

class TrendsResponse(BaseModel):
    trends: list[TrendPointOut] = Field(default_factory=list)

class HistogramBucketOut(BaseModel):
    bucket_label: str  # "0-4h", "4-8h", etc.
    count: int = 0

class PercentilesOut(BaseModel):
    p50: float = 0.0
    p75: float = 0.0
    p90: float = 0.0
    p99: float = 0.0

class ProcessingTimesResponse(BaseModel):
    histogram: list[HistogramBucketOut] = Field(default_factory=list)
    percentiles: PercentilesOut = Field(default_factory=PercentilesOut)

class CountryStatsOut(BaseModel):
    country: str
    count: int = 0
    approved: int = 0
    rejected: int = 0
    approval_rate: float = 0.0

class GeographicResponse(BaseModel):
    countries: list[CountryStatsOut] = Field(default_factory=list)

class DropOffStepOut(BaseModel):
    from_step: str
    to_step: str
    continued: int = 0
    dropped: int = 0
    drop_rate: float = 0.0
    avg_time_in_step_hours: float = 0.0

class DropOffResponse(BaseModel):
    steps: list[DropOffStepOut] = Field(default_factory=list)

class AnalyticsSnapshotOut(BaseModel):
    period_start: int = 0
    period_end: int = 0
    total_applications: int = 0
    approved_count: int = 0
    rejected_count: int = 0
    pending_count: int = 0
    conversion_rate: float = 0.0
    avg_processing_hours: float = 0.0
    processing_time_distribution: PercentilesOut = Field(default_factory=PercentilesOut)
    funnel: list[FunnelStepOut] = Field(default_factory=list)
    rejection_reasons: dict[str, int] = Field(default_factory=dict)
    geographic_distribution: list[CountryStatsOut] = Field(default_factory=list)
    tier_breakdown: dict[str, dict[str, int]] = Field(default_factory=dict)

class DeltasOut(BaseModel):
    conversion_rate_delta: float = 0.0
    volume_delta: int = 0
    volume_delta_pct: float = 0.0
    approved_delta: int = 0
    rejected_delta: int = 0
    avg_processing_hours_delta: float = 0.0

class CompareResponse(BaseModel):
    current: AnalyticsSnapshotOut
    previous: AnalyticsSnapshotOut
    deltas: DeltasOut
```

### 3.6 Router Endpoints

Add to a new router `app/routers/kyc_analytics.py`:

<!-- NOTE: app/routers/kyc_analytics.py does not exist yet — new implementation required -->

```python
router = APIRouter(prefix="/v1/kyc/analytics", tags=["kyc-analytics"])

# All endpoints require admin session: use require_ui_session + manual role check
# (same pattern as app/routers/kyc_cases.py:950-953)
GET /funnel?from={ts}&to={ts}&country={cc}&tier={tier}
  -- KYC funnel with optional filters
  -- Response: { "funnel": [FunnelStep], "conversion_rate": float }

GET /snapshot?from={ts}&to={ts}&country={cc}&tier={tier}
  -- Full analytics snapshot
  -- Response: { "snapshot": AnalyticsSnapshot }

GET /trends?granularity={daily|weekly|monthly}&periods={N}
  -- Volume trends time series
  -- Response: { "trends": [{ period, started, submitted, approved, rejected }] }

GET /processing-times?from={ts}&to={ts}&bucket_hours={N}
  -- Processing time histogram
  -- Response: { "histogram": [{ bucket_label, count }], "percentiles": { p50, p75, p90, p99 } }

GET /rejection-reasons?from={ts}&to={ts}
  -- Rejection reason breakdown
  -- Response: { "reasons": { reason_code: count } }

GET /screening-hits?granularity={daily|weekly}&periods={N}
  -- Screening hit rate trends
  -- Response: { "trends": [{ period, total_screened, hits, hit_rate }] }

GET /geographic?from={ts}&to={ts}
  -- Geographic distribution
  -- Response: { "countries": [{ country, count, approved, rejected, approval_rate }] }

GET /compare?current_from={ts}&current_to={ts}&previous_from={ts}&previous_to={ts}
  -- Period comparison
  -- Response: { "current": Snapshot, "previous": Snapshot, "deltas": {...} }

GET /drop-off?from={ts}&to={ts}
  -- Drop-off analysis between funnel steps
  -- Response: { "steps": [{ from_step, to_step, continued, dropped, drop_rate }] }
```

Register in `app/main.py` (see existing KYC router registration at line 88, 406; background tasks registered via `add_event_handler("startup", ...)` at lines 375-379, 466-469):

```python
from app.routers.kyc_analytics import router as kyc_analytics_router
app.include_router(kyc_analytics_router)
```

### 3.7 API Request/Response Examples

**Get funnel data:**
```bash
curl "http://localhost:8000/v1/kyc/analytics/funnel?from=1748304000&to=1748476800&country=SE" \
  -H "Cookie: ui_session=sess_root; ui_csrf=csrf_root; ui_access_token=tok_root"

# Response 200:
{
  "funnel": [
    {"step": "started", "count": 15, "percentage": 100.0, "drop_off_count": 0, "drop_off_pct": 0.0},
    {"step": "docs_uploaded", "count": 12, "percentage": 80.0, "drop_off_count": 3, "drop_off_pct": 20.0},
    {"step": "submitted", "count": 11, "percentage": 73.3, "drop_off_count": 1, "drop_off_pct": 8.3},
    {"step": "under_review", "count": 11, "percentage": 73.3, "drop_off_count": 0, "drop_off_pct": 0.0},
    {"step": "approved", "count": 9, "percentage": 60.0, "drop_off_count": 2, "drop_off_pct": 18.2}
  ],
  "conversion_rate": 0.60
}
```

**Get volume trends:**
```bash
curl "http://localhost:8000/v1/kyc/analytics/trends?granularity=daily&periods=7" \
  -H "Cookie: ui_session=sess_root; ui_csrf=csrf_root; ui_access_token=tok_root"

# Response 200:
{
  "trends": [
    {"period": "2026-05-22", "started": 8, "submitted": 6, "approved": 4, "rejected": 1},
    {"period": "2026-05-23", "started": 12, "submitted": 9, "approved": 7, "rejected": 2},
    {"period": "2026-05-24", "started": 10, "submitted": 8, "approved": 6, "rejected": 1},
    {"period": "2026-05-25", "started": 15, "submitted": 11, "approved": 9, "rejected": 2},
    {"period": "2026-05-26", "started": 11, "submitted": 9, "approved": 7, "rejected": 1},
    {"period": "2026-05-27", "started": 14, "submitted": 10, "approved": 8, "rejected": 2},
    {"period": "2026-05-28", "started": 9, "submitted": 7, "approved": 5, "rejected": 1}
  ]
}
```

**Compare two periods:**
```bash
curl "http://localhost:8000/v1/kyc/analytics/compare?current_from=1748217600&current_to=1748476800&previous_from=1747612800&previous_to=1747872000" \
  -H "Cookie: ui_session=sess_root; ui_csrf=csrf_root; ui_access_token=tok_root"

# Response 200:
{
  "current": {
    "total_applications": 45,
    "approved_count": 28,
    "rejected_count": 7,
    "conversion_rate": 0.622,
    "avg_processing_hours": 6.3
  },
  "previous": {
    "total_applications": 38,
    "approved_count": 22,
    "rejected_count": 8,
    "conversion_rate": 0.579,
    "avg_processing_hours": 8.1
  },
  "deltas": {
    "conversion_rate_delta": 0.043,
    "volume_delta": 7,
    "volume_delta_pct": 18.4,
    "approved_delta": 6,
    "rejected_delta": -1,
    "avg_processing_hours_delta": -1.8
  }
}
```

### 3.8 Frontend: `frontend/src/pages/admin/KycAnalyticsDashboard.tsx`

**Route in `App.tsx`:**

```tsx
const KycAnalyticsDashboard = lazy(() => import("@/pages/admin/KycAnalyticsDashboard"));
<Route path="admin/kyc/analytics" element={<KycAnalyticsDashboard />} />
```

**Frontend Component Tree:**

```
KycAnalyticsDashboard
  +-- PageHeader ("KYC Analytics")
  +-- FilterBar
  |     +-- DateRangePicker (from / to date inputs)
  |     +-- CountrySelect (dropdown with country list)
  |     +-- TierSelect (dropdown: All / Tier 1 / Tier 2 / Tier 3)
  |     +-- CompareToggle (checkbox: "Compare with previous period")
  |
  +-- MetricCardsRow
  |     +-- ConversionRateCard (large % number with trend arrow)
  |     +-- TotalApplicationsCard
  |     +-- ApprovedCard (with count and rate)
  |     +-- AvgProcessingTimeCard (hours)
  |
  +-- FunnelSection
  |     +-- FunnelChart
  |     |     +-- For each step: colored bar with count and percentage
  |     |     +-- Drop-off indicators between bars (red arrows with %)
  |     +-- DropOffChart (optional detailed view)
  |
  +-- TrendsSection
  |     +-- VolumeChart
  |     |     +-- Line chart with daily/weekly volume
  |     |     +-- GranularityToggle (Daily / Weekly / Monthly)
  |     |     +-- Optional comparison overlay (dashed line for previous period)
  |
  +-- DistributionSection
  |     +-- ProcessingTimeHistogram
  |     |     +-- Bar chart with hour buckets
  |     |     +-- Percentile markers (p50, p75, p90, p99 vertical lines)
  |     +-- RejectionReasonsPie
  |           +-- Donut chart with top 10 reasons
  |           +-- Legend with counts
  |
  +-- GeographicSection
  |     +-- GeographicTable
  |           +-- DataTable (country, count, approved, rejected, approval_rate)
  |           +-- Sortable columns
  |           +-- Country flag emoji in first column
  |
  +-- PeriodComparisonSection (visible when compare toggle is ON)
        +-- PeriodComparisonCards
              +-- Side-by-side metric cards
              +-- Delta arrows (green up = improvement, red down = decline)
```

**TypeScript Props Interfaces:**

```typescript
interface FunnelChartProps {
  funnel: FunnelStep[];
  conversionRate: number;
}

interface VolumeChartProps {
  trends: TrendPoint[];
  comparisonTrends?: TrendPoint[];
  granularity: "daily" | "weekly" | "monthly";
}

interface ProcessingTimeHistogramProps {
  histogram: HistogramBucket[];
  percentiles: Percentiles;
}

interface RejectionReasonsPieProps {
  reasons: Record<string, number>;
}

interface GeographicTableProps {
  countries: CountryStats[];
}

interface PeriodComparisonCardsProps {
  current: AnalyticsSnapshot;
  previous: AnalyticsSnapshot;
  deltas: Deltas;
}
```

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

---

## 4. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|---|---|---|---|
| Non-admin accessing analytics | 403 | `admin_required` | "Admin access required to view KYC analytics." | Log in as admin |
| Invalid date range (from > to) | 400 | `invalid_date_range` | "Start date must be before end date." | Fix date range |
| Too many periods requested (>90) | 400 | `max_periods_exceeded` | "Maximum 90 periods allowed." | Reduce period count |
| Invalid granularity value | 422 | `validation_error` | Pydantic validation error | Use daily/weekly/monthly |
| No data for date range | 200 | -- | Returns empty arrays / zero counts | Widen date range |
| Pre-computation in progress | 200 | -- | Returns stale snapshot with `computed_at` timestamp | Data refreshes automatically |
| DDB scan timeout for large datasets | 504 | `analytics_timeout` | "Analytics computation timed out. Try a smaller date range." | Narrow date range |

---

## 5. Observability & Monitoring

### 5.1 Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `kyc_analytics_requests_total` | Counter | `endpoint`, `status` | Total API requests to analytics endpoints |
| `kyc_analytics_compute_duration_seconds` | Histogram | `type` (funnel/trends/snapshot) | Real-time computation duration |
| `kyc_analytics_precompute_duration_seconds` | Histogram | -- | Background precomputation duration |
| `kyc_analytics_precompute_errors_total` | Counter | -- | Precomputation failures |
| `kyc_analytics_cache_hit_rate` | Gauge | -- | Percentage of requests served from snapshots |
| `kyc_analytics_scan_items_total` | Counter | `endpoint` | DDB items scanned per request |

### 5.2 Log Events

| Event | Level | Fields | Description |
|---|---|---|---|
| `analytics.request` | INFO | `endpoint`, `filters`, `duration_ms` | Analytics API request |
| `analytics.precompute.started` | INFO | `date` | Background task started |
| `analytics.precompute.completed` | INFO | `date`, `duration_ms`, `items_scanned` | Background task completed |
| `analytics.precompute.failed` | ERROR | `date`, `error` | Background task failed |
| `analytics.scan.large` | WARN | `endpoint`, `items_scanned` | Scan exceeded warning threshold |

### 5.3 Alerting Rules

| Alert | Condition | Severity |
|---|---|---|
| Precomputation failure | `kyc_analytics_precompute_errors_total` > 3 in 24 hours | P3 |
| Analytics latency high | P95 of `kyc_analytics_compute_duration_seconds` > 10s for 15 min | P3 |
| Large scan detected | `kyc_analytics_scan_items_total` > 50000 | P3 (capacity planning) |

---

## 6. Rollout Plan

### 6.1 Feature Flags

| Flag | Default (Dev) | Default (Prod) | Description |
|---|---|---|---|
| `KYC_ANALYTICS_PRECOMPUTE_ENABLED` | `true` | `true` | Enable hourly snapshot precomputation |
| `KYC_ANALYTICS_CACHE_TTL` | `300` | `300` | Cache TTL in seconds for real-time queries |
| `KYC_ANALYTICS_MAX_SCAN_ITEMS` | `10000` | `10000` | Max items scanned per real-time computation |
| `KYC_ANALYTICS_TREND_MAX_PERIODS` | `90` | `90` | Max periods for trend queries |

### 6.2 Phased Deployment

| Phase | Scope | Duration | Success Criteria |
|---|---|---|---|
| Phase 1: Backend API | Deploy analytics service + endpoints | 2 days | API returns correct data, no errors |
| Phase 2: Precomputation | Enable background task | 1 day | Daily snapshots stored, data matches real-time |
| Phase 3: Frontend dashboard | Deploy React dashboard page | 2 days | All charts render, filters work |
| Phase 4: Optimization | Add caching, optimize scans | 1 day | P95 < 3 seconds |

### 6.3 Rollback Procedure

1. Disable `KYC_ANALYTICS_PRECOMPUTE_ENABLED` -- stops background task
2. Remove route from `App.tsx` or hide behind admin feature flag
3. Pre-computed snapshot items remain in DDB (harmless, can be cleaned up later)
4. No data migration needed -- analytics is read-only

---

## 7. Performance Considerations

### 7.1 Query Cost Analysis

| Operation | DDB Operations | Estimated Cost | Notes |
|---|---|---|---|
| Get pre-computed snapshot | 1 GetItem | 1 RCU | Fast path for cached data |
| Real-time funnel computation | N queries (1 per status) | N * ~10 RCU | Status GSI queries, filtered by date |
| Volume trends (30 days) | 30 GetItem (snapshots) | 30 RCU | One per daily snapshot |
| Processing time histogram | 1 scan with filter | ~100 RCU (depends on volume) | Scan approved/rejected cases |
| Geographic distribution | 1 scan with filter | ~100 RCU | Full scan, filter by country |
| Period comparison | 2 * snapshot computation | 2x single snapshot cost | Parallel computation |

### 7.2 Caching Strategy

| Data | Cache | TTL | Invalidation |
|---|---|---|---|
| Pre-computed daily snapshots | DynamoDB (persistent) | Permanent | Overwritten by next precomputation |
| Real-time analytics responses | In-memory (backend) | 5 minutes | Time-based expiry |
| Frontend chart data | React Query | 5 minutes | Manual refresh button |
| Filter selections | URL query params | Session | Navigation preserves filters |

### 7.3 Scan Optimization

- **Pre-computed snapshots**: Primary optimization -- avoid real-time scans for historical data
- **GSI queries over scans**: Use status-updated-index GSI for funnel computation (indexed by status)
- **Pagination**: All real-time scans paginate with `LastEvaluatedKey`, limit 1MB per page
- **Item limit**: `KYC_ANALYTICS_MAX_SCAN_ITEMS` (default 10000) caps expensive computations
- **Parallel queries**: Funnel computation queries each status in parallel (`asyncio.gather`)

---

## 8. E2E Test Plan

**Test file**: `frontend/e2e/kyc-analytics.spec.ts`
**Total**: ~22 tests across 4 sections (237-240)

### Section 237: Analytics API (7 tests)

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

test("237.7 Screening hits trend returns data", async ({ page }) => {
  // GET /v1/kyc/analytics/screening-hits?granularity=daily&periods=7
  // Expect trends array with period, total_screened, hits, hit_rate
});
```

### Section 238: Comparison & Geographic API (6 tests)

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

test("238.6 Invalid date range (from > to) returns 400", async ({ page }) => {
  // GET funnel with from=9999999 to=1000000
  // Expect 400
});
```

### Section 239: Analytics Dashboard UI (5 tests)

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

test("239.5 Granularity toggle changes trend chart", async ({ page }) => {
  // Click "Weekly" granularity button
  // Expect trends data to re-fetch with granularity=weekly
});
```

### Section 240: Pre-computation & Edge Cases (4 tests)

```typescript
test("240.1 Precomputed snapshot is returned for full-day queries", async ({ page }) => {
  // Trigger precomputation for a specific date
  // GET snapshot for that date -> computed_at timestamp present
});

test("240.2 Trends max periods enforced", async ({ page }) => {
  // GET trends with periods=100 -> 400
});

test("240.3 Analytics with zero cases returns valid empty structure", async ({ page }) => {
  // Query analytics for a date range with no cases
  // All arrays empty, all counts zero, conversion_rate=0
});

test("240.4 Multiple concurrent analytics queries return consistent data", async ({ page }) => {
  // Fire 5 parallel requests for different endpoints
  // All return successfully, no timeouts
});
```

---

## 9. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/kyc_analytics.py` | **New** | Funnel computation, trends, histograms, geographic, comparisons |
| `app/routers/kyc_analytics.py` | **New** | 9 analytics API endpoints |
| `app/main.py` | Modify | Register `kyc_analytics_router`, add precompute background task |
| `app/core/settings.py` | Modify | Add `kyc_analytics_precompute_enabled`, `kyc_analytics_cache_ttl` |
| `app/core/tables.py` | Modify | No new table needed (uses kyc_cases single-table) |
| `app/models.py` | Modify | Add analytics Pydantic models |
| `frontend/src/api/endpoints/kyc-analytics.ts` | **New** | API client functions for all analytics endpoints |
<!-- NOTE: frontend/src/api/endpoints/kyc-analytics.ts does not exist yet — new file required -->
| `frontend/src/api/types.ts` | Modify | Add `FunnelStep`, `TrendPoint`, `HistogramBucket`, `CountryStats`, etc. |
| `frontend/src/pages/admin/KycAnalyticsDashboard.tsx` | **New** | Main analytics dashboard page |
<!-- NOTE: frontend/src/pages/admin/KycAnalyticsDashboard.tsx does not exist yet — new file required -->
| `frontend/src/components/shared/FunnelChart.tsx` | **New** | Horizontal bar funnel chart |
| `frontend/src/components/shared/VolumeChart.tsx` | **New** | Time-series line chart |
| `frontend/src/components/shared/ProcessingTimeHistogram.tsx` | **New** | Histogram bar chart |
| `frontend/src/components/shared/RejectionReasonsPie.tsx` | **New** | Donut chart component |
| `frontend/src/components/shared/PeriodComparisonCards.tsx` | **New** | Comparison metric cards |
| `frontend/src/App.tsx` | Modify | Add `/admin/kyc/analytics` route |
| `frontend/e2e/kyc-analytics.spec.ts` | **New** | 22 E2E tests across sections 237-240 |

---

## 10. Configuration Reference

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `KYC_ANALYTICS_PRECOMPUTE_ENABLED` | `true` | Enable/disable hourly snapshot precomputation |
| `KYC_ANALYTICS_CACHE_TTL` | `300` | Cache TTL in seconds for real-time analytics queries |
| `KYC_ANALYTICS_MAX_SCAN_ITEMS` | `10000` | Maximum items to scan for real-time computation |
| `KYC_ANALYTICS_TREND_MAX_PERIODS` | `90` | Maximum periods for trend queries |

---

## Codebase References

| File | Lines | What was verified |
|------|-------|-------------------|
| `app/routers/kyc_cases.py` | 946-959 | `get_admin_kyc_metrics` endpoint confirmed; uses `require_ui_session` + role check |
| `app/routers/kyc_cases.py` | 48 | Router prefix `/v1/kyc/cases` confirmed |
| `app/routers/kyc_cases.py` | 950-953 | Admin auth pattern: `require_ui_session` + `normalize_role(user.role) not in {Role.ADMIN, Role.ROOT}` |
| `app/services/kyc_cases.py` | 701-714 | `get_metrics_snapshot` method confirmed; queries per-status counts |
| `app/services/kyc_cases.py` | 617-628 | `list_cases_by_status` queries `status-updated-index` GSI |
| `app/services/kyc_cases.py` | 48 | `_status_pk(status)` returns `STATUS#{status}` |
| `app/core/settings.py` | 1066-1067 | KYC GSI index names: `owner-updated-index`, `status-updated-index` |
| `scripts/local-ddb-init.py` | 91-96 | KYC cases table + 2 GSI definitions |
| `app/main.py` | 88, 406 | Existing KYC router registration |
| `app/main.py` | 375-379, 466-469 | Background task startup pattern via `add_event_handler("startup", ...)` |
| `app/auth/deps.py` | 126, 184 | `AuthenticatedUser` and `get_authenticated_user` confirmed |
| `frontend/src/pages/admin/ModerationBoardPage.tsx` | -- | Exists (301 lines) — admin dashboard pattern reference |
| `frontend/src/pages/admin/RateLimitDashboard.tsx` | -- | Exists (544 lines) — admin dashboard pattern reference |
| `frontend/src/pages/admin/AuditExportPage.tsx` | -- | Exists (168 lines) — admin dashboard pattern reference |
| `app/services/kyc_analytics.py` | -- | **Does not exist yet** — new implementation required |
| `app/routers/kyc_analytics.py` | -- | **Does not exist yet** — new implementation required |
| `frontend/src/pages/admin/KycAnalyticsDashboard.tsx` | -- | **Does not exist yet** — new implementation required |
| `frontend/src/api/endpoints/kyc-analytics.ts` | -- | **Does not exist yet** — new file required |
| `frontend/src/components/shared/FunnelChart.tsx` | -- | **Does not exist yet** — new component required |
| `frontend/src/components/shared/VolumeChart.tsx` | -- | **Does not exist yet** — new component required |
| `frontend/src/components/shared/ProcessingTimeHistogram.tsx` | -- | **Does not exist yet** — new component required |
| `frontend/src/components/shared/RejectionReasonsPie.tsx` | -- | **Does not exist yet** — new component required |
| `frontend/src/components/shared/PeriodComparisonCards.tsx` | -- | **Does not exist yet** — new component required |

---

## Testing Strategy

### Unit Tests (`tests/test_kyc_analytics.py`)
**Framework**: pytest + moto (DynamoDB/S3 mock)

| # | Test Function | What It Verifies |
|---|--------------|-----------------|
| 1 | `test_compute_funnel_counts_by_status` | Compute funnel counts by status |
| 2 | `test_compute_funnel_filtered_by_tier` | Compute funnel filtered by tier |
| 3 | `test_volume_trends_daily_granularity` | Volume trends daily granularity |
| 4 | `test_processing_time_histogram_buckets` | Processing time histogram buckets |
| 5 | `test_compare_periods_calculates_deltas` | Compare periods calculates deltas |
| 6 | `test_geographic_distribution_by_country` | Geographic distribution by country |
| 7 | `test_drop_off_analysis_between_steps` | Drop off analysis between steps |
| 8 | `test_precompute_daily_snapshot_stores` | Precompute daily snapshot stores |
| 9 | `test_snapshot_retrieval_from_cache` | Snapshot retrieval from cache |
| 10 | `test_empty_date_range_returns_zeros` | Empty date range returns zeros |

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/kyc-analytics.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~22 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

**Negative/Edge Tests**: 401 without auth, 403 for wrong role, 404 for missing resources, 409 for conflicts, 422 for validation errors.

### Test Data Requirements
- Test users: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- Session seeding: `python3 e2e_admin_session_setup.py` before test run

### CI/Pipeline
- Feature flags: `KYC_ANALYTICS_PRECOMPUTE_ENABLED=true`
- Tests run serially (single Playwright worker, `workers: 1`)
- Retry safety: 1 retry configured; tests use unique timestamps (`Date.now()`) for isolation
- Run: `cd frontend && npx playwright test e2e/<spec-file>`

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What It Provides | Hard/Soft |
|--------|-----------------|-----------|
| KYC-001 | Admin Review Dashboard for admin auth pattern | Hard |
| KYC-008 | Risk Scoring Engine for tier segmentation | Soft |
| KYC-012 | Compliance Reporting for data export | Soft |

### Depended On By

No downstream dependents identified.

### Merge Strategy
**Independent -- analytics endpoints are read-only and additive. New router at /v1/kyc/analytics with no overlap. Pre-computation background task is optional.**

### Merge Checklist
- [ ] Feature flags configured in `.env.local`: KYC_ANALYTICS_PRECOMPUTE_ENABLED=true
- [ ] Service file created/modified: `app/services/kyc_analytics.py`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/kyc-analytics.spec.ts`
- [ ] Unit tests pass: `.venv/bin/pytest tests/test_kyc_analytics.py`

# ADS-008: Ad Analytics Dashboard

**Ticket**: ADS-008
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 7-9 days
**Dependencies**: ADS-001 (Accounts), ADS-004 (Serving — impression data), ADS-007 (Billing — spend data) — all sibling tickets, not yet implemented
<!-- NOTE: All ADS dependencies are sibling tickets not yet in the codebase. Existing: creator_analytics.py, ad_impressions table, AnalyticsRollups table. -->

---

## 1. Overview & Motivation

### 1.1 Purpose

ADS-008 builds a comprehensive analytics dashboard for advertisers. It provides real-time and historical metrics across campaigns, creatives, targeting dimensions, surfaces, and time periods. The dashboard shows KPIs (impressions, clicks, CTR, conversions, spend, ROAS), time-series charts, and breakdowns with export capability.

This ticket also introduces pre-computed analytics rollups — a background process that aggregates raw impression data from the `ad_impressions` table into hourly/daily/weekly summaries stored in a rollup table for fast dashboard queries.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Advertiser | As an advertiser, I want to see my campaign performance at a glance. | Dashboard shows KPI cards: impressions, clicks, CTR, spend, CPA. |
| Advertiser | As an advertiser, I want to see performance over time. | Line chart showing daily impressions/clicks for the selected period. |
| Advertiser | As an advertiser, I want to compare this period to the previous period. | Toggle "Compare" shows overlay of current vs previous period lines. |
| Advertiser | As an advertiser, I want to break down performance by creative. | Table showing each creative's impressions, clicks, CTR, spend. |
| Advertiser | As an advertiser, I want to see which surfaces perform best. | Breakdown by newsfeed/broadcast/vod with metrics per surface. |
| Advertiser | As an advertiser, I want to export analytics as CSV. | "Export" button downloads CSV with selected metrics and date range. |
| Advertiser | As an advertiser, I want live counters for active campaigns. | Real-time impression/click counts that update without page refresh. |

### 1.3 Dashboard Layout

```
┌──────────────────────────────────────────────────────────────────┐
│  Ad Analytics Dashboard                    [Date Range ▼] [Export]│
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐  │
│  │Impressns│ │ Clicks  │ │  CTR    │ │ Spend   │ │  CPA    │  │
│  │ 142,531 │ │  3,214  │ │  2.25%  │ │ $712.65 │ │  $2.22  │  │
│  │ +12.3%  │ │  +8.7%  │ │  -0.3%  │ │ +15.1%  │ │  +1.2%  │  │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  Performance Over Time (line chart)                      │    │
│  │  ─── Impressions  ─── Clicks                            │    │
│  │  ···  (previous period comparison)                       │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────┐ ┌──────────────────────────────┐   │
│  │ By Creative (table)     │ │ By Surface (pie chart)       │   │
│  │ Creative A: 45K imp     │ │ [Newsfeed 52%]               │   │
│  │ Creative B: 32K imp     │ │ [Broadcast 28%]              │   │
│  │ Creative C: 18K imp     │ │ [VOD 20%]                    │   │
│  └─────────────────────────┘ └──────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. Current State Analysis

### 2.1 Ad Impressions Table

The `ad_impressions` table stores raw events with PK=`AD_IMP#{date}`, SK=`VIDEO#{video_id}#{user_id}#{ts}`. GSIs `ByVideoCreatedAt` and `ByCreatorCreatedAt` support video-level and creator-level queries. However, there is no campaign-level or creative-level aggregation — querying requires scanning all date partitions.

### 2.2 Creator Analytics (`app/services/creator_analytics.py`)

The existing creator analytics service provides earnings dashboards for creators. It aggregates billing ledger entries by type and time period. The ad analytics dashboard follows a similar pattern but for advertisers, aggregating impression/click/spend data.

### 2.3 Analytics Rollups Table

The `AnalyticsRollups` table (PK=`pk`, SK=`sk`, GSI `ByDateCreatedAt`) exists for creator analytics. Ad analytics rollups can use the same table with a different PK prefix, or a dedicated `ad_analytics_rollups` table for cleaner separation. This ticket uses a dedicated table to avoid contention.

### 2.4 Gaps

1. **No ad analytics rollup table** — no pre-computed aggregations for campaign metrics.
2. **No rollup computation** — no background process to aggregate impressions.
3. **No analytics API** — no endpoints for summary, time series, or breakdowns.
4. **No analytics dashboard** — no frontend visualizations.
5. **No CSV export** — no data export capability.
6. **No period comparison** — no "vs previous period" logic.
7. **No real-time counters** — no live updating metrics.

---

## 3. Technical Design

### 3.1 DynamoDB Table

#### `ad_analytics_rollups` Table

| PK | SK | Fields |
|----|----|--------|
| `CAMP#{campaign_id}` | `ROLLUP#{period}#{date}` | `campaign_id`, `account_id`, `period` (hourly/daily/weekly/monthly), `date` (ISO string), `impressions`, `clicks`, `skips`, `completes`, `spend_cents`, `revenue_cents`, `unique_users`, `by_creative` (map), `by_surface` (map), `by_targeting` (map), `computed_at` |

Period formats:
- hourly: `ROLLUP#hourly#2026-05-29T14`
- daily: `ROLLUP#daily#2026-05-29`
- weekly: `ROLLUP#weekly#2026-W22`
- monthly: `ROLLUP#monthly#2026-05`

**GSIs**:

| GSI Name | Partition Key | Sort Key | Purpose |
|----------|--------------|----------|---------|
| `ByAccountDate` | `account_id` (S) | `date` (S) | Account-level aggregation across campaigns |

**`scripts/local-ddb-init.py`**:
```python
TableDef(
    os.environ.get("DDB_AD_ANALYTICS_ROLLUPS", "AdAnalyticsRollups"),
    "pk",
    "sk",
    gsi=[
        {"index_name": "ByAccountDate", "partition_key": "account_id", "sort_key": "date"},
    ],
),
```

### 3.2 Backend Service

**File**: `app/services/ad_analytics.py`

```python
"""Ad analytics — pre-computed rollups, summary, time series, breakdowns."""

import csv
import io
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def get_summary(account_id: str, campaign_id: Optional[str] = None, days: int = 30) -> dict:
    """Get aggregated KPI summary for an account or campaign."""
    rollups = _fetch_daily_rollups(account_id, campaign_id, days)

    total_impressions = sum(r.get("impressions", 0) for r in rollups)
    total_clicks = sum(r.get("clicks", 0) for r in rollups)
    total_spend = sum(r.get("spend_cents", 0) for r in rollups)
    total_completes = sum(r.get("completes", 0) for r in rollups)
    total_skips = sum(r.get("skips", 0) for r in rollups)

    ctr = (total_clicks / total_impressions * 100) if total_impressions > 0 else 0.0
    cpa = (total_spend / total_clicks) if total_clicks > 0 else 0
    effective_cpm = (total_spend / total_impressions * 1000) if total_impressions > 0 else 0

    # Previous period comparison
    prev_rollups = _fetch_daily_rollups(account_id, campaign_id, days, offset_days=days)
    prev_impressions = sum(r.get("impressions", 0) for r in prev_rollups)
    prev_clicks = sum(r.get("clicks", 0) for r in prev_rollups)
    prev_spend = sum(r.get("spend_cents", 0) for r in prev_rollups)

    return {
        "impressions": total_impressions,
        "clicks": total_clicks,
        "ctr_pct": round(ctr, 2),
        "spend_cents": total_spend,
        "cpa_cents": cpa,
        "effective_cpm_cents": round(effective_cpm, 2),
        "completes": total_completes,
        "skips": total_skips,
        "completion_rate_pct": round(total_completes / max(1, total_impressions) * 100, 2),
        "previous_period": {
            "impressions": prev_impressions,
            "clicks": prev_clicks,
            "spend_cents": prev_spend,
        },
        "impressions_change_pct": _pct_change(prev_impressions, total_impressions),
        "clicks_change_pct": _pct_change(prev_clicks, total_clicks),
        "spend_change_pct": _pct_change(prev_spend, total_spend),
        "days": days,
    }


def get_timeseries(
    account_id: str, campaign_id: Optional[str] = None,
    days: int = 30, granularity: str = "daily",
) -> list[dict]:
    """Get time-series data points for charting."""
    rollups = _fetch_rollups(account_id, campaign_id, days, granularity)
    return [
        {
            "date": r.get("date", ""),
            "impressions": int(r.get("impressions", 0)),
            "clicks": int(r.get("clicks", 0)),
            "spend_cents": int(r.get("spend_cents", 0)),
            "completes": int(r.get("completes", 0)),
            "ctr_pct": round(int(r.get("clicks", 0)) / max(1, int(r.get("impressions", 1))) * 100, 2),
        }
        for r in rollups
    ]


def get_breakdown(
    account_id: str, campaign_id: Optional[str] = None,
    dimension: str = "creative", days: int = 30,
) -> list[dict]:
    """Get metrics broken down by a dimension (creative, surface, targeting)."""
    rollups = _fetch_daily_rollups(account_id, campaign_id, days)

    aggregated: Dict[str, Dict[str, int]] = {}
    dim_key = f"by_{dimension}"

    for r in rollups:
        dim_data = r.get(dim_key, {})
        if isinstance(dim_data, dict):
            for key, metrics in dim_data.items():
                if key not in aggregated:
                    aggregated[key] = {"impressions": 0, "clicks": 0, "spend_cents": 0}
                if isinstance(metrics, dict):
                    aggregated[key]["impressions"] += int(metrics.get("impressions", 0))
                    aggregated[key]["clicks"] += int(metrics.get("clicks", 0))
                    aggregated[key]["spend_cents"] += int(metrics.get("spend_cents", 0))

    result = []
    for key, metrics in aggregated.items():
        ctr = metrics["clicks"] / max(1, metrics["impressions"]) * 100
        result.append({
            "dimension_key": key,
            "dimension": dimension,
            **metrics,
            "ctr_pct": round(ctr, 2),
        })

    result.sort(key=lambda x: x["impressions"], reverse=True)
    return result


def export_csv(account_id: str, campaign_id: Optional[str], days: int = 30) -> str:
    """Export analytics data as CSV string."""
    timeseries = get_timeseries(account_id, campaign_id, days, "daily")

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["date", "impressions", "clicks", "ctr_pct", "spend_cents", "completes"])
    writer.writeheader()
    writer.writerows(timeseries)
    return output.getvalue()


def compute_hourly_rollup(campaign_id: str, account_id: str, hour: str) -> dict:
    """Compute rollup for a specific campaign and hour.

    hour format: "2026-05-29T14"
    Called by background rollup job.
    """
    date_str = hour[:10]  # "2026-05-29"

    # Query raw impressions for this hour
    # In a real system, this would scan ad_impressions by campaign.
    # In dev mode, return mock data from the billing ledger.
    from app.services.ad_billing import get_campaign_spending
    entries = get_campaign_spending(campaign_id, limit=1000)

    impressions = sum(1 for e in entries if e.get("entry_type") == "impression_charge")
    clicks = sum(1 for e in entries if e.get("entry_type") == "click_charge")
    spend = sum(int(e.get("amount_cents", 0)) for e in entries)

    rollup = {
        "pk": f"CAMP#{campaign_id}",
        "sk": f"ROLLUP#hourly#{hour}",
        "campaign_id": campaign_id,
        "account_id": account_id,
        "period": "hourly",
        "date": hour,
        "impressions": impressions,
        "clicks": clicks,
        "skips": 0,
        "completes": 0,
        "spend_cents": spend,
        "revenue_cents": int(spend * 0.7),  # 70% creator share
        "unique_users": 0,  # Would require distinct count
        "by_creative": {},
        "by_surface": {},
        "by_targeting": {},
        "computed_at": now_ts(),
    }

    T.ad_analytics_rollups.put_item(Item={k: v for k, v in rollup.items() if v is not None})
    return rollup


def _fetch_daily_rollups(account_id: str, campaign_id: Optional[str], days: int, offset_days: int = 0) -> list[dict]:
    now = datetime.now(timezone.utc) - timedelta(days=offset_days)
    start_date = (now - timedelta(days=days)).strftime("%Y-%m-%d")
    end_date = now.strftime("%Y-%m-%d")

    if campaign_id:
        resp = T.ad_analytics_rollups.query(
            KeyConditionExpression=Key("pk").eq(f"CAMP#{campaign_id}")
                & Key("sk").between(f"ROLLUP#daily#{start_date}", f"ROLLUP#daily#{end_date}z"),
        )
    else:
        resp = T.ad_analytics_rollups.query(
            IndexName="ByAccountDate",
            KeyConditionExpression=Key("account_id").eq(account_id)
                & Key("date").between(start_date, end_date + "z"),
            FilterExpression=Attr("period").eq("daily"),
        )
    return resp.get("Items", [])


def _fetch_rollups(account_id: str, campaign_id: Optional[str], days: int, granularity: str) -> list[dict]:
    now = datetime.now(timezone.utc)
    start_date = (now - timedelta(days=days)).strftime("%Y-%m-%d")
    end_date = now.strftime("%Y-%m-%d")
    prefix = f"ROLLUP#{granularity}#"

    if campaign_id:
        resp = T.ad_analytics_rollups.query(
            KeyConditionExpression=Key("pk").eq(f"CAMP#{campaign_id}")
                & Key("sk").between(f"{prefix}{start_date}", f"{prefix}{end_date}z"),
        )
    else:
        resp = T.ad_analytics_rollups.query(
            IndexName="ByAccountDate",
            KeyConditionExpression=Key("account_id").eq(account_id)
                & Key("date").between(start_date, end_date + "z"),
            FilterExpression=Attr("period").eq(granularity),
        )
    return resp.get("Items", [])


def _pct_change(old: int, new: int) -> float:
    if old == 0:
        return 100.0 if new > 0 else 0.0
    return round((new - old) / old * 100, 1)
```

### 3.3 Backend Router

**File**: `app/routers/ads.py` (extend)

```python
# ── Ad Analytics ──

@router.get("/analytics/summary")
def analytics_summary(account_id: str, campaign_id: Optional[str] = None, days: int = 30, ctx=Depends(require_ui_session)):
    _require_account_owner(account_id, ctx["user_sub"])
    return get_summary(account_id, campaign_id, days)

@router.get("/analytics/timeseries")
def analytics_timeseries(account_id: str, campaign_id: Optional[str] = None, days: int = 30, granularity: str = "daily", ctx=Depends(require_ui_session)):
    _require_account_owner(account_id, ctx["user_sub"])
    return get_timeseries(account_id, campaign_id, days, granularity)

@router.get("/analytics/breakdown")
def analytics_breakdown(account_id: str, campaign_id: Optional[str] = None, dimension: str = "creative", days: int = 30, ctx=Depends(require_ui_session)):
    _require_account_owner(account_id, ctx["user_sub"])
    return get_breakdown(account_id, campaign_id, dimension, days)

@router.get("/analytics/export")
def analytics_export(account_id: str, campaign_id: Optional[str] = None, days: int = 30, ctx=Depends(require_ui_session)):
    _require_account_owner(account_id, ctx["user_sub"])
    csv_data = export_csv(account_id, campaign_id, days)
    return Response(content=csv_data, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=ad_analytics.csv"})
```

### 3.4 Frontend Pages

**File**: `frontend/src/pages/ads/AdAnalyticsDashboard.tsx`

- Route: `/ads/analytics`
- Date range picker (Last 7 days / 30 days / 90 days / Custom)
- Campaign filter dropdown
- KPI cards row: Impressions, Clicks, CTR, Spend, CPA (with % change vs previous period)
- Time series line chart (Recharts or similar): impressions + clicks over time
- "Compare to previous period" toggle adds dotted overlay lines
- Breakdown tables: By Creative, By Surface, By Targeting Dimension (tabs)
- Export button: downloads CSV
- `data-testid="ad-analytics-dashboard"`

### 3.5 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface AdAnalyticsSummary {
  impressions: number;
  clicks: number;
  ctr_pct: number;
  spend_cents: number;
  cpa_cents: number;
  effective_cpm_cents: number;
  completes: number;
  skips: number;
  completion_rate_pct: number;
  previous_period: { impressions: number; clicks: number; spend_cents: number };
  impressions_change_pct: number;
  clicks_change_pct: number;
  spend_change_pct: number;
  days: number;
}

export interface AdTimeSeriesPoint {
  date: string;
  impressions: number;
  clicks: number;
  spend_cents: number;
  completes: number;
  ctr_pct: number;
}

export interface AdBreakdownEntry {
  dimension_key: string;
  dimension: string;
  impressions: number;
  clicks: number;
  spend_cents: number;
  ctr_pct: number;
}
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/ad_analytics.py` | Analytics aggregation, rollups, export |
| `frontend/src/pages/ads/AdAnalyticsDashboard.tsx` | Analytics dashboard with charts and KPIs |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/ads.py` | Add analytics endpoints (summary, timeseries, breakdown, export) |
| `app/core/settings.py` | Add `ad_analytics_rollups_table_name` |
| `app/core/tables.py` | Add `ad_analytics_rollups` table handle |
| `scripts/local-ddb-init.py` | Add `AdAnalyticsRollups` table definition |
| `frontend/src/api/types.ts` | Add analytics types |
| `frontend/src/api/endpoints/ads.ts` | Add analytics API functions |
| `frontend/src/App.tsx` | Add `/ads/analytics` route |

### 4.3 Step-by-Step Order

1. Add DDB table definition
2. Add settings + table handle
3. Implement `ad_analytics.py` service (summary, timeseries, breakdown, export)
4. Add rollup computation logic
5. Add analytics endpoints to router
6. Add frontend types + API endpoints
7. Build AdAnalyticsDashboard with charts
8. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/ads-analytics.spec.ts` — 18 tests across 5 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let accountId: string;
let campaignId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice (advertiser with active account + campaign)
  // Seed rollup data: write mock daily rollups for last 7 days
  // Seed with known values for deterministic assertions
});
```

### 5.3 Section 374: Summary API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 374.1 | Get analytics summary | GET `/ui/ads/analytics/summary?account_id=X&days=7`; 200; has impressions, clicks, ctr_pct |
| 374.2 | Summary includes previous period | Response has `previous_period` with impressions/clicks/spend |
| 374.3 | Summary includes change percentages | `impressions_change_pct`, `clicks_change_pct` present and numeric |
| 374.4 | Campaign-specific summary | GET with `campaign_id=Y`; metrics scoped to campaign |

### 5.4 Section 375: Time Series API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 375.1 | Get daily time series | GET `timeseries?days=7&granularity=daily`; 200; array of 7 data points |
| 375.2 | Each point has required fields | First point has `date`, `impressions`, `clicks`, `spend_cents`, `ctr_pct` |
| 375.3 | Hourly granularity | GET with `granularity=hourly`; data points have hour-level dates |
| 375.4 | Time series sorted by date ascending | Dates in response are in ascending order |

### 5.5 Section 376: Breakdown API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 376.1 | Breakdown by creative | GET `breakdown?dimension=creative`; 200; array with `dimension_key` per creative |
| 376.2 | Breakdown by surface | GET `breakdown?dimension=surface`; entries for newsfeed/broadcast/vod |
| 376.3 | Breakdown sorted by impressions | First entry has highest impressions |
| 376.4 | Breakdown includes CTR | Each entry has `ctr_pct` field |

### 5.6 Section 377: CSV Export API (2 tests)

| # | Test | Assertion |
|---|------|-----------|
| 377.1 | Export returns CSV | GET `export?days=7`; content-type=text/csv; body starts with header row |
| 377.2 | CSV contains expected columns | Header row includes date, impressions, clicks, ctr_pct, spend_cents |

### 5.7 Section 378: Analytics Dashboard UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 378.1 | Dashboard loads with KPI cards | Navigate to `/ads/analytics`; cards for "Impressions", "Clicks", "CTR", "Spend" visible |
| 378.2 | Date range selector works | Click "Last 7 days"; KPI values update |
| 378.3 | Time series chart renders | Chart container `[data-testid="analytics-chart"]` visible |
| 378.4 | Export button triggers download | Click "Export"; file download initiated (intercept download event) |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Account not found | 404 | "Account not found" |
| Invalid granularity | 400 | "Granularity must be hourly, daily, weekly, or monthly" |
| Invalid dimension | 400 | "Dimension must be creative, surface, or targeting" |
| No data for period | 200 | Returns zero-filled summary / empty time series |
| CSV export failure | 500 | Log error; return empty CSV with headers only |

---

## 7. Security Considerations

- Analytics data accessible only to account owner
- Rollup data pre-computed server-side; no raw impression access from client
- CSV export respects same ownership check as API queries
- No PII in analytics data (no user IDs, only aggregate counts)
- Rollup computation is idempotent (re-running for same period overwrites)

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| ADS-001 | Account + campaign hierarchy | Required |
| ADS-004 | Impression/click data | Required |
| ADS-007 | Spending data from billing | Required |

### 8.1 Downstream Dependents

None — ADS-008 is a terminal analytics consumer.

---

## 9. Architecture & Data Flow

```
Analytics Pipeline
──────────────────

  Ad Impression Event
  (from ADS-004 serving engine)
       │
       ▼
  ┌────────────────────────────────────┐
  │  ad_impressions table              │
  │  PK=AD_IMP#{date}                 │
  │  SK=VIDEO#{vid}#{user}#{ts}       │
  │  Raw event: creative_id, campaign, │
  │  surface, click, skip, complete    │
  └──────────┬─────────────────────────┘
             │
             ▼ (background rollup job, hourly)
  ┌────────────────────────────────────┐
  │  compute_hourly_rollup()           │
  │                                    │
  │  1. Scan raw impressions for hour  │
  │  2. Aggregate: impressions, clicks │
  │     skips, completes, spend        │
  │  3. Group by creative, surface     │
  │  4. Write rollup to DDB           │
  └──────────┬─────────────────────────┘
             │
             ▼
  ┌────────────────────────────────────┐
  │  ad_analytics_rollups table        │
  │  PK=CAMP#{campaign_id}            │
  │  SK=ROLLUP#{period}#{date}        │
  │                                    │
  │  Periods: hourly, daily,           │
  │           weekly, monthly          │
  └──────────┬─────────────────────────┘
             │
             ▼ (API request)
  ┌────────────────────────────────────┐
  │  Dashboard API Endpoints           │
  │                                    │
  │  GET /summary  → KPI cards         │
  │  GET /timeseries → line chart      │
  │  GET /breakdown → creative/surface │
  │  GET /export → CSV download        │
  └────────────────────────────────────┘

  Period Comparison Logic
  ───────────────────────
  Current: days [today-30 .. today]
  Previous: days [today-60 .. today-30]

  change_pct = (current - previous) / previous * 100
```

---

## 10. API Request/Response Examples

### 10.1 Analytics Summary

```bash
curl "http://localhost:8000/ui/ads/analytics/summary?account_id=adv_alice&days=7" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=jwt_tok"
```

**Response (200)**:
```json
{
  "impressions": 14253,
  "clicks": 321,
  "ctr_pct": 2.25,
  "spend_cents": 71265,
  "cpa_cents": 222,
  "effective_cpm_cents": 5000,
  "completes": 8500,
  "skips": 3200,
  "completion_rate_pct": 59.64,
  "previous_period": {
    "impressions": 12700,
    "clicks": 295,
    "spend_cents": 61900
  },
  "impressions_change_pct": 12.2,
  "clicks_change_pct": 8.8,
  "spend_change_pct": 15.1,
  "days": 7
}
```

### 10.2 Time Series

```bash
curl "http://localhost:8000/ui/ads/analytics/timeseries?account_id=adv_alice&days=7&granularity=daily" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=jwt_tok"
```

**Response (200)**:
```json
[
  {"date": "2026-05-22", "impressions": 1800, "clicks": 42, "spend_cents": 9000, "completes": 1100, "ctr_pct": 2.33},
  {"date": "2026-05-23", "impressions": 2100, "clicks": 48, "spend_cents": 10500, "completes": 1300, "ctr_pct": 2.29},
  {"date": "2026-05-24", "impressions": 1950, "clicks": 45, "spend_cents": 9750, "completes": 1200, "ctr_pct": 2.31}
]
```

### 10.3 CSV Export

```bash
curl "http://localhost:8000/ui/ads/analytics/export?account_id=adv_alice&days=7" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=jwt_tok"
```

**Response (200, Content-Type: text/csv)**:
```
date,impressions,clicks,ctr_pct,spend_cents,completes
2026-05-22,1800,42,2.33,9000,1100
2026-05-23,2100,48,2.29,10500,1300
```

---

## 11. Error Handling Matrix

| # | Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|----------------|-------------|------------|---------------------|-----------------|
| 1 | Account not found | 404 | `ACCOUNT_NOT_FOUND` | "Account not found." | Verify account_id |
| 2 | Not account owner | 403 | `NOT_ACCOUNT_OWNER` | "You do not own this account." | Use owning credentials |
| 3 | Invalid granularity | 400 | `INVALID_GRANULARITY` | "Granularity must be hourly, daily, weekly, or monthly." | Use valid value |
| 4 | Invalid dimension | 400 | `INVALID_DIMENSION` | "Dimension must be creative, surface, or targeting." | Use valid value |
| 5 | No data for period | 200 | -- | Returns zero-filled summary / empty array | Normal (no error) |
| 6 | CSV export failure | 500 | `EXPORT_FAILED` | "Export failed. Try again." | Retry request |
| 7 | Days out of range | 400 | `INVALID_DAYS` | "days must be between 1 and 365." | Use valid range |
| 8 | Rollup computation fails | -- | -- | Summary shows stale data (last successful rollup) | Background retry |

---

## 12. Observability

### 12.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `ad_analytics_summary_requests_total` | Counter | `account_id` | Summary endpoint calls |
| `ad_analytics_timeseries_requests_total` | Counter | `granularity` | Timeseries endpoint calls |
| `ad_analytics_breakdown_requests_total` | Counter | `dimension` | Breakdown endpoint calls |
| `ad_analytics_export_requests_total` | Counter | -- | CSV export downloads |
| `ad_analytics_rollup_computed_total` | Counter | `period` | Rollup computations completed |
| `ad_analytics_rollup_duration_ms` | Histogram | `period` | Time to compute a rollup |
| `ad_analytics_query_duration_ms` | Histogram | `endpoint` | API query latency |

### 12.2 Log Events

| Event | Level | Fields |
|-------|-------|--------|
| `analytics_summary_served` | INFO | account_id, campaign_id, days |
| `analytics_timeseries_served` | INFO | account_id, granularity, data_points |
| `analytics_breakdown_served` | INFO | account_id, dimension, entries |
| `analytics_export_served` | INFO | account_id, days, rows |
| `rollup_computed` | INFO | campaign_id, period, date, impressions, clicks |
| `rollup_failed` | ERROR | campaign_id, period, error |

### 12.3 Alerting Rules

| Alert | Condition | Severity |
|-------|-----------|----------|
| Rollup job missed | No rollup for any campaign in 2 hours | P2 |
| Analytics API errors | >5% error rate on analytics endpoints in 15 min | P3 |
| Summary query slow | p99 > 3s for summary endpoint | P3 |

---

## 13. Rollout Plan

### 13.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `AD_ANALYTICS_ENABLED` | `false` | Enable analytics endpoints |
| `AD_ANALYTICS_ROLLUP_ENABLED` | `false` | Enable background rollup computation |

### 13.2 Phased Deployment

| Phase | Scope | Duration | Details |
|-------|-------|----------|---------|
| Phase 1: Rollup Pipeline | Internal | Week 1 | Deploy rollup table, computation job. Populate historical rollups. Verify data accuracy. |
| Phase 2: API Endpoints | Advertisers | Week 2 | `AD_ANALYTICS_ENABLED=true`. Summary, timeseries, breakdown, export live. |
| Phase 3: Dashboard UI | All users | Week 3 | AdAnalyticsDashboard deployed. Charts, date range picker, CSV export button. |

---

## 14. Performance Considerations

### 14.1 Latency Targets

| Endpoint | Target p50 | Target p99 |
|----------|-----------|-----------|
| GET /summary | 80ms | 400ms |
| GET /timeseries | 60ms | 300ms |
| GET /breakdown | 80ms | 400ms |
| GET /export (CSV) | 200ms | 1000ms |
| compute_hourly_rollup() | 500ms | 3000ms |

### 14.2 Caching Strategy

| Data | Cache | staleTime | Invalidation |
|------|-------|-----------|-------------|
| Summary (7d) | React Query | 60_000ms | On date range change |
| Summary (30d) | React Query | 120_000ms | On date range change |
| Time series | React Query | 60_000ms | On granularity/date change |
| Breakdown | React Query | 60_000ms | On dimension change |
| Rollup data (server) | DDB (pre-computed) | Hourly recompute | On rollup job completion |

### 14.3 Rollup Scalability

Rollups are computed per-campaign per-hour. For 100 campaigns, the hourly job executes 100 computations. Each computation queries the raw impressions table for that campaign's events. To avoid hot partitions, the `ad_impressions` table uses date-based PK partitioning (`AD_IMP#{date}`). Daily/weekly/monthly rollups are aggregated from hourly rollups, not from raw data.

---

## 15. Expanded E2E Tests

### 15.1 Section 379: Input Validation (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 379.1 | Invalid granularity rejected | GET timeseries with granularity=minutely; 400 |
| 379.2 | Invalid dimension rejected | GET breakdown with dimension=country; 400 |
| 379.3 | Days=0 rejected | GET summary with days=0; 400 |
| 379.4 | Days=400 rejected | GET summary with days=400; 400 |

### 15.2 Section 380: Authorization Boundary (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 380.1 | Non-owner cannot view summary | Bob GET Alice's account summary; 403 |
| 380.2 | Non-owner cannot export CSV | Bob GET Alice's export; 403 |
| 380.3 | Non-owner cannot view breakdown | Bob GET Alice's breakdown; 403 |

### 15.3 Section 381: Edge Cases (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 381.1 | Empty account returns zero-filled summary | New account with no data; GET summary; impressions=0, ctr_pct=0 |
| 381.2 | Time series with no data returns empty array | GET timeseries for new campaign; 200; [] |
| 381.3 | CSV export with no data returns headers only | GET export for new campaign; header row present, no data rows |
| 381.4 | Breakdown with single creative | One creative only; breakdown returns single entry |

### 15.4 Section 382: Period Comparison (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 382.1 | Previous period data returned | GET summary with days=7; previous_period has impressions >= 0 |
| 382.2 | Change percentages computed | impressions_change_pct is a number (not NaN) |
| 382.3 | Campaign-scoped comparison | GET summary with campaign_id; metrics scoped to that campaign only |

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/services/creator_analytics.py` | — | Existing creator analytics service (reference pattern for ad analytics) |
| `app/core/settings.py` | 1334 | Existing `analytics_rollups_table_name` (AnalyticsRollups — for creator analytics, not ad analytics) |
| `app/services/ad_placement.py` | 222 | Existing `record_ad_impression` — source of impression data |
| `app/core/tables.py` | 93, 217 | Existing `ad_impressions` table handle |
| `app/services/ad_analytics.py` | — | Does not exist yet — new implementation required |
| `ad_analytics_rollups` DDB table | — | Does not exist yet — separate from existing AnalyticsRollups table |

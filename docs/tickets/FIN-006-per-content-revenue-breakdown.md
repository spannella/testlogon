# FIN-006: Per-Content Revenue Breakdown

**Ticket**: FIN-006
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

FIN-006 adds a dedicated per-content revenue breakdown view so creators can see exactly how much each piece of content (video, post, broadcast) has earned, broken down by revenue source (tips, unlocks, subscriptions, ad revenue). Today, `creator_analytics.py:_get_content_revenue_breakdown` scans the billing ledger filtering by `meta.content_id`, but there is no aggregated content revenue index, no time-range filtering, no CSV export, and the data is not surfaced in a standalone revenue table on the frontend. This ticket fills those gaps.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to see earnings for each video I published. | Revenue table lists each video with total earnings and per-source breakdown. |
| Creator | As a creator, I want to sort content by revenue to find my top earners. | Table is sortable by total revenue, tips, unlocks, date published. |
| Creator | As a creator, I want to filter revenue data by date range. | Date picker filters results; only revenue earned within the range is shown. |
| Creator | As a creator, I want to export my content revenue data as CSV. | "Export CSV" button downloads a CSV file with all visible rows. |
| Creator | As a creator, I want to see revenue from ad impressions attributed to my content. | Ad revenue column shows ad earnings per content item. |
| System | Revenue attribution must be correct even when content earns from multiple sources simultaneously. | Sum of per-source amounts equals total for every content item. |
| Creator | As a creator, I want to click a content item to see its detailed analytics. | Row click navigates to the existing content detail analytics view. |

### 1.3 Why This Is Needed

Creators currently see aggregate revenue on the analytics dashboard (`get_overview`) and can drill into a single content item (`get_content_detail`), but there is no intermediate view that lists all content with revenue side-by-side. Without this, creators cannot answer "which of my 50 videos earns the most?" without clicking into each one individually. The billing ledger already stores `content_id` in the `meta` field of ledger entries, so the data exists -- it just needs aggregation and a proper UI.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Content revenue breakdown | `app/services/creator_analytics.py:714-756` | `_get_content_revenue_breakdown` scans billing ledger for a single content_id |
| Top content | `app/services/creator_analytics.py:424-476` | `get_top_content` aggregates from daily rollups; returns top N by views or revenue |
| Content detail | `app/services/creator_analytics.py:565-638` | `get_content_detail` returns per-content views, revenue, engagement |
| Billing ledger | `app/services/billing_shared.py:217-248` | `new_ledger_entry` writes entries with optional `meta` dict |
| Tip ledger | `app/services/tip_ledger.py` | Writes tip credits with `meta.content_id` for content tips |
| Creator earnings | `app/services/creator_earnings.py:47-114` | `get_earnings_summary` aggregates credits by category |
| Analytics router | `app/routers/creator_analytics.py:196-220` | `analytics_top_content` endpoint |
| Analytics models | `app/models.py:2614-2748` | `ContentAnalyticsOut`, `AnalyticsTopContentItem` |

### 2.2 Billing Ledger Meta Pattern

From `app/services/tip_ledger.py` and `app/services/billing_shared.py`, ledger entries include a `meta` dict:

```python
new_ledger_entry(
    T.billing, f"USER#{creator_id}",
    amount_cents=500,
    entry_type="credit",
    reason="Tip on content",
    meta={
        "content_id": "vid_abc123",
        "content_type": "vod",
        "tipper_user_id": "bob@test.local",
    },
)
```

The `content_id` and `content_type` fields in `meta` are the attribution link. Not all ledger entries have `content_id` (e.g., direct tips to a user, subscription credits without content attribution).

### 2.3 Gaps

1. **No aggregated content revenue index** -- `_get_content_revenue_breakdown` scans the full billing ledger for each content item, which is O(N) per item.
2. **No time-range filtering** on content revenue -- the existing function returns all-time totals only.
3. **No CSV export** endpoint or frontend functionality.
4. **No ad revenue attribution** -- ad billing entries do not consistently include `content_id` in `meta`.
5. **No frontend table view** listing all content with revenue columns.
6. **Subscription revenue is not attributed to specific content** -- subscription credits are lump-sum, not split by content engagement.

---

## 3. Technical Design

### 3.1 Architecture & Data Flow

```
                           ┌──────────────────────────────────┐
                           │        Content Revenue Flow      │
                           └──────────────────────────────────┘

  Billing Event (tip/unlock/purchase/ad)
       │
       │  meta.content_id present?
       │
       ├── YES ──▶ upsert_content_revenue_rollup()
       │              │
       │              ├── Write daily row:  PK=CREV#{user_id}  SK={date}#{content_id}
       │              │     tips_cents += N, unlocks_cents += N, etc.
       │              │
       │              └── Write summary row: PK=CREVTOTAL#{user_id}  SK={content_id}
       │                    total_cents += N, GSI4SK = total_cents (for sort queries)
       │
       └── NO ───▶ Normal single-credit (no content attribution)

  Frontend Request Flow:
       │
  GET /ui/analytics/content-revenue
       │
       ├── sort_by=total_cents ──▶ Query ByUserRevenue GSI (sorted by total)
       │
       ├── from_date/to_date ─────▶ Query base table PK=CREV#{user_id}
       │                              SK between {from_date} and {to_date}~
       │                              Aggregate in-memory by content_id
       │
       └── content_type filter ───▶ FilterExpression on content_type

  GET /ui/analytics/content-revenue/export
       │
       └── Same query ──▶ csv.StringIO ──▶ StreamingResponse (text/csv)
```

### 3.2 Data Model

#### 3.2.1 Content Revenue Rollup (Analytics Rollups Table)

Extend the existing analytics rollup table with content-level revenue entries.

**PK**: `CREV#{user_id}`, **SK**: `{date}#{content_id}`

| Field | Type | Description |
|-------|------|-------------|
| `content_id` | S | Video or post ID |
| `content_type` | S | `"vod"`, `"post"`, `"broadcast"` |
| `date` | S | `YYYY-MM-DD` |
| `tips_cents` | N | Tip revenue for this content on this date |
| `unlocks_cents` | N | Unlock revenue |
| `subscriptions_cents` | N | Attributed subscription revenue |
| `ads_cents` | N | Ad impression revenue |
| `vod_cents` | N | VOD purchase revenue |
| `total_cents` | N | Sum of all sources |
| `title` | S | Cached content title for display |
| `published_at` | N | Content publish timestamp |
| `updated_at` | N | Last rollup update timestamp |

#### 3.2.2 GSI for User-Date Queries

**GSI name**: `ByUserDate`
**PK**: `CREV#{user_id}`, **SK**: `{date}#{content_id}`

This is the base table key, so no additional GSI needed for date-range queries (use `begins_with` on SK for date prefix filtering).

#### 3.2.3 GSI for User-Revenue Ranking

**GSI name**: `ByUserRevenue`
**PK**: `CREVTOTAL#{user_id}`, **SK**: `total_cents` (N)

For sorting by total revenue. This requires a separate summary row per content item:

**PK**: `CREVTOTAL#{user_id}`, **SK**: `{content_id}`

| Field | Type | Description |
|-------|------|-------------|
| `total_cents` | N | All-time total revenue |
| `tips_cents` | N | All-time tips |
| `unlocks_cents` | N | All-time unlocks |
| `subscriptions_cents` | N | All-time attributed subscriptions |
| `ads_cents` | N | All-time ad revenue |
| `vod_cents` | N | All-time VOD purchases |
| `content_type` | S | `"vod"`, `"post"`, `"broadcast"` |
| `title` | S | Cached content title |
| `published_at` | N | Content publish timestamp |
| `GSI4PK` | S | `CREVTOTAL#{user_id}` |
| `GSI4SK` | N | `total_cents` (for sort-by-revenue queries) |

### 3.3 Detailed DynamoDB Access Patterns

| # | Access Pattern | Table/GSI | PK | SK/Condition | Example |
|---|---------------|-----------|-----|-------------|---------|
| 1 | List content revenue (all-time, sorted by total) | ByUserRevenue GSI | `CREVTOTAL#{user_id}` | `ScanIndexForward=False` | Top earners first |
| 2 | List content revenue filtered by date range | Base table | `CREV#{user_id}` | `SK between '2026-05-01' and '2026-05-31~'` | May 2026 revenue |
| 3 | Get single content revenue detail (all-time) | Base table | `CREVTOTAL#{user_id}` | `SK = {content_id}` | Summary for one item |
| 4 | Get single content daily time series | Base table | `CREV#{user_id}` | `SK begins_with '{date_prefix}' and contains content_id` | Daily breakdown |
| 5 | Upsert daily rollup for content | Base table | `CREV#{user_id}` | `SK = {date}#{content_id}` | Atomic ADD on source field |
| 6 | Upsert all-time summary | Base table | `CREVTOTAL#{user_id}` | `SK = {content_id}` | Atomic ADD on total_cents |
| 7 | Filter by content_type | Any query above | — | `FilterExpression: content_type = :ct` | Only videos |
| 8 | Rebuild from ledger (scan) | Billing table | `USER#{user_id}` | `SK begins_with 'LEDGER#'` | Full ledger scan for backfill |

### 3.4 Backend Service

**New file**: `app/services/content_revenue.py` (~300 lines)

```python
"""Per-content revenue breakdown service (FIN-006)."""

from __future__ import annotations
import csv
import io
import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def get_content_revenue_list(
    user_id: str,
    *,
    from_date: str = "",
    to_date: str = "",
    sort_by: str = "total_cents",
    sort_order: str = "desc",
    content_type: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List all content items with revenue breakdown for a creator."""
    ...


def get_content_revenue_detail(
    user_id: str,
    content_id: str,
    from_date: str = "",
    to_date: str = "",
) -> Optional[Dict[str, Any]]:
    """Get revenue breakdown for a single content item with time series."""
    ...


def export_content_revenue_csv(
    user_id: str,
    from_date: str = "",
    to_date: str = "",
) -> str:
    """Generate CSV string of all content revenue for the date range."""
    ...


def upsert_content_revenue_rollup(
    user_id: str,
    content_id: str,
    content_type: str,
    date_str: str,
    source: str,
    amount_cents: int,
    title: str = "",
) -> None:
    """Increment revenue for a content item on a given date.

    Called by billing hooks (tip, unlock, purchase) when content_id is present in meta.
    """
    ...


def rebuild_content_revenue_from_ledger(user_id: str) -> int:
    """Scan billing ledger and rebuild all content revenue rollups.

    Returns count of entries processed. Used for backfill/repair.
    """
    ...
```

### 3.5 Backend Router

**Extend**: `app/routers/creator_analytics.py`

### 3.6 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/analytics/content-revenue` | `require_ui_session` | List all content items with revenue breakdown |
| `GET` | `/ui/analytics/content-revenue/{content_id}` | `require_ui_session` | Revenue detail for a single content item |
| `GET` | `/ui/analytics/content-revenue/export` | `require_ui_session` | Download CSV of content revenue |
| `POST` | `/internal/analytics/content-revenue/rebuild` | Internal | Backfill content revenue rollups from ledger |

### 3.7 API Request/Response Examples

**GET /ui/analytics/content-revenue**

Request:
```
GET /ui/analytics/content-revenue?from_date=2026-05-01&to_date=2026-05-31&sort_by=total_cents&sort_order=desc&content_type=vod&limit=20
Cookie: ui_session=...; ui_access_token=...; ui_csrf=...
```

Response (200):
```json
{
  "items": [
    {
      "content_id": "vid_abc123",
      "content_type": "vod",
      "title": "How to Build a SaaS",
      "published_at": 1716000000,
      "tips_cents": 12500,
      "unlocks_cents": 8000,
      "subscriptions_cents": 3200,
      "ads_cents": 1500,
      "vod_cents": 25000,
      "total_cents": 50200
    },
    {
      "content_id": "vid_def456",
      "content_type": "vod",
      "title": "React Hooks Deep Dive",
      "published_at": 1716100000,
      "tips_cents": 8000,
      "unlocks_cents": 0,
      "subscriptions_cents": 1500,
      "ads_cents": 900,
      "vod_cents": 15000,
      "total_cents": 25400
    }
  ],
  "total_items": 2,
  "total_revenue_cents": 75600,
  "next_cursor": null,
  "currency": "USD"
}
```

**GET /ui/analytics/content-revenue/{content_id}**

Request:
```
GET /ui/analytics/content-revenue/vid_abc123?from_date=2026-05-01&to_date=2026-05-07
Cookie: ui_session=...; ui_access_token=...; ui_csrf=...
```

Response (200):
```json
{
  "content_id": "vid_abc123",
  "content_type": "vod",
  "title": "How to Build a SaaS",
  "published_at": 1716000000,
  "tips_cents": 5000,
  "unlocks_cents": 3000,
  "subscriptions_cents": 1000,
  "ads_cents": 600,
  "vod_cents": 10000,
  "total_cents": 19600,
  "time_series": [
    {"date": "2026-05-01", "tips_cents": 1000, "unlocks_cents": 500, "ads_cents": 100, "vod_cents": 2000, "total_cents": 3600},
    {"date": "2026-05-02", "tips_cents": 800, "unlocks_cents": 400, "ads_cents": 80, "vod_cents": 1500, "total_cents": 2780},
    {"date": "2026-05-03", "tips_cents": 600, "unlocks_cents": 300, "ads_cents": 70, "vod_cents": 1200, "total_cents": 2170}
  ],
  "currency": "USD"
}
```

**GET /ui/analytics/content-revenue/export**

Request:
```
GET /ui/analytics/content-revenue/export?from_date=2026-05-01&to_date=2026-05-31
Cookie: ui_session=...; ui_access_token=...; ui_csrf=...
```

Response (200):
```
Content-Type: text/csv
Content-Disposition: attachment; filename="content-revenue-2026-05-31.csv"

Content ID,Type,Title,Published Date,Tips ($),Unlocks ($),Subscriptions ($),Ads ($),VOD ($),Total ($)
vid_abc123,vod,How to Build a SaaS,2026-05-18,125.00,80.00,32.00,15.00,250.00,502.00
vid_def456,vod,React Hooks Deep Dive,2026-05-19,80.00,0.00,15.00,9.00,150.00,254.00
```

**POST /internal/analytics/content-revenue/rebuild**

Request:
```
POST /internal/analytics/content-revenue/rebuild
Content-Type: application/json
X-Internal-Token: ...

{"user_id": "alice@test.local"}
```

Response (200):
```json
{
  "user_id": "alice@test.local",
  "entries_processed": 347,
  "content_items_found": 12,
  "completed_at": 1716500000
}
```

### 3.8 Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | Error Message | Recovery Action |
|---|----------|-------------|------------|---------------|-----------------|
| 1 | Not authenticated | 401 | `UNAUTHORIZED` | "Authentication required" | Redirect to login |
| 2 | Invalid date format in from_date/to_date | 422 | `VALIDATION_ERROR` | "Date must be YYYY-MM-DD format" | Fix date parameter |
| 3 | from_date > to_date | 422 | `VALIDATION_ERROR` | "from_date must be before to_date" | Swap dates |
| 4 | Invalid sort_by field | 422 | `VALIDATION_ERROR` | "sort_by must be one of: total_cents, tips_cents, unlocks_cents, published_at" | Use valid field |
| 5 | Invalid content_type filter | 422 | `VALIDATION_ERROR` | "content_type must be vod, post, or broadcast" | Use valid type |
| 6 | Content ID not found | 404 | `NOT_FOUND` | "Content revenue record not found" | Verify content_id |
| 7 | Content belongs to another user | 404 | `NOT_FOUND` | "Content revenue record not found" | Same 404 to prevent enumeration |
| 8 | Invalid cursor format | 400 | `BAD_REQUEST` | "Invalid pagination cursor" | Start from first page |
| 9 | CSV export too many rows (>10000) | 400 | `EXPORT_LIMIT` | "Export limited to 10,000 rows; narrow your date range" | Apply date filter |
| 10 | Rebuild in progress | 409 | `CONFLICT` | "Rebuild already in progress for this user" | Wait and retry |
| 11 | DynamoDB throttling | 503 | `SERVICE_UNAVAILABLE` | "Temporary service error, please retry" | Exponential backoff |
| 12 | Date range exceeds 1 year | 422 | `VALIDATION_ERROR` | "Date range cannot exceed 365 days" | Narrow range |

### 3.9 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Per-Content Revenue Breakdown (FIN-006) --

class ContentRevenueItem(BaseModel):
    content_id: str
    content_type: str  # "vod" | "post" | "broadcast"
    title: str = ""
    published_at: int = 0
    tips_cents: int = 0
    unlocks_cents: int = 0
    subscriptions_cents: int = 0
    ads_cents: int = 0
    vod_cents: int = 0
    total_cents: int = 0

class ContentRevenueListOut(BaseModel):
    items: List[ContentRevenueItem] = Field(default_factory=list)
    total_items: int = 0
    total_revenue_cents: int = 0
    next_cursor: Optional[str] = None
    currency: str = "USD"

class ContentRevenueDetailOut(BaseModel):
    content_id: str
    content_type: str
    title: str = ""
    published_at: int = 0
    tips_cents: int = 0
    unlocks_cents: int = 0
    subscriptions_cents: int = 0
    ads_cents: int = 0
    vod_cents: int = 0
    total_cents: int = 0
    time_series: List[Dict[str, Any]] = Field(default_factory=list)
    currency: str = "USD"
```

### 3.10 Integration with Billing Hooks

When a ledger credit entry is written with `meta.content_id`, the billing hook calls `upsert_content_revenue_rollup`. Integration points:

1. **Tip credits** (`app/services/tip_ledger.py`): After writing tip credit, call `upsert_content_revenue_rollup(creator_id, content_id, content_type, date, "tips", amount)`.
2. **Unlock credits** (`app/routers/messaging.py` unlock path): After unlock credit, call with source `"unlocks"`.
3. **VOD purchase credits**: After purchase credit, call with source `"vod"`.
4. **Ad revenue** (ADS tickets): After ad impression credit, call with source `"ads"`.

### 3.11 Frontend Component Tree

```
ContentRevenuePage
├── Card: "Content Revenue"
│   ├── Toolbar
│   │   ├── DateRangePicker (from/to)
│   │   ├── ContentTypeFilter (All / Videos / Posts / Broadcasts)
│   │   ├── SortSelector (Revenue / Tips / Date Published)
│   │   └── Button: "Export CSV" (Download icon)
│   ├── Summary Row
│   │   ├── Total Revenue badge
│   │   ├── Content Count badge
│   │   └── Avg Revenue per Content badge
│   └── DataTable
│       ├── Column: Title (clickable → content detail)
│       ├── Column: Type (badge: VOD / Post / Broadcast)
│       ├── Column: Published
│       ├── Column: Tips
│       ├── Column: Unlocks
│       ├── Column: Subscriptions
│       ├── Column: Ads
│       └── Column: Total (bold, sortable)
└── Pagination controls
```

**TypeScript Props Interfaces**:

```typescript
// frontend/src/api/types.ts
export interface ContentRevenueItem {
  content_id: string;
  content_type: "vod" | "post" | "broadcast";
  title: string;
  published_at: number;
  tips_cents: number;
  unlocks_cents: number;
  subscriptions_cents: number;
  ads_cents: number;
  vod_cents: number;
  total_cents: number;
}

export interface ContentRevenueListResponse {
  items: ContentRevenueItem[];
  total_items: number;
  total_revenue_cents: number;
  next_cursor: string | null;
  currency: string;
}

export interface ContentRevenueDetailResponse {
  content_id: string;
  content_type: string;
  title: string;
  published_at: number;
  tips_cents: number;
  unlocks_cents: number;
  subscriptions_cents: number;
  ads_cents: number;
  vod_cents: number;
  total_cents: number;
  time_series: Array<{
    date: string;
    tips_cents: number;
    unlocks_cents: number;
    ads_cents: number;
    vod_cents: number;
    total_cents: number;
  }>;
  currency: string;
}

// ContentRevenuePage props
interface ContentRevenuePageProps {}

// ContentRevenueToolbar props
interface ContentRevenueToolbarProps {
  fromDate: string;
  toDate: string;
  onDateChange: (from: string, to: string) => void;
  contentType: string | null;
  onContentTypeChange: (type: string | null) => void;
  sortBy: string;
  onSortChange: (field: string) => void;
  onExport: () => void;
  isExporting: boolean;
}

// ContentRevenueSummary props
interface ContentRevenueSummaryProps {
  totalRevenueCents: number;
  contentCount: number;
  currency: string;
}
```

### 3.12 Frontend Components

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/analytics/ContentRevenuePage.tsx` | Content revenue table with filters | ~350 |
| `frontend/src/api/endpoints/content-revenue.ts` | API wrappers | ~40 |

### 3.13 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/content_revenue.py` | Content revenue aggregation service | ~300 |
| `frontend/src/pages/analytics/ContentRevenuePage.tsx` | Revenue table UI | ~350 |
| `frontend/src/api/endpoints/content-revenue.ts` | API wrappers | ~40 |
| `frontend/e2e/fin-content-revenue.spec.ts` | E2E tests | ~500 |

### 3.14 Files to Modify

| File | Change |
|------|--------|
| `app/routers/creator_analytics.py` | Add content-revenue endpoints |
| `app/models.py` | Add ContentRevenueItem, ContentRevenueListOut, ContentRevenueDetailOut |
| `app/services/tip_ledger.py` | Call `upsert_content_revenue_rollup` after writing tip credit with content_id |
| `scripts/local-ddb-init.py` | Add content revenue rollup table or extend analytics rollups table |
| `frontend/src/api/types.ts` | Add TypeScript interfaces |
| `frontend/src/App.tsx` | Add `/analytics/content-revenue` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add link under Analytics group |

---

## 4. CSV Export Format

### 4.1 Columns

```
Content ID, Type, Title, Published Date, Tips ($), Unlocks ($), Subscriptions ($), Ads ($), VOD ($), Total ($)
```

### 4.2 Implementation

The `export_content_revenue_csv` function uses Python's `csv.StringIO` writer. The router endpoint returns a `StreamingResponse` with `Content-Type: text/csv` and `Content-Disposition: attachment; filename="content-revenue-{date}.csv"`.

### 4.3 Limits

Maximum 10,000 rows per export. If the creator has more content items, the export includes the top 10,000 by total revenue with a note row at the end.

---

## 5. Pydantic Model Definitions

```python
# -- Full Pydantic models for FIN-006 --

from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

class ContentRevenueItem(BaseModel):
    """Single content item with per-source revenue breakdown."""
    content_id: str
    content_type: str = Field(
        ..., pattern="^(vod|post|broadcast)$",
        description="Type of content"
    )
    title: str = Field(default="", max_length=500)
    published_at: int = Field(default=0, ge=0)
    tips_cents: int = Field(default=0, ge=0)
    unlocks_cents: int = Field(default=0, ge=0)
    subscriptions_cents: int = Field(default=0, ge=0)
    ads_cents: int = Field(default=0, ge=0)
    vod_cents: int = Field(default=0, ge=0)
    total_cents: int = Field(default=0, ge=0)

    class Config:
        json_schema_extra = {
            "example": {
                "content_id": "vid_abc123",
                "content_type": "vod",
                "title": "How to Build a SaaS",
                "published_at": 1716000000,
                "tips_cents": 12500,
                "unlocks_cents": 8000,
                "subscriptions_cents": 3200,
                "ads_cents": 1500,
                "vod_cents": 25000,
                "total_cents": 50200,
            }
        }


class ContentRevenueListOut(BaseModel):
    """Paginated list of content items with revenue."""
    items: List[ContentRevenueItem] = Field(default_factory=list)
    total_items: int = Field(default=0, ge=0)
    total_revenue_cents: int = Field(default=0, ge=0)
    next_cursor: Optional[str] = None
    currency: str = Field(default="USD", pattern="^[A-Z]{3}$")


class ContentRevenueTimeSeriesPoint(BaseModel):
    """Single day in the revenue time series."""
    date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    tips_cents: int = 0
    unlocks_cents: int = 0
    subscriptions_cents: int = 0
    ads_cents: int = 0
    vod_cents: int = 0
    total_cents: int = 0


class ContentRevenueDetailOut(BaseModel):
    """Revenue breakdown for a single content item with time series."""
    content_id: str
    content_type: str
    title: str = ""
    published_at: int = 0
    tips_cents: int = 0
    unlocks_cents: int = 0
    subscriptions_cents: int = 0
    ads_cents: int = 0
    vod_cents: int = 0
    total_cents: int = 0
    time_series: List[ContentRevenueTimeSeriesPoint] = Field(default_factory=list)
    currency: str = "USD"


class RebuildContentRevenueIn(BaseModel):
    """Request to rebuild content revenue rollups from ledger."""
    user_id: str = Field(..., min_length=1)


class RebuildContentRevenueOut(BaseModel):
    """Result of a content revenue rebuild."""
    user_id: str
    entries_processed: int = 0
    content_items_found: int = 0
    completed_at: int = 0
```

---

## 6. Observability

### 6.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `content_revenue_list_latency_ms` | Histogram | `sort_by`, `has_date_filter` | Time to serve list request |
| `content_revenue_detail_latency_ms` | Histogram | `has_date_filter` | Time to serve detail request |
| `content_revenue_export_latency_ms` | Histogram | — | Time to generate CSV export |
| `content_revenue_export_rows` | Histogram | — | Number of rows in CSV export |
| `content_revenue_rollup_upsert_latency_ms` | Histogram | `source` | Time to upsert a rollup record |
| `content_revenue_rebuild_duration_s` | Gauge | — | Duration of last rebuild job |
| `content_revenue_rebuild_entries` | Counter | — | Entries processed across rebuilds |
| `content_revenue_errors_total` | Counter | `endpoint`, `error_type` | Error count by endpoint |

### 6.2 Logging

```python
# content_revenue.py
logger.info("content_revenue.list user=%s items=%d total=%d from=%s to=%s",
            user_id, len(items), total_revenue, from_date, to_date)
logger.info("content_revenue.detail user=%s content=%s total=%d",
            user_id, content_id, total_cents)
logger.info("content_revenue.export user=%s rows=%d from=%s to=%s",
            user_id, row_count, from_date, to_date)
logger.info("content_revenue.rollup_upsert user=%s content=%s source=%s amount=%d",
            user_id, content_id, source, amount_cents)
logger.warning("content_revenue.export_limit_hit user=%s requested=%d max=10000",
               user_id, requested_rows)
logger.error("content_revenue.rebuild_failed user=%s error=%s",
             user_id, str(e))
```

### 6.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Export latency high | `content_revenue_export_latency_ms p99 > 10000` | Warning | Investigate DDB throughput |
| Rollup upsert failures | `content_revenue_errors_total{endpoint="rollup"} > 10/min` | Critical | Check DDB capacity, billing hook errors |
| Rebuild taking too long | `content_revenue_rebuild_duration_s > 300` | Warning | May need pagination or throttle |
| Export error rate | `content_revenue_errors_total{endpoint="export"} / requests > 5%` | Warning | Check S3 or memory issues |

---

## 7. Rollout Plan

### 7.1 Feature Flag

```python
# app/core/settings.py
content_revenue_enabled: bool = os.environ.get("CONTENT_REVENUE_ENABLED", "true").lower() == "true"

# In router:
@router.get("/ui/analytics/content-revenue")
async def list_content_revenue(...):
    if not S.content_revenue_enabled:
        raise HTTPException(404, "Feature not available")
    ...
```

### 7.2 Phased Rollout

| Phase | Scope | Duration | Gate |
|-------|-------|----------|------|
| 1 - Backend only | Rollup upserts on billing hooks + rebuild endpoint | 2 days | Feature flag OFF for frontend |
| 2 - Internal testing | Enable API endpoints for admin users only | 2 days | Role check in middleware |
| 3 - Limited rollout | Enable for 10% of creators (by user_id hash) | 3 days | Gradual percentage ramp |
| 4 - GA | Enable for all creators + frontend route | Ongoing | Feature flag ON |

### 7.3 Rollback Plan

1. Set `CONTENT_REVENUE_ENABLED=false` -- disables all endpoints immediately.
2. Remove billing hook calls (revert tip_ledger.py, messaging.py changes) -- stops new rollup writes.
3. Rollup data in DDB is inert and can remain; rebuild will re-aggregate if re-enabled.

---

## 8. Performance Considerations

### 8.1 Latency Targets

| Endpoint | Target p50 | Target p99 | Strategy |
|----------|-----------|-----------|----------|
| GET content-revenue (list) | < 200ms | < 500ms | GSI query with Limit; no scan |
| GET content-revenue/{id} (detail) | < 150ms | < 400ms | Single PK query + date range |
| GET content-revenue/export | < 3s | < 10s | Streaming CSV; paginated DDB reads |
| POST rollup upsert | < 50ms | < 150ms | Single DDB UpdateItem (atomic ADD) |

### 8.2 Caching Strategy

- **No cache for list/detail**: Data changes on every billing event; stale data is unacceptable for financial views.
- **Client-side React Query cache**: `staleTime: 30_000` (30 seconds) -- prevents duplicate fetches during tab switches.
- **CSV export**: No server-side caching. Each export generates fresh data.

### 8.3 Pagination

- Default page size: 50 items.
- Maximum page size: 200 items.
- Cursor-based pagination using DDB `LastEvaluatedKey` encoded via `app/core/cursor.py`.
- Date-range queries paginate through DDB pages (up to 4 pages per request, 1MB each).

### 8.4 Memory Management

- CSV export streams rows via `csv.writer(StringIO)` and flushes to `StreamingResponse` in chunks of 100 rows.
- Date-range aggregation uses `defaultdict(lambda: defaultdict(int))` for in-memory grouping; bounded by content count (typically < 1000 per creator).

---

## 9. E2E Test Plan

**File**: `frontend/e2e/fin-content-revenue.spec.ts`

### Section 559: Content Revenue List API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 559.1 | Seed tip on video content and list revenue | POST tip with content_id; GET content-revenue; video appears with tips_cents > 0 |
| 559.2 | Seed unlock revenue and verify attribution | POST unlock with content_id; GET content-revenue; unlocks_cents > 0 for that content |
| 559.3 | Filter by date range excludes out-of-range revenue | Seed revenue on two dates; GET with from/to filtering one date; only that date's revenue included |
| 559.4 | Filter by content type returns only matching items | Seed video and post revenue; GET with content_type=vod; only videos returned |
| 559.5 | Sort by total_cents descending returns highest first | Seed multiple items with different amounts; GET with sort_by=total_cents; first item has highest total |

### Section 560: Content Revenue Detail API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 560.1 | Get revenue detail for a specific content item | GET content-revenue/{id}; returns tips_cents, unlocks_cents, total_cents |
| 560.2 | Detail includes time series when date range spans multiple days | Seed revenue on 2 dates; GET detail with range; time_series has 2 entries |
| 560.3 | Returns 404 for non-existent content | GET content-revenue/fake_id; 404 |
| 560.4 | Cannot view another creator's content revenue | Alice requests Bob's content_id; 403 or empty result |

### Section 561: CSV Export API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 561.1 | Export CSV returns valid CSV with headers | GET export; Content-Type is text/csv; first row has expected headers |
| 561.2 | CSV rows match list API data | Compare CSV row values with GET list response amounts |
| 561.3 | Export respects date range filter | GET export with date range; CSV only contains matching data |

### Section 562: Content Revenue UI (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 562.1 | Content Revenue page loads with table | Navigate to /analytics/content-revenue; table with columns visible |
| 562.2 | Table rows show revenue breakdown | At least one row with Tips and Total columns populated |
| 562.3 | Sort by Total column reorders rows | Click Total header; first row has highest total |
| 562.4 | Export CSV button triggers download | Click "Export CSV"; download initiated (intercept network response) |

### Section 563: Edge Cases & Negative Tests (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 563.1 | Empty result for creator with no content | GET content-revenue; items = [], total_items = 0 |
| 563.2 | Invalid date format returns 422 | GET with from_date=not-a-date; 422 |
| 563.3 | from_date after to_date returns 422 | GET with from_date=2026-12-01&to_date=2026-01-01; 422 |
| 563.4 | Invalid sort_by field returns 422 | GET with sort_by=invalid_field; 422 |
| 563.5 | Pagination cursor returns next page | Seed 60 items; GET with limit=50; next_cursor present; GET with cursor returns remaining |
| 563.6 | Revenue sum invariant holds | For every item in response: tips + unlocks + subscriptions + ads + vod = total |

### Section 564: Rollup & Rebuild API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 564.1 | Multiple tips on same content accumulate | Send 3 tips on one video; GET detail; tips_cents = sum of all 3 |
| 564.2 | Mixed sources on same content tracked separately | Send tip + unlock on same video; GET detail; both fields > 0 |
| 564.3 | Rebuild from ledger matches original rollups | Clear rollup data; POST rebuild; GET list matches pre-rebuild data |

**Total E2E tests: 25**

---

## 10. Security Considerations

### 10.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| GET content-revenue | `require_ui_session` | Returns only caller's own content revenue |
| GET content-revenue/{id} | `require_ui_session` | Validates caller owns the content item |
| GET content-revenue/export | `require_ui_session` | Exports only caller's own data |
| POST rebuild (internal) | Internal middleware | Admin/system only |

### 10.2 Data Isolation

- All queries are scoped to `CREV#{user_id}` or `CREVTOTAL#{user_id}`, ensuring creators can only see their own content revenue.
- Content ownership is validated by checking `owner_user_id` on the content metadata record.

### 10.3 Rate Limiting

- CSV export: max 10 requests per hour per user (prevent abuse).
- Rebuild: max 1 concurrent rebuild per user.

---

## 11. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/billing_shared.py` | Exists | Ledger entries with `meta.content_id` |
| `app/services/creator_analytics.py` | Exists | `_get_content_revenue_breakdown` pattern, `_resolve_content_details` |
| `app/services/tip_ledger.py` | Exists | Tip credit entries with content attribution |
| `app/routers/creator_analytics.py` | Exists | Router to extend with new endpoints |
| ANALYTICS-002 | Exists | Per-content detail view (navigation target from revenue table) |

---

## 12. Acceptance Criteria

1. Creator can view a table of all their content items with per-source revenue breakdown.
2. Table is sortable by total revenue, tips, unlocks, and publish date.
3. Date range filter restricts revenue to the selected period.
4. Content type filter shows only videos, posts, or broadcasts.
5. CSV export downloads a valid file matching the displayed data.
6. Revenue attribution is correct: sum of per-source amounts equals total for each item.
7. Creators cannot view other creators' content revenue.
8. All 25 E2E tests pass.

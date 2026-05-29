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

### 3.1 Data Model

#### 3.1.1 Content Revenue Rollup (Analytics Rollups Table)

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

#### 3.1.2 GSI for User-Date Queries

**GSI name**: `ByUserDate`
**PK**: `CREV#{user_id}`, **SK**: `{date}#{content_id}`

This is the base table key, so no additional GSI needed for date-range queries (use `begins_with` on SK for date prefix filtering).

#### 3.1.3 GSI for User-Revenue Ranking

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

### 3.2 Backend Service

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

### 3.3 Backend Router

**Extend**: `app/routers/creator_analytics.py`

### 3.4 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/analytics/content-revenue` | `require_ui_session` | List all content items with revenue breakdown |
| `GET` | `/ui/analytics/content-revenue/{content_id}` | `require_ui_session` | Revenue detail for a single content item |
| `GET` | `/ui/analytics/content-revenue/export` | `require_ui_session` | Download CSV of content revenue |
| `POST` | `/internal/analytics/content-revenue/rebuild` | Internal | Backfill content revenue rollups from ledger |

### 3.5 Request/Response Models

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

### 3.6 Integration with Billing Hooks

When a ledger credit entry is written with `meta.content_id`, the billing hook calls `upsert_content_revenue_rollup`. Integration points:

1. **Tip credits** (`app/services/tip_ledger.py`): After writing tip credit, call `upsert_content_revenue_rollup(creator_id, content_id, content_type, date, "tips", amount)`.
2. **Unlock credits** (`app/routers/messaging.py` unlock path): After unlock credit, call with source `"unlocks"`.
3. **VOD purchase credits**: After purchase credit, call with source `"vod"`.
4. **Ad revenue** (ADS tickets): After ad impression credit, call with source `"ads"`.

### 3.7 Frontend Components

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/analytics/ContentRevenuePage.tsx` | Content revenue table with filters | ~350 |
| `frontend/src/api/endpoints/content-revenue.ts` | API wrappers | ~40 |

**Component tree for ContentRevenuePage**:

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

### 3.8 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/content_revenue.py` | Content revenue aggregation service | ~300 |
| `frontend/src/pages/analytics/ContentRevenuePage.tsx` | Revenue table UI | ~350 |
| `frontend/src/api/endpoints/content-revenue.ts` | API wrappers | ~40 |
| `frontend/e2e/fin-content-revenue.spec.ts` | E2E tests | ~400 |

### 3.9 Files to Modify

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

## 5. E2E Test Plan

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

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| GET content-revenue | `require_ui_session` | Returns only caller's own content revenue |
| GET content-revenue/{id} | `require_ui_session` | Validates caller owns the content item |
| GET content-revenue/export | `require_ui_session` | Exports only caller's own data |
| POST rebuild (internal) | Internal middleware | Admin/system only |

### 6.2 Data Isolation

- All queries are scoped to `CREV#{user_id}` or `CREVTOTAL#{user_id}`, ensuring creators can only see their own content revenue.
- Content ownership is validated by checking `owner_user_id` on the content metadata record.

### 6.3 Rate Limiting

- CSV export: max 10 requests per hour per user (prevent abuse).
- Rebuild: max 1 concurrent rebuild per user.

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/billing_shared.py` | Exists | Ledger entries with `meta.content_id` |
| `app/services/creator_analytics.py` | Exists | `_get_content_revenue_breakdown` pattern, `_resolve_content_details` |
| `app/services/tip_ledger.py` | Exists | Tip credit entries with content attribution |
| `app/routers/creator_analytics.py` | Exists | Router to extend with new endpoints |
| ANALYTICS-002 | Exists | Per-content detail view (navigation target from revenue table) |

---

## 8. Acceptance Criteria

1. Creator can view a table of all their content items with per-source revenue breakdown.
2. Table is sortable by total revenue, tips, unlocks, and publish date.
3. Date range filter restricts revenue to the selected period.
4. Content type filter shows only videos, posts, or broadcasts.
5. CSV export downloads a valid file matching the displayed data.
6. Revenue attribution is correct: sum of per-source amounts equals total for each item.
7. Creators cannot view other creators' content revenue.
8. All 16 E2E tests pass.

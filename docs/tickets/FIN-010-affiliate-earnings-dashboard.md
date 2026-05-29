# FIN-010: Affiliate Earnings Dashboard

**Ticket**: FIN-010
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

FIN-010 builds a comprehensive affiliate earnings dashboard on top of the existing affiliate link infrastructure. The backend (`app/services/affiliate_links.py`, 364 lines) supports link creation, click tracking, and conversion recording, and DynamoDB tables exist (AffiliateLinks, AffiliateClicks). The frontend (`frontend/src/pages/affiliates/AffiliateDashboard.tsx`, 204 lines) shows a basic list of affiliate links with create/delete functionality, but has no performance analytics, no earnings breakdown, no time-series charts, and no click-through analytics. This ticket fills those gaps.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to see all my affiliate links with performance stats. | Dashboard lists links with clicks, conversions, conversion rate, and earnings. |
| Creator | As a creator, I want to see earnings broken down by status (pending, approved, paid). | Earnings cards show pending, approved, and paid amounts separately. |
| Creator | As a creator, I want to see click-through analytics over time. | Time-series chart shows clicks per day/week for selected link or all links. |
| Creator | As a creator, I want to create affiliate links with custom tracking codes. | Create dialog supports custom code input with validation. |
| Creator | As a creator, I want to see the commission rate for each link. | Commission percentage displayed on each link card. |
| Creator | As a creator, I want to see which products perform best. | Product performance table sorted by conversions or earnings. |
| Creator | As a creator, I want to copy affiliate links to clipboard. | Copy button on each link; toast confirmation. |
| Admin | As an admin, I want to see platform-wide affiliate stats. | Admin panel shows total clicks, conversions, commissions across all creators. |

### 1.3 Why This Is Needed

The affiliate system backend is feature-complete: links are created, clicks are tracked with device/geo classification, conversions are recorded with commission calculations, and stats are aggregated per link. But the frontend is a minimal list view with no analytics. Creators cannot see which links are performing, which products convert best, or how their affiliate earnings trend over time. Without this dashboard, the affiliate program is effectively invisible to creators.

---

## 2. Current State Analysis

### 2.1 Existing Backend

| Function | Location | Status |
|----------|----------|--------|
| `create_affiliate_link` | `app/services/affiliate_links.py:63` | Complete -- creates link with commission, tracking code, GSI keys |
| `get_link` | `app/services/affiliate_links.py:135` | Complete -- by link_id |
| `get_link_by_code` | `app/services/affiliate_links.py:141` | Complete -- by tracking code via GSI |
| `list_creator_links` | `app/services/affiliate_links.py:152` | Complete -- by creator via ByAffiliate GSI |
| `delete_link` | `app/services/affiliate_links.py:162` | Complete -- soft delete (status=revoked) |
| `record_click` | `app/services/affiliate_links.py:190` | Complete -- records click with device/UA classification |
| `record_conversion` | `app/services/affiliate_links.py:272` | Complete -- records conversion with commission calculation |
| `get_link_stats` | `app/services/affiliate_links.py:336` | Complete -- click_count, unique_click_count, conversion_count, revenue_cents, commission_earned_cents |

### 2.2 Existing Router Endpoints

| Method | Path | Auth | Status |
|--------|------|------|--------|
| `POST` | `/ui/affiliates/links` | `require_ui_session` | Complete |
| `GET` | `/ui/affiliates/links` | `require_ui_session` | Complete |
| `GET` | `/ui/affiliates/links/{id}` | `require_ui_session` | Complete |
| `DELETE` | `/ui/affiliates/links/{id}` | `require_ui_session` | Complete |
| `GET` | `/ui/affiliates/links/{id}/stats` | `require_ui_session` | Complete |
| `POST` | `/ui/affiliates/links/{id}/conversions` | Internal | Complete |
| `GET` | `/r/{code}` | Public | Redirect to destination with tracking |

### 2.3 Existing Frontend (Stub)

The current `AffiliateDashboard.tsx` (204 lines) includes:
- Basic list of affiliate links (name, code, clicks, earnings)
- Create link dialog (target type, target ID, commission %, custom code)
- Delete link button
- Copy link button

### 2.4 Gaps

1. **No earnings breakdown** by status (pending, approved, paid).
2. **No time-series click analytics** -- no chart showing clicks over time.
3. **No conversion rate display** -- conversion_count / click_count not calculated.
4. **No product performance ranking** -- no way to compare which products convert best.
5. **No summary cards** -- no aggregate totals (total clicks, total earnings, etc.).
6. **No link detail view** -- clicking a link does not show detailed stats.
7. **No admin aggregate view** -- no platform-wide affiliate stats.
8. **No click analytics endpoint** -- need time-series click data from AffiliateClicks table.

### 2.5 New Backend Endpoints Needed

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/affiliates/summary` | `require_ui_session` | Creator's aggregate affiliate stats |
| `GET` | `/ui/affiliates/links/{id}/clicks` | `require_ui_session` | Time-series click data for a link |
| `GET` | `/ui/affiliates/earnings` | `require_ui_session` | Earnings breakdown (pending/approved/paid) |
| `GET` | `/ui/affiliates/top-products` | `require_ui_session` | Top products by conversions/earnings |
| `GET` | `/ui/admin/affiliates/stats` | `require_admin_session` | Platform-wide affiliate stats |

---

## 3. Technical Design

### 3.1 Backend Service Extension

**Extend**: `app/services/affiliate_links.py` (~200 additional lines)

```python
# -- Affiliate Earnings Dashboard (FIN-010) --

def get_affiliate_summary(creator_id: str) -> Dict[str, Any]:
    """Get aggregate stats for all of a creator's affiliate links.

    Returns: {
        total_links, active_links,
        total_clicks, total_unique_clicks,
        total_conversions, overall_conversion_rate,
        total_revenue_cents, total_commission_cents
    }
    """
    ...


def get_link_click_timeseries(
    link_id: str,
    creator_id: str,
    from_date: str,
    to_date: str,
    granularity: str = "day",
) -> List[Dict[str, Any]]:
    """Get click time-series for a specific link.

    Queries AffiliateClicks table by link_id, groups by date.
    Returns: [{date, clicks, unique_clicks}]
    """
    ...


def get_earnings_breakdown(creator_id: str) -> Dict[str, Any]:
    """Get earnings broken down by status.

    Scans conversion records for the creator's links.
    Returns: {pending_cents, approved_cents, paid_cents, total_cents}
    """
    ...


def get_top_products(
    creator_id: str,
    sort_by: str = "conversions",
    limit: int = 10,
) -> List[Dict[str, Any]]:
    """Get top products by conversions or earnings across all creator links.

    Groups by target_id, aggregates clicks/conversions/earnings.
    Returns: [{target_id, target_name, target_type, clicks, conversions, earnings_cents, commission_cents}]
    """
    ...


def get_platform_affiliate_stats() -> Dict[str, Any]:
    """Admin: platform-wide affiliate statistics.

    Returns: {total_links, total_clicks, total_conversions, total_commission_cents}
    """
    ...
```

### 3.2 Router Extension

**Extend**: `app/routers/affiliate_links.py` (~80 additional lines)

### 3.3 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Affiliate Earnings Dashboard (FIN-010) --

class AffiliateSummaryOut(BaseModel):
    total_links: int = 0
    active_links: int = 0
    total_clicks: int = 0
    total_unique_clicks: int = 0
    total_conversions: int = 0
    overall_conversion_rate: float = 0.0
    total_revenue_cents: int = 0
    total_commission_cents: int = 0

class AffiliateClickTimeSeriesItem(BaseModel):
    date: str
    clicks: int = 0
    unique_clicks: int = 0

class AffiliateClickTimeSeriesOut(BaseModel):
    link_id: str
    items: List[AffiliateClickTimeSeriesItem] = Field(default_factory=list)

class AffiliateEarningsBreakdownOut(BaseModel):
    pending_cents: int = 0
    approved_cents: int = 0
    paid_cents: int = 0
    total_cents: int = 0
    currency: str = "USD"

class AffiliateTopProductItem(BaseModel):
    target_id: str
    target_name: str = ""
    target_type: str = ""
    clicks: int = 0
    conversions: int = 0
    conversion_rate: float = 0.0
    earnings_cents: int = 0
    commission_cents: int = 0

class AffiliateTopProductsOut(BaseModel):
    items: List[AffiliateTopProductItem] = Field(default_factory=list)

class AffiliatePlatformStatsOut(BaseModel):
    total_links: int = 0
    total_clicks: int = 0
    total_conversions: int = 0
    total_commission_cents: int = 0
```

### 3.4 Frontend Components

**Rewrite**: `frontend/src/pages/affiliates/AffiliateDashboard.tsx` (~600 lines, replacing 204)

**Component tree**:

```
AffiliateDashboard
├── SummaryCards (4-card grid)
│   ├── Card: "Total Clicks" (MousePointerClick icon)
│   ├── Card: "Conversions" (ShoppingCart icon)
│   ├── Card: "Conversion Rate" (Percent icon)
│   └── Card: "Total Earnings" (DollarSign icon)
├── Tabs
│   ├── Tab: "My Links"
│   │   ├── LinkTable
│   │   │   ├── Column: Name (link text)
│   │   │   ├── Column: Tracking Code (monospace, Copy button)
│   │   │   ├── Column: Product
│   │   │   ├── Column: Commission (%)
│   │   │   ├── Column: Clicks
│   │   │   ├── Column: Conversions
│   │   │   ├── Column: Conv. Rate (%)
│   │   │   ├── Column: Earnings ($)
│   │   │   ├── Column: Status (badge)
│   │   │   └── Column: Actions (Stats / Delete)
│   │   ├── CreateLinkDialog
│   │   │   ├── Target Type selector
│   │   │   ├── Target ID / Product search
│   │   │   ├── Commission % input
│   │   │   ├── Custom Code input (optional)
│   │   │   └── Button: "Create Link"
│   │   └── Button: "Create Affiliate Link" (Plus icon)
│   ├── Tab: "Analytics"
│   │   ├── LinkSelector (dropdown to pick a link or "All Links")
│   │   ├── DateRangePicker
│   │   ├── ClickChart (line chart: clicks over time)
│   │   │   ├── Line: Total Clicks
│   │   │   └── Line: Unique Clicks
│   │   └── ConversionChart (bar chart: conversions over time)
│   ├── Tab: "Earnings"
│   │   ├── EarningsCards (3-card)
│   │   │   ├── Card: "Pending" (yellow)
│   │   │   ├── Card: "Approved" (blue)
│   │   │   └── Card: "Paid" (green)
│   │   └── EarningsTable (per-link earnings detail)
│   │       ├── Column: Link Name
│   │       ├── Column: Revenue
│   │       ├── Column: Commission
│   │       └── Column: Status
│   └── Tab: "Top Products"
│       └── ProductTable
│           ├── Column: Product Name
│           ├── Column: Type
│           ├── Column: Clicks
│           ├── Column: Conversions
│           ├── Column: Conv. Rate
│           └── Column: Earnings
└── [Admin Only] Tab: "Platform Stats"
    └── PlatformStatsCards
```

### 3.5 New Frontend API Endpoints

**Extend**: `frontend/src/api/endpoints/affiliates.ts` (~50 additional lines)

```typescript
export const getAffiliateSummary = () =>
  api.get<AffiliateSummaryOut>("/ui/affiliates/summary");

export const getLinkClickTimeSeries = (linkId: string, params: { from_date: string; to_date: string }) =>
  api.get<AffiliateClickTimeSeriesOut>(`/ui/affiliates/links/${linkId}/clicks`, params);

export const getAffiliateEarnings = () =>
  api.get<AffiliateEarningsBreakdownOut>("/ui/affiliates/earnings");

export const getTopProducts = (params?: { sort_by?: string; limit?: number }) =>
  api.get<AffiliateTopProductsOut>("/ui/affiliates/top-products", params);

export const getPlatformAffiliateStats = () =>
  api.get<AffiliatePlatformStatsOut>("/ui/admin/affiliates/stats");
```

### 3.6 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/e2e/fin-affiliates.spec.ts` | E2E tests | ~380 |

### 3.7 Files to Modify

| File | Change |
|------|--------|
| `app/services/affiliate_links.py` | Add summary, click timeseries, earnings breakdown, top products functions |
| `app/routers/affiliate_links.py` | Add new endpoints |
| `app/models.py` | Add affiliate dashboard models |
| `frontend/src/pages/affiliates/AffiliateDashboard.tsx` | Full rewrite with tabs, analytics, earnings |
| `frontend/src/api/endpoints/affiliates.ts` | Add new API wrappers |
| `frontend/src/api/types.ts` | Add TypeScript interfaces |

---

## 4. Click Time-Series Implementation

### 4.1 Data Source

The `AffiliateClicks` table stores individual click records:

**PK**: `link_id`, **SK**: `click_id`

Each click record has a `created_at` timestamp. To build time-series data:

1. Query `AffiliateClicks` with `link_id` PK.
2. Filter by `created_at` within the date range.
3. Group by date (truncate timestamp to day).
4. Count total clicks and unique clicks (by `visitor_hash`).

### 4.2 Performance Consideration

For links with high click volumes, querying and grouping in-process may be slow. For v1, use DynamoDB query with pagination (max 4 pages). For v2, pre-aggregate daily click counts into a summary record.

### 4.3 Conversion Rate Calculation

```
conversion_rate = (conversion_count / click_count) * 100
```

If `click_count == 0`, `conversion_rate = 0.0`. Displayed as percentage with 1 decimal place (e.g., "3.2%").

---

## 5. E2E Test Plan

**File**: `frontend/e2e/fin-affiliates.spec.ts`

### Section 575: Affiliate Summary API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 575.1 | Create link and verify summary | Create link; GET summary; total_links >= 1 |
| 575.2 | Record click and verify summary updates | POST click; GET summary; total_clicks >= 1 |
| 575.3 | Record conversion and verify earnings | POST conversion; GET summary; total_commission_cents > 0 |

### Section 576: Click Analytics API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 576.1 | Get click time series for a link | Record clicks; GET clicks; items array has entries with date and click count |
| 576.2 | Time series filters by date range | Record clicks on different dates; GET with range; only matching dates returned |
| 576.3 | Unique clicks are deduplicated | Record 3 clicks with same visitor; unique_clicks = 1 |
| 576.4 | Empty time series for new link | Create link (no clicks); GET clicks; items = [] |

### Section 577: Earnings and Top Products API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 577.1 | Earnings breakdown shows pending commission | Record conversion; GET earnings; pending_cents > 0 |
| 577.2 | Top products sorted by conversions | Create 2 links to different products; record conversions; GET top-products; sorted by conversion count |
| 577.3 | Top products include conversion rate | GET top-products; each item has conversion_rate field |
| 577.4 | Earnings scoped to authenticated creator | Bob cannot see Alice's earnings; GET returns only own data |

### Section 578: Affiliate Dashboard UI (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 578.1 | Dashboard shows summary cards | Navigate to /affiliates; "Total Clicks", "Conversions", "Earnings" visible |
| 578.2 | My Links tab shows affiliate links table | Click "My Links"; table with tracking code column visible |
| 578.3 | Create Link dialog works | Click "Create Affiliate Link"; fill form; submit; new link appears |
| 578.4 | Copy tracking code to clipboard | Click copy button on link; toast "Copied" appears |
| 578.5 | Earnings tab shows breakdown cards | Click "Earnings" tab; "Pending", "Approved", "Paid" cards visible |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| All creator endpoints | `require_ui_session` | Returns only caller's links and data |
| Admin stats | `require_admin_session` | Admin role required |
| Click recording | Internal/public | Rate-limited, no user auth needed |

### 6.2 Data Isolation

- All affiliate queries filter by `creator_id` (via ByAffiliate GSI with `GSI1PK = AFL#{creator_id}`).
- Click analytics queries filter by `link_id`, which is validated to belong to the requesting creator.
- Admin stats endpoint aggregates across all creators (admin only).

### 6.3 Rate Limiting

- Click recording: IP-based rate limiting (100 clicks per minute per IP) to prevent click fraud.
- API endpoints: standard per-user rate limiting.

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/affiliate_links.py` | Exists (complete backend) | Link CRUD, click tracking, conversion recording |
| `app/routers/affiliate_links.py` | Exists (core endpoints) | Extend with new endpoints |
| AffiliateLinks DDB table | Exists | Link storage with GSIs |
| AffiliateClicks DDB table | Exists | Click tracking storage |
| `frontend/src/pages/affiliates/AffiliateDashboard.tsx` | Exists (stub) | Rewrite target |
| `frontend/src/api/endpoints/affiliates.ts` | Exists | Extend with new wrappers |

---

## 8. Acceptance Criteria

1. Summary cards show total clicks, conversions, conversion rate, and earnings.
2. My Links tab shows all affiliate links with performance stats per link.
3. Analytics tab shows click time-series chart for a selected link.
4. Earnings tab shows pending, approved, and paid earnings breakdown.
5. Top Products tab ranks products by conversions or earnings.
6. Creator can create affiliate links with custom tracking codes.
7. Creator can copy tracking links to clipboard.
8. Creators see only their own affiliate data.
9. Admin can view platform-wide affiliate stats.
10. All 16 E2E tests pass.

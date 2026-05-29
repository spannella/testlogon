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

FIN-010 builds a comprehensive affiliate earnings dashboard on top of the existing affiliate link infrastructure. The backend (`app/services/affiliate_links.py`, 382 lines) supports link creation, click tracking, and conversion recording, and DynamoDB tables exist (`AffiliateLinks` at `scripts/local-ddb-init.py:990`, `AffiliateClicks` at `scripts/local-ddb-init.py:1001`). The frontend (`frontend/src/pages/affiliates/AffiliateDashboard.tsx`, 204 lines) shows a basic list of affiliate links with create/delete functionality, but has no performance analytics, no earnings breakdown, no time-series charts, and no click-through analytics. This ticket fills those gaps.

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
| `create_affiliate_link` | `app/services/affiliate_links.py:63` | **Verified** -- creates link with commission, tracking code, GSI keys |
| `get_link` | `app/services/affiliate_links.py:135` | **Verified** -- by link_id |
| `get_link_by_code` | `app/services/affiliate_links.py:141` | **Verified** -- by tracking code via GSI |
| `list_creator_links` | `app/services/affiliate_links.py:152` | **Verified** -- by creator via ByAffiliate GSI |
| `delete_link` | `app/services/affiliate_links.py:162` | **Verified** -- soft delete (status=revoked) |
| `record_click` | `app/services/affiliate_links.py:190` | **Verified** -- records click with device/UA classification |
| `record_conversion` | `app/services/affiliate_links.py:272` | **Verified** -- records conversion with commission calculation |
| `get_link_stats` | `app/services/affiliate_links.py:336` | **Verified** -- click_count, unique_click_count, conversion_count, revenue_cents, commission_earned_cents |

### 2.2 Existing Router Endpoints

| Method | Path | Auth | Status |
|--------|------|------|--------|
| `POST` | `/ui/affiliates/links` | `require_ui_session` | **Verified** (see `app/routers/affiliate_links.py:66`) |
| `GET` | `/ui/affiliates/links` | `require_ui_session` | **Verified** (see `app/routers/affiliate_links.py:96`) |
| `GET` | `/ui/affiliates/links/{id}` | `require_ui_session` | **Verified** (see `app/routers/affiliate_links.py:106`) |
| `DELETE` | `/ui/affiliates/links/{id}` | `require_ui_session` | **Verified** (see `app/routers/affiliate_links.py:120`) |
| `GET` | `/ui/affiliates/links/{id}/stats` | `require_ui_session` | **Verified** (see `app/routers/affiliate_links.py:133`) |
| `POST` | `/ui/affiliates/links/{id}/conversions` | Internal | **Verified** (see `app/routers/affiliate_links.py:148`) |
| `GET` | `/r/{code}` | Public | **Verified** — Redirect to destination with tracking (see `app/routers/affiliate_links.py:174`) |

### 2.3 Existing Frontend (Stub)

The current `AffiliateDashboard.tsx` (204 lines) includes:
- Basic list of affiliate links (name, code, clicks, earnings)
- Create link dialog (target type, target ID, commission %, custom code)
- Delete link button
- Copy link button

### 2.4 DynamoDB Access Patterns

| Access Pattern | Table | Key Condition | Filter | Use Case |
|---------------|-------|---------------|--------|----------|
| List links by creator | `AffiliateLinks` ByAffiliate GSI | GSI1PK=`AFL#{creator_id}` (see `scripts/local-ddb-init.py:994`) | — | Creator's link list |
| Get link by ID | `AffiliateLinks` | PK=`link_id` (note: table has NO sort key — see `scripts/local-ddb-init.py:992`) | — | Link detail |
| Get link by tracking code | `AffiliateLinks` ByCode GSI | GSI2PK=`CODE#{code}` (see `scripts/local-ddb-init.py:995`) | — | Redirect endpoint |
| Record click | `AffiliateClicks` | PK=`link_id`, SK=`click_id` (see `scripts/local-ddb-init.py:1003-1004`) | — | Click event storage |
| Click time series | `AffiliateClicks` ByVisitor GSI | GSI1PK, GSI1SK(N) (see `scripts/local-ddb-init.py:1006`) | — | Daily aggregated clicks |
| Get summary | `AffiliateLinks` ByAffiliate GSI | GSI1PK=`AFL#{creator_id}` | — | Aggregate all link stats |
| Top products | `AffiliateLinks` ByProduct GSI | GSI3PK (see `scripts/local-ddb-init.py:996`) | — | Sort in-memory by conversions |

**Example DynamoDB Item** (affiliate link):

```json
{
  "pk": {"S": "LINK#afl_abc123"},
  "sk": {"S": "META"},
  "GSI1PK": {"S": "AFL#alice@test.local"},
  "link_id": {"S": "afl_abc123"},
  "tracking_code": {"S": "alice-summer"},
  "product_id": {"S": "prod_123"},
  "commission_pct": {"N": "10"},
  "total_clicks": {"N": "342"},
  "unique_clicks": {"N": "218"},
  "total_conversions": {"N": "28"},
  "total_commission_cents": {"N": "14200"},
  "created_at": {"N": "1748520100"}
}
```

**Example DynamoDB Item** (click event):

```json
{
  "pk": {"S": "LINK#afl_abc123"},
  "sk": {"S": "CLK#1748520500#uuid123"},
  "visitor_ip_hash": {"S": "sha256_of_ip"},
  "user_agent": {"S": "Mozilla/5.0..."},
  "is_unique": {"BOOL": true},
  "created_at": {"N": "1748520500"}
}
```

### 2.5 Pydantic Models

```python
class AffiliateLinkOut(BaseModel):
    link_id: str
    tracking_code: str
    product_id: str
    tracking_url: str
    commission_pct: int
    total_clicks: int = 0
    unique_clicks: int = 0
    total_conversions: int = 0
    conversion_rate_pct: float = 0.0
    total_commission_cents: int = 0
    created_at: int

class AffiliateSummaryOut(BaseModel):
    total_links: int
    total_clicks: int
    total_unique_clicks: int
    total_conversions: int
    conversion_rate_pct: float
    total_commission_cents: int
    pending_commission_cents: int
    approved_commission_cents: int
    paid_commission_cents: int

class AffiliateClickSeriesOut(BaseModel):
    items: List[Dict[str, Any]]  # [{date, clicks, unique_clicks}]

class CreateAffiliateLinkIn(BaseModel):
    product_id: str
    tracking_code: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-z0-9-]+$")
    commission_pct: int = Field(..., ge=1, le=50)
```

### 2.6 Gaps

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

### Section 579: Affiliate Edge Cases & Negative Tests (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 579.1 | Duplicate tracking code rejected | Create link with same code twice; second returns 409 |
| 579.2 | Click on expired link not counted | Expire link; record click; summary doesn't increment |
| 579.3 | Conversion with zero amount | POST conversion with amount=0; 400 or conversion not recorded |
| 579.4 | Delete affiliate link | DELETE link; GET links; deleted link absent |
| 579.5 | Large time range analytics | GET clicks with 365-day range; response paginated correctly |

**Total E2E tests: 21**

---

## 6. API Request/Response Examples

**Get affiliate summary** (curl):

```bash
curl -X GET http://localhost:8000/ui/affiliates/summary \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_a; ui_access_token=eyJ..."
```

**Response (200)**:
```json
{
  "total_links": 5,
  "total_clicks": 342,
  "total_unique_clicks": 218,
  "total_conversions": 28,
  "conversion_rate_pct": 12.8,
  "total_commission_cents": 14200,
  "pending_commission_cents": 5000,
  "approved_commission_cents": 7200,
  "paid_commission_cents": 2000
}
```

**Create affiliate link** (curl):

```bash
curl -X POST http://localhost:8000/ui/affiliates/links \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_a; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_a" \
  -d '{"product_id": "prod_123", "tracking_code": "alice-summer", "commission_pct": 10}'
```

**Response (201)**:
```json
{
  "link_id": "afl_abc123",
  "tracking_code": "alice-summer",
  "product_id": "prod_123",
  "tracking_url": "https://platform.com/r/alice-summer",
  "commission_pct": 10,
  "created_at": 1748520100
}
```

**Get click analytics** (curl):

```bash
curl -X GET "http://localhost:8000/ui/affiliates/links/afl_abc123/clicks?period=7d" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_a; ui_access_token=eyJ..."
```

**Response (200)**:
```json
{
  "items": [
    {"date": "2026-05-28", "clicks": 12, "unique_clicks": 8},
    {"date": "2026-05-29", "clicks": 15, "unique_clicks": 11}
  ]
}
```

**Get earnings breakdown** (curl):

```bash
curl -X GET http://localhost:8000/ui/affiliates/earnings \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_a; ui_access_token=eyJ..."
```

**Response (200)**:
```json
{
  "pending_cents": 5000,
  "approved_cents": 7200,
  "paid_cents": 2000,
  "total_cents": 14200
}
```

---

## 7. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Duplicate tracking code | 409 | `duplicate_code` | "Tracking code already exists" | Choose a different code |
| Product not found | 404 | `product_not_found` | "Product not found" | Verify product ID |
| Link not found | 404 | `not_found` | "Affiliate link not found" | Check link ID |
| Not link owner | 403 | `forbidden` | "Not authorized" | Use own links |
| Invalid commission pct | 422 | `validation_error` | "Commission must be 1-50%" | Adjust value |
| Unauthenticated | 401 | `unauthorized` | "Authentication required" | Log in |
| Click fraud detected | 429 | `rate_limited` | N/A (server-side) | IP rate limited |

---

## 8. Observability

### 8.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `affiliate_link_created_total` | Counter | — | Links created |
| `affiliate_click_total` | Counter | `is_unique` | Clicks recorded |
| `affiliate_conversion_total` | Counter | — | Conversions recorded |
| `affiliate_commission_cents` | Counter | `status` (pending/approved/paid) | Commission amounts |
| `affiliate_click_fraud_blocked_total` | Counter | — | Rate-limited click attempts |

### 8.2 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Click fraud spike | > 1000 clicks/min from single IP | High | Auto-block IP |
| Conversion anomaly | > 50% conversion rate on single link | Medium | Review for fraud |
| Commission payout backlog | > 100 pending commissions for > 7d | Medium | Process payouts |

---

## 9. Rollout Plan

### 9.1 Feature Flag

```python
affiliate_dashboard_enabled: bool = os.environ.get("AFFILIATE_DASHBOARD_ENABLED", "true").lower() == "true"
```

### 9.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Backend | Deploy new endpoints; flag OFF | 2 days | Unit tests pass |
| Phase 2: Internal | Enable dashboard for internal | 3 days | All 21 E2E pass |
| Phase 3: Canary 10% | Enable for 10% of creators | 3 days | No fraud anomalies |
| Phase 4: GA | Enable for all | Permanent | Healthy conversion metrics |

### 9.3 Rollback

1. Set flag OFF — dashboard shows read-only summary
2. Click tracking continues (independent of dashboard)
3. Commission data preserved

---

## 10. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Summary aggregation | < 200ms | Pre-computed counters in DDB; updated on each event |
| Click time series query | < 100ms | DDB query on GSI by link + date range |
| Top products sort | < 200ms | In-memory sort of cached product data |
| Dashboard initial load | < 500ms | Parallel queries: summary + links + earnings |
| Click recording latency | < 10ms | Async fire-and-forget write |

---

## 11. Frontend Component Tree

```
AffiliateDashboard
├── SummaryCards (row)
│   ├── TotalClicksCard
│   ├── ConversionsCard
│   ├── ConversionRateCard
│   └── TotalEarningsCard
├── Tabs
│   ├── MyLinksTab
│   │   ├── LinksTable
│   │   │   └── LinkRow (code, product, clicks, conversions, earnings, copy button)
│   │   └── CreateLinkButton → CreateLinkDialog
│   ├── AnalyticsTab
│   │   ├── LinkSelector (dropdown to pick link)
│   │   ├── ClickChart (line/bar chart, 7d/30d/90d toggle)
│   │   └── StatsCards (unique vs total clicks, geo breakdown)
│   ├── EarningsTab
│   │   ├── EarningsBreakdownCards (pending, approved, paid)
│   │   └── EarningsHistoryTable
│   └── TopProductsTab
│       └── ProductTable (product name, clicks, conversions, rate, earnings)
└── ExportButton (CSV download)
```

---

## 12. Security Considerations

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

---

## Codebase References

| Ref | File | Line(s) | What |
|-----|------|---------|------|
| 1 | `app/services/affiliate_links.py` | 63 | `create_affiliate_link()` |
| 2 | `app/services/affiliate_links.py` | 135 | `get_link()` |
| 3 | `app/services/affiliate_links.py` | 141 | `get_link_by_code()` |
| 4 | `app/services/affiliate_links.py` | 152 | `list_creator_links()` |
| 5 | `app/services/affiliate_links.py` | 162 | `delete_link()` |
| 6 | `app/services/affiliate_links.py` | 190 | `record_click()` |
| 7 | `app/services/affiliate_links.py` | 272 | `record_conversion()` |
| 8 | `app/services/affiliate_links.py` | 336 | `get_link_stats()` |
| 9 | `app/routers/affiliate_links.py` | 66 | `POST /ui/affiliates/links` |
| 10 | `app/routers/affiliate_links.py` | 96 | `GET /ui/affiliates/links` |
| 11 | `app/routers/affiliate_links.py` | 106 | `GET /ui/affiliates/links/{id}` |
| 12 | `app/routers/affiliate_links.py` | 120 | `DELETE /ui/affiliates/links/{id}` |
| 13 | `app/routers/affiliate_links.py` | 133 | `GET /ui/affiliates/links/{id}/stats` |
| 14 | `app/routers/affiliate_links.py` | 148 | `POST /ui/affiliates/links/{id}/conversions` |
| 15 | `app/routers/affiliate_links.py` | 174 | `GET /r/{tracking_code}` |
| 16 | `app/main.py` | 117, 452 | `affiliate_links_router` import and registration |
| 17 | `scripts/local-ddb-init.py` | 990-998 | `AffiliateLinks` table definition (PK=link_id, no SK; 3 GSIs: ByAffiliate, ByCode, ByProduct) |
| 18 | `scripts/local-ddb-init.py` | 1001-1008 | `AffiliateClicks` table definition (PK=link_id, SK=click_id; 1 GSI: ByVisitor) |
| 19 | `app/core/settings.py` | 1436-1441 | `affiliate_links_enabled`, `affiliate_links_table_name`, `affiliate_clicks_table_name` |
| 20 | `frontend/src/pages/affiliates/AffiliateDashboard.tsx` | — | Current 204-line stub dashboard |
| 21 | `frontend/src/api/endpoints/affiliates.ts` | — | Existing frontend API wrappers |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_affiliate_dashboard.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_fin_010_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_fin_010_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_fin_010_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_fin_010_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_fin_010_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_fin_010_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_fin_010_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_fin_010_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/affiliate-dashboard.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 12

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `AFFILIATE_LINKS_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `AFFILIATE_LINKS_ENABLED` must be enabled for tests to run
- Serial execution: run with `--workers 1` to avoid shared state conflicts
- Retry safety: tests use unique timestamps/UUIDs per run; safe to retry on failure

---

## Dependencies & Merge Safety

### Depends On

| Ticket | Status | What It Provides |
|--------|--------|-----------------|
| (none) | -- | This ticket has no upstream ticket dependencies |

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| (none currently) | -- |

### Merge Strategy

**Independent** -- Changes are additive (new service files, new router, new frontend pages). Shared infrastructure files (`main.py`, `settings.py`, `tables.py`, `local-ddb-init.py`) receive only additive modifications.

### Merge Checklist

- [ ] All new DDB tables/GSIs added to `scripts/local-ddb-init.py`
- [ ] Settings added to `app/core/settings.py`
- [ ] Table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Frontend routes added to `App.tsx`
- [ ] Feature flag `AFFILIATE_LINKS_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite

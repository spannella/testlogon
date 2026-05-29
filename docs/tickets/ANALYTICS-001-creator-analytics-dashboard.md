# ANALYTICS-001: Creator Analytics Dashboard

**Status**: Proposed
**Author**: Engineering
**Date**: 2026-05-27
**Priority**: Medium
**Estimated effort**: 8-10 days

---

## 1. Executive Summary

The Creator Analytics Dashboard provides a unified, data-driven view for creators to understand their content performance, audience composition, and revenue attribution across every monetization channel the platform supports. Today, creators have no self-service way to answer fundamental questions about their business -- which content performs best, where revenue comes from, how their subscriber base is growing, or what their audience looks like. MON-003 (Creator Earnings Dashboard) offers a revenue-only slice through `creator_earnings.py`, but it lacks content engagement metrics, audience demographics, and cross-channel attribution.

This ticket builds a full analytics stack: a DynamoDB-backed rollup pipeline that pre-aggregates daily metrics from the billing ledger, video views, subscription records, post engagement, ad impressions, and call billing tables; a set of REST endpoints that serve time-ranged, granularity-selectable data; and a React dashboard page with charts powered by Recharts. The design prioritizes query efficiency -- dashboard loads read from pre-computed rollup rows rather than scanning source tables -- and extensibility, so future event sources (e.g., broadcast tips, shop sales) can be added as new rollup dimensions without schema migration.

The end goal is to give every creator a Shopify-analytics-grade view of their platform business, accessible at `/analytics`, integrated into the sidebar navigation, and responsive on both desktop and mobile viewports.

> **Codebase context**: The existing MON-003 Creator Earnings Dashboard is implemented at `app/services/creator_earnings.py` (service) and `app/routers/creator_earnings.py` (router, prefix `/ui/earnings`). <!-- VERIFIED: creator_earnings.py:1, creator_earnings router line 16 --> The earnings router is registered in `app/main.py` at line 106/429. <!-- VERIFIED -->

---

## 2. Detailed Problem Analysis

### User Stories

| As a... | I want to... | So that... |
|---------|-------------|-----------|
| Creator | See total views, revenue, and subscribers for this week | I can gauge my current performance at a glance |
| Creator | Compare revenue from tips vs. subscriptions vs. unlocks | I can focus on the monetization channels that work best |
| Creator | See which content gets the most views | I can create more of what my audience wants |
| Creator | Track subscriber growth and churn over time | I can measure the health of my recurring income |
| Creator | See audience country and device breakdown | I can tailor content to my actual audience |
| Creator | Choose daily, weekly, or monthly granularity | I can spot both short-term spikes and long-term trends |
| Creator | Trigger an on-demand data refresh | I can see up-to-the-minute metrics after a viral post |
| Admin | Audit per-creator analytics access | I can ensure no cross-user data leakage |

### Pain Points

1. **No visibility into content ROI**: A creator who posts three VOD videos has no way to know which one drove the most subscription conversions.
2. **Revenue is spread across multiple ledger entries**: Tips, unlocks, subscriptions, VOD purchases, ad impressions, and call billing each live in different tables with different schemas. Manually correlating them is impossible.
3. **No historical trending**: Even if a creator checks the Earnings page daily, they cannot see how today compares to last week or last month -- there is no time-series data.
4. **Audience is invisible**: The platform collects device user-agent and GeoIP headers at request time, but this data is never surfaced to creators.

### Competitive Analysis

| Platform | Analytics Offered | Gap vs. This Ticket |
|----------|------------------|-------------------|
| YouTube Studio | Views, watch time, revenue, demographics, traffic sources, real-time | We match views + revenue + demographics; defer traffic sources + real-time to future |
| OnlyFans | Earnings, subscriber count, top posts | We exceed with time-series, granularity, audience breakdown |
| Patreon | Patrons, earnings, per-post engagement | We match and add multi-source revenue attribution |

---

## 3. Technical Architecture

### System Diagram

```
+-------------------+     +---------------------+     +------------------+
|  Billing Ledger   |     |   Video Views       |     |  Subscriptions   |
|  (T.billing)      |     |   (T.video_views)   |     |  (T.subscriptions)|
<!-- VERIFIED: T.billing at tables.py:22/146, T.video_views at tables.py:91/215, T.subscriptions at tables.py:36/160 -->
+--------+----------+     +---------+-----------+     +--------+---------+
         |                          |                           |
         v                          v                           v
+------------------------------------------------------------------------+
|                    Analytics Rollup Job                                 |
|  app/services/analytics_rollup_job.py                                  |
|                                                                        |
|  Scans source tables for date range, aggregates into daily buckets,    |
|  writes rollup rows to T.analytics_rollups                             |
+--------+------+-------+------+---------+------+-----------------------+
         |      |       |      |         |      |
         v      v       v      v         v      v
+--------+-+  +-+------+-+ +--+------+ +-+-----+-+ +------+---+ +------+
| Post     |  | Ad       | | Call    | | Newsfeed | | Broadcast| | Shop |
| Reactions|  | Impressn | | Billing | | Comments | | Chat Msg | | Sales|
| (T.app)  |  |(T.ad_imp)| |(T.call)|  | (T.app) | |(T.bcast) | |(T.) |
<!-- VERIFIED: T.ad_impressions at tables.py:93/217, T.call_billing_ledger at tables.py:94/218 -->
<!-- CORRECTED: "T.ad_imp" should be "T.ad_impressions"; "T.call" should be "T.call_billing_ledger" -->
+----------+  +----------+ +--------+ +----------+ +----------+ +------+

                              |
                              v
            +----------------------------------+
            |   analytics_rollups table        |
            |   PK: CREATOR#{user_id}          |
            |   SK: DAILY#{YYYY-MM-DD}         |
            +--------+-------------------------+
                     |
                     v
            +----------------------------------+
            |   Analytics Router               |
            |   /ui/analytics/*                |
            |   app/routers/creator_analytics  |
            +--------+-------------------------+
                     |
                     v
            +----------------------------------+
            |   Frontend Dashboard             |
            |   /analytics                     |
            |   React + Recharts               |
            +----------------------------------+
```

### Data Flow

1. **Rollup aggregation** (background job, runs every 15 minutes or on-demand):
   - Scans `T.billing` (LEDGER entries) for the target date, grouped by `creator_user_id` and `reason` (tip, unlock, subscription, vod, call). <!-- VERIFIED: billing table pk/sk pattern. LEDGER entries use sk="LEDGER#{ts}#{entry_id}" per billing_shared.py:213-214 -->
   - Scans `T.video_views` for the date, grouped by `video_id` owner. <!-- VERIFIED: video_views_table_name at settings.py:1180 -->
   - Scans `T.subscriptions` for new SUBSCRIBER entries and churn events on the date. <!-- VERIFIED: subscriptions_table_name at settings.py:1008 -->
   - Scans `T.app_single_table` for post reactions/comments (newsfeed engagement). <!-- CORRECTED: T.app_single_table is not a handle on T. The table handle is accessible via ddb.Table(S.app_single_table_name). The settings name is `app_single_table_name` but it's not wired through T in tables.py. The actual table is defined in local-ddb-init.py at line 216-228 with pk/sk and 6 GSIs. -->
   - Scans `T.ad_impressions` for ad revenue attributed to the date. <!-- VERIFIED: ad_impressions at tables.py:91/175, settings.py:1188 -->
   - Scans `T.call_billing_ledger` for call revenue entries on the date. <!-- VERIFIED: call_billing_ledger at tables.py:92/176, settings.py:1141 -->
   - Writes one `DAILY#{YYYY-MM-DD}` row per creator per day.

2. **API request** (read path):
   - Frontend sends `GET /ui/analytics/revenue?from_date=2026-05-01&to_date=2026-05-27&granularity=day`.
   - Router calls `creator_analytics.get_revenue_breakdown(user_id, from_date, to_date, granularity)`.
   - Service queries `T.analytics_rollups` with PK `CREATOR#{user_id}` and SK between `DAILY#{from_date}` and `DAILY#{to_date}`.
   - If `granularity=week`, service aggregates daily rows into ISO-week buckets in-memory.
   - Returns structured response with time series + totals.

3. **Frontend rendering**:
   - React Query hooks fetch each endpoint independently (overview, revenue, views, subscribers, top-content, audience).
   - Recharts renders line charts, bar charts, donut charts.
   - Date range picker updates all queries simultaneously.

### Component Interactions

- `analytics_rollup_job.py` imports from `creator_earnings.py` for revenue aggregation logic (DRY -- avoids duplicating ledger scanning). <!-- VERIFIED: creator_earnings.py exists at app/services/creator_earnings.py with get_earnings_summary() and get_earnings_transactions() -->
- `creator_analytics.py` service is read-only; it never writes to source tables.
- The router uses `require_ui_session` -- no new auth mechanism needed. <!-- VERIFIED: require_ui_session defined at app/services/sessions.py:283, imported by existing creator_earnings_router -->
- The rollup job can run in-process (asyncio background task started at app startup) or via an external cron trigger hitting `POST /ui/analytics/refresh`. <!-- VERIFIED: Background task pattern exists in main.py (e.g. lines 326-327, 366-370) -->

---

## 4. Data Model Deep Dive

### DynamoDB Table: `analytics_rollups`

**Table definition for `scripts/local-ddb-init.py`:**

```python
TableDef(
    os.environ.get("DDB_ANALYTICS_ROLLUPS", "AnalyticsRollups"),
    "pk",
    "sk",
    gsi=[
        # GSI1: Query all creators for a given date (admin use)
        {"index_name": "ByDateCreatedAt", "partition_key": "date_scope", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
)
```

**Settings entry for `app/core/settings.py`:**

```python
analytics_rollups_table_name: str = os.environ.get("DDB_ANALYTICS_ROLLUPS", "AnalyticsRollups")
analytics_rollup_enabled: bool = os.environ.get("ANALYTICS_ROLLUP_ENABLED", "1") not in ("0", "false", "False")
analytics_rollup_interval_seconds: int = int(os.environ.get("ANALYTICS_ROLLUP_INTERVAL_SECONDS", "900"))
analytics_rollup_lookback_days: int = int(os.environ.get("ANALYTICS_ROLLUP_LOOKBACK_DAYS", "3"))
```
<!-- VERIFIED: All four settings exist at app/core/settings.py:1334-1337 -->

**Tables entry for `app/core/tables.py`:**

```python
# In Tables dataclass (app/core/tables.py)
analytics_rollups: Any  # line 97
# ...
analytics_rollups=ddb.Table(S.analytics_rollups_table_name),  # line 221
```
<!-- VERIFIED: analytics_rollups handle exists at app/core/tables.py:97 (declaration) and :221 (wiring) -->

### Primary Access Patterns

| Access Pattern | Key Condition | Index | Notes |
|---|---|---|---|
| Get daily rollups for creator in date range | PK=`CREATOR#{user_id}`, SK between `DAILY#{from}` and `DAILY#{to}` | Table | Primary read path |
| Get all creators for a date (admin) | GSI1PK=`DATE#{YYYY-MM-DD}` | ByDateCreatedAt | Admin-only aggregation |
| Get latest rollup for creator | PK=`CREATOR#{user_id}`, SK begins_with `DAILY#`, ScanIndexForward=False, Limit=1 | Table | Quick freshness check |

### Example Items

**Daily rollup row:**

```json
{
  "pk": "CREATOR#alice-uuid-1234",
  "sk": "DAILY#2026-05-27",
  "date_scope": "DATE#2026-05-27",
  "total_views": 1543,
  "unique_viewers": 892,
  "watch_time_seconds": 45230,
  "revenue_cents": 8750,
  "revenue_tips_cents": 2000,
  "revenue_subscriptions_cents": 4000,
  "revenue_unlocks_cents": 1500,
  "revenue_vod_cents": 500,
  "revenue_ads_cents": 250,
  "revenue_calls_cents": 500,
  "new_subscribers": 12,
  "churned_subscribers": 3,
  "net_subscribers": 9,
  "total_subscribers": 347,
  "top_content_ids": ["vid_abc", "post_def", "vid_ghi"],
  "audience_countries": {"US": 523, "GB": 145, "DE": 98, "CA": 67, "AU": 59},
  "audience_devices": {"mobile": 612, "desktop": 245, "tablet": 35},
  "post_reactions": 89,
  "post_comments": 23,
  "created_at": 1748361600,
  "updated_at": 1748361600
}
```

**Creator summary sentinel (for quick total subscriber count):**

```json
{
  "pk": "CREATOR#alice-uuid-1234",
  "sk": "SUMMARY",
  "total_subscribers": 347,
  "lifetime_revenue_cents": 125000,
  "lifetime_views": 45230,
  "last_rollup_date": "2026-05-27",
  "updated_at": 1748361600
}
```

---

## 5. API Contract Design

### GET `/ui/analytics/overview`

**Query parameters:**

| Param | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| from_date | str (YYYY-MM-DD) | No | 7 days ago | Start of period |
| to_date | str (YYYY-MM-DD) | No | today | End of period |

**Response 200:**

```json
{
  "period_views": 10524,
  "period_revenue_cents": 52750,
  "period_new_subscribers": 67,
  "total_subscribers": 347,
  "top_content": [
    {
      "content_id": "vid_abc123",
      "content_type": "vod",
      "title": "Summer Workout Routine",
      "views": 3200,
      "revenue_cents": 12500
    },
    {
      "content_id": "post_def456",
      "content_type": "post",
      "title": "Behind the scenes...",
      "views": 1800,
      "revenue_cents": 4000
    }
  ],
  "currency": "USD"
}
```

**Error responses:**

| Status | Body | Condition |
|--------|------|-----------|
| 400 | `{"detail": "from_date must be before to_date"}` | Invalid date range |
| 400 | `{"detail": "Date range cannot exceed 365 days"}` | Range too large |
| 401 | `{"detail": "Not authenticated"}` | Missing/invalid session |

### GET `/ui/analytics/revenue`

**Query parameters:**

| Param | Type | Required | Default |
|-------|------|----------|---------|
| from_date | str | No | 30 days ago |
| to_date | str | No | today |
| granularity | str | No | "day" |

**Response 200:**

```json
{
  "total_cents": 52750,
  "breakdown": {
    "tips": 15000,
    "subscriptions": 25000,
    "unlocks": 8000,
    "vod": 2500,
    "ads": 1250,
    "calls": 1000
  },
  "time_series": [
    {"date": "2026-05-01", "total_cents": 1850, "tips_cents": 500, "subscriptions_cents": 1000, "unlocks_cents": 200, "vod_cents": 50, "ads_cents": 50, "calls_cents": 50},
    {"date": "2026-05-02", "total_cents": 2100, "tips_cents": 700, "subscriptions_cents": 900, "unlocks_cents": 300, "vod_cents": 100, "ads_cents": 50, "calls_cents": 50}
  ],
  "currency": "USD"
}
```

### GET `/ui/analytics/views`

**Response 200:**

```json
{
  "time_series": [
    {"date": "2026-05-01", "views": 543, "unique_viewers": 312, "watch_time_seconds": 16290}
  ],
  "total_views": 10524,
  "total_watch_time_seconds": 315720
}
```

### GET `/ui/analytics/subscribers`

**Response 200:**

```json
{
  "time_series": [
    {"date": "2026-05-01", "new": 5, "churned": 1, "net": 4, "total": 284}
  ],
  "current_total": 347,
  "net_change": 67
}
```

### GET `/ui/analytics/top-content`

**Query parameters:** `from_date`, `to_date`, `sort_by` (views|revenue, default: views), `limit` (default: 20, max: 100).

**Response 200:**

```json
{
  "items": [
    {
      "content_id": "vid_abc123",
      "content_type": "vod",
      "title": "Summer Workout Routine",
      "views": 3200,
      "revenue_cents": 12500,
      "engagement_rate": 0.15
    }
  ],
  "total_items": 42
}
```

### GET `/ui/analytics/audience`

**Response 200:**

```json
{
  "countries": [
    {"code": "US", "name": "United States", "viewers": 523, "percentage": 58.6},
    {"code": "GB", "name": "United Kingdom", "viewers": 145, "percentage": 16.3}
  ],
  "devices": [
    {"type": "mobile", "viewers": 612, "percentage": 68.6},
    {"type": "desktop", "viewers": 245, "percentage": 27.5},
    {"type": "tablet", "viewers": 35, "percentage": 3.9}
  ],
  "total_unique_viewers": 892
}
```

### POST `/ui/analytics/refresh`

**Response 200:**

```json
{
  "ok": true,
  "message": "Rollup refresh triggered for 3 days",
  "days_refreshed": 3
}
```

**Rate limit:** 1 request per 5 minutes per user.

---

## 6. Frontend Component Design

### Component Tree

```
<AnalyticsPage>
  <PageHeader title="Analytics" icon={BarChart3} />
  <DateRangePicker
    presets={["7d", "30d", "90d", "1y"]}
    onRangeChange={setDateRange}
  />
  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
    <SummaryCard title="Views" value={overview.period_views} icon={Eye} />
    <SummaryCard title="Revenue" value={formatCents(overview.period_revenue_cents)} icon={DollarSign} />
    <SummaryCard title="New Subscribers" value={overview.period_new_subscribers} icon={UserPlus} />
    <SummaryCard title="Total Subscribers" value={overview.total_subscribers} icon={Users} />
  </div>
  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <ViewTrendsChart data={viewsData} granularity={granularity} />
    <RevenueBreakdownChart data={revenueData} />
  </div>
  <SubscriberGrowthChart data={subscriberData} granularity={granularity} />
  <TopContentTable data={topContentData} sortBy={sortBy} onSortChange={setSortBy} />
  <AudienceDemographics data={audienceData} />
</AnalyticsPage>
```

### State Management

- **URL state**: `from_date`, `to_date`, `granularity` stored in URL search params via `useSearchParams` for shareability.
- **React Query hooks**: Each section has its own query key for independent loading/caching.
  - `["analytics", "overview", { from_date, to_date }]`
  - `["analytics", "revenue", { from_date, to_date, granularity }]`
  - `["analytics", "views", { from_date, to_date, granularity }]`
  - `["analytics", "subscribers", { from_date, to_date, granularity }]`
  - `["analytics", "top-content", { from_date, to_date, sort_by }]`
  - `["analytics", "audience", { from_date, to_date }]`
- **Refresh mutation**: `useMutation` on `POST /ui/analytics/refresh`, invalidates all `["analytics", ...]` queries on success.

### React Query Hooks (`frontend/src/api/endpoints/analytics.ts`)

```typescript
import api from "../client";

export const getAnalyticsOverview = (params: DateRangeParams) =>
  api.get("/ui/analytics/overview", { params }).then(r => r.data);

export const getAnalyticsRevenue = (params: DateRangeParams & { granularity?: string }) =>
  api.get("/ui/analytics/revenue", { params }).then(r => r.data);

export const getAnalyticsViews = (params: DateRangeParams & { granularity?: string }) =>
  api.get("/ui/analytics/views", { params }).then(r => r.data);

export const getAnalyticsSubscribers = (params: DateRangeParams & { granularity?: string }) =>
  api.get("/ui/analytics/subscribers", { params }).then(r => r.data);

export const getAnalyticsTopContent = (params: DateRangeParams & { sort_by?: string; limit?: number }) =>
  api.get("/ui/analytics/top-content", { params }).then(r => r.data);

export const getAnalyticsAudience = (params: DateRangeParams) =>
  api.get("/ui/analytics/audience", { params }).then(r => r.data);

export const refreshAnalytics = () =>
  api.post("/ui/analytics/refresh").then(r => r.data);
```

### UI Mockup Descriptions

1. **Summary Cards Row**: Four cards in a responsive grid (4 columns on desktop, 2 on tablet, 1 on mobile). Each card shows an icon, a metric label, the current-period value, and a small percentage-change badge comparing to the previous equivalent period.

2. **View Trends Chart**: Recharts `AreaChart` with gradient fill. X-axis: dates. Y-axis: view count. Tooltip shows views, unique viewers, and watch time. Toggle between views and watch time on the Y-axis.

3. **Revenue Breakdown Chart**: Two visualizations side by side -- a `PieChart` (donut style) showing proportional revenue by source, and a stacked `BarChart` showing the same breakdown over time.

4. **Subscriber Growth Chart**: Recharts `ComposedChart` with bars (new/churned) and a line (net total). Green bars for new, red bars for churned, blue line for cumulative total.

5. **Top Content Table**: DataTable with columns: Rank, Thumbnail (if VOD), Title, Type badge, Views, Revenue, Engagement Rate. Sortable by Views or Revenue. Pagination (20 per page).

6. **Audience Demographics**: Two `PieChart` donuts side by side -- countries and devices. Below each, a ranked list showing the top 10 entries with bar indicators.

### Navigation Integration

- **Route**: `/analytics` added to `App.tsx` with `React.lazy(() => import("./pages/analytics/AnalyticsPage"))`.
- **Sidebar** (`Sidebar.tsx` + `AppShell.tsx`): Add `{ icon: BarChart3, label: "Analytics", path: "/analytics" }` to Monetization group, after "Earnings".
- **MobileNav** (`MobileNav.tsx`): Add "Analytics" to `MORE_LINKS` array.

---

## 7. Security & Privacy Considerations

### Authentication & Authorization

- All endpoints require `require_ui_session` (cookie-based auth with CSRF for non-GET requests).
- Creator can only access their own analytics -- the `user_sub` from the session is used as the partition key. There is no endpoint parameter for specifying another user's ID.
- The `POST /ui/analytics/refresh` endpoint only refreshes the authenticated creator's data.
- Admin/root analytics (platform-wide metrics) is out of scope for this ticket but the GSI `ByDateCreatedAt` enables it for a future admin dashboard.

### Input Validation

- `from_date` and `to_date` validated as `YYYY-MM-DD` format strings. Reject any other format with 400.
- `granularity` validated against enum `["day", "week", "month"]`.
- `sort_by` validated against enum `["views", "revenue"]`.
- `limit` clamped to `[1, 100]`.
- Date range capped at 365 days to prevent expensive queries.

### Data Protection

- Analytics rollup rows do not contain PII -- they store aggregate counts and IDs only.
- `audience_countries` and `audience_devices` store counts, not individual user records.
- The `top_content_ids` list contains content IDs that are resolved to titles only if the content still exists and the creator owns it.

### Abuse Prevention

- Refresh endpoint rate-limited to 1 per 5 minutes per user (using DDB-based rate limit pattern from `app/services/rate_limit.py`). <!-- VERIFIED: _bucket_limit() at rate_limit.py:60; rate_limit_or_429() at line 17. Uses T.sessions for rate limit storage. -->
- Rollup job processes at most `analytics_rollup_lookback_days` (default 3) days per run, preventing a single refresh from doing unbounded work.

---

## 8. Performance & Scalability

### Query Cost Analysis

| Endpoint | DDB Reads | Estimated RCU | Notes |
|----------|-----------|---------------|-------|
| Overview (7 days) | 7 items | ~1 RCU | 7 small items, likely <4KB each |
| Revenue (30 days) | 30 items | ~2 RCU | Eventually consistent reads |
| Views (30 days) | 30 items | ~2 RCU | Same table, same query pattern |
| Subscribers (30 days) | 30 items | ~2 RCU | Same |
| Top content (30 days) | 30 items + in-memory sort | ~2 RCU | Sort + top-K in Python |
| Audience (30 days) | 30 items + in-memory merge | ~2 RCU | Merge country/device maps |

**Total per dashboard load**: ~11 RCU (6 parallel queries, each reading at most 365 items for a full year view). This is extremely efficient compared to scanning source tables.

### Caching Strategy

- **React Query**: `staleTime: 5 * 60 * 1000` (5 minutes). Dashboard data does not change frequently.
- **Backend**: No additional caching layer needed -- DDB reads are fast and cheap. The rollup table itself IS the cache.
- **CDN**: Not applicable (authenticated, user-specific data).

### DynamoDB Capacity Planning

- **Rollup table write throughput**: At most `N_creators * 1` writes per rollup cycle (one row per creator per day). For 10,000 creators running every 15 minutes, this is ~11 writes/second during the rollup window -- well within PAY_PER_REQUEST capacity.
- **Rollup table storage**: Each row is ~500 bytes. 10,000 creators x 365 days = 3.65M rows = ~1.8 GB. Well within DDB limits.

### Known Bottlenecks

1. **Source table scans during rollup**: Scanning `T.billing` for all LEDGER entries on a given date requires a full table scan with FilterExpression (the billing table is not indexed by date). Mitigation: The rollup job runs in the background and processes one date at a time. If this becomes slow, add a GSI on `T.billing` with PK=`DATE#{YYYY-MM-DD}`. <!-- NOTE: The billing table (local-ddb-init.py line 59) has PK=pk, SK=sk. LEDGER entries use sk="LEDGER#{ts}#{entry_id}". A per-user scan with SK begins_with("LEDGER#") is feasible per creator, but a cross-creator date scan requires a full table scan or a new GSI. creator_earnings.py already does per-user LEDGER scanning (line 57-73). -->
2. **In-memory aggregation**: For the top-content endpoint with a 365-day range, the service loads 365 daily rows and merges `top_content_ids` lists. This is O(365 * 10) = O(3650) -- trivial.

---

## 9. Migration & Rollback Plan

### Deployment Phases

1. **Phase 1 -- Table creation**: Add `AnalyticsRollups` to `scripts/local-ddb-init.py`. Add settings to `app/core/settings.py` and table handle to `app/core/tables.py`. Safe: no behavioral change.
2. **Phase 2 -- Rollup job**: Deploy `analytics_rollup_job.py` with feature flag `ANALYTICS_ROLLUP_ENABLED=false` in production. Enable in staging first. Backfill historical data by running the job with `analytics_rollup_lookback_days=90`.
3. **Phase 3 -- API endpoints**: Deploy router behind feature flag. Endpoints return empty data if rollups have not been generated yet.
4. **Phase 4 -- Frontend**: Deploy page, route, and sidebar entry. The page gracefully handles empty-state (no rollup data).
5. **Phase 5 -- Enable in production**: Set `ANALYTICS_ROLLUP_ENABLED=true`. Monitor for 24 hours, then announce to creators.

### Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `ANALYTICS_ROLLUP_ENABLED` | `false` (prod), `true` (dev) | Controls whether rollup background job runs |
| `ANALYTICS_ROLLUP_INTERVAL_SECONDS` | `900` | How often the rollup job runs |
| `ANALYTICS_ROLLUP_LOOKBACK_DAYS` | `3` | How many days back each rollup run processes |

### Rollback Steps

1. Set `ANALYTICS_ROLLUP_ENABLED=false` to stop the background job.
2. Remove the `/analytics` route from `App.tsx` (or hide behind feature flag).
3. The rollup table can remain in place -- it is read-only from the API perspective and causes no harm.
4. No source table data is modified by this feature, so there is no data to revert.

---

## 10. Testing Strategy

### Unit Tests (`tests/test_creator_analytics.py`)

| Test | Description |
|------|-------------|
| `test_rollup_aggregates_billing_ledger` | Seed billing LEDGER entries for a creator; run rollup; assert daily row has correct revenue_tips_cents, revenue_subscriptions_cents, etc. |
| `test_rollup_aggregates_video_views` | Seed video view records; run rollup; assert total_views and unique_viewers correct. |
| `test_rollup_aggregates_subscriber_changes` | Seed SUBSCRIBER entries; run rollup; assert new_subscribers, churned_subscribers, net_subscribers correct. |
| `test_rollup_idempotent` | Run rollup twice for the same date; assert row is updated, not duplicated. |
| `test_overview_empty_creator` | No rollup data; assert overview returns all zeros. |
| `test_revenue_breakdown_correct_attribution` | Seed rollups with known values; assert breakdown dict matches. |
| `test_date_range_validation` | Assert 400 for from_date > to_date, range > 365 days, malformed date strings. |
| `test_granularity_week_aggregation` | Seed 14 daily rollups; request granularity=week; assert 2 data points in time_series. |
| `test_granularity_month_aggregation` | Seed 60 daily rollups; request granularity=month; assert 2 data points. |
| `test_top_content_sort_by_views` | Seed rollups with top_content_ids; assert sort by views returns highest first. |
| `test_top_content_sort_by_revenue` | Same, sorted by revenue. |
| `test_audience_country_merge` | Two daily rollups with overlapping countries; assert merged counts correct. |
| `test_refresh_rate_limit` | Call refresh twice within 5 minutes; assert second returns 429. |
| `test_cross_user_isolation` | Create rollups for two creators; assert each can only see their own. |

### E2E Test Matrix (`frontend/e2e/analytics.spec.ts`)

**Section A: Analytics API (8 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 1 | Empty analytics returns zero for new creator | Alice (no seeded data) | Overview returns `period_views: 0`, `period_revenue_cents: 0` |
| 2 | Revenue breakdown includes seeded tip/subscription/unlock credits | Seed LEDGER entries + run rollup | Breakdown keys match expected sources |
| 3 | Time range filter excludes out-of-range data | Seed rollups for May 1-27; query May 10-15 | Time series has exactly 6 entries |
| 4 | Daily granularity produces per-day time series | Query with granularity=day | Each time_series entry is one day |
| 5 | Top content returns ranked list by view count | Seed rollups with known top_content_ids | First item has highest views |
| 6 | Subscriber growth shows correct net change | Seed rollups with subscriber data | net_change matches sum of daily net |
| 7 | Audience endpoint returns country/device breakdown | Seed rollups with audience maps | Countries and devices arrays populated |
| 8 | Overview returns aggregated summary cards | Seed multiple daily rollups | period_views = sum of daily views |

**Section B: Analytics API Edge Cases (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Invalid date range returns 400 | from_date=2026-06-01, to_date=2026-05-01 -> 400 |
| 2 | Unauthenticated request returns 401 | No session cookies -> 401 |
| 3 | Very large date range caps at rollup limit | from_date=2024-01-01, to_date=2026-05-27 -> 400 (>365 days) |
| 4 | Refresh endpoint triggers without error | POST /ui/analytics/refresh -> 200 with ok=true |

**Section C: Analytics UI (6 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Analytics page loads with summary cards | Navigate to /analytics; 4 summary cards visible |
| 2 | Revenue breakdown chart renders category legend | Legend contains "Tips", "Subscriptions", "Unlocks" |
| 3 | Date range selector updates all charts | Click "30d" preset; URL params update; charts re-render |
| 4 | Top content table shows content titles and metrics | Table rows have Title, Views, Revenue columns |
| 5 | Subscriber growth chart renders line with data points | SVG path elements present in chart container |
| 6 | Page is responsive on mobile viewport | Set viewport 375x667; cards stack vertically; charts full-width |

---

## 11. Monitoring & Alerting

### Metrics to Track

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `analytics_rollup_duration_seconds` | Histogram | - | Time taken for each rollup job execution |
| `analytics_rollup_creators_processed` | Counter | - | Number of creator rollups written per run |
| `analytics_rollup_errors_total` | Counter | `error_type` | Errors during rollup (DDB timeout, source scan failure) |
| `analytics_api_request_duration_seconds` | Histogram | `endpoint` | Latency per analytics API endpoint |
| `analytics_api_requests_total` | Counter | `endpoint`, `status` | Request count by endpoint and HTTP status |
| `analytics_refresh_requests_total` | Counter | - | Manual refresh trigger count |

### Dashboard Queries

- **Rollup health**: `rate(analytics_rollup_errors_total[5m]) > 0` -- any rollup errors in the last 5 minutes.
- **API latency**: `histogram_quantile(0.95, analytics_api_request_duration_seconds)` -- 95th percentile should be < 500ms.
- **Rollup freshness**: Compare `now()` to the latest `updated_at` timestamp in the SUMMARY sentinel. Alert if > 30 minutes stale.

### Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Rollup job failing | `analytics_rollup_errors_total` increases for 3 consecutive runs | Warning |
| Rollup job stalled | No `analytics_rollup_creators_processed` increase for 1 hour | Critical |
| API latency high | P95 > 2 seconds for 5 minutes | Warning |
| Dashboard error rate | `analytics_api_requests_total{status="5xx"}` / total > 5% for 5 minutes | Critical |

---

## 12. Open Questions & Risks

### Unresolved Decisions

1. **Real-time vs. batch**: Should the rollup job run in-process as an asyncio background task, or be triggered externally (e.g., via a cron-style `POST /internal/analytics/rollup`)? In-process is simpler but ties rollup to the web server lifecycle. Recommendation: Start in-process, migrate to external trigger when scaling to multiple backend instances.

2. **Content title resolution**: The `top_content_ids` list contains IDs but not titles. Should the API endpoint resolve titles by querying `T.video_metadata` / `T.app_single_table` (newsfeed posts)? This adds latency. Alternative: Store titles in the rollup row at aggregation time (stale if title changes). Recommendation: Resolve at read time with a parallel batch-get; cache titles in React Query.

3. **Audience GeoIP source**: Where does the country data come from? Options: (a) Parse `X-Forwarded-For` + GeoIP database in the view-tracking middleware. (b) Use Cloudfront's `CloudFront-Viewer-Country` header. Recommendation: (a) for dev mode with a free MaxMind GeoLite2 DB; (b) for production.

4. **Watch time tracking**: Currently the platform tracks view events but not watch duration. Should this ticket also add a `POST /ui/analytics/heartbeat` endpoint that the video player calls every 30 seconds? This adds complexity. Recommendation: Defer watch time to a follow-up ticket; use view count as the primary engagement metric for v1.

### Technical Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Billing table scan is slow for large datasets | Rollup job takes > 15 minutes | Add date-based GSI to billing table; process in parallel per creator |
| Rollup job conflicts with web server memory | OOM on small instances | Set `analytics_rollup_lookback_days=1` in production; run full backfill off-hours |
| Recharts bundle size | Adds ~50KB gzipped to frontend bundle | Already used for other charts in the app; lazy-load analytics page |

### Dependency Risks

- **MON-003 not yet deployed**: If `creator_earnings.py` is not available, the revenue aggregation logic must be reimplemented. Mitigation: Review `creator_earnings.py` early; extract shared utility functions. <!-- VERIFIED: creator_earnings.py EXISTS and is deployed. get_earnings_summary() at line 47, get_earnings_transactions() at line 117. Router registered in main.py at line 100/363. This dependency risk is already mitigated. -->
- **Video view tracking not consistent**: If `T.video_views` is not populated for all view events, view counts will be underreported. Mitigation: Add view count validation in E2E tests.

---

## 13. Implementation Timeline

### Phase 1: Backend Foundation (Days 1-3)

| Day | Task |
|-----|------|
| 1 | Add settings, table definition, table handle. Create `app/services/creator_analytics.py` with rollup query functions. Create Pydantic models in `app/models.py`. |
| 2 | Create `app/services/analytics_rollup_job.py` -- implement source table scanners (billing, views, subscriptions, posts, ads, calls). Write daily aggregation logic. |
| 3 | Create `app/routers/creator_analytics.py` -- implement all 7 endpoints. Register router in `app/main.py`. Write unit tests. |

### Phase 2: Backend Polish + Background Job (Days 4-5)

| Day | Task |
|-----|------|
| 4 | Implement background rollup job (asyncio task in app startup). Add refresh endpoint with rate limiting. Add granularity aggregation (week/month). |
| 5 | Write comprehensive unit tests. Edge cases: empty data, date boundaries, cross-user isolation, rate limits. Fix bugs found during testing. |

### Phase 3: Frontend (Days 6-8)

| Day | Task |
|-----|------|
| 6 | Create `AnalyticsPage.tsx`, `SummaryCard`, `DateRangePicker`. Create API endpoints and TypeScript types. Add route to `App.tsx`, sidebar/mobile nav entries. |
| 7 | Create `ViewTrendsChart.tsx`, `RevenueBreakdownChart.tsx`, `SubscriberGrowthChart.tsx` using Recharts. Wire up React Query hooks with URL-param-driven date range. |
| 8 | Create `TopContentTable.tsx` and `AudienceDemographics.tsx`. Responsive layout tuning. Loading skeletons and empty states. |

### Phase 4: E2E Tests + Polish (Days 9-10)

| Day | Task |
|-----|------|
| 9 | Write `frontend/e2e/analytics.spec.ts` -- API tests (sections A + B) with seeded rollup data. |
| 10 | Write UI E2E tests (section C). Final integration testing. Performance testing with 365-day range. Documentation updates. |

---

## Codebase References

| Claim | Verified? | File:Line | Notes |
|-------|-----------|-----------|-------|
| `T.billing` table handle | Yes | `app/core/tables.py:22,146` | PK=pk, SK=sk. billing_table_name at settings.py:306 |
| `T.video_views` table handle | Yes | `app/core/tables.py:91,215` | video_views_table_name at settings.py:1180 |
| `T.subscriptions` table handle | Yes | `app/core/tables.py:36,160` | subscriptions_table_name at settings.py:1008 |
| `T.ad_impressions` table handle | Yes | `app/core/tables.py:93,217` | ad_impressions_table_name at settings.py:1188 |
| `T.call_billing_ledger` table handle | Yes | `app/core/tables.py:94,218` | call_billing_ledger_table_name at settings.py:1141 |
| `creator_earnings.py` service exists | Yes | `app/services/creator_earnings.py:1-208` | get_earnings_summary() at line 47, get_earnings_transactions() at line 117 |
| `creator_earnings` router exists | Yes | `app/routers/creator_earnings.py:1-62` | Prefix `/ui/earnings`, registered in main.py:106/429 |
| `require_ui_session` auth dependency | Yes | `app/services/sessions.py:283` | Used by creator_earnings_router at line 12,23,46 |
| `_bucket_limit()` rate limit function | Yes | `app/services/rate_limit.py:60` | Uses T.sessions for storage |
| Background task startup pattern | Yes | `app/main.py:326-327,366-370` | `app.add_event_handler("startup", ...)` |
| `TableDef` pattern for DDB init | Yes | `scripts/local-ddb-init.py:28-35` | `TableDef(name, partition_key, sort_key=None, gsi=[], attr_types={})` |
| Prometheus-style metrics in `app/metrics.py` | Yes | `app/metrics.py:1-1782+` | METRICS_ENABLED flag at line 16, noop pattern when not prod |
| `T.app_single_table` reference | **Partial** | `scripts/local-ddb-init.py:216-228` | Table exists in DDB init with pk/sk + 6 GSIs, but it is NOT wired as `T.app_single_table` in tables.py. Must access via `ddb.Table(S.app_single_table_name)` or add a handle. |
| Settings now exist | Yes | `app/core/settings.py:1334-1337` | `analytics_rollups_table_name`, `analytics_rollup_enabled`, `analytics_rollup_interval_seconds`, `analytics_rollup_lookback_days` |
| Tables handle now exists | Yes | `app/core/tables.py:97,221` | `T.analytics_rollups` field + wiring |
| AnalyticsRollups DDB table | Yes | `scripts/local-ddb-init.py:853-861` | With ByDateCreatedAt GSI, `created_at` numeric attr |
| `creator_analytics.py` service | Yes | `app/services/creator_analytics.py` | Queries `T.analytics_rollups`, has rollup job logic |
| `creator_analytics_router` registered | Yes | `app/main.py:109,432` | Import + `include_router` |
| Recharts in package.json | Yes | `frontend/package.json:64` | `"recharts": "^3.8.1"` |

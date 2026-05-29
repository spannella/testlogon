# PLATFORM-019: Analytics Engine

**Ticket**: PLATFORM-019
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 12-15 days

---

## 1. Overview & Motivation

### 1.1 Purpose

PLATFORM-019 replaces the placeholder analytics pipeline with a real computation engine. The codebase has a comprehensive analytics read layer: `app/services/creator_analytics.py` (~720 lines) serves overview, revenue, views, subscribers, top content, audience demographics, and per-content detail endpoints. The dashboard router (`app/routers/creator_analytics.py`) exposes these via `GET /ui/analytics/*`. The frontend `AnalyticsPage.tsx` and `ContentDetailPage.tsx` render charts and tables. However, the "write" side is hollow -- the `/refresh` endpoint returns success immediately without processing (line 307: "For now it serves as a rate-limited placeholder"), `upsert_daily_rollup()` exists but is never called from any event pipeline, and `engagement_rate` calculations use whatever value happens to be in the rollup row (which is never computed). This ticket builds the event ingestion pipeline, time-series rollup aggregation jobs, and admin platform-wide analytics view.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to see how many views my content received today so that I know what is performing. | Analytics overview shows `period_views` computed from real page view events. |
| Creator | As a creator, I want to see revenue broken down by source (subscriptions, tips, unlocks, shop) so that I understand my income. | Revenue chart shows time series with per-source breakdown summing to total. |
| Creator | As a creator, I want to see subscriber growth and churn over time so that I can evaluate retention strategies. | Subscribers chart shows new, cancelled, and net growth per period. |
| Creator | As a creator, I want to see engagement rate (likes + comments / views) for each piece of content so that I know what resonates. | Top content table shows engagement_rate as a real computed percentage, not 0.0. |
| Creator | As a creator, I want to trigger an analytics refresh so that I see up-to-date numbers. | POST `/refresh` triggers real rollup computation; data updates within 30 seconds. |
| Admin | As a platform admin, I want to see platform-wide analytics (total users, total revenue, active creators) so that I monitor business health. | Admin analytics dashboard shows aggregate metrics across all creators. |
| System | As the system, I want hourly rollup jobs to aggregate raw events into daily buckets so that read queries are fast. | Background job runs hourly; daily rollup rows are written to `T.analytics_rollups`. |

### 1.3 Why This Is Needed

Creators cannot make informed decisions about their content, pricing, or marketing without real analytics. The current dashboard displays whatever is in the rollup table, which is always empty because no process writes to it. The `/refresh` endpoint is a no-op. Engagement rate is meaningless (always 0.0 or whatever stale value exists). Revenue breakdowns show $0 unless manually seeded. Without real analytics, creators have no visibility into their business, which reduces platform stickiness and monetization.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Analytics read service | `app/services/creator_analytics.py` (~720 lines) | `get_overview()`, `get_revenue()`, `get_views()`, `get_subscribers()`, `get_top_content()`, `get_audience()`, `get_content_detail()` -- all read from `T.analytics_rollups` |
| Analytics write stubs | `app/services/creator_analytics.py:523-559` | `upsert_daily_rollup()` and `upsert_summary_sentinel()` exist but are never called from any event pipeline |
| Analytics router | `app/routers/creator_analytics.py` (~310 lines) | `GET /ui/analytics/{overview,revenue,views,subscribers,top-content,audience,content/{id}}`, `POST /ui/analytics/refresh` |
| Analytics rollups table | `T.analytics_rollups` (DDB) | PK: `CREATOR#{user_id}`, SK: `DAILY#{date}` or `SUMMARY`; GSI: ByDateCreatedAt |
| Analytics frontend | `frontend/src/pages/analytics/AnalyticsPage.tsx` | Overview cards, revenue chart, views chart, subscribers chart, top content table, audience demographics |
| Content detail page | `frontend/src/pages/analytics/ContentDetailPage.tsx` | Per-content view time series, revenue breakdown |
| Billing events | `app/services/billing_shared.py` | Wallet deposits, tips, unlocks, subscription payments -- all write LEDGER entries to `T.billing` |
| Newsfeed events | `app/routers/newsfeed.py` | Post creation, reactions, comments -- increment counters on post items |
| Video metadata | `T.video_metadata` | `view_count`, `like_count`, `comment_count` stored per video |
| Refresh endpoint | `app/routers/creator_analytics.py:288-307` | Rate-limited to 1 per 5 min; returns success immediately without processing |
| Settings | `app/core/settings.py` | `analytics_rollup_lookback_days` (default 90) |

### 2.2 Gaps

1. **No event ingestion** -- platform events (page views, tips, unlocks, subscriptions) are recorded in their respective tables but never fed into the analytics pipeline.
2. **No rollup computation** -- `upsert_daily_rollup()` exists but is never called. The daily rollup rows are always empty or stale.
3. **No background aggregation job** -- no scheduled task computes hourly/daily rollups from raw event data.
4. **Refresh is a no-op** -- `POST /refresh` logs a message and returns; no actual computation happens.
5. **Engagement rate is never computed** -- `get_top_content()` reads `engagement_rate` from rollup items, which are never populated. The field defaults to 0.0.
6. **No admin platform-wide view** -- analytics endpoints only serve per-creator data. No aggregate view for admins.
7. **No event tracking table** -- page views and content impressions have no storage mechanism. Other events (tips, subscriptions) are in billing/subscription tables but not in a normalized analytics event format.
8. **Revenue breakdown by source missing** -- `get_revenue()` reads `revenue_cents` from rollups but does not break down by source (tips, subscriptions, unlocks, shop sales).

---

## 3. Technical Design

### 3.1 DynamoDB Schema

#### 3.1.1 Analytics Events Table (new)

**Table name**: `analytics_events`
**PK**: `pk` (S), **SK**: `sk` (S)

Raw event storage for analytics-relevant actions. Events are written inline during API calls and consumed by the rollup job.

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `CREATOR#{creator_id}` | `EVT#{timestamp}#{event_id}` | Raw event | `event_type`, `content_id`, `content_type`, `viewer_id`, `amount_cents`, `currency`, `metadata` |

**GSI1** (`GSI1PK` / `GSI1SK`): Query events by date for rollup processing.
- `GSI1PK`: `DATE#{YYYY-MM-DD}`
- `GSI1SK`: `CREATOR#{creator_id}#{timestamp}`
- Projected: ALL

**TTL**: `ttl_epoch` -- events expire after 90 days (raw events are disposable once rolled up).

#### 3.1.2 Analytics Rollups Table (existing, extend)

Existing table: `T.analytics_rollups`
PK: `pk` (S), SK: `sk` (S)

Add new SK patterns for extended rollups:

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `CREATOR#{user_id}` | `DAILY#{date}` | Daily metrics (existing) | Extended with `revenue_by_source`, `engagement_rate`, `churn_count`, `retention_rate` |
| `CREATOR#{user_id}` | `WEEKLY#{year}-W{week}` | Weekly aggregate | Same fields as DAILY, aggregated |
| `CREATOR#{user_id}` | `MONTHLY#{year}-{month}` | Monthly aggregate | Same fields as DAILY, aggregated |
| `CREATOR#{user_id}` | `SUMMARY` | Lifetime totals (existing) | Extended with `total_revenue_cents`, `total_views`, `lifetime_churn_rate` |
| `PLATFORM` | `DAILY#{date}` | Platform-wide daily stats | `total_creators`, `total_users`, `total_revenue_cents`, `total_views`, `active_creators` |
| `PLATFORM` | `SUMMARY` | Platform lifetime stats | `total_users`, `total_creators`, `total_revenue_all_time_cents` |

#### 3.1.3 Daily Rollup Item (extended)

```json
{
  "pk": "CREATOR#alice@test.local",
  "sk": "DAILY#2026-05-29",
  "date_scope": "DATE#2026-05-29",
  "created_at": 1748520000,
  "updated_at": 1748523600,
  "total_views": 1523,
  "unique_viewers": 892,
  "new_subscribers": 12,
  "cancelled_subscribers": 3,
  "net_subscriber_change": 9,
  "total_subscribers": 456,
  "revenue_cents": 15800,
  "revenue_by_source": {
    "subscriptions": 8500,
    "tips": 4200,
    "unlocks": 2100,
    "shop": 1000
  },
  "top_content_ids": ["vid_abc123", "post_xyz789"],
  "content_metrics": {
    "vid_abc123": {"views": 450, "likes": 32, "comments": 8, "revenue_cents": 3200},
    "post_xyz789": {"views": 280, "likes": 45, "comments": 12, "revenue_cents": 1500}
  },
  "engagement_rate": 0.0842,
  "audience_countries": {"US": 520, "GB": 180, "DE": 95, "CA": 70},
  "audience_devices": {"desktop": 600, "mobile": 820, "tablet": 103},
  "churn_rate": 0.0066,
  "retention_rate": 0.9934
}
```

#### 3.1.4 TableDef Entry (analytics_events)

```python
TableDef(
    "analytics_events", "pk", "sk",
    gsis=[
        {"name": "GSI1", "pk": "GSI1PK", "sk": "GSI1SK"},
    ],
    ttl_field="ttl_epoch",
),
```

### 3.2 Event Ingestion

**New file: `app/services/analytics_events.py`** (~200 lines)

Lightweight event recording functions called inline from existing API handlers. Each writes a single item to `T.analytics_events` with 90-day TTL:

| Function | Parameters | Event Type Written |
|----------|------------|--------------------|
| `record_page_view(creator_id, content_id, content_type, viewer_id)` | creator, content, viewer | `page_view` |
| `record_revenue_event(creator_id, source, amount_cents, content_id, payer_id)` | creator, source, amount | `revenue` with `metadata.source` |
| `record_subscriber_event(creator_id, subscriber_id, action)` | creator, subscriber, new/cancelled/renewed | `subscriber_{action}` |
| `record_engagement_event(creator_id, content_id, content_type, action, actor_id)` | creator, content, like/comment/reaction/share | `engagement_{action}` |

All events share the same DDB item shape: `pk=CREATOR#{creator_id}`, `sk=EVT#{ts}#{evt_id}`, plus GSI1 keys `GSI1PK=DATE#{YYYY-MM-DD}`, `GSI1SK=CREATOR#{creator_id}#{ts}` for the rollup job to query by date.

### 3.3 Event Instrumentation Points

Add `record_*()` calls to existing handlers:

| Handler Location | Event Function | Trigger |
|------------------|----------------|---------|
| `app/routers/newsfeed.py` POST `/posts/{id}/reactions` | `record_engagement_event(author_id, post_id, "post", "reaction")` | User reacts to a post |
| `app/routers/newsfeed.py` POST `/posts/{id}/comments` | `record_engagement_event(author_id, post_id, "post", "comment")` | User comments on a post |
| `app/routers/newsfeed.py` POST `/posts/{id}/tip` | `record_revenue_event(author_id, "tip", amount)` | User tips a post |
| `app/routers/newsfeed.py` POST `/posts/{id}/unlock` | `record_revenue_event(author_id, "unlock", price)` | User unlocks a locked post |
| `app/routers/messaging.py` POST `/messages/{id}/tip` | `record_revenue_event(recipient_id, "tip", amount)` | User tips a message |
| `app/routers/messaging.py` POST `/messages/{id}/unlock` | `record_revenue_event(sender_id, "unlock", price)` | User unlocks a locked message |
| `app/routers/profile.py` GET `/profile/public/{id}` | `record_page_view(user_id, user_id, "profile")` | Profile page visited |
| `app/routers/video_listing.py` GET `/videos/{id}` | `record_page_view(owner_id, video_id, "video")` | Video page visited |
| Subscription service (subscribe) | `record_subscriber_event(creator_id, subscriber_id, "new")` | New subscription |
| Subscription service (cancel) | `record_subscriber_event(creator_id, subscriber_id, "cancelled")` | Subscription cancelled |
| `app/routers/catalog.py` POST purchase | `record_revenue_event(creator_id, "shop", amount)` | Shop item purchased |

### 3.4 Rollup Computation Engine

**New file: `app/services/analytics_rollup_engine.py`** (~300 lines)

Background job that aggregates raw events into daily, weekly, and monthly rollups.

**Key functions**:

| Function | Purpose |
|----------|---------|
| `run_rollup_loop()` | Async background loop; runs `compute_daily_rollups()` every hour (`ROLLUP_INTERVAL_SECONDS = 3600`) |
| `compute_daily_rollups(date_str)` | Query all events for the date via GSI1 (`DATE#{YYYY-MM-DD}`), group by creator, compute per-creator and platform-wide rollups, write via `upsert_daily_rollup()` |
| `_compute_creator_daily(creator_id, events, date_str)` | Aggregate events into a single rollup dict: `total_views`, `unique_viewers`, `new_subscribers`, `cancelled_subscribers`, `revenue_cents`, `revenue_by_source` (dict), `engagement_rate`, `content_metrics` (per-content views/likes/comments/revenue, capped at 50 entries), `audience_countries`, `churn_rate` |
| `_query_date_events(date_str)` | Paginated GSI1 query returning all events for a date (1000 per page, loop on `LastEvaluatedKey`) |
| `_compute_platform_daily(creator_events, date_str)` | Sum `total_views`, `total_revenue_cents`, `active_creators` across all creators |
| `_upsert_platform_daily(date_str, data)` | Write platform-wide rollup row (`pk=PLATFORM`, `sk=DAILY#{date}`) to `T.analytics_rollups` |

**Engagement rate formula**: `engagement_actions / views` where engagement_actions = count of `engagement_*` events.
**Churn rate formula**: `cancelled_subscribers / max(new_subscribers + cancelled_subscribers, 1)`.

### 3.5 Refresh Endpoint Enhancement

**Modify `app/routers/creator_analytics.py`**:

Replace the placeholder refresh (line 307: "it serves as a rate-limited placeholder") with a call to `compute_daily_rollups()` for today and yesterday. Keep existing rate limit (1 per 5 minutes). Import `compute_daily_rollups` from `analytics_rollup_engine`. Return `AnalyticsRefreshOut(ok=True, refreshed_at=now_ts())`.

### 3.6 Admin Platform Analytics

**New endpoints in `app/routers/creator_analytics.py`**:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/admin/analytics/overview` | `require_admin_session` | Platform-wide overview (total users, revenue, creators, active) |
| `GET` | `/ui/admin/analytics/revenue` | `require_admin_session` | Platform-wide revenue time series |
| `GET` | `/ui/admin/analytics/creators` | `require_admin_session` | Top creators by revenue/views with time range |

### 3.7 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Analytics Engine (PLATFORM-019) --

class AnalyticsRefreshOut(BaseModel):
    ok: bool = True
    refreshed_at: int = 0

class AnalyticsEventIn(BaseModel):
    event_type: str = Field(..., pattern="^(page_view|engagement_like|engagement_comment|engagement_reaction|engagement_share)$")
    content_id: str = Field(default="", max_length=100)
    content_type: str = Field(default="", max_length=50)
    metadata: Optional[Dict[str, str]] = None

class RevenueBySourceOut(BaseModel):
    subscriptions: int = 0
    tips: int = 0
    unlocks: int = 0
    shop: int = 0
    other: int = 0

class AdminPlatformOverviewOut(BaseModel):
    total_users: int = 0
    total_creators: int = 0
    active_creators_today: int = 0
    total_revenue_cents: int = 0
    period_revenue_cents: int = 0
    period_views: int = 0
    currency: str = "USD"

class AdminTopCreatorOut(BaseModel):
    creator_id: str
    display_name: str = ""
    period_revenue_cents: int = 0
    period_views: int = 0
    subscriber_count: int = 0

class AdminCreatorsOut(BaseModel):
    creators: List[AdminTopCreatorOut] = Field(default_factory=list)
```

### 3.8 Frontend Changes

**Modify `frontend/src/pages/analytics/AnalyticsPage.tsx`** (~40 lines added):

- Add "Revenue by Source" breakdown chart (pie/donut) using `revenue_by_source` from overview.
- Add engagement rate display in top content table.
- Wire "Refresh" button to POST `/ui/analytics/refresh` (existing button, ensure it shows loading state).
- Add churn/retention metrics card.

**New file: `frontend/src/pages/admin/AdminAnalyticsPage.tsx`** (~200 lines):

Admin-only page showing platform-wide analytics:

```
AdminAnalyticsPage
├── Overview Cards
│   ├── Total Users
│   ├── Total Creators
│   ├── Active Creators (today)
│   ├── Period Revenue
│   └── Period Views
├── Revenue Time Series Chart (platform-wide)
├── Top Creators Table
│   └── Creator name, revenue, views, subscribers
```

**Add to `frontend/src/App.tsx`**:

```typescript
<Route path="/admin/analytics" element={<AdminAnalyticsPage />} />
```

### 3.9 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/analytics_events.py` | Event ingestion functions | ~200 |
| `app/services/analytics_rollup_engine.py` | Rollup computation engine | ~300 |
| `frontend/src/pages/admin/AdminAnalyticsPage.tsx` | Admin analytics page | ~200 |
| `frontend/src/api/endpoints/admin-analytics.ts` | Admin analytics API wrappers | ~30 |
| `frontend/e2e/analytics-engine.spec.ts` | E2E tests | ~500 |

### 3.10 Files to Modify

| File | Change |
|------|--------|
| `app/routers/creator_analytics.py` | Replace refresh placeholder; add admin endpoints |
| `app/services/creator_analytics.py` | Ensure read functions handle `revenue_by_source`, `engagement_rate`, `churn_rate` from rollup items |
| `app/main.py` | Register rollup background task at startup; register admin analytics router |
| `app/models.py` | Add analytics Pydantic models |
| `app/core/settings.py` | Add `analytics_events_table_name`, `analytics_rollup_interval_seconds` settings |
| `app/core/tables.py` | Add `T.analytics_events` table handle |
| `scripts/local-ddb-init.py` | Add `analytics_events` TableDef with GSI1 and TTL |
| `app/routers/newsfeed.py` | Add `record_engagement_event()` calls on reaction/comment/tip/unlock |
| `app/routers/messaging.py` | Add `record_revenue_event()` calls on tip/unlock |
| `app/routers/profile.py` | Add `record_page_view()` on public profile view |
| `frontend/src/pages/analytics/AnalyticsPage.tsx` | Add revenue breakdown chart, engagement rate column, churn metrics |
| `frontend/src/api/types.ts` | Add admin analytics TypeScript types |
| `frontend/src/App.tsx` | Add admin analytics route |
| `frontend/src/components/layout/Sidebar.tsx` | Add admin analytics link (admin only) |

---

## 4. Rollup Aggregation Architecture

### 4.1 Time-Series Hierarchy

```
Raw Events (90-day TTL)
    │
    ▼  (hourly background job)
Daily Rollups (DAILY#{date})
    │
    ▼  (weekly job, Sunday midnight UTC)
Weekly Rollups (WEEKLY#{year}-W{week})
    │
    ▼  (monthly job, 1st of month UTC)
Monthly Rollups (MONTHLY#{year}-{month})
    │
    ▼  (updated on each daily rollup)
Summary Sentinel (SUMMARY) — lifetime totals
```

### 4.2 Rollup Idempotency

Rollup computation is idempotent: re-running for the same date overwrites the daily row with fresh aggregates from raw events. This means:
- Hourly runs refine the current day's numbers.
- The `/refresh` endpoint can safely re-trigger computation.
- Late-arriving events (e.g., webhook-delayed subscription events) are captured on the next run.

### 4.3 Engagement Rate Calculation

Currently hardcoded to 0.0. New formula:

```
engagement_rate = (likes + comments + reactions + shares) / views
```

Per-content: computed from `content_metrics[cid]` in the daily rollup.
Per-creator: computed as total engagement actions / total views across all content for the period.

### 4.4 Churn Rate Calculation

```
churn_rate = cancelled_subscribers / (new_subscribers + cancelled_subscribers)
retention_rate = 1 - churn_rate
```

If no subscriber activity: churn_rate = 0, retention_rate = 1.0.

### 4.5 Platform Rollup

Platform-wide daily rollup (PK=`PLATFORM`, SK=`DAILY#{date}`) aggregates across all creators. Used by admin analytics dashboard. Updated during the same rollup job that processes creator rollups.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/analytics-engine.spec.ts`

### Section 535: Analytics Event Ingestion API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 535.1 | Page view event is recorded | GET public profile; verify event written to analytics_events table (DDB query) |
| 535.2 | Tip revenue event is recorded | POST tip on a message; verify revenue event with `source=tip`, `amount_cents` |
| 535.3 | Reaction engagement event is recorded | POST reaction on a post; verify engagement_reaction event |
| 535.4 | Subscriber event is recorded on subscription | Subscribe to a plan; verify subscriber_new event |

### Section 536: Rollup Computation API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 536.1 | Refresh endpoint triggers real computation | Seed events via API actions; POST `/ui/analytics/refresh`; 200; GET overview returns non-zero `period_views` |
| 536.2 | Revenue breakdown by source is populated | Seed tip + subscription events; refresh; GET revenue; `revenue_by_source` has non-zero `tips` and `subscriptions` |
| 536.3 | Engagement rate is computed correctly | Seed 10 views + 3 reactions; refresh; GET top-content; `engagement_rate` is approximately 0.3 |
| 536.4 | Refresh rate limiting returns 429 | POST refresh; immediately POST again; 429 |

### Section 537: Analytics Dashboard API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 537.1 | Overview returns period metrics | GET `/ui/analytics/overview?from=2026-05-28&to=2026-05-29`; response has `period_views`, `period_revenue_cents` |
| 537.2 | Subscribers endpoint returns growth data | GET `/ui/analytics/subscribers`; response has `time_series` with `new_subscribers`, `cancelled` |
| 537.3 | Top content includes engagement rate | GET `/ui/analytics/top-content`; response items have `engagement_rate` field that is not 0.0 (after seeding) |
| 537.4 | Content detail returns per-content metrics | GET `/ui/analytics/content/{id}`; response has `view_time_series`, `revenue_breakdown` |

### Section 538: Admin Platform Analytics API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 538.1 | Admin overview returns platform-wide metrics | Root GET `/ui/admin/analytics/overview`; response has `total_creators`, `period_revenue_cents`, `period_views` |
| 538.2 | Admin top creators returns sorted list | Root GET `/ui/admin/analytics/creators`; response has `creators` array sorted by `period_revenue_cents` desc |
| 538.3 | Non-admin cannot access admin analytics | Alice GET `/ui/admin/analytics/overview`; 403 |
| 538.4 | Admin revenue time series returns daily data | Root GET `/ui/admin/analytics/revenue?from=2026-05-28&to=2026-05-29`; response has time_series array |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| `GET /ui/analytics/*` | `require_ui_session` | Creator sees own analytics only |
| `POST /ui/analytics/refresh` | `require_ui_session` | Creator triggers own refresh only |
| `GET /ui/admin/analytics/*` | `require_admin_session` | Admin/Root only |
| Page view recording | None (inline) | Implicit from API call context |

### 6.2 Data Isolation

- Creators can only query their own analytics data (PK includes their user_sub).
- Admin endpoints aggregate across creators but do not expose individual user identities to non-admin roles.
- Raw events in `analytics_events` table include `viewer_id` but this is never exposed via the analytics read API (only aggregated counts).

### 6.3 Privacy

- Page view events record `viewer_id` only for authenticated users; anonymous views use "anon".
- Viewer IDs are used only for unique viewer counting; they are not exposed in API responses.
- Raw events have 90-day TTL; they are automatically deleted by DDB TTL after rollup.

### 6.4 Rate Limiting

- Analytics refresh: max 1 per user per 5 minutes (existing).
- Analytics read endpoints: max 60 per user per minute.
- Admin analytics: max 30 per admin per minute.
- Event ingestion is inline (no separate rate limit; bounded by the rate of the triggering API call).

### 6.5 DDB Cost Optimization

- Raw events are write-heavy but short-lived (90-day TTL).
- Rollup reads are the hot path; daily rollups are a single DDB get_item per date.
- GSI1 on events is used only by the rollup job (hourly, batch scan).
- Content metrics in rollup items are capped at 50 entries to prevent item size explosion.

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/creator_analytics.py` | Exists | Read layer; `upsert_daily_rollup()`, `upsert_summary_sentinel()` |
| `app/routers/creator_analytics.py` | Exists (modify) | Refresh endpoint; admin endpoints |
| `T.analytics_rollups` table | Exists | Daily/weekly/monthly rollup storage |
| `T.analytics_events` table | New | Raw event storage |
| `app/routers/newsfeed.py` | Exists (modify) | Add engagement/revenue event recording |
| `app/routers/messaging.py` | Exists (modify) | Add revenue event recording (tips/unlocks) |
| `app/routers/profile.py` | Exists (modify) | Add page view recording |
| `frontend/src/pages/analytics/AnalyticsPage.tsx` | Exists (modify) | Add revenue breakdown, engagement rate |
| `app/main.py` | Exists (modify) | Register rollup background task |

---

## 8. Acceptance Criteria

1. Platform events (page views, tips, reactions, comments, subscriptions) are recorded as raw analytics events.
2. Background rollup job runs hourly and computes daily aggregates from raw events.
3. `/refresh` endpoint triggers real rollup computation (not a no-op).
4. Revenue breakdown shows per-source amounts (subscriptions, tips, unlocks, shop).
5. Engagement rate is computed as (likes + comments + reactions) / views, not hardcoded to 0.0.
6. Subscriber growth/churn metrics are computed from real subscriber events.
7. Weekly and monthly rollups aggregate from daily rollups.
8. Admin platform-wide analytics dashboard shows aggregate metrics.
9. Raw events expire after 90 days via DDB TTL.
10. Non-admin users cannot access admin analytics endpoints (403).
11. All 16 E2E tests pass.
12. Rollup computation is idempotent (re-running produces the same result).

# FIN-012: Engagement Rate Calculation

**Ticket**: FIN-012
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 6-8 days

---

## 1. Overview & Motivation

### 1.1 Purpose

FIN-012 replaces the hardcoded `0.0` engagement rate in `creator_analytics.py` with a real calculation. The current code at line 610-613 computes a per-content engagement rate as `(likes + comments) / views`, but the platform-level engagement rate for a creator (across all content) is not calculated, and there is no formula that accounts for shares, tips, follower count, or posting frequency. This ticket implements a comprehensive engagement rate system with per-post calculation, rolling averages, historical trending via analytics rollups, and optional display on public profiles.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to see my engagement rate. | Analytics dashboard shows engagement rate as a percentage with trend indicator. |
| Creator | As a creator, I want to see engagement rate per post. | Each content item in analytics shows its own engagement rate. |
| Creator | As a creator, I want to see how my engagement rate trends over time. | Time-series chart shows engagement rate by day/week/month. |
| Creator | As a creator, I want to compare my engagement to the platform average. | Benchmark card shows my rate vs. platform average and category average. |
| Creator | As a creator, I want to choose whether my engagement rate shows on my public profile. | Toggle in settings; when enabled, rate appears on public profile. |
| Viewer | As a viewer, I want to see a creator's engagement rate on their profile. | If enabled, engagement rate badge visible on creator's public profile page. |
| System | Engagement rate must be recalculated on each analytics rollup. | Daily rollup job updates engagement rate for all active creators. |
| Admin | As an admin, I want to see platform-wide engagement benchmarks. | Admin dashboard shows average, median, and distribution of engagement rates. |

### 1.3 Why This Is Needed

Engagement rate is the single most important metric for creator performance. It tells creators whether their content resonates with their audience. The current implementation returns `0.0` everywhere because:

1. The per-content formula `(likes + comments) / views` at `creator_analytics.py:610` works but is limited to individual content items. There is no creator-level aggregate.
2. The formula does not account for shares, tips, or follower count -- factors that distinguish high-engagement creators from those who merely get views.
3. There is no historical tracking of engagement rate, so trends are invisible.
4. Platform benchmarks do not exist, so creators have no context for their numbers.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Per-content engagement | `app/services/creator_analytics.py:610-613` | `engagement_rate = (likes + comments) / views` -- per-content only |
| Content detail | `app/services/creator_analytics.py:565-638` | `get_content_detail` returns engagement_rate per content item |
| Top content resolver | `app/services/creator_analytics.py:357-421` | `_resolve_content_details` returns views, likes, comments per content |
| Analytics overview | `app/services/creator_analytics.py:192-230` | `get_overview` returns period views, revenue, subscribers -- no engagement |
| Analytics rollups | `app/services/creator_analytics.py:523-563` | `upsert_daily_rollup` updates daily analytics data |
| Summary sentinel | `app/services/creator_analytics.py:544-563` | `upsert_summary_sentinel` stores cumulative analytics |
| Analytics models | `app/models.py:2612-2748` | `AnalyticsOverviewOut`, `ContentAnalyticsOut` with `engagement_rate: float` |
| Newsfeed posts | `app/services/newsfeed.py` | Post metadata with `like_count`, `comment_count`, `view_count`, `share_count` |
| Video metadata | DDB `video_metadata` table | `view_count`, `like_count`, `comment_count` |
| Followers | `app/services/followers.py` | `get_follower_count(user_id)` |

### 2.2 Current Engagement Rate Code

From `app/services/creator_analytics.py:610-613`:

```python
engagement_rate = round(
    (like_count + comment_count) / total_views if total_views > 0 else 0.0,
    4,
)
```

This is per-content only. The creator-level engagement rate (across all content) is returned as `0.0` in the overview response (not calculated).

### 2.3 Gaps

1. **No creator-level engagement rate** -- only per-content calculation exists.
2. **Formula is incomplete** -- does not include shares, tips, or follower count.
3. **No historical tracking** -- engagement rate not stored in daily rollups.
4. **No platform benchmarks** -- no average/median calculations across all creators.
5. **No public profile display** -- no toggle or display component.
6. **No time-series data** -- no chart-friendly engagement data over time.

---

## 3. Technical Design

### 3.1 Engagement Rate Formula

#### 3.1.1 Per-Post Engagement Rate

```
post_engagement = (likes + comments + shares + (tips > 0 ? 1 : 0)) / impressions * 100
```

Where:
- `likes`: total like/reaction count on the post
- `comments`: total comment count
- `shares`: total share/repost count
- `tips > 0 ? 1 : 0`: binary indicator that the post received at least one tip (tips are high-signal engagement)
- `impressions`: total view/impression count (denominator)

If `impressions == 0`, the engagement rate is `0.0`.

#### 3.1.2 Creator-Level Engagement Rate (Rolling)

```
creator_engagement = sum(post_engagements) / count(posts_in_period) * 100

where:
  post_engagements = sum(likes + comments + shares + tip_indicators) for all posts in period
  posts_in_period = number of posts published within the period
```

Simplified:

```
creator_engagement = total_interactions / (follower_count * posts_in_period) * 100
```

Where:
- `total_interactions` = sum of (likes + comments + shares + tip_count) across all posts in the period
- `follower_count` = current follower count (from followers service)
- `posts_in_period` = number of posts published in the period

If `follower_count == 0` or `posts_in_period == 0`, the rate is `0.0`.

This formula rewards:
- Higher interaction counts relative to audience size
- Consistent posting (more posts = lower rate if engagement doesn't scale)
- Tip engagement (high-value signal)

#### 3.1.3 Period Selection

- **Default period**: Last 30 days
- **Configurable**: 7, 14, 30, 60, 90 days
- **Stored**: Daily rollup includes engagement rate calculated over trailing 30 days

### 3.2 Data Model Extensions

#### 3.2.1 Analytics Rollup Enhancement

Extend the existing daily rollup record (PK: `ANALYTICS#{user_id}`, SK: `{date}`) with:

| Field | Type | Description |
|-------|------|-------------|
| `engagement_rate` | N | Creator-level engagement rate (trailing 30d) |
| `total_interactions` | N | Sum of likes + comments + shares + tips in this date |
| `post_count` | N | Number of posts published on this date |
| `engagement_likes` | N | Total likes on this date |
| `engagement_comments` | N | Total comments on this date |
| `engagement_shares` | N | Total shares on this date |
| `engagement_tips` | N | Number of tips received on this date |

#### 3.2.2 Summary Sentinel Enhancement

Extend the summary sentinel (PK: `ANALYTICS#{user_id}`, SK: `SUMMARY`) with:

| Field | Type | Description |
|-------|------|-------------|
| `engagement_rate_30d` | N | Trailing 30-day engagement rate |
| `engagement_rate_7d` | N | Trailing 7-day engagement rate |
| `total_posts` | N | All-time post count |
| `show_engagement_public` | BOOL | Whether to display on public profile |

#### 3.2.3 Platform Benchmarks (App Single Table)

**PK**: `PLATFORM_BENCHMARKS`, **SK**: `ENGAGEMENT#{date}`

| Field | Type | Description |
|-------|------|-------------|
| `date` | S | `YYYY-MM-DD` |
| `average_rate` | N | Platform average engagement rate |
| `median_rate` | N | Platform median engagement rate |
| `p25_rate` | N | 25th percentile |
| `p75_rate` | N | 75th percentile |
| `sample_size` | N | Number of creators with data |
| `category_averages` | M | Map of `{category: rate}` |
| `computed_at` | N | Computation timestamp |

### 3.3 Backend Service Extension

**Extend**: `app/services/creator_analytics.py` (~200 additional lines)

```python
# -- Engagement Rate Calculation (FIN-012) --

def calculate_post_engagement_rate(
    likes: int,
    comments: int,
    shares: int,
    tip_count: int,
    impressions: int,
) -> float:
    """Calculate engagement rate for a single post.

    Formula: (likes + comments + shares + min(tip_count, 1)) / impressions * 100
    Returns 0.0 if impressions == 0.
    """
    if impressions <= 0:
        return 0.0
    interactions = likes + comments + shares + min(tip_count, 1)
    return round(interactions / impressions * 100, 4)


def calculate_creator_engagement_rate(
    user_id: str,
    period_days: int = 30,
) -> Dict[str, Any]:
    """Calculate creator-level engagement rate over a period.

    Queries posts and interactions within the period.
    Uses follower count as denominator normalizer.

    Returns: {
        engagement_rate, total_interactions, follower_count,
        posts_in_period, period_days, likes, comments, shares, tips
    }
    """
    ...


def get_engagement_time_series(
    user_id: str,
    from_date: str,
    to_date: str,
    granularity: str = "day",
) -> List[Dict[str, Any]]:
    """Get engagement rate time series from daily rollups.

    Returns: [{date, engagement_rate, interactions, post_count}]
    """
    ...


def compute_platform_benchmarks(date_str: str = "") -> Dict[str, Any]:
    """Compute platform-wide engagement benchmarks.

    Scans all creator summary sentinels, calculates average, median, percentiles.
    Called by daily job.

    Returns: {average_rate, median_rate, p25_rate, p75_rate, sample_size}
    """
    ...


def get_platform_benchmarks(date_str: str = "") -> Dict[str, Any]:
    """Get most recent platform benchmarks."""
    ...


def set_public_engagement_visibility(user_id: str, visible: bool) -> None:
    """Toggle whether engagement rate is shown on public profile."""
    ...


def get_public_engagement(user_id: str) -> Optional[Dict[str, Any]]:
    """Get engagement rate for public profile display.

    Returns None if user has opted out.
    Returns {engagement_rate_30d, engagement_rate_7d} if opted in.
    """
    ...


def update_daily_engagement_rollup(user_id: str, date_str: str) -> None:
    """Update the engagement fields in the daily analytics rollup.

    Called by the analytics rollup job after aggregating daily interactions.
    """
    ...
```

### 3.4 Backend Router Extension

**Extend**: `app/routers/creator_analytics.py` (~80 additional lines)

### 3.5 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/analytics/engagement` | `require_ui_session` | Get creator engagement rate with breakdown |
| `GET` | `/ui/analytics/engagement/history` | `require_ui_session` | Get engagement time-series |
| `GET` | `/ui/analytics/engagement/benchmarks` | `require_ui_session` | Get platform benchmarks |
| `PUT` | `/ui/analytics/engagement/public` | `require_ui_session` | Toggle public profile display |
| `GET` | `/api/creators/{user_id}/engagement` | Public | Get public engagement rate (if enabled) |
| `POST` | `/internal/analytics/engagement/compute-benchmarks` | Internal | Compute platform benchmarks (daily job) |

### 3.6 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Engagement Rate Calculation (FIN-012) --

class EngagementRateOut(BaseModel):
    engagement_rate: float = 0.0
    period_days: int = 30
    total_interactions: int = 0
    follower_count: int = 0
    posts_in_period: int = 0
    likes: int = 0
    comments: int = 0
    shares: int = 0
    tips: int = 0
    trend: str = ""  # "up", "down", "stable"
    trend_delta: float = 0.0  # change from previous period

class EngagementTimeSeriesItem(BaseModel):
    date: str
    engagement_rate: float = 0.0
    interactions: int = 0
    post_count: int = 0

class EngagementTimeSeriesOut(BaseModel):
    items: List[EngagementTimeSeriesItem] = Field(default_factory=list)

class EngagementBenchmarksOut(BaseModel):
    average_rate: float = 0.0
    median_rate: float = 0.0
    p25_rate: float = 0.0
    p75_rate: float = 0.0
    sample_size: int = 0
    my_rate: float = 0.0
    my_percentile: str = ""  # "top 10%", "above average", etc.
    category_averages: Dict[str, float] = Field(default_factory=dict)

class EngagementPublicToggleIn(BaseModel):
    visible: bool

class EngagementPublicOut(BaseModel):
    engagement_rate_30d: float = 0.0
    engagement_rate_7d: float = 0.0
    visible: bool = False
```

### 3.7 Integration with Analytics Rollup

The existing `upsert_daily_rollup` function in `creator_analytics.py:523` writes daily rollup records. Extend it to include engagement fields:

```python
def upsert_daily_rollup(user_id: str, date_str: str, data: Dict[str, Any]) -> None:
    # ... existing logic ...
    # NEW: add engagement fields
    if "engagement_rate" not in data:
        data["engagement_rate"] = 0
    if "total_interactions" not in data:
        data["total_interactions"] = 0
    # ... write to DDB ...
```

After the daily rollup is written, call `update_daily_engagement_rollup` to compute the trailing engagement rate from the interaction data.

### 3.8 Frontend Components

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/analytics/EngagementSection.tsx` | Engagement section on analytics dashboard | ~250 |
| `frontend/src/components/shared/EngagementBadge.tsx` | Public profile engagement badge | ~40 |

**Component tree for EngagementSection**:

```
EngagementSection (within analytics dashboard)
├── Card: "Engagement Rate"
│   ├── Large rate display: "4.2%"
│   ├── Trend arrow: ↑ 0.3% from last period
│   ├── Period selector: 7d / 14d / 30d / 60d / 90d
│   └── Breakdown row
│       ├── Likes: 1,234
│       ├── Comments: 456
│       ├── Shares: 78
│       └── Tips: 23
├── Card: "Engagement Trend"
│   └── LineChart (engagement rate over time)
│       ├── X-axis: dates
│       ├── Y-axis: engagement rate (%)
│       └── Tooltip: date, rate, interactions
├── Card: "Platform Benchmarks"
│   ├── Your Rate vs. Average comparison bar
│   ├── Percentile badge: "Top 15%"
│   ├── Platform Average: 3.1%
│   ├── Platform Median: 2.8%
│   └── Category Average: 3.5% (if applicable)
└── Toggle: "Show engagement rate on public profile"
    └── Switch component with label
```

**EngagementBadge** (for public profile):

```
EngagementBadge
├── Sparkle icon
├── "4.2% engagement"
└── Tooltip: "30-day engagement rate based on likes, comments, shares, and tips"
```

### 3.9 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/analytics/EngagementSection.tsx` | Engagement dashboard section | ~250 |
| `frontend/src/components/shared/EngagementBadge.tsx` | Public profile badge | ~40 |
| `frontend/e2e/fin-engagement.spec.ts` | E2E tests | ~350 |

### 3.10 Files to Modify

| File | Change |
|------|--------|
| `app/services/creator_analytics.py` | Add engagement calculation, time-series, benchmarks functions |
| `app/routers/creator_analytics.py` | Add engagement endpoints |
| `app/models.py` | Add engagement models |
| `frontend/src/api/types.ts` | Add TypeScript interfaces |
| `frontend/src/api/endpoints/analytics.ts` | Add engagement API wrappers (or create new file) |
| `frontend/src/pages/analytics/AnalyticsPage.tsx` | Add EngagementSection to dashboard |

---

## 4. Benchmark Calculation

### 4.1 Daily Benchmark Job

A daily internal job calls `compute_platform_benchmarks`:

1. Scan all summary sentinels (PK `ANALYTICS#*`, SK `SUMMARY`).
2. Collect `engagement_rate_30d` from each.
3. Filter out creators with fewer than 5 posts in 30 days (too little data).
4. Calculate average, median, 25th percentile, 75th percentile.
5. Write to `PLATFORM_BENCHMARKS` record.

### 4.2 Percentile Labeling

| Percentile | Label |
|------------|-------|
| >= 90th | "Top 10%" |
| >= 75th | "Top 25%" |
| >= 50th | "Above Average" |
| >= 25th | "Average" |
| < 25th | "Below Average" |

### 4.3 Category Averages

If creators have content categories (e.g., "fitness", "cooking", "tech"), benchmarks can be computed per category. For v1, platform-wide benchmarks only. Category benchmarks are a future enhancement.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/fin-engagement.spec.ts`

### Section 583: Engagement Rate Calculation API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 583.1 | Engagement rate for creator with posts | Seed posts with likes/comments; GET engagement; engagement_rate > 0 |
| 583.2 | Engagement rate includes tip interactions | Seed post with tip; GET engagement; tips count > 0 and rate reflects it |
| 583.3 | Engagement rate is zero with no followers | Creator with 0 followers; GET engagement; engagement_rate = 0.0 |
| 583.4 | Period selector changes calculation window | GET engagement with period_days=7; different rate than period_days=30 |
| 583.5 | Per-post engagement rate returned in content detail | GET content detail; engagement_rate > 0 for post with interactions |

### Section 584: Engagement Time Series API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 584.1 | Time series returns engagement data points | Seed rollups with engagement; GET history; items array has date/rate entries |
| 584.2 | Time series filters by date range | Seed data on multiple dates; GET with range; only matching dates returned |
| 584.3 | Granularity groups data correctly | GET with granularity=week; fewer data points than daily |

### Section 585: Benchmarks and Public Profile API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 585.1 | Platform benchmarks returns aggregate stats | Seed benchmarks; GET benchmarks; average_rate > 0, sample_size > 0 |
| 585.2 | Benchmarks include my_percentile | GET benchmarks; my_percentile is non-empty string |
| 585.3 | Toggle public engagement on | PUT /engagement/public with visible=true; 200 |
| 585.4 | Public endpoint returns rate when enabled | Enable public; GET /api/creators/{id}/engagement; engagement_rate_30d > 0 |

### Section 586: Engagement UI (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 586.1 | Engagement section visible on analytics dashboard | Navigate to analytics; "Engagement Rate" card visible |
| 586.2 | Engagement rate displays as percentage | Rate card shows value with "%" suffix |
| 586.3 | Trend indicator shows direction | Trend arrow (up/down/stable) visible next to rate |
| 586.4 | Public profile toggle persists setting | Toggle switch; reload page; switch remains in toggled state |

### Section 587: Engagement Edge Cases (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 587.1 | Creator with 0 posts gets rate 0 | No posts in period; engagement_rate = 0.0 |
| 587.2 | Self-tipping doesn't inflate rate | Creator tips own post; tip_indicator still 0 for that post |
| 587.3 | Deleted post excluded from calculation | Delete a post with likes; recalculate; rate excludes it |
| 587.4 | Engagement rate capped at 100% | Post with more interactions than followers; rate capped at 100.0 |
| 587.5 | Public engagement off returns 404 | Disable public; GET public endpoint; 404 |

**Total E2E tests: 21**

---

## 6. API Request/Response Examples

**Get engagement rate** (curl):

```bash
curl -X GET "http://localhost:8000/ui/engagement?period_days=30" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_a; ui_access_token=eyJ..."
```

**Response (200)**:
```json
{
  "engagement_rate": 4.2,
  "total_interactions": 840,
  "total_posts": 20,
  "follower_count": 1000,
  "period_days": 30,
  "breakdown": {
    "likes": 500,
    "comments": 220,
    "shares": 80,
    "tips": 40
  },
  "trend": "up",
  "trend_delta": 0.8
}
```

**Get engagement time series** (curl):

```bash
curl -X GET "http://localhost:8000/ui/engagement/history?period_days=30&granularity=day" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_a; ui_access_token=eyJ..."
```

**Response (200)**:
```json
{
  "items": [
    {"date": "2026-05-01", "engagement_rate": 3.5, "interactions": 35},
    {"date": "2026-05-02", "engagement_rate": 4.1, "interactions": 41}
  ]
}
```

**Get platform benchmarks** (curl):

```bash
curl -X GET http://localhost:8000/ui/engagement/benchmarks \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_a; ui_access_token=eyJ..."
```

**Response (200)**:
```json
{
  "average_rate": 3.2,
  "median_rate": 2.8,
  "p25_rate": 1.5,
  "p75_rate": 5.0,
  "sample_size": 450,
  "my_rate": 4.2,
  "my_percentile": "top 25%"
}
```

---

## 7. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| No posts in period | 200 | — | engagement_rate = 0.0 | Normal; create posts |
| Invalid period_days | 422 | `validation_error` | "period_days must be 7, 14, 30, 60, or 90" | Use valid value |
| Public endpoint disabled | 404 | `not_public` | "Engagement data not available" | Creator hasn't opted in |
| Unauthenticated | 401 | `unauthorized` | "Authentication required" | Log in |
| Benchmark computation pending | 200 | — | Returns empty benchmarks; sample_size=0 | Wait for daily job |

---

## 8. Observability

### 8.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `engagement_rate_calculated_total` | Counter | `period` | Rate calculations |
| `engagement_benchmark_computed_total` | Counter | — | Benchmark computations |
| `engagement_public_enabled_total` | Counter | — | Public toggles |
| `engagement_rate_value` | Histogram | — | Distribution of rates |

### 8.2 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Benchmark job failed | Job didn't complete in 24h | Medium | Check job logs |
| Rate calculation errors | > 5% of calcs fail | High | Check DDB queries |
| Gaming detected | Rate > 50% for creator with > 100 followers | Medium | Review interactions |

---

## 9. Rollout Plan

### 9.1 Feature Flag

```python
engagement_rate_enabled: bool = os.environ.get("ENGAGEMENT_RATE_ENABLED", "true").lower() == "true"
```

### 9.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Backend | Deploy calculation logic; flag OFF | 2 days | Unit tests pass |
| Phase 2: Internal | Enable for internal; seed benchmark | 3 days | All 21 E2E pass |
| Phase 3: Canary 10% | Enable for 10% of creators | 3 days | Rates look reasonable |
| Phase 4: GA | Enable for all | Permanent | Benchmarks populated |

---

## 10. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Rate calculation | < 200ms | Query post interactions from analytics rollup (pre-aggregated) |
| Benchmark computation | < 30s for 10K creators | Batch scan; compute percentiles in-memory |
| Time series query | < 50ms | GSI on user_sub + date |
| Public endpoint | < 20ms | Single GetItem for cached rate |

---

## 11. Frontend Component Tree

```
EngagementSection (in analytics dashboard)
├── EngagementRateCard
│   ├── RateValue (large percentage display)
│   ├── TrendIndicator (up/down/stable arrow + delta)
│   └── PeriodSelector (7d, 14d, 30d, 60d, 90d)
├── EngagementChart (line chart)
│   ├── TimeSeriesData (rate over time)
│   └── GranularityToggle (day/week)
├── BreakdownCards (row)
│   ├── LikesCard
│   ├── CommentsCard
│   ├── SharesCard
│   └── TipsCard
├── BenchmarkComparison
│   ├── PercentileBar (visual percentile position)
│   ├── PlatformAverage (reference line)
│   └── MyPosition (highlighted)
└── PublicProfileToggle
    ├── Switch (on/off)
    └── Description text
```

---

## 12. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| GET engagement | `require_ui_session` | Returns only caller's data |
| GET engagement/history | `require_ui_session` | Returns only caller's data |
| GET engagement/benchmarks | `require_ui_session` | Benchmarks are platform-wide but include caller's percentile |
| PUT engagement/public | `require_ui_session` | Only caller can toggle their own setting |
| GET /api/creators/{id}/engagement | Public (no auth) | Returns data only if creator has opted in |
| POST compute-benchmarks (internal) | Internal middleware | System job only |

### 6.2 Data Privacy

- Public engagement endpoint only returns data if `show_engagement_public = true`.
- Engagement rate alone does not expose sensitive information.
- Platform benchmarks are aggregated (no individual creator data exposed).

### 6.3 Gaming Prevention

- Engagement rate uses `impressions` (server-side counted) not self-reported views.
- Tip count is capped at 1 per post (binary indicator) to prevent self-tipping inflation.
- Benchmarks filter out creators with fewer than 5 posts in the period.

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/creator_analytics.py` | Exists | Analytics rollup framework, per-content engagement |
| `app/routers/creator_analytics.py` | Exists | Router to extend |
| `app/services/followers.py` | Exists | `get_follower_count` for denominator |
| `app/services/newsfeed.py` | Exists | Post metadata (likes, comments, shares) |
| Video metadata DDB table | Exists | Video engagement counts |
| Analytics rollup DDB records | Exists | Historical engagement storage |

---

## 8. Acceptance Criteria

1. Creator engagement rate is calculated using the formula: `(likes + comments + shares + tip_indicator) / (followers * posts_in_period) * 100`.
2. Per-post engagement rate accounts for likes, comments, shares, and tip presence.
3. Engagement rate is calculated for configurable periods (7, 14, 30, 60, 90 days).
4. Time-series data shows engagement rate trending over time.
5. Platform benchmarks provide average, median, and percentile comparison.
6. Public profile toggle controls whether engagement rate is visible to visitors.
7. Engagement rate is stored in daily analytics rollups for historical tracking.
8. Engagement rate is not `0.0` when a creator has posts with interactions.
9. All 16 E2E tests pass.

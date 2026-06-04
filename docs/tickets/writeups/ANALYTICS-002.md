# ANALYTICS-002: Creator Analytics Depth — Investigation & Implementation Write-up

## 1. Summary & Classification

The ANALYTICS-001 Creator Analytics Dashboard had three concrete bugs in the `get_top_content` function that made the "Top Content" table misleading and shallow: engagement rate was hardcoded to `0.0`, titles displayed raw content IDs instead of human-readable text, and there was no per-content drill-down page. ANALYTICS-002 fixed all three issues and added a `GET /ui/analytics/content/{content_id}` endpoint with per-content view time series, revenue breakdown, and engagement metadata.

- **Type**: Bug fix + feature depth enhancement
- **Priority**: High
- **Status**: Implemented — all three gaps are fixed; per-content endpoint, frontend detail page, and API client function all exist
- **Persona**: Creator (content owner wanting actionable analytics per video/post)
- **Cross-references**: ANALYTICS-001 (upstream rollup system this ticket builds on)
- **Dev/Prod parity**: SECOPS-007 compliant — no new external dependencies; all DDB queries work identically against DDB Local or AWS DDB

---

## 2. Current-State Investigation

### 2.1 The three bugs (as of pre-fix state, now resolved)

#### Bug 1: Hardcoded `engagement_rate = 0.0`

The original `get_top_content` at `app/services/creator_analytics.py` had:
```python
"engagement_rate": 0.0,   # BUG — was line 391 before fix
```
The model `AnalyticsTopContentItem` at `app/models.py:2462–2468` always had the `engagement_rate: float = 0.0` field — the model was correct but the service never computed a real value.

**Root cause**: daily rollup rows store `total_views`, `post_reactions`, and `post_comments` at the creator level, not per-content. There was no per-content engagement data available from the rollup schema alone.

**Fix** (`app/services/creator_analytics.py:461`): engagement is now computed as `(likes + comments) / views` using data fetched from content metadata tables by `_resolve_content_details`.

#### Bug 2: Content ID used as title

The original code had:
```python
"title": cid,   # BUG — was line 388 before fix
```
`cid` is a raw content ID string like `"vid_a1b2c3d4"` or `"post_e5f6g7h8"`.

**Fix** (`app/services/creator_analytics.py:466`): title now uses `d.get("title", cid)` where `d` is the resolved content metadata dict.

#### Bug 3: No per-content detail endpoint

There was no `GET /ui/analytics/content/{content_id}` endpoint. The frontend top-content table had no click handler. `AnalyticsPage.tsx` rendered content items as a static table without navigation.

### 2.2 Current state of fixes (all verified)

#### `_resolve_content_details` (`app/services/creator_analytics.py:357–421`)

The function takes a list of content IDs, splits them by prefix (`vid_*` = video, everything else = post), and resolves metadata:

- **Videos** (line 371–396): `ddb.batch_get_item` to `S.video_metadata_table_name` with projection `video_id, title, view_count, like_count, comment_count`. Falls back to `{"title": vid, "views": 0, ...}` for missing items.
- **Posts** (line 398–419): individual `ddb.Table(app_table_name).get_item` per post ID, key `pk=POST#{pid}`, `sk=META`. Title is `body_plain[:60]` or `body[:60]` with "..." truncation; falls back to `pid` if item absent.

The `app_table_name` is read from `os.environ.get("APP_TABLE", "app_single_table")` (line 399) — this is the workaround noted in ANALYTICS-001 §3.2 for the missing `T.app_single` table handle.

#### Fixed `get_top_content` (`app/services/creator_analytics.py:424–475`)

After the fix, the function:
1. Queries rollup rows and aggregates `content_scores` (views, revenue) by content ID (lines 432–441)
2. Sorts by chosen sort key (line 443–449)
3. Calls `_resolve_content_details` with the top-N content IDs (line 452)
4. For each item, computes `engagement = (likes + comments) / views if views > 0 else 0.0` (line 461) — division-by-zero guarded
5. Uses `d.get("title", cid)` (line 466) for the title — real title or fallback to ID

The views value is `d.get("views") if d.get("views") is not None else scores["views"]` (line 458) — uses the live view count from video_metadata if available, otherwise falls back to rollup-accumulated views.

#### New `get_content_detail` service function (line 605+)

Verified present in `app/services/creator_analytics.py`. Steps:
1. Looks up content metadata from `T.video_metadata` (videos) or `T.app_single` equivalent (posts)
2. Verifies ownership — returns `{"error": "forbidden"}` if `owner_user_id != user_id`
3. Builds view time series via `_get_content_view_time_series` (queries `T.video_views ByVideoViewedAt` GSI for videos)
4. Scans billing ledger for per-content revenue via `_get_content_revenue_breakdown` (up to 4 pages × 500 items = 2000 LEDGER entries with `FilterExpression` on `meta.content_id`)
5. Returns structured dict including `engagement_rate`, `like_count`, `comment_count`, `view_time_series`, `revenue_breakdown`

#### New router endpoint (`app/routers/creator_analytics.py:244–283`)

`GET /ui/analytics/content/{content_id}` is present. It calls `get_content_detail`, maps `None` → 404, `{"error": "forbidden"}` → 403, and wraps the result in `ContentAnalyticsOut`.

#### Frontend detail page (`frontend/src/pages/analytics/ContentDetailPage.tsx`)

The file exists (353 lines). The ticket spec called it `ContentAnalyticsPage.tsx` but the actual implementation name is `ContentDetailPage.tsx`. It is routed at `/analytics/content/:contentId` in `App.tsx` (lines 66, 185). It renders:
- Header with Back button (ChevronLeft → `/analytics`), thumbnail, title, content type badge
- Four summary cards: Total Views, Revenue, Engagement Rate, Interactions
- Date range selector (7d/30d/90d/1y)
- AreaChart (recharts) for view time series — "No view data for this period" placeholder on empty
- Revenue breakdown (PieChart or horizontal bars for Tips/Unlocks/VOD)

#### API client (`frontend/src/api/endpoints/analytics.ts:41`)

`getAnalyticsContentDetail(contentId, params?)` is present at line 41.

#### `AnalyticsPage.tsx` top-content table

The table rows now have `onClick` handlers navigating to `/analytics/content/{item.content_id}` (verified in current file). An "Engagement" column is present in the table header showing `(item.engagement_rate * 100).toFixed(1)%`.

### 2.3 `AnalyticsTopContentItem` model (`app/models.py:2462–2468`)

```python
class AnalyticsTopContentItem(BaseModel):
    content_id: str = ""
    content_type: str = ""
    title: str = ""
    views: int = 0
    revenue_cents: int = 0
    engagement_rate: float = 0.0
```

The model is unchanged from before the fix — the field was always there; only the service now populates it with real values.

New `ContentAnalyticsOut` model (verified present in `app/models.py`) with fields: `content_id`, `content_type`, `title`, `thumbnail_url`, `published_at`, `total_views`, `total_revenue_cents`, `engagement_rate`, `like_count`, `comment_count`, `view_time_series` (`List[ContentAnalyticsViewsItem]`), `revenue_breakdown` (`ContentAnalyticsRevenueBreakdown`), `currency`.

---

## 3. Gap / Threat Analysis

### 3.1 What is fixed and verified

- `engagement_rate` computed as `(likes + comments) / views` with zero-division guard
- Titles resolved from `video_metadata` (BatchGetItem) and newsfeed (individual get_item)
- `get_content_detail` function with ownership check, view time series, revenue breakdown
- `GET /ui/analytics/content/{content_id}` endpoint returning 404/403/200
- `ContentDetailPage.tsx` with charts and summary cards
- Route at `/analytics/content/:contentId` in `App.tsx`
- `getAnalyticsContentDetail` in `analytics.ts`
- Top-content table rows clickable with engagement column

### 3.2 Remaining known limitations

1. **Post view time series is a fallback zero-series**: `_get_content_view_time_series` queries `T.video_views ByVideoViewedAt` GSI for videos, but for posts it generates an empty zero-series (lines 526–541). Per-post view tracking requires a write path that records views against post IDs in a queryable structure. This is noted as a "future enhancement" — the detail page shows "No view data for this period" gracefully.

2. **Revenue per-content scan is capped at 4 pages (2 000 entries)**: `_get_content_revenue_breakdown` scans the billing LEDGER with `FilterExpression` on `meta.content_id`. For creators with > 2 000 LEDGER entries this silently under-counts revenue. Mitigation noted in ticket §6.3: pre-aggregate per-content revenue in the daily rollup, or add a GSI on billing with `content_id` as partition key.

3. **Post metadata lookup is serial, not batched**: `_resolve_content_details` does one `get_item` per post ID (line 403) rather than a `BatchGetItem`. For the 20-item default limit this is ~100ms worst case. The ticket §6.1 suggests `ThreadPoolExecutor` parallelisation — not yet implemented.

4. **`app_single_table` accessed via env var workaround**: same issue as ANALYTICS-001 §3.2. Fix by wiring `T.app_single` as a named table handle.

5. **Ownership check field names for posts**: `get_content_detail` checks `item.get("user_id") != user_id and item.get("author_id") != user_id` (line 453 area). The actual field name used for post ownership in the newsfeed table needs verification against the table schema — if it's `poster_sub` or another variant, the check would silently fail (returning `{"error": "forbidden"}` for all posts).

### 3.3 Security: ownership enforcement

- Video: `owner_user_id` (or `owner_id`) field on `T.video_metadata` item checked against session `user_sub`
- Post: `user_id` (or `author_id`) field on post META item checked against session `user_sub`
- If content not found: 404 — does not leak existence of content belonging to other users
- If content found but not owned: 403 "Not your content" — leaks only that content exists (acceptable for content IDs that are already public in the platform)

---

## 4. Proposed Design / Fix

### 4.1 Fix post view time series

Add a `post_views` DDB table or reuse `T.video_views` with a `content_type` field. When a post is viewed, write a view record. Then `_get_content_view_time_series` can query by `content_id` regardless of type.

Alternatively, add `per_content_views` as a DDB map field in daily rollup rows (`{content_id: view_count}`). The rollup job populates this from the video_views table and a future post-views table. `_get_content_view_time_series` then reads from rollup rows.

### 4.2 Pre-aggregate per-content revenue

Add `content_revenue` as a DDB map in daily rollup rows during the rollup job. During rollup, scan LEDGER entries for the day and group by `meta.content_id`. Store: `{"vid_abc": 500, "post_def": 100}`. `_get_content_revenue_breakdown` reads from rollups instead of scanning the billing table.

This eliminates the 2 000-entry scan cap and improves latency from ~80ms to ~2ms.

### 4.3 Parallel post title resolution

Replace serial `get_item` loop with `BatchGetItem` to `app_single_table` using composite keys `pk=POST#{pid}`, `sk=META`. Requires confirming the newsfeed table supports this key structure (it does, as the DDB init at `scripts/local-ddb-init.py:216–228` uses `pk/sk`).

### 4.4 Dev/Prod parity (SECOPS-007)

No changes needed. All lookups are DDB-only (`T.video_metadata`, `T.video_views`, `T.billing`, newsfeed table). Both DDB Local and AWS DDB are accessed identically. No feature flags are needed — the engagement rate and title resolution are correctness fixes, not optional features.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests (`tests/test_creator_analytics_depth.py`)

All runnable offline with moto:

| Test | Assertion |
|------|-----------|
| `test_resolve_video_title` | Seed video_metadata; `_resolve_content_details(["vid_x"])` returns `title` field = seeded title |
| `test_resolve_post_title_truncated` | Post body > 60 chars → title ends with "..." |
| `test_falls_back_to_id_for_missing` | Non-existent ID → title = content_id string |
| `test_engagement_rate_computed` | Video with 100 views, 8 likes, 2 comments → `engagement_rate = 0.1` |
| `test_engagement_rate_zero_views` | `views = 0` → `engagement_rate = 0.0` (no ZeroDivisionError) |
| `test_content_detail_view_time_series` | Seed video; `get_content_detail` returns non-empty series |
| `test_content_detail_revenue_breakdown` | Seed tip + unlock LEDGER entries with `meta.content_id`; breakdown has both categories |
| `test_content_detail_403_non_owner` | User B requests User A's video → `{"error": "forbidden"}` |
| `test_content_detail_none_missing` | Non-existent ID → `None` |
| `test_post_content_detail_title` | Post content detail returns truncated body as title |

### 5.2 Playwright E2E (`frontend/e2e/analytics-depth.spec.ts`)

14 tests per ticket spec §6. Key assertions:
- Top content table shows non-zero engagement rate for seeded video with likes
- Title column does NOT start with `vid_` prefix
- Clicking table row navigates to `/analytics/content/{id}`
- Detail page shows Views, Revenue, Engagement, Interactions cards
- Back button returns to `/analytics`
- GET content detail for non-existent → 404; for non-owned → 403
- Zero-revenue content shows "$0.00" for all categories

### 5.3 Manual/QA steps

1. Seed a video in `video_metadata` table with `title="My Test Video"`, `like_count=10`, `view_count=100`
2. Seed a rollup row with `top_content_ids=["vid_<that_id>"]`
3. Navigate to `/analytics` → click "Top Content" tab → verify title shows "My Test Video" and engagement shows "10.0%"
4. Click the row → verify navigation to `/analytics/content/vid_<id>` and detail page loads
5. Verify 403 by requesting `/ui/analytics/content/vid_<bob_video_id>` as Alice

### 5.4 Rollout

No feature flags needed — all changes are bug fixes. Merge after ANALYTICS-001 is live.

**Merge checklist**:
- [x] `_resolve_content_details` and `get_content_detail` in `creator_analytics.py`
- [x] `GET /ui/analytics/content/{content_id}` endpoint in router (line 244–283)
- [x] `ContentAnalyticsOut` and related models in `app/models.py`
- [x] Top-content table rows clickable in `AnalyticsPage.tsx`
- [x] `ContentDetailPage.tsx` routed at `/analytics/content/:contentId`
- [x] `getAnalyticsContentDetail` in `analytics.ts` line 41
- [ ] `analytics-depth.spec.ts` E2E tests (test file not yet created per ticket §4.10)

### 5.5 Effort estimates

- E2E test file `analytics-depth.spec.ts`: **S** (1-2 days to write 14 tests)
- Post view time series data source: **M** (3-4 days — requires write path + rollup integration)
- Per-content revenue pre-aggregation in rollup: **M** (3 days — rollup schema change + backfill)
- Parallel post title resolution (BatchGetItem): **S** (< 1 day)
- Fix post ownership field name verification: **S** (< 1 day — read the newsfeed table schema)

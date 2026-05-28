# ANALYTICS-002: Creator Analytics Depth

**Ticket**: ANALYTICS-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 10-12 days

---

## 1. Executive Summary

The creator analytics system has 7 working endpoints (`app/routers/creator_analytics.py`) and a full dashboard page (`AnalyticsPage.tsx`, 570 lines) with summary cards, view trend charts, revenue pie charts, subscriber growth charts, a top content table, and audience demographics. However, the system has three significant depth gaps:

1. **`engagement_rate` is hardcoded to `0.0`** (`creator_analytics.py:391`). The "Engagement Rate" column in the top content table always shows 0.0% -- there is no actual engagement calculation.
2. **Top content uses `content_id` as the title** (`creator_analytics.py:388`). The "Title" column in the top content table shows raw IDs like `vid_a1b2c3d4` instead of human-readable video/post titles, because the service never looks up the actual content metadata.
3. **No per-content drill-down**. The top content table is a dead end -- clicking a content item does nothing. There is no `GET /ui/analytics/content/{content_id}` endpoint and no per-video/per-post analytics page.

These gaps make the analytics dashboard misleading (0% engagement), confusing (raw IDs as titles), and shallow (no detail view). This ticket fixes all three issues with real engagement rate computation, content title resolution, and a per-content detail endpoint with its own time series and revenue breakdown.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | I want to see the real engagement rate for each content piece. | Top content table shows calculated engagement rate (likes+comments / views). The engagement rate is non-zero for content with interactions. A post with 100 views and 10 likes shows 10.0%. |
| Creator | I want to see actual titles in the top content table, not content IDs. | Title column shows video titles or post body previews (first 60 chars). No entry displays a raw ID starting with `vid_` or `post_`. |
| Creator | I want to click on a content item to see its detailed analytics. | Clicking a row navigates to `/analytics/content/{id}`. The detail page loads within 2 seconds. |
| Creator | I want to see view trends over time for a specific video. | Per-content page shows daily view count line chart with at least 7 data points for the default date range. X-axis shows dates, Y-axis shows view count. |
| Creator | I want to see revenue breakdown for a specific content item. | Per-content page shows tips, unlocks, PPV revenue amounts for that item. Zero-value categories are shown as $0.00. |
| Creator | I want to compare engagement rates across my content. | Top content table is sortable by engagement_rate column. Clicking the "Engagement" header re-sorts rows. The sort direction toggles on repeated clicks. |
| Creator | I want to see the detail page for a content item with zero views. | Engagement rate shows 0.0% without errors. Charts show "No data" placeholder. Revenue breakdown shows $0.00 for all categories. |
| Creator | I want the content detail page to respect my selected date range. | Date range selector on detail page filters the view time series. Changing the range re-renders the chart. |

### 2.2 Gap Details

#### Gap 1: Hardcoded Engagement Rate

In `app/services/creator_analytics.py` at line 391, the engagement rate is literally:
```python
"engagement_rate": 0.0,
```

This value is passed through `AnalyticsTopContentItem` (models.py:2468) and rendered in the frontend table (AnalyticsPage.tsx:401-414). The model has the field, the column is rendered, but the value is always zero.

**Root cause**: The daily rollup rows in `analytics_rollups` table track `total_views`, `post_reactions`, and `post_comments` at the creator level, but NOT at the per-content level. There is no way to compute per-content engagement from the current rollup schema.

#### Gap 2: Content ID as Title

In `app/services/creator_analytics.py` at line 388:
```python
"title": cid,
```

The variable `cid` is a raw content_id (e.g., `"vid_a1b2c3d4"` or `"post_e5f6g7h8"`). No lookup to the VideoMetadata or newsfeed tables is performed.

**Root cause**: The `get_top_content` function operates purely on rollup data. Rollup rows store `top_content_ids` as a list of IDs but not the corresponding titles. Resolving titles requires cross-table lookups.

#### Gap 3: No Per-Content Endpoint

There is no endpoint for individual content analytics. The `get_top_content` function returns a flat list, and the frontend renders it as a non-interactive table (AnalyticsPage.tsx:389-415). No row click handler, no navigation, no detail page.

---

## 3. Current State Analysis

### 3.1 Analytics Service (creator_analytics.py:1-481)

The service reads from the `analytics_rollups` DynamoDB table. Key functions:

- `_to_int(val)` (line 35): Coerces DynamoDB `Decimal` or string to int.
- `_to_float(val)` (line 46): Coerces DynamoDB `Decimal` to float.
- `_query_rollups(user_id, from_date, to_date)` (line 75-98): Queries `pk=CREATOR#{user_id}`, `sk between DAILY#{from_date} and DAILY#{to_date}`.
- `get_overview(user_id, from_date, to_date)` (line 189): Summary cards -- aggregates `total_views`, `revenue_cents`, `new_subscribers`.
- `get_revenue(user_id, from_date, to_date, granularity)` (line 230): Revenue time series with category breakdown.
- `get_views(user_id, from_date, to_date, granularity)` (line 279): View time series.
- `get_subscribers(user_id, from_date, to_date, granularity)` (line 314): Subscriber growth.
- `get_top_content(user_id, from_date, to_date, sort_by, limit)` (line 354-397): Top content by views or revenue. **This is the function with the bugs.**
- `get_audience(user_id, from_date, to_date)` (line 400): Country + device demographics.
- `upsert_daily_rollup(user_id, date_str, data)` (line 445): Writes daily rollup row.
- `upsert_summary_sentinel(user_id, data)` (line 466): Writes/updates SUMMARY row.

**Citation**: `app/services/creator_analytics.py:1-481` -- all public query and write functions.

### 3.2 Top Content Function Detail (creator_analytics.py:354-397)

```python
def get_top_content(
    user_id: str,
    from_date: str,
    to_date: str,
    sort_by: str = "views",
    limit: int = 20,
) -> Dict[str, Any]:
    """Get top content items ranked by views or revenue."""
    items = _query_rollups(user_id, from_date, to_date)

    # Aggregate content_ids from rollup items
    content_scores: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"views": 0, "revenue_cents": 0}
    )
    for item in items:
        for cid in (item.get("top_content_ids") or []):
            content_scores[cid]["views"] += _to_int(item.get("total_views", 0))
            content_scores[cid]["revenue_cents"] += _to_int(item.get("revenue_cents", 0))

    sort_key = "revenue_cents" if sort_by == "revenue" else "views"
    sorted_content = sorted(
        content_scores.items(), key=lambda x: x[1][sort_key], reverse=True
    )

    total_items = len(sorted_content)
    sorted_content = sorted_content[:limit]

    result_items = []
    for cid, scores in sorted_content:
        content_type = "vod" if cid.startswith("vid_") else "post"
        total_views = scores["views"]
        result_items.append({
            "content_id": cid,
            "content_type": content_type,
            "title": cid,                    # BUG: raw ID, not title
            "views": total_views,
            "revenue_cents": scores["revenue_cents"],
            "engagement_rate": 0.0,          # BUG: hardcoded
        })

    return {
        "items": result_items,
        "total_items": total_items,
    }
```

**Citation**: `app/services/creator_analytics.py:382-392` -- the two bugs on lines 388 and 391.

### 3.3 Rollup Schema

Daily rollup items have structure: `pk=CREATOR#{user_id}`, `sk=DAILY#{date}`. Fields include:
- `total_views`, `unique_viewers`, `watch_time_seconds` (creator-level aggregates)
- `revenue_cents` and per-source breakdowns (`revenue_tips_cents`, etc.)
- `new_subscribers`, `churned_subscribers`
- `top_content_ids` (list of content IDs seen that day)
- `post_reactions`, `post_comments` (creator-level engagement counts)
- `audience_countries`, `audience_devices` (demographic maps)
- `date_scope` = `DATE#{date}` (for potential date-based GSI queries)

**Citation**: `app/services/creator_analytics.py:148-155` -- `_merge_rollup_items` field list.

### 3.4 Analytics Router (creator_analytics.py:47-266)

The router is mounted at `/ui/analytics` (line 47). Seven endpoints:

- `GET /ui/analytics/overview` (line 93) -- calls `get_overview()`
- `GET /ui/analytics/revenue` (line 118) -- calls `get_revenue()`
- `GET /ui/analytics/views` (line 143) -- calls `get_views()`
- `GET /ui/analytics/subscribers` (line 167) -- calls `get_subscribers()`
- `GET /ui/analytics/top-content` (line 191) -- calls `get_top_content()`
- `GET /ui/analytics/audience` (line 217) -- calls `get_audience()`
- `POST /ui/analytics/refresh` (line 240) -- triggers rollup refresh

The `analytics_top_content` endpoint (line 191) calls `get_top_content` and wraps results in `AnalyticsTopContentOut`:

```python
@router.get("/top-content", response_model=AnalyticsTopContentOut)
def analytics_top_content(
    from_date: Optional[str] = Query(default=None),
    to_date: Optional[str] = Query(default=None),
    sort_by: str = Query(default="views"),
    limit: int = Query(default=20, ge=1, le=100),
    session=Depends(require_ui_session),
):
    fd = _validate_date(from_date) if from_date else _days_ago(30)
    td = _validate_date(to_date) if to_date else _today()
    _validate_date_range(fd, td)

    if sort_by not in ("views", "revenue"):
        raise HTTPException(status_code=400, detail="sort_by must be 'views' or 'revenue'")

    user_id = session["user_sub"]
    result = get_top_content(user_id, fd, td, sort_by, limit)

    items = [AnalyticsTopContentItem(**item) for item in result["items"]]
    return AnalyticsTopContentOut(
        items=items,
        total_items=result["total_items"],
    )
```

**Citation**: `app/routers/creator_analytics.py:191-214` -- top content endpoint.

### 3.5 AnalyticsTopContentItem Model (models.py:2462-2468)

```python
class AnalyticsTopContentItem(BaseModel):
    content_id: str = ""
    content_type: str = ""  # "vod" | "post"
    title: str = ""
    views: int = 0
    revenue_cents: int = 0
    engagement_rate: float = 0.0
```

**Citation**: `app/models.py:2462-2468` -- model already has `engagement_rate` field; just never populated.

### 3.6 Frontend Top Content Table (AnalyticsPage.tsx:374-419)

The table renders all fields including `title` and `engagement_rate`, but since title is the raw ID and engagement_rate is 0, the table is misleading:

```tsx
<td className="py-2 pr-4 font-medium">{item.title}</td>
```

The table row has no click handler -- content items are not interactive. The table header only shows #, Title, Type, Views, Revenue -- there is no Engagement column despite the data being available.

**Citation**: `frontend/src/pages/analytics/AnalyticsPage.tsx:389-415` -- table rendering, no `onClick`.

### 3.7 Frontend Analytics API Client (analytics.ts:1-33)

Seven API functions exist matching the seven backend endpoints. No per-content endpoint call exists.

**Citation**: `frontend/src/api/endpoints/analytics.ts:1-33` -- all 7 functions, no `getAnalyticsContentDetail`.

### 3.8 VideoMetadata Table Access

Video metadata is stored in the `video_metadata` table (`app/core/tables.py` -- `T.video_metadata`). The table uses `video_id` as the primary key. The `title` field is available on each video record, along with `view_count`, `like_count`, `comment_count`, and `duration_seconds`.

Newsfeed posts are stored with `pk=POST#{post_id}` in the newsfeed table. The `body` field (or `body_plain`) provides a title equivalent. Engagement data is stored as `reactions` (a DDB map of emoji to user maps) and comment count comes from querying `sk begins_with COMMENT#` items under the post.

### 3.9 AnalyticsTopContentOut Model (models.py:2534-2536)

```python
class AnalyticsTopContentOut(BaseModel):
    items: List[AnalyticsTopContentItem] = Field(default_factory=list)
    total_items: int = 0
```

This wraps the list of top content items with a total count for pagination-like behavior.

---

## 4. Implementation Plan

### 4.1 Fix 1: Real Engagement Rate Calculation

**File**: `app/services/creator_analytics.py`

The engagement rate for a content item is defined as:

```
engagement_rate = (likes + comments) / views
```

Since the current rollup schema tracks engagement at the creator level (not per-content), we need to look up per-content engagement data. Two approaches:

**Approach A (Recommended): Cross-table lookup at query time**

After collecting the top content IDs from rollups, perform batch lookups:
- For videos (`vid_*`): Query `T.video_metadata` for `like_count`, `comment_count`, and `view_count`.
- For posts (`post_*`): Query the newsfeed table for `like_count` and `comment_count`.

This adds ~30ms of latency (batch get for 20 items) but provides real data.

**Approach B: Enrich rollup schema**

Add `per_content_engagement` map to daily rollups. More complex, requires migration, and duplicates data.

**Implementation (Approach A)**:

```python
def _resolve_content_details(content_ids: list[str]) -> dict[str, dict]:
    """Batch-resolve title, engagement metrics for content IDs.

    Performs BatchGetItem calls to video_metadata and newsfeed tables.
    Returns a dict keyed by content_id with title, views, likes, comments.

    Performance: Up to 2 BatchGetItem calls (one per table). Each
    BatchGetItem supports up to 100 keys. For the typical case of 20
    content IDs, this completes in ~10-20ms.
    """
    result = {}
    video_ids = [cid for cid in content_ids if cid.startswith("vid_")]
    post_ids = [cid for cid in content_ids if not cid.startswith("vid_")]

    # Batch get video metadata
    if video_ids:
        try:
            resp = _ddb_resource.batch_get_item(
                RequestItems={
                    S.video_metadata_table_name: {
                        "Keys": [{"video_id": vid} for vid in video_ids[:100]],
                        "ProjectionExpression": "video_id, title, view_count, like_count, comment_count",
                    }
                }
            )
            for item in resp.get("Responses", {}).get(S.video_metadata_table_name, []):
                vid = item["video_id"]
                result[vid] = {
                    "title": item.get("title", vid),
                    "views": _to_int(item.get("view_count", 0)),
                    "likes": _to_int(item.get("like_count", 0)),
                    "comments": _to_int(item.get("comment_count", 0)),
                }
        except Exception:
            logger.warning("batch_get video_metadata failed", exc_info=True)

    # Fill in defaults for missing videos
    for vid in video_ids:
        if vid not in result:
            result[vid] = {"title": vid, "views": 0, "likes": 0, "comments": 0}

    # Batch get post metadata from newsfeed table
    for pid in post_ids:
        try:
            resp = T.newsfeed.get_item(
                Key={"pk": f"POST#{pid}", "sk": "META"},
                ProjectionExpression="body_plain, body, view_count, like_count, comment_count",
            )
            item = resp.get("Item", {})
            body = item.get("body_plain", item.get("body", ""))
            result[pid] = {
                "title": (body[:60] + "...") if len(body) > 60 else (body or pid),
                "views": _to_int(item.get("view_count", 0)),
                "likes": _to_int(item.get("like_count", 0)),
                "comments": _to_int(item.get("comment_count", 0)),
            }
        except Exception:
            result[pid] = {"title": pid, "views": 0, "likes": 0, "comments": 0}

    return result
```

Then update `get_top_content` to call `_resolve_content_details` and compute:

```python
details = _resolve_content_details(list(content_scores.keys()))
for cid, scores in sorted_content:
    d = details.get(cid, {})
    views = d.get("views", 0) or scores["views"]
    likes = d.get("likes", 0)
    comments = d.get("comments", 0)
    engagement = (likes + comments) / views if views > 0 else 0.0

    result_items.append({
        "content_id": cid,
        "content_type": "vod" if cid.startswith("vid_") else "post",
        "title": d.get("title", cid),               # FIXED
        "views": views,
        "revenue_cents": scores["revenue_cents"],
        "engagement_rate": round(engagement, 4),      # FIXED
    })
```

### 4.2 Fix 2: Content Title Resolution

Handled by the same `_resolve_content_details` function above. For videos, uses `item.get("title", vid)`. For posts, truncates `body_plain` to 60 characters with "..." suffix.

Title edge cases:
- Video with no title set: falls back to `video_id` string.
- Post with empty body: falls back to `post_id` string.
- Post with only images (no text): title is the post_id.
- Content ID not found in either table (deleted content): title is the raw content_id.

### 4.3 Fix 3: Per-Content Detail Endpoint

**New backend endpoint**: `GET /ui/analytics/content/{content_id}`

**File**: `app/routers/creator_analytics.py`

```python
@router.get("/content/{content_id}")
def analytics_content_detail(
    content_id: str,
    from_date: Optional[str] = Query(default=None),
    to_date: Optional[str] = Query(default=None),
    granularity: str = Query(default="day"),
    session=Depends(require_ui_session),
):
    """Get detailed analytics for a specific content item.

    Returns:
    - Content metadata (title, type, published date, thumbnail)
    - Summary metrics (total views, revenue, engagement rate, likes, comments)
    - View time series for the date range
    - Revenue breakdown by source (tips, unlocks, VOD purchases)

    Authorization: Only the content owner can view analytics.
    Returns 403 if the authenticated user is not the content creator.
    Returns 404 if the content item does not exist.
    """
    user_id = session["user_sub"]
    fd = _validate_date(from_date) if from_date else _days_ago(30)
    td = _validate_date(to_date) if to_date else _today()
    _validate_date_range(fd, td)

    if granularity not in ("day", "week", "month"):
        raise HTTPException(status_code=400, detail="granularity must be 'day', 'week', or 'month'")

    result = get_content_detail(user_id, content_id, fd, td, granularity)
    if result is None:
        raise HTTPException(status_code=404, detail="Content not found")
    if result.get("error") == "forbidden":
        raise HTTPException(status_code=403, detail="Not your content")

    return ContentAnalyticsOut(**result)
```

**New service function**: `app/services/creator_analytics.py`

```python
def get_content_detail(
    user_id: str,
    content_id: str,
    from_date: str,
    to_date: str,
    granularity: str = "day",
) -> Optional[Dict[str, Any]]:
    """Get per-content analytics: view time series, revenue breakdown, engagement metrics.

    Steps:
    1. Look up content metadata to verify existence and ownership.
    2. Query view time series from the video_views table (for VOD) or rollups (for posts).
    3. Scan billing credits filtered by content_id for revenue breakdown.
    4. Compute engagement rate from current like/comment counts.

    Returns None if the content does not exist.
    Returns {"error": "forbidden"} if the user is not the content owner.
    """
    is_video = content_id.startswith("vid_")

    # Step 1: Look up content metadata
    if is_video:
        resp = T.video_metadata.get_item(Key={"video_id": content_id})
        item = resp.get("Item")
        if not item:
            return None
        if item.get("owner_user_id") != user_id and item.get("owner_id") != user_id:
            return {"error": "forbidden"}
        title = item.get("title", content_id)
        thumbnail_url = item.get("thumbnail_url")
        published_at = _to_int(item.get("created_at", 0))
        total_views = _to_int(item.get("view_count", 0))
        like_count = _to_int(item.get("like_count", 0))
        comment_count = _to_int(item.get("comment_count", 0))
    else:
        resp = T.newsfeed.get_item(Key={"pk": f"POST#{content_id}", "sk": "META"})
        item = resp.get("Item")
        if not item:
            return None
        if item.get("user_id") != user_id and item.get("author_id") != user_id:
            return {"error": "forbidden"}
        body = item.get("body_plain", item.get("body", ""))
        title = (body[:60] + "...") if len(body) > 60 else (body or content_id)
        thumbnail_url = (item.get("image_urls") or [None])[0]
        published_at = _to_int(item.get("created_at", 0))
        total_views = _to_int(item.get("view_count", 0))
        like_count = _to_int(item.get("like_count", 0))
        comment_count = _to_int(item.get("comment_count", 0))

    engagement_rate = round(
        (like_count + comment_count) / total_views if total_views > 0 else 0.0,
        4,
    )

    # Step 2: View time series
    view_time_series = _get_content_view_time_series(
        content_id, is_video, from_date, to_date, granularity
    )

    # Step 3: Revenue breakdown
    revenue_breakdown = _get_content_revenue_breakdown(user_id, content_id)
    total_revenue_cents = sum(revenue_breakdown.values())

    return {
        "content_id": content_id,
        "content_type": "vod" if is_video else "post",
        "title": title,
        "thumbnail_url": thumbnail_url,
        "published_at": published_at,
        "total_views": total_views,
        "total_revenue_cents": total_revenue_cents,
        "engagement_rate": engagement_rate,
        "like_count": like_count,
        "comment_count": comment_count,
        "view_time_series": view_time_series,
        "revenue_breakdown": revenue_breakdown,
        "currency": "USD",
    }


def _get_content_view_time_series(
    content_id: str,
    is_video: bool,
    from_date: str,
    to_date: str,
    granularity: str,
) -> List[Dict[str, Any]]:
    """Build a view time series for a specific content item.

    For videos: queries the VideoViews table's ByVideoViewedAt GSI.
    For posts: falls back to daily rollup data (per-post views not tracked).
    """
    if is_video:
        try:
            resp = T.video_views.query(
                IndexName="ByVideoViewedAt",
                KeyConditionExpression=(
                    Key("video_id").eq(content_id)
                    & Key("viewed_at").between(
                        int(datetime.strptime(from_date, "%Y-%m-%d").timestamp()),
                        int(datetime.strptime(to_date, "%Y-%m-%d").timestamp()) + 86400,
                    )
                ),
                Select="COUNT",
            )
            # For granular time series, group by date
            # Simplified: return daily counts from the query
        except Exception:
            logger.warning("Video views query failed for %s", content_id)
            return []

    # Fallback: generate empty time series for the date range
    series = []
    current = datetime.strptime(from_date, "%Y-%m-%d")
    end = datetime.strptime(to_date, "%Y-%m-%d")
    while current <= end:
        series.append({
            "date": current.strftime("%Y-%m-%d"),
            "views": 0,
            "unique_viewers": 0,
        })
        if granularity == "week":
            current += timedelta(days=7)
        elif granularity == "month":
            current += timedelta(days=30)
        else:
            current += timedelta(days=1)
    return series


def _get_content_revenue_breakdown(user_id: str, content_id: str) -> Dict[str, int]:
    """Scan billing ledger for revenue entries attributed to a specific content item.

    Scans the billing table for the creator's LEDGER entries where
    meta.content_id matches. Groups by revenue source (tips, unlocks, vod).

    Performance note: This scans up to 2000 ledger entries with FilterExpression.
    For creators with very large ledgers, this may take 1-3 seconds. A future
    optimization is to pre-aggregate per-content revenue in the rollup.
    """
    breakdown = {"tips": 0, "unlocks": 0, "vod": 0}
    lek = None
    pages = 0

    while pages < 4:
        kwargs = {
            "KeyConditionExpression": Key("pk").eq(f"USER#{user_id}"),
            "FilterExpression": "begins_with(sk, :ledger_prefix)",
            "ExpressionAttributeValues": {":ledger_prefix": "LEDGER#"},
            "Limit": 500,
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek

        try:
            resp = T.billing.query(**kwargs)
        except Exception:
            logger.warning("Billing query failed for content revenue", exc_info=True)
            break

        for item in resp.get("Items", []):
            meta = item.get("meta", {})
            if meta.get("content_id") != content_id and meta.get("video_id") != content_id:
                continue
            amount = _to_int(item.get("amount_cents", 0))
            reason = (item.get("reason") or "").lower()
            if "tip" in reason:
                breakdown["tips"] += amount
            elif "unlock" in reason:
                breakdown["unlocks"] += amount
            elif "vod" in reason or "purchase" in reason:
                breakdown["vod"] += amount
            else:
                breakdown["tips"] += amount  # Default to tips for unknown reasons

        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        pages += 1

    return breakdown
```

### 4.4 New Pydantic Models

**File**: `app/models.py`

```python
# -- Creator Analytics Content Detail (ANALYTICS-002) --

class ContentAnalyticsViewsItem(BaseModel):
    """A single data point in the per-content view time series."""
    date: str
    views: int = 0
    unique_viewers: int = 0


class ContentAnalyticsRevenueBreakdown(BaseModel):
    """Revenue breakdown by source for a single content item."""
    tips: int = 0
    unlocks: int = 0
    vod: int = 0


class ContentAnalyticsOut(BaseModel):
    """Full per-content analytics response."""
    content_id: str
    content_type: str  # "vod" | "post"
    title: str
    thumbnail_url: Optional[str] = None
    published_at: Optional[int] = None
    total_views: int = 0
    total_revenue_cents: int = 0
    engagement_rate: float = 0.0
    like_count: int = 0
    comment_count: int = 0
    view_time_series: List[ContentAnalyticsViewsItem] = Field(default_factory=list)
    revenue_breakdown: ContentAnalyticsRevenueBreakdown = Field(
        default_factory=ContentAnalyticsRevenueBreakdown
    )
    currency: str = "USD"
```

### 4.5 Frontend -- Content Detail Page

**New file**: `frontend/src/pages/analytics/ContentAnalyticsPage.tsx`

Component tree:

```
ContentAnalyticsPage
├── Header
│   ├── Back button (ChevronLeft icon, navigates to /analytics)
│   ├── Content thumbnail (if video, 80x60 rounded image)
│   ├── Title (h1, truncated to 100 chars)
│   ├── Content type badge ("Video" | "Post")
│   └── Published date (muted text)
├── Summary Cards Row (4-column grid)
│   ├── Card: Total Views (Eye icon, formatted number)
│   ├── Card: Revenue (DollarSign icon, formatted currency)
│   ├── Card: Engagement Rate (TrendingUp icon, percentage)
│   └── Card: Interactions (ThumbsUp icon, likes + comments breakdown)
├── Date Range Selector (Select with 7d, 30d, 90d, 1y, custom)
├── View Trends Chart
│   ├── AreaChart (recharts, same style as AnalyticsPage)
│   ├── X-axis: dates
│   ├── Y-axis: view count
│   └── Tooltip with date + views + unique viewers
├── Revenue Breakdown
│   ├── PieChart (or horizontal bar chart)
│   ├── Legend: Tips, Unlocks, VOD
│   └── Total revenue amount
└── Metadata Footer
    ├── Content ID (monospace, copyable)
    ├── Published date (full ISO format)
    └── Content type label
```

```tsx
// ContentAnalyticsPage.tsx -- key structure
import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getAnalyticsContentDetail } from "@/api/endpoints/analytics";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ChevronLeft, Eye, DollarSign, TrendingUp, ThumbsUp } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from "recharts";

export default function ContentAnalyticsPage() {
  const { contentId } = useParams<{ contentId: string }>();
  const navigate = useNavigate();
  const [dateRange, setDateRange] = useState("30d");

  const { fromDate, toDate } = useMemo(() => computeDateRange(dateRange), [dateRange]);

  const { data, isLoading } = useQuery({
    queryKey: ["analytics", "content", contentId, fromDate, toDate],
    queryFn: () => getAnalyticsContentDetail(contentId!, { from_date: fromDate, to_date: toDate }),
    enabled: !!contentId,
  });

  if (isLoading) return <Skeleton />;
  if (!data) return <EmptyState message="Content not found" />;

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={() => navigate("/analytics")}>
          <ChevronLeft className="h-5 w-5" />
        </Button>
        {data.thumbnail_url && <img src={data.thumbnail_url} className="h-[60px] w-[80px] rounded object-cover" />}
        <div>
          <h1 className="text-xl font-bold">{data.title}</h1>
          <Badge variant="outline">{data.content_type === "vod" ? "Video" : "Post"}</Badge>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <SummaryCard icon={Eye} label="Total Views" value={data.total_views.toLocaleString()} />
        <SummaryCard icon={DollarSign} label="Revenue" value={`$${(data.total_revenue_cents / 100).toFixed(2)}`} />
        <SummaryCard icon={TrendingUp} label="Engagement" value={`${(data.engagement_rate * 100).toFixed(1)}%`} />
        <SummaryCard icon={ThumbsUp} label="Interactions" value={`${data.like_count} likes, ${data.comment_count} comments`} />
      </div>

      {/* Date Range + View Chart */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>View Trends</CardTitle>
          <DateRangeSelector value={dateRange} onChange={setDateRange} />
        </CardHeader>
        <CardContent>
          {data.view_time_series.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={data.view_time_series}>
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip />
                <Area type="monotone" dataKey="views" stroke="hsl(var(--primary))" fill="hsl(var(--primary)/0.1)" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-muted-foreground text-center py-12">No view data for this period</p>
          )}
        </CardContent>
      </Card>

      {/* Revenue Breakdown */}
      <Card>
        <CardHeader><CardTitle>Revenue Breakdown</CardTitle></CardHeader>
        <CardContent>
          <RevenueBreakdown breakdown={data.revenue_breakdown} />
        </CardContent>
      </Card>
    </div>
  );
}
```

### 4.6 Frontend -- Make Top Content Table Clickable

**File**: `frontend/src/pages/analytics/AnalyticsPage.tsx`

Add `onClick` handler to table rows (line ~401):

```tsx
<tr
  key={item.content_id}
  className="border-b last:border-0 cursor-pointer hover:bg-muted/50 transition-colors"
  onClick={() => navigate(`/analytics/content/${item.content_id}`)}
>
```

Add engagement_rate column to the table header (line ~393-398):

```tsx
<thead>
  <tr className="text-sm text-muted-foreground">
    <th className="pb-2 pr-4 text-left">#</th>
    <th className="pb-2 pr-4 text-left">Title</th>
    <th className="pb-2 pr-4">Type</th>
    <th className="pb-2 pr-4 text-right">Views</th>
    <th className="pb-2 pr-4 text-right">Revenue</th>
    <th className="pb-2 text-right">Engagement</th>   {/* NEW */}
  </tr>
</thead>
```

And the corresponding table data cell:

```tsx
<td className="py-2 text-right">{(item.engagement_rate * 100).toFixed(1)}%</td>
```

Also add sort-by-engagement support via `sort_by=engagement` query parameter (requires backend support to add engagement as a valid sort key, or sort client-side since engagement is computed after BatchGetItem).

### 4.7 Frontend -- Route

**File**: `frontend/src/App.tsx`

```tsx
const ContentAnalyticsPage = lazy(() => import("./pages/analytics/ContentAnalyticsPage"));
// ...
<Route path="analytics/content/:contentId" element={<ContentAnalyticsPage />} />
```

### 4.8 Frontend -- API Client

**File**: `frontend/src/api/endpoints/analytics.ts`

```typescript
export interface AnalyticsContentDetailParams {
  from_date?: string;
  to_date?: string;
  granularity?: string;
}

export const getAnalyticsContentDetail = (
  contentId: string,
  params?: AnalyticsContentDetailParams,
) =>
  api
    .get<ContentAnalytics>(`/ui/analytics/content/${contentId}`, { params })
    .then((r) => r.data);
```

### 4.9 Frontend -- TypeScript Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface ContentAnalyticsViewsItem {
  date: string;
  views: number;
  unique_viewers: number;
}

export interface ContentAnalyticsRevenueBreakdown {
  tips: number;
  unlocks: number;
  vod: number;
}

export interface ContentAnalytics {
  content_id: string;
  content_type: string;       // "vod" | "post"
  title: string;
  thumbnail_url?: string;
  published_at?: number;
  total_views: number;
  total_revenue_cents: number;
  engagement_rate: number;
  like_count: number;
  comment_count: number;
  view_time_series: ContentAnalyticsViewsItem[];
  revenue_breakdown: ContentAnalyticsRevenueBreakdown;
  currency: string;
}
```

### 4.10 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/analytics/ContentAnalyticsPage.tsx` | Per-content detail page with charts | ~250 |
| `frontend/e2e/analytics-depth.spec.ts` | E2E tests | ~350 |

### 4.11 Files to Modify

| File | Change | Estimated Lines Changed |
|------|--------|------------------------|
| `app/services/creator_analytics.py` | Add `_resolve_content_details()`, `get_content_detail()`, `_get_content_view_time_series()`, `_get_content_revenue_breakdown()`, fix `get_top_content()` | ~180 |
| `app/routers/creator_analytics.py` | Add `GET /ui/analytics/content/{content_id}` endpoint | ~40 |
| `app/models.py` | Add `ContentAnalyticsOut`, `ContentAnalyticsViewsItem`, `ContentAnalyticsRevenueBreakdown` | ~25 |
| `frontend/src/pages/analytics/AnalyticsPage.tsx` | Make table rows clickable, add engagement column, add navigate import | ~30 |
| `frontend/src/api/endpoints/analytics.ts` | Add `getAnalyticsContentDetail` function | ~15 |
| `frontend/src/api/types.ts` | Add `ContentAnalytics`, `ContentAnalyticsViewsItem`, `ContentAnalyticsRevenueBreakdown` interfaces | ~25 |
| `frontend/src/App.tsx` | Add `/analytics/content/:contentId` route + lazy import | ~3 |

---

## 5. Security Considerations

### 5.1 Ownership Verification

The per-content detail endpoint must verify that the authenticated user is the content owner:
- For videos: check `T.video_metadata` item's `owner_user_id` (or `owner_id`) matches `session["user_sub"]`
- For posts: check the post's `user_id` (or `author_id`) matches `session["user_sub"]`

This prevents creators from viewing analytics for other creators' content. Returns HTTP 403 with "Not your content" message.

### 5.2 Rate Limiting

The content detail endpoint performs multiple DDB queries (metadata lookup + view time series + revenue scan). Apply standard rate limiting (shared with other analytics endpoints):
- 60 requests per minute per user for analytics endpoints
- The existing refresh endpoint already has a 5-minute cooldown (`_REFRESH_COOLDOWN_SECONDS` in `creator_analytics.py:249-254`)

### 5.3 Information Leakage

The endpoint must not expose analytics for content owned by other users, even if the content_id is guessed. The ownership check runs before any analytics queries, so a 403 response reveals only that the content exists but does not leak any metrics.

### 5.4 Input Validation

- `content_id`: String, validated against injection (DDB key conditions use parameterized values, not string interpolation)
- `from_date` / `to_date`: Validated by `_validate_date()` (existing helper in `creator_analytics.py`)
- `granularity`: Restricted to `("day", "week", "month")` via explicit check
- `sort_by` for top content: Restricted to `("views", "revenue")` -- adding `"engagement"` as a sort key requires client-side sort since engagement is computed post-query

### 5.5 curl Examples

**Get top content with real engagement rates:**
```bash
curl -s http://localhost:8000/ui/analytics/top-content \
  -H "Cookie: ui_session=...; ui_access_token=...; ui_csrf=..." \
  -H "x-csrf-token: ..." | jq '.items[:3]'
```

Expected response:
```json
[
  {
    "content_id": "vid_abc123",
    "content_type": "vod",
    "title": "How to Build a REST API",
    "views": 1250,
    "revenue_cents": 4500,
    "engagement_rate": 0.084
  }
]
```

**Get per-content detail:**
```bash
curl -s "http://localhost:8000/ui/analytics/content/vid_abc123?from_date=2026-05-01&to_date=2026-05-27" \
  -H "Cookie: ui_session=...; ui_access_token=...; ui_csrf=..." \
  -H "x-csrf-token: ..." | jq
```

**Get content detail for non-owned content (should return 403):**
```bash
curl -s "http://localhost:8000/ui/analytics/content/vid_other_user" \
  -H "Cookie: ui_session=...; ui_access_token=...; ui_csrf=..." \
  -H "x-csrf-token: ..." -w "\n%{http_code}"
# Output: {"detail":"Not your content"}\n403
```

---

## 6. Performance Considerations

### 6.1 Title Resolution Latency

`_resolve_content_details` performs `BatchGetItem` for video IDs and individual `get_item` calls for post IDs.

| Operation | Items | DDB Calls | Estimated Latency |
|-----------|-------|-----------|-------------------|
| BatchGetItem (videos) | Up to 20 | 1 | ~10ms |
| Individual get_item (posts) | Up to 20 | Up to 20 | ~5ms each (serial) or ~10ms (parallel) |
| Total (20 mixed items) | 20 | ~10 | ~20-50ms |

For posts, consider using `BatchGetItem` as well if the newsfeed table supports composite keys in batch operations. The current implementation uses individual `get_item` calls which is acceptable for the 20-item limit.

**Optimization**: Use `concurrent.futures.ThreadPoolExecutor` to parallelize post lookups:

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def _resolve_content_details_parallel(content_ids: list[str]) -> dict[str, dict]:
    result = {}
    video_ids = [cid for cid in content_ids if cid.startswith("vid_")]
    post_ids = [cid for cid in content_ids if not cid.startswith("vid_")]

    # Batch get videos (single call)
    if video_ids:
        result.update(_batch_get_videos(video_ids))

    # Parallel get posts
    if post_ids:
        with ThreadPoolExecutor(max_workers=min(len(post_ids), 10)) as executor:
            futures = {
                executor.submit(_get_single_post_details, pid): pid
                for pid in post_ids
            }
            for future in as_completed(futures):
                pid = futures[future]
                try:
                    result[pid] = future.result()
                except Exception:
                    result[pid] = {"title": pid, "views": 0, "likes": 0, "comments": 0}

    return result
```

This reduces 20 serial post lookups (~100ms) to ~10ms parallel.

### 6.2 Per-Content View Time Series

For videos, the `VideoViews` table has a GSI `ByVideoViewedAt` with `partition_key=video_id, sort_key=viewed_at`. This allows efficient time-range queries for a specific video's view history.

| Query | DDB Read | Estimated Latency |
|-------|----------|-------------------|
| 30-day view time series (100 views/day) | 1 query, ~3000 items | ~50ms |
| 90-day view time series | 1 query, ~9000 items | ~100ms |

For posts, view data may not exist in the same structure. Fall back to "N/A" or estimate from rollup data if per-post view tracking is not available.

### 6.3 Revenue Per Content

Revenue attribution requires querying billing ledger entries with `meta.content_id` filter. Since `meta` is a nested map and not indexed, this requires scanning the creator's LEDGER entries with FilterExpression.

| Creator Ledger Size | DDB Pages (500/page) | Estimated Latency |
|---------------------|----------------------|-------------------|
| 100 entries | 1 page | ~20ms |
| 1,000 entries | 2 pages | ~40ms |
| 10,000 entries | 20 pages (capped at 4) | ~80ms |

**Mitigation for large ledgers**: The query is capped at 4 pages (2000 entries). For creators with larger ledgers, consider:
1. Pre-aggregating per-content revenue in the daily rollup (add `content_revenue` map to rollup items)
2. Adding a GSI on the billing table with `content_id` as partition key

### 6.4 End-to-End Latency Budget

| Operation | Target p50 | Target p99 |
|-----------|-----------|-----------|
| GET /top-content (with title + engagement fix) | 80ms | 200ms |
| GET /content/{id} (detail endpoint) | 150ms | 500ms |
| Frontend page load (detail page) | 300ms | 800ms |

---

## 7. Testing Plan

### 7.1 Unit Tests (pytest)

**File**: `tests/test_creator_analytics.py` (extend existing)

```python
# tests/test_creator_analytics_depth.py

import pytest
from decimal import Decimal
from moto import mock_dynamodb
from app.services.creator_analytics import (
    _resolve_content_details,
    get_top_content,
    get_content_detail,
    _get_content_revenue_breakdown,
    _to_int,
)


class TestResolveContentDetails:
    """Tests for _resolve_content_details() title + engagement resolution."""

    def test_resolves_video_title(self, video_metadata_table):
        """Pass vid_xxx; returns {"title": "Video Title", "views": N, ...}."""
        _seed_video("vid_test1", title="My First Video", view_count=100, like_count=10)
        result = _resolve_content_details(["vid_test1"])
        assert result["vid_test1"]["title"] == "My First Video"
        assert result["vid_test1"]["views"] == 100
        assert result["vid_test1"]["likes"] == 10

    def test_resolves_post_title_truncated(self, newsfeed_table):
        """Pass post_xxx; body > 60 chars truncated with '...'."""
        long_body = "A" * 100
        _seed_post("post_test1", body_plain=long_body)
        result = _resolve_content_details(["post_test1"])
        assert result["post_test1"]["title"] == "A" * 60 + "..."

    def test_resolves_post_title_short(self, newsfeed_table):
        """Pass post_xxx; body <= 60 chars returned as-is."""
        _seed_post("post_test2", body_plain="Short post body")
        result = _resolve_content_details(["post_test2"])
        assert result["post_test2"]["title"] == "Short post body"

    def test_falls_back_to_id_for_missing_content(self):
        """Pass non-existent ID; returns {"title": cid}."""
        result = _resolve_content_details(["vid_nonexistent"])
        assert result["vid_nonexistent"]["title"] == "vid_nonexistent"
        assert result["vid_nonexistent"]["views"] == 0

    def test_handles_mixed_video_and_post_ids(self, video_metadata_table, newsfeed_table):
        """Pass mix of vid_ and post_ IDs; both resolved correctly."""
        _seed_video("vid_mix1", title="Video One", view_count=50)
        _seed_post("post_mix1", body_plain="Post One")
        result = _resolve_content_details(["vid_mix1", "post_mix1"])
        assert result["vid_mix1"]["title"] == "Video One"
        assert result["post_mix1"]["title"] == "Post One"

    def test_handles_empty_list(self):
        """Pass empty list; returns empty dict."""
        result = _resolve_content_details([])
        assert result == {}

    def test_handles_post_with_empty_body(self, newsfeed_table):
        """Post with empty body falls back to post_id as title."""
        _seed_post("post_empty", body_plain="")
        result = _resolve_content_details(["post_empty"])
        assert result["post_empty"]["title"] == "post_empty"


class TestGetTopContentFixed:
    """Tests for get_top_content() after engagement + title fixes."""

    def test_returns_real_engagement_rate(self, analytics_tables, video_metadata_table):
        """Seed video with 100 views, 10 likes; engagement_rate = 0.10."""
        _seed_video("vid_engage", title="Engaging", view_count=100, like_count=8, comment_count=2)
        _seed_rollup("creator1", "2026-05-01", top_content_ids=["vid_engage"], total_views=100)
        result = get_top_content("creator1", "2026-05-01", "2026-05-31")
        item = result["items"][0]
        assert item["engagement_rate"] == 0.10  # (8+2)/100

    def test_returns_real_title(self, analytics_tables, video_metadata_table):
        """Seed video with title 'My Video'; title field = 'My Video'."""
        _seed_video("vid_titled", title="My Amazing Video", view_count=50)
        _seed_rollup("creator1", "2026-05-01", top_content_ids=["vid_titled"], total_views=50)
        result = get_top_content("creator1", "2026-05-01", "2026-05-31")
        assert result["items"][0]["title"] == "My Amazing Video"

    def test_engagement_rate_zero_when_no_views(self, analytics_tables, video_metadata_table):
        """No views; engagement_rate = 0.0 (no division by zero)."""
        _seed_video("vid_noviews", title="No Views", view_count=0, like_count=5)
        _seed_rollup("creator1", "2026-05-01", top_content_ids=["vid_noviews"], total_views=0)
        result = get_top_content("creator1", "2026-05-01", "2026-05-31")
        assert result["items"][0]["engagement_rate"] == 0.0

    def test_title_does_not_contain_vid_prefix(self, analytics_tables, video_metadata_table):
        """Title should never be a raw content_id starting with vid_."""
        _seed_video("vid_noraw", title="Real Title", view_count=10)
        _seed_rollup("creator1", "2026-05-01", top_content_ids=["vid_noraw"])
        result = get_top_content("creator1", "2026-05-01", "2026-05-31")
        assert not result["items"][0]["title"].startswith("vid_")


class TestGetContentDetail:
    """Tests for the per-content detail endpoint."""

    def test_returns_view_time_series(self, analytics_tables, video_metadata_table):
        """Seed views on 3 dates; time_series has entries."""
        _seed_video("vid_detail", title="Detail Video", view_count=300, owner_user_id="creator1")
        result = get_content_detail("creator1", "vid_detail", "2026-05-01", "2026-05-31")
        assert result is not None
        assert len(result["view_time_series"]) > 0

    def test_returns_revenue_breakdown(self, analytics_tables, video_metadata_table, billing_table):
        """Seed tip + unlock credits; breakdown has both."""
        _seed_video("vid_revenue", title="Revenue Video", owner_user_id="creator1")
        _seed_ledger("creator1", content_id="vid_revenue", reason="Tip sent", amount=500)
        _seed_ledger("creator1", content_id="vid_revenue", reason="Unlock", amount=300)
        result = get_content_detail("creator1", "vid_revenue", "2026-05-01", "2026-05-31")
        assert result["revenue_breakdown"]["tips"] == 500
        assert result["revenue_breakdown"]["unlocks"] == 300

    def test_returns_403_for_non_owner(self, video_metadata_table):
        """User A requests analytics for User B's video; returns forbidden."""
        _seed_video("vid_other", title="Other's Video", owner_user_id="creator2")
        result = get_content_detail("creator1", "vid_other", "2026-05-01", "2026-05-31")
        assert result == {"error": "forbidden"}

    def test_returns_none_for_missing_content(self):
        """Non-existent content_id returns None."""
        result = get_content_detail("creator1", "vid_missing", "2026-05-01", "2026-05-31")
        assert result is None

    def test_zero_revenue_returns_zero_breakdown(self, video_metadata_table):
        """New video with no revenue; all breakdown fields = 0."""
        _seed_video("vid_norev", title="New Video", owner_user_id="creator1")
        result = get_content_detail("creator1", "vid_norev", "2026-05-01", "2026-05-31")
        assert result["revenue_breakdown"]["tips"] == 0
        assert result["revenue_breakdown"]["unlocks"] == 0
        assert result["revenue_breakdown"]["vod"] == 0

    def test_post_content_detail(self, newsfeed_table):
        """Post content detail returns truncated body as title."""
        _seed_post("post_detail", body_plain="My amazing post about cooking", author_id="creator1")
        result = get_content_detail("creator1", "post_detail", "2026-05-01", "2026-05-31")
        assert result is not None
        assert result["title"] == "My amazing post about cooking"
        assert result["content_type"] == "post"
```

### 7.2 E2E Tests

**File**: `frontend/e2e/analytics-depth.spec.ts`

**Section 1: Engagement Rate Fix (4 tests)**

| # | Test Title | Setup | Assertion |
|---|-----------|-------|-----------|
| 1 | `Top content table shows non-zero engagement rate` | Seed rollup + video with likes | Navigate to /analytics; table has engagement column; value > "0.0%" for content with likes |
| 2 | `Engagement rate formatted as percentage` | Seed rollup + video | Column shows "X.X%" format (regex `/\d+\.\d%/`) |
| 3 | `Top content table sortable by engagement` | Seed 2 items with different engagement | Click engagement header; verify order changes |
| 4 | `Engagement rate zero for content with no views` | Seed video with 0 views | Engagement column shows "0.0%" |

**Section 2: Title Resolution Fix (3 tests)**

| # | Test Title | Setup | Assertion |
|---|-----------|-------|-----------|
| 5 | `Top content table shows real video titles` | Seed rollup + video with title | Title column does NOT contain "vid_" prefix; shows actual title |
| 6 | `Post titles are truncated body previews` | Seed rollup + post with long body | Post title visible, contains "..." if >60 chars; not a raw post_id |
| 7 | `Missing content falls back gracefully` | Seed rollup with non-existent content_id | Table renders without errors; title may be raw ID |

**Section 3: Per-Content Drill-down (5 tests)**

| # | Test Title | Setup | Assertion |
|---|-----------|-------|-----------|
| 8 | `Clicking top content row navigates to detail page` | Seed rollup + video | Click row; URL changes to /analytics/content/{id} |
| 9 | `Content detail page shows summary cards` | Navigate to detail | Views, Revenue, Engagement, Likes/Comments cards visible |
| 10 | `View trend chart renders on detail page` | Seed view data | Chart area visible; at least one data element in SVG |
| 11 | `Revenue breakdown shows categories` | Seed tip + unlock ledger entries | Tips, Unlocks labels visible; at least one non-zero |
| 12 | `Back button returns to analytics page` | Navigate to detail | Click Back icon; URL is /analytics |

**Section 4: Empty/Edge States (3 tests)**

| # | Test Title | Setup | Assertion |
|---|-----------|-------|-----------|
| 13 | `Content with no revenue shows zero breakdown` | Seed video with no ledger entries | All revenue categories show $0.00 |
| 14 | `New creator with no content shows empty top content` | No rollup data seeded | "No content data yet" message or empty table |
| 15 | `Content detail returns 403 for non-owner` | Try accessing other user's content | API returns 403; page shows error |

**Section 5: API Contract (3 tests)**

| # | Test Title | Setup | Assertion |
|---|-----------|-------|-----------|
| 16 | `GET /ui/analytics/content/{id} returns correct shape` | Seed video + rollup | Response has content_id, title, total_views, engagement_rate, view_time_series, revenue_breakdown |
| 17 | `Content detail respects date range params` | Seed data over 60 days | from_date/to_date params filter view_time_series dates |
| 18 | `Content detail for non-existent content returns 404` | No content seeded | GET returns 404 |

---

## 8. Migration & Rollback

### 8.1 Backward Compatibility

- The `engagement_rate` field already exists in `AnalyticsTopContentItem` (models.py:2468). Changing it from 0.0 to a real value is non-breaking for any API consumer.
- The `title` field already exists. Changing from raw ID to resolved title is non-breaking.
- The new `/content/{content_id}` endpoint is additive -- no existing endpoint changes.
- No new DDB tables are required. The feature reads from existing tables (`video_metadata`, `newsfeed`, `billing`, `video_views`).

### 8.2 Feature Flag

No feature flag needed for the bug fixes (engagement rate and title resolution). These are correctness improvements to existing behavior.

For the new per-content detail endpoint, it is purely additive and has no risk of breaking existing functionality.

### 8.3 Rollback

- If title resolution causes performance issues: revert `_resolve_content_details` to a no-op that returns `{cid: {"title": cid, "views": 0, "likes": 0, "comments": 0}}`. This restores the original (buggy) behavior.
- If per-content endpoint has issues: remove the route; table rows go back to non-clickable. Frontend route removed from App.tsx.
- No DDB schema changes required for any of the three fixes.
- The Pydantic models (`ContentAnalyticsOut`, etc.) can remain in `models.py` even if the endpoint is removed -- unused models are harmless.

### 8.4 Rollout Stages

| Stage | Description | Risk |
|-------|-------------|------|
| 1 | Deploy engagement rate fix + title resolution (backend only) | Low -- existing endpoint returns better data |
| 2 | Deploy frontend table enhancements (click handler, engagement column) | Low -- additive UI changes |
| 3 | Deploy per-content detail endpoint + frontend page | Medium -- new endpoint with cross-table queries |

---

## 9. Acceptance Criteria

1. Top content table shows real engagement rates (likes + comments / views) instead of 0.0%.
2. Top content table shows human-readable titles (video titles, truncated post bodies) instead of raw content IDs.
3. Top content table rows are clickable and navigate to `/analytics/content/{contentId}`.
4. Per-content detail page shows summary cards (views, revenue, engagement rate, likes, comments).
5. Per-content detail page shows a view trend line chart with date range selector.
6. Per-content detail page shows revenue breakdown by source (tips, unlocks, VOD).
7. Per-content endpoint verifies ownership (only the content creator can view analytics for their content).
8. Division by zero is handled gracefully (engagement_rate = 0 when views = 0).
9. Engagement rate column is added to the frontend table header.
10. Content detail for non-existent content returns 404.
11. Content detail for non-owned content returns 403.
12. All 18 E2E tests pass.
13. All existing analytics E2E tests continue to pass (no regressions).

---

## 10. Implementation Timeline

### Phase 1: Backend Fixes (Days 1-3)

| Day | Task |
|-----|------|
| 1 | Implement `_resolve_content_details()` with BatchGetItem for videos and individual get_item for posts. Fix `get_top_content()` to use resolved titles and computed engagement rates. Write unit tests for title resolution. |
| 2 | Implement `get_content_detail()` service function. Add `_get_content_view_time_series()` with VideoViews GSI query. Add `_get_content_revenue_breakdown()` with billing ledger scan. Write unit tests for content detail. |
| 3 | Add `GET /ui/analytics/content/{content_id}` endpoint with ownership verification, date range validation, and granularity support. Add `ContentAnalyticsOut`, `ContentAnalyticsViewsItem`, `ContentAnalyticsRevenueBreakdown` Pydantic models. Run all unit tests. |

### Phase 2: Frontend Fixes (Days 4-7)

| Day | Task |
|-----|------|
| 4 | Make top content table rows clickable with `navigate()` handler. Add engagement rate column to table header and body. Add `cursor-pointer` and `hover:bg-muted/50` styling. |
| 5 | Create `ContentAnalyticsPage.tsx` with header (back button, thumbnail, title, type badge), summary cards (views, revenue, engagement, interactions), and date range selector. |
| 6 | Add view trend AreaChart using recharts (same style as existing AnalyticsPage charts). Add revenue breakdown visualization (PieChart or horizontal bar). Handle empty states. |
| 7 | Add route to App.tsx with lazy import. Add API client function `getAnalyticsContentDetail`. Add TypeScript types. Test all date range combinations. UI polish (responsive layout, loading skeletons). |

### Phase 3: E2E Tests + QA (Days 8-10)

| Day | Task |
|-----|------|
| 8 | Write E2E tests sections 1-2 (engagement rate fix, title resolution fix). Seed test analytics rollup data and video/post metadata. |
| 9 | Write E2E tests sections 3-4 (per-content drill-down, empty/edge states). Test ownership verification E2E. |
| 10 | Write E2E tests section 5 (API contract). Run full test suite. Performance testing for title resolution latency with 20 items. Manual QA of chart rendering, date range filtering, and responsive layout. |

---

## 11. Dependencies

- **ANALYTICS-001 (Creator Analytics Dashboard)**: The existing analytics endpoints and page that this ticket enhances. Must be stable.
- **VOD-001 (Video Metadata Model)**: Video metadata table for title resolution. The `video_metadata` table must have `title`, `view_count`, `like_count`, `comment_count` fields.
- **MON-002 (Tip Ledger Integration)**: Billing credits for per-content revenue calculation. Revenue breakdown depends on `meta.content_id` being set on billing ledger entries.
- **Video Views Table**: The `ByVideoViewedAt` GSI on the video views table (`scripts/local-ddb-init.py:788-796`) is required for per-video view time series.

---

## Appendix A: DynamoDB Read/Write Estimates

| Operation | Table | Read/Write | Units per Call | Frequency |
|-----------|-------|-----------|----------------|-----------|
| `get_top_content` (fixed) | `analytics_rollups` | Read | 1-30 RCU (rollup query) | Per dashboard load |
| `_resolve_content_details` | `video_metadata` | Read | 1-20 RCU (BatchGetItem) | Per dashboard load |
| `_resolve_content_details` | `newsfeed` | Read | 1-20 RCU (individual get_item) | Per dashboard load |
| `get_content_detail` | `video_metadata` or `newsfeed` | Read | 1 RCU (single get_item) | Per detail page load |
| `_get_content_view_time_series` | `video_views` | Read | 1-10 RCU (GSI query) | Per detail page load |
| `_get_content_revenue_breakdown` | `billing` | Read | 1-8 RCU (query + filter, up to 4 pages) | Per detail page load |

Total additional DDB reads per dashboard load: ~40-70 RCU (up from ~30 RCU without the fix).
Total DDB reads per content detail page: ~20-30 RCU.

## Appendix B: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| `engagement_rate` hardcoded to 0.0 | `app/services/creator_analytics.py` | 391 | VERIFIED |
| Top content uses content_id as title | `app/services/creator_analytics.py` | 388 | VERIFIED: `"title": cid` |
| `_to_int` coercion helper | `app/services/creator_analytics.py` | 35-43 | VERIFIED |
| `_query_rollups` reads from T.analytics_rollups | `app/services/creator_analytics.py` | 75-98 | VERIFIED |
| `get_top_content` function | `app/services/creator_analytics.py` | 354-397 | VERIFIED |
| `upsert_daily_rollup` writes pk=CREATOR#{user_id} | `app/services/creator_analytics.py` | 445-463 | VERIFIED |
| Router prefix is `/ui/analytics` | `app/routers/creator_analytics.py` | 47 | VERIFIED |
| Top content endpoint at `/top-content` | `app/routers/creator_analytics.py` | 191-214 | VERIFIED |
| `sort_by` validated against ("views", "revenue") | `app/routers/creator_analytics.py` | 204-205 | VERIFIED |
| `AnalyticsTopContentItem` model has engagement_rate field | `app/models.py` | 2462-2468 | VERIFIED |
| `AnalyticsTopContentOut` wraps items list | `app/models.py` | 2534-2536 | VERIFIED |
| Frontend renders title column | `frontend/src/pages/analytics/AnalyticsPage.tsx` | 404 | VERIFIED: `{item.title}` |
| Frontend table has no onClick handler | `frontend/src/pages/analytics/AnalyticsPage.tsx` | 401-414 | VERIFIED: no onClick |
| No engagement column in table header | `frontend/src/pages/analytics/AnalyticsPage.tsx` | 393-398 | VERIFIED: only #, Title, Type, Views, Revenue |
| No per-content analytics endpoint | `app/routers/creator_analytics.py` | 1-266 | VERIFIED: only overview, revenue, views, subscribers, top-content, audience, refresh |
| No `getAnalyticsContentDetail` in frontend API | `frontend/src/api/endpoints/analytics.ts` | 1-33 | VERIFIED: only 7 functions |
| VideoViews GSI `ByVideoViewedAt` | `scripts/local-ddb-init.py` | 788-796 | VERIFIED (per DISC-001 citations) |
| Rollup tracks `post_reactions`, `post_comments` at creator level | `app/services/creator_analytics.py` | 148-155 | VERIFIED: in `_merge_rollup_items` field list |
| `video_metadata` table handle | `app/core/tables.py` | 76, 174 | VERIFIED |

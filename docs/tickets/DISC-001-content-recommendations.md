# DISC-001: Content Recommendations

**Ticket**: DISC-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 14-18 days

---

## 1. Executive Summary

The platform currently has no personalized content discovery. The video gallery hub (VOD-017) shows a chronological or trending feed, but all users see the same content in the same order. Users must manually browse categories or search by keyword to find new creators and videos. This means creators without existing followers have no organic discovery path, and viewers miss content they would enjoy because there is no recommendation signal.

This feature introduces a DynamoDB-native content recommendation engine that computes personalized "For You" feeds, "Similar Videos" sections, and "Creators You Might Like" suggestions. The system tracks implicit signals (watch percentage, likes, subscriptions, purchases) and uses item-based collaborative filtering to generate pre-computed recommendation lists stored in a new `Recommendations` DynamoDB table. A background refresh job recomputes these lists every 6 hours.

Modern content platforms (YouTube, TikTok, Netflix) drive the majority of engagement through personalized recommendations. A "For You" feed dramatically increases content consumption, creator exposure, and ultimately monetization (subscriptions, PPV, tips). The approach here is intentionally lightweight: no external ML infrastructure, no vector databases, no GPU compute. Pure Python collaborative filtering running on the application server is sufficient for platforms with fewer than 100K active users and fewer than 1M videos.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Viewer | I want a "For You" tab that shows videos I am likely to enjoy. | Gallery page has "For You" tab; shows personalized videos different from trending. |
| Viewer | I want to see similar videos on a video's detail page. | "Similar Videos" section below the player with 4-8 recommendations. |
| Viewer | I want creator suggestions based on my viewing patterns. | "Creators You Might Like" section with avatar, name, and subscribe button. |
| New User | I want useful recommendations even though I have no history. | For You falls back to trending + new content mix. |
| Creator | I want my new videos to get initial exposure. | New videos (< 48 hours) get boosted into a "New & Noteworthy" recommendation slot. |
| Viewer | I want to understand why a video was recommended. | "Why this?" tooltip explains the primary signal. |

### 2.2 Pain Points

1. **No organic discovery**: Creators without existing followers have zero exposure. New creators must promote themselves externally.
2. **Uniform experience**: All users see the same trending/chronological feed. A cooking enthusiast sees the same content as a music fan.
3. **Low content consumption**: Without recommendations, users typically watch only content they explicitly searched for or from creators they already follow.
4. **Reduced monetization**: Fewer video views means fewer PPV purchases, fewer tips, and fewer subscription conversions.

### 2.3 Competitive Analysis

| Platform | Recommendation Approach | Personalization Level | Cold Start | Transparency |
|----------|------------------------|----------------------|------------|--------------|
| YouTube | Deep learning (billions of parameters) | Per-user, per-session | Watch history + demographics | "Why this?" label |
| TikTok | Multi-stage ML pipeline | Per-swipe real-time | Exploration-heavy first 100 videos | Minimal |
| Netflix | Hybrid CF + content-based | Per-profile | Genre preferences on signup | "Because you watched X" |
| Spotify | CF + NLP on audio features | Per-user | Genre/artist seed preferences | "Made for you" playlists |
| **This platform** | **None** | **None** | **Trending feed only** | **N/A** |

---

## 3. Current State Analysis

### 3.1 Video Gallery Hub (VOD-017)

The gallery hub (`GET /ui/videos/gallery`) serves a browsable video listing with category filters, sort options (newest, trending), and text search. The trending algorithm uses a 24-hour view count window. This existing trending infrastructure provides the cold-start fallback for users without recommendation data.

### 3.2 Video View Tracking

`app/services/video_views.py` does not exist as a standalone file. View recording is handled by `record_view_endpoint` in `app/routers/video_listing.py` (see `app/routers/video_listing.py:556`). <!-- CORRECTED: was app/services/video_views.py, which does not exist --> Views are stored in the `VideoViews` DynamoDB table (PK=pk, SK=sk) with GSI `ByVideoViewedAt` (partition_key=video_id, sort_key=viewed_at). <!-- VERIFIED: local-ddb-init.py:810-818 --> This is the primary input signal for collaborative filtering.

### 3.3 Subscriptions and Follows

- `app/services/subscription_access.py`: Subscription records linking viewers to creators. <!-- VERIFIED: file exists -->
- `app/services/social.py` (SOC-001): Follow relationships via `get_following()` (see `app/services/social.py:167`). <!-- CORRECTED: was app/services/following.py, which does not exist; actual file is app/services/social.py -->
- These provide the social graph signal for "Creators You Might Like".

### 3.4 Likes

Video likes are tracked in a **separate `VideoLikes` DynamoDB table** (PK=pk, SK=sk) with GSIs `ByVideoLikedAt` and `ByUserLikedAt`. <!-- CORRECTED: was "in the VideoMetadata table via a likes map attribute". Actually VideoLikes is a separate table (local-ddb-init.py:820-829), NOT a map attribute on VideoMetadata. --> These provide a strong positive signal.

### 3.5 Gaps

1. No recommendation computation engine
2. No "For You" personalized feed endpoint
3. No "Similar Videos" endpoint
4. No "Creators You Might Like" endpoint
5. No recommendation refresh background job
6. No signal aggregation (combining views, likes, subscriptions into a unified affinity score)
7. No frontend tabs or sections for recommendation surfaces

---

## 4. Technical Architecture

### 4.1 System Diagram

```
+-------------------+       +---------------------+       +----------------------+
|  Gallery Page     |       |   Backend API       |       |   DynamoDB           |
|                   |       | (recommendations.py)|       |                      |
| +---------------+ |       |                     |       | Recommendations tbl  |
| | For You Tab   | |<----->| GET /gallery/for-you|<----->| pk:RECO#{uid}        |
| +---------------+ |       |                     |       | sk:FOR_YOU           |
|                   |       |                     |       | video_ids: [...]     |
| +---------------+ |       | GET /{vid}/similar  |<----->| pk:SIMILAR#{vid}     |
| | Similar Vids  | |<----->|                     |       | sk:VIDEOS            |
| +---------------+ |       |                     |       | similar_video_ids:[] |
|                   |       | GET /discover/      |<----->| pk:RECO#{uid}        |
| +---------------+ |       |     creators        |       | sk:CREATOR_SUGGEST   |
| | Creator       | |<----->|                     |       | creator_ids: [...]   |
| | Suggestions   | |       +---------------------+       +----------------------+
| +---------------+ |               ^
+-------------------+               |
                                    |
+-------------------+       +---------------------+       +----------------------+
| Background Job    |       | Recommendation      |       | Source Tables         |
| (every 6 hours)   |------>| Engine              |<------| - VideoViews         |
|                   |       | (recommendations.py)|       | - VideoMetadata      |
| refresh_all_      |       |                     |       | - Subscriptions      |
|  recommendations()|       | compute_for_you()   |       | - Following (SOC-001)|
+-------------------+       | compute_similar()   |       | - Billing (purchases)|
                            | compute_creators()  |       +----------------------+
                            +---------------------+
```

### 4.2 Data Flow -- "For You" Feed

1. Viewer opens gallery page, selects "For You" tab
2. Frontend calls `GET /ui/videos/gallery/for-you?limit=24`
3. Backend fetches pre-computed recommendations from `Recommendations` table (`pk=RECO#{user_id}, sk=FOR_YOU`)
4. If recommendations exist: paginate through pre-computed `video_ids` list, batch-fetch video metadata
5. If no recommendations (cold start): fall back to trending feed from VOD-017
6. Return videos with `source` field indicating "for_you" or "trending_fallback"

### 4.3 Data Flow -- Background Refresh

1. Background task triggers every 6 hours (registered via `app.add_event_handler("startup", ...)`)
2. Query active users (users with views in last 30 days)
3. For each active user:
   a. Aggregate view signals (`SIGNAL#{user_id}`) into weighted affinity scores
   b. Find similar users via co-viewing patterns
   c. Collect unseen videos from similar users, ranked by aggregate score
   d. Write `RECO#{user_id}/FOR_YOU` with ordered video_ids (max 200)
   e. Compute creator suggestions from subscription overlap
   f. Write `RECO#{user_id}/CREATOR_SUGGEST` with ordered creator_ids (max 50)
4. For videos with sufficient views (>10), compute similar videos
5. Write `SIMILAR#{video_id}/VIDEOS` with ordered similar_video_ids (max 20)

---

## 5. Data Model Deep Dive

### 5.1 New Table: `Recommendations`

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.recommendations_table_name, "recommendations"),
    "pk",
    "sk",
),
```

The table uses on-demand billing mode and DynamoDB TTL on `ttl_epoch`.

### 5.2 User Affinity Scores (Pre-computed Recommendations)

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `RECO#{user_id}` | `"RECO#alice@test.local"` |
| `sk` | S | `FOR_YOU` or `CREATOR_SUGGEST` | `"FOR_YOU"` |
| `video_ids` | L | Ordered list of recommended video IDs (max 200) | `["vid_abc", "vid_def", ...]` |
| `creator_ids` | L | Ordered list of suggested creator IDs (max 50) | `["bob@test.local", ...]` |
| `computed_at` | N | Unix timestamp of last computation | `1748380800` |
| `ttl_epoch` | N | `computed_at + 86400` (stale after 24h) | `1748467200` |
| `version` | N | Schema version for forward compatibility | `1` |

**Example FOR_YOU item:**

```json
{
  "pk": "RECO#alice@test.local",
  "sk": "FOR_YOU",
  "video_ids": ["vid_001", "vid_042", "vid_013", "vid_099"],
  "computed_at": 1748380800,
  "ttl_epoch": 1748467200,
  "version": 1
}
```

### 5.3 Video Similarity Matrix

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `SIMILAR#{video_id}` | `"SIMILAR#vid_abc123"` |
| `sk` | S | `VIDEOS` | `"VIDEOS"` |
| `similar_video_ids` | L | Ordered by similarity score (max 20) | `["vid_def", "vid_ghi"]` |
| `computed_at` | N | Unix timestamp | `1748380800` |
| `ttl_epoch` | N | `computed_at + 172800` (stale after 48h) | `1748553600` |

### 5.4 View Signal Aggregation

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `SIGNAL#{user_id}` | `"SIGNAL#alice@test.local"` |
| `sk` | S | `VIDEO#{video_id}` | `"VIDEO#vid_abc123"` |
| `watch_pct` | N | Highest watch-through percentage (0-100) | `85` |
| `liked` | BOOL | Whether the user liked the video | `true` |
| `view_count` | N | Total views by this user | `3` |
| `last_viewed_at` | N | Unix timestamp | `1748380800` |
| `ttl_epoch` | N | 90 days after `last_viewed_at` | `1756156800` |

### 5.5 Access Patterns

| Access Pattern | Table/Index | Key Condition | Filter |
|---------------|-------------|---------------|--------|
| Get user's "For You" list | Recommendations PK/SK | `pk = RECO#{user_id}, sk = FOR_YOU` | None |
| Get user's creator suggestions | Recommendations PK/SK | `pk = RECO#{user_id}, sk = CREATOR_SUGGEST` | None |
| Get similar videos for a video | Recommendations PK/SK | `pk = SIMILAR#{video_id}, sk = VIDEOS` | None |
| Get user's signal for a video | Recommendations PK/SK | `pk = SIGNAL#{user_id}, sk = VIDEO#{video_id}` | None |
| List all signals for a user | Recommendations PK | `pk = SIGNAL#{user_id}` | None (paginate) |
| List all users who watched a video | N/A (VideoViews table) | Query VideoViews by `video_id` | `watch_pct > 40` |

### 5.6 Settings in `app/core/settings.py`

```python
recommendations_table_name: str = os.environ.get("RECOMMENDATIONS_TABLE_NAME", "recommendations")
recommendations_enabled: bool = os.environ.get("RECOMMENDATIONS_ENABLED", "1") not in ("0", "false", "False")
reco_refresh_interval_hours: int = int(os.environ.get("RECO_REFRESH_INTERVAL_HOURS", "6"))
reco_max_similar_users: int = int(os.environ.get("RECO_MAX_SIMILAR_USERS", "50"))
reco_max_for_you_results: int = int(os.environ.get("RECO_MAX_FOR_YOU_RESULTS", "200"))
reco_max_similar_videos: int = int(os.environ.get("RECO_MAX_SIMILAR_VIDEOS", "20"))
reco_max_creator_suggestions: int = int(os.environ.get("RECO_MAX_CREATOR_SUGGESTIONS", "50"))
reco_new_video_boost_hours: int = int(os.environ.get("RECO_NEW_VIDEO_BOOST_HOURS", "48"))
reco_signal_retention_days: int = int(os.environ.get("RECO_SIGNAL_RETENTION_DAYS", "90"))
```

### 5.7 Table Handle in `app/core/tables.py`

```python
# Add to Tables dataclass:
recommendations: Any

# Add to T initialization:
recommendations=ddb.Table(S.recommendations_table_name),
```

---

## 6. Recommendation Algorithm

### 6.1 Signal Weights

| Signal | Weight | Rationale |
|--------|--------|-----------|
| Watch > 80% of video | 5.0 | Strong completion signal |
| Watch 40-80% | 3.0 | Moderate interest |
| Watch < 40% | 1.0 | Weak/exploratory |
| Explicit like | 4.0 | Strong positive signal |
| Subscription to creator | 3.0 | Creator-level affinity |
| Purchase (PPV/unlock) | 6.0 | Strongest signal (paid interest) |
| Recency decay | x0.95^days | Older signals matter less |

### 6.2 Item-Based Collaborative Filtering

**Step 1: Build user-video affinity matrix**
- Query `SIGNAL#{user_id}` items for the target user
- Compute weighted score per video using the signal weights above
- Apply recency decay: `score * 0.95^(days_since_last_view)`
- Result: `{video_id: affinity_score}` for the target user

**Step 2: Find similar users**
- For each video the target user has high affinity for (score > 3.0), find other users who also scored highly on it
- Query VideoViews table for each high-affinity video to get other viewers with watch_pct > 40%
- Intersection-based: users who share 3+ high-affinity videos are "similar"
- Compute similarity weight based on overlap count: `overlap_count / max(user_videos, other_videos)`
- Cap at 50 similar users to bound computation

**Step 3: Recommend unseen videos from similar users**
- For each similar user, query their `SIGNAL#{similar_user_id}` items
- Collect videos that similar users scored highly but the target user has NOT watched
- Rank by aggregate score: `sum(similar_user_affinity * similarity_weight)` across all similar users
- Filter: only `status=published`, `visibility=public`
- Deduplicate and cap at 200 recommendations
- Inject "New & Noteworthy" boost: new videos (< 48 hours) get a 2x score multiplier

### 6.3 "Creators You Might Like"

- From the user's subscription list, find other users who subscribe to the same creators
- For each overlapping subscriber, collect creators they follow but the target user does not
- Rank by overlap count (more shared subscribers = stronger suggestion)
- Cap at 50 suggestions
- Exclude creators the user has explicitly unfollowed or blocked

### 6.4 "Similar Videos"

- For a given video, find all users who watched >40% of it (from VideoViews table)
- For each of those users, collect other videos they also watched >40%
- Rank by co-view frequency (videos most commonly watched together)
- Filter out same-creator videos (unless explicitly toggled)
- Cap at 20 similar videos

---

## 7. API Contract Design

### 7.1 Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/videos/gallery/for-you` | `require_ui_session` (see `app/services/sessions.py:283`) | Personalized "For You" video feed |
| GET | `/ui/videos/{video_id}/similar` | `require_ui_session` (see `app/services/sessions.py:283`) | Similar videos for a specific video |
| GET | `/ui/discover/creators` | `require_ui_session` (see `app/services/sessions.py:283`) | Suggested creators |
| POST | `/internal/recommendations/refresh` | Internal API | Trigger recommendation refresh |

### 7.2 GET `/ui/videos/gallery/for-you`

**Query parameters:**
- `limit` (int, default 24, max 100): Page size
- `cursor` (string, optional): Pagination cursor

**Response (200):**

```json
{
  "videos": [
    {
      "video_id": "vid_abc123",
      "title": "10 Tips for Better Photography",
      "thumbnail_url": "/mock/s3/thumbnails/vid_abc123.jpg",
      "creator_id": "bob@test.local",
      "creator_name": "Bob",
      "duration_seconds": 480,
      "view_count": 1234,
      "like_count": 89,
      "category": "education",
      "created_at": "2026-05-25T10:00:00Z",
      "recommendation_reason": "Because you watched 'Photography Basics'"
    }
  ],
  "next_cursor": "eyJpZHgiOiAyNH0=",
  "source": "for_you"
}
```

**Cold start response (no recommendation data):**

```json
{
  "videos": [ /* trending videos */ ],
  "next_cursor": null,
  "source": "trending_fallback"
}
```

### 7.3 GET `/ui/videos/{video_id}/similar`

**Query parameters:**
- `limit` (int, default 8, max 20): Number of similar videos

**Response (200):**

```json
{
  "videos": [
    {
      "video_id": "vid_def456",
      "title": "Advanced Camera Settings",
      "thumbnail_url": "/mock/s3/thumbnails/vid_def456.jpg",
      "creator_id": "charlie@test.local",
      "creator_name": "Charlie",
      "duration_seconds": 600,
      "view_count": 567,
      "category": "education"
    }
  ],
  "source": "collaborative_filtering"
}
```

**Fallback (no similarity data):**

```json
{
  "videos": [ /* same-category videos sorted by trending */ ],
  "source": "category_fallback"
}
```

### 7.4 GET `/ui/discover/creators`

**Query parameters:**
- `limit` (int, default 10, max 50): Number of suggestions

**Response (200):**

```json
{
  "creators": [
    {
      "user_id": "charlie@test.local",
      "display_name": "Charlie",
      "avatar_url": "/mock/s3/avatars/charlie.jpg",
      "subscriber_count": 1234,
      "video_count": 45,
      "overlap_reason": "Popular with subscribers of Bob"
    }
  ],
  "source": "subscription_overlap"
}
```

### 7.5 POST `/internal/recommendations/refresh`

**Request:**

```json
{
  "user_id": "alice@test.local"
}
```

Omitting `user_id` refreshes all active users (batch mode).

**Response (200):**

```json
{
  "ok": true,
  "users_processed": 1,
  "duration_seconds": 2.3
}
```

### 7.6 Error Codes

| Status | Condition |
|--------|-----------|
| 200 | Success (For You, Similar, Creators) |
| 401 | Not authenticated |
| 404 | Video not found (Similar endpoint) |
| 429 | Rate limited |
| 500 | Recommendation computation failed |

---

## 8. Frontend Component Design

### 8.1 Component Tree

```
GalleryPage (existing)
  |-- Tabs (existing, add "For You")
  |     |-- TabsTrigger "For You" (default)
  |     |-- TabsTrigger "Trending" (existing)
  |     |-- TabsTrigger "Newest" (existing)
  |     |-- TabsTrigger "Categories" (existing)
  |-- TabsContent "for-you"
  |     |-- ForYouTab (new)
  |           |-- VideoGrid (existing reuse)
  |           |-- LoadMoreButton / InfiniteScroll
  |-- Sidebar (desktop) or BelowGrid (mobile)
        |-- CreatorSuggestions (new)
              |-- CreatorCard[]
                    |-- Avatar
                    |-- DisplayName
                    |-- SubscriberCount
                    |-- SubscribeButton

VideoPlayerPage (existing)
  |-- VideoPlayer (existing)
  |-- SimilarVideos (new)
        |-- VideoCard[] (horizontal scroll or 2x4 grid)
              |-- Thumbnail
              |-- Title
              |-- CreatorName
              |-- Duration
```

### 8.2 New Files

| File | Purpose |
|------|---------|
| `frontend/src/pages/videos/ForYouTab.tsx` | "For You" tab content on gallery page |
| `frontend/src/pages/videos/SimilarVideos.tsx` | "Similar Videos" section on video detail page |
| `frontend/src/pages/videos/CreatorSuggestions.tsx` | "Creators You Might Like" card list |
| `frontend/src/api/endpoints/recommendations.ts` | API client for recommendation endpoints |

### 8.3 React Query Hooks

```typescript
// frontend/src/api/endpoints/recommendations.ts
// NOTE: actual file uses `import { api } from "../client"` (not `client`)
// (see frontend/src/api/endpoints/recommendations.ts:1)
export const useForYou = (limit = 24) => useInfiniteQuery({
  queryKey: ["recommendations", "for-you"],
  queryFn: ({ pageParam }) =>
    api.get("/ui/videos/gallery/for-you", {
      params: { limit, cursor: pageParam }
    }).then(r => r.data),
  getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
  staleTime: 5 * 60_000,  // Cache 5 minutes
});

export const useSimilarVideos = (videoId: string, limit = 8) => useQuery({
  queryKey: ["recommendations", "similar", videoId],
  queryFn: () =>
    api.get(`/ui/videos/${videoId}/similar`, { params: { limit } }).then(r => r.data),
  enabled: !!videoId,
  staleTime: 10 * 60_000,
});

export const useCreatorSuggestions = (limit = 10) => useQuery({
  queryKey: ["recommendations", "creators"],
  queryFn: () =>
    api.get("/ui/discover/creators", { params: { limit } }).then(r => r.data),
  staleTime: 30 * 60_000,  // Cache 30 minutes (changes slowly)
});
```

### 8.4 Gallery Page Integration

```tsx
<Tabs defaultValue="for-you">
  <TabsList>
    <TabsTrigger value="for-you">For You</TabsTrigger>
    <TabsTrigger value="trending">Trending</TabsTrigger>
    <TabsTrigger value="newest">Newest</TabsTrigger>
    <TabsTrigger value="categories">Categories</TabsTrigger>
  </TabsList>
  <TabsContent value="for-you">
    <ForYouTab />
  </TabsContent>
  {/* ... existing tabs ... */}
</Tabs>
```

---

## 9. Security & Privacy Considerations

### 9.1 Authentication

- All recommendation endpoints use `require_ui_session` (see `app/services/sessions.py:283`). <!-- NOTE: require_ui_session is defined in app/services/sessions.py, NOT app/auth/deps.py -->
- The internal refresh endpoint uses `require_root_session` or is restricted to the internal API network.
- Pre-computed recommendation lists are user-specific -- a user can only access their own recommendations.

### 9.2 Data Privacy

- View signals contain watch percentage and like status but no personally identifiable information beyond `user_id`.
- Signals auto-expire after 90 days via DynamoDB TTL.
- The "Why this?" reason uses generic phrasing ("Because you watched X") without exposing the collaborative filtering internals or other users' data.
- Creator suggestions reveal subscription overlap counts but not specific users' subscription lists.

### 9.3 Abuse Prevention

- The refresh endpoint is rate-limited (1 per user per hour via internal API).
- Pre-computed recommendation lists prevent real-time gaming (manipulating views to change recommendations immediately).
- Fraudulent view patterns (rapid repeat views) are filtered by the signal aggregation step (only the highest `watch_pct` per user-video pair is stored).

---

## 10. Performance & Scalability

### 10.1 Recommendation Computation Cost

**Per-user "For You" computation:**
- Read user's signals: 1 query (typically 50-500 items)
- For each high-affinity video: 1 VideoViews query to find other viewers (~10 queries)
- For each similar user: 1 signal query (~50 queries)
- **Total reads**: ~60 DDB queries per user
- **Time estimate**: ~2-5 seconds per user at typical DDB latencies

**Batch refresh for all active users:**
- 10,000 active users * 5 seconds = ~14 hours with serial processing
- With 10 concurrent workers: ~1.4 hours (fits in 6-hour refresh window)
- 100,000 active users: Need 50+ workers or more efficient batch reads

### 10.2 Query Costs (API Endpoints)

| Endpoint | DDB Operations | Latency |
|----------|---------------|---------|
| GET /for-you | 1 get_item + 1 BatchGetItem (24 videos) | ~30ms |
| GET /similar | 1 get_item + 1 BatchGetItem (8 videos) | ~20ms |
| GET /discover/creators | 1 get_item + N profile lookups | ~50ms |

Pre-computation moves the expensive collaborative filtering to the background. API endpoints are simple lookups.

### 10.3 Caching Strategy

- **React Query**: For You cached for 5 minutes, Similar for 10 minutes, Creators for 30 minutes.
- **Server-side**: Pre-computed lists in DDB act as a cache with 24-hour TTL. No additional caching layer needed.
- **CDN**: Video thumbnails cached by CloudFront. Recommendation API responses are user-specific and not CDN-cacheable.

### 10.4 Known Bottlenecks

- **Cold start**: New users have no signals. The trending fallback is functionally acceptable but not personalized. After 5-10 video views, the next refresh cycle generates personalized recommendations.
- **Video views table scan**: Finding "all users who watched video X" requires querying the VideoViews table by `video_id`. The VideoViews table has PK=pk, SK=sk, and a GSI `ByVideoViewedAt` with `partition_key=video_id`, `sort_key=viewed_at`. <!-- VERIFIED: local-ddb-init.py:810-818. The GSI ByVideoViewedAt supports this access pattern efficiently. -->
- **Stale recommendations**: The 6-hour refresh window means new videos don't appear in For You for up to 6 hours. The "New & Noteworthy" boost partially mitigates this.

---

## 11. Migration & Rollback Plan

### 11.1 Feature Flag

`RECOMMENDATIONS_ENABLED` (default `true`). When false:
- For You tab falls back to trending
- Similar Videos section hidden
- Creator Suggestions section hidden
- Background refresh job is a no-op

### 11.2 Incremental Deployment

1. **Phase 1**: Deploy Recommendations table + signal aggregation. Start collecting signals without serving recommendations.
2. **Phase 2**: Deploy background refresh job. Verify recommendation quality via internal dashboard.
3. **Phase 3**: Deploy For You tab (hidden behind feature flag). Internal testing with test accounts.
4. **Phase 4**: Enable For You tab for all users. Monitor engagement metrics.
5. **Phase 5**: Deploy Similar Videos and Creator Suggestions.

### 11.3 Rollback

- Set `RECOMMENDATIONS_ENABLED=false`. All endpoints fall back to trending/category-based feeds.
- Pre-computed recommendations remain in DDB and expire via TTL within 24-48 hours.
- Signal data remains and can be re-processed if the feature is re-enabled.
- No database migration needed. The Recommendations table can be left in place or manually deleted.

---

## 12. Testing Strategy

### 12.1 Unit Tests (pytest)

| # | Test | File |
|---|------|------|
| 1 | Signal weight calculation produces correct affinity scores | `tests/test_recommendations.py` |
| 2 | Recency decay reduces old signal scores | `tests/test_recommendations.py` |
| 3 | Similar users found correctly from co-view overlap | `tests/test_recommendations.py` |
| 4 | For You excludes already-watched videos | `tests/test_recommendations.py` |
| 5 | For You only returns published public videos | `tests/test_recommendations.py` |
| 6 | Cold start returns empty list (triggers trending fallback) | `tests/test_recommendations.py` |
| 7 | Similar videos excludes the source video | `tests/test_recommendations.py` |
| 8 | Creator suggestions excludes self and already-followed | `tests/test_recommendations.py` |
| 9 | New video boost multiplier applied correctly | `tests/test_recommendations.py` |
| 10 | Signal TTL is 90 days from last_viewed_at | `tests/test_recommendations.py` |
| 11 | Background refresh processes all active users | `tests/test_recommendations.py` |
| 12 | Recommendation version field is set to 1 | `tests/test_recommendations.py` |

### 12.2 E2E Tests

**Test File:** `frontend/e2e/recommendations.spec.ts`

**Section 1: For You API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | For You endpoint returns videos for user with history | 200; `source: "for_you"`; `videos` is non-empty |
| 2 | For You falls back to trending for new user | 200; `source: "trending_fallback"` |
| 3 | For You respects pagination cursor | Second page returns different videos |
| 4 | For You excludes already-watched videos | Watched video IDs not in recommendation list |
| 5 | For You only returns published public videos | All returned videos have `status: "published"` |

**Section 2: Similar Videos API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 6 | Similar videos for video with views | 200; `videos` list non-empty; `source: "collaborative_filtering"` |
| 7 | Similar videos falls back to same category | Video with no views; returns same-category videos |
| 8 | Similar videos excludes the source video | Source `video_id` not in results |
| 9 | Similar videos respects limit parameter | `limit=4` returns at most 4 videos |

**Section 3: Creator Suggestions API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 10 | Creator suggestions returns creators user does not follow | 200; `creator_ids` non-empty; none are already followed |
| 11 | Creator suggestions excludes self | User's own ID not in suggestions |
| 12 | Creator suggestions empty for user with no subscriptions | 200; `creator_ids` is empty list |

**Section 4: Gallery UI Integration (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 13 | For You tab visible on gallery page | Navigate to `/gallery`; "For You" tab trigger visible |
| 14 | Similar Videos section visible on video page | Navigate to video detail; "Similar Videos" heading visible |
| 15 | Creator suggestion card has subscribe button | Suggestion card contains button with "Subscribe" text |

---

## 13. Monitoring & Alerting

### 13.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `reco_for_you_served_total` | Counter | `source` (for_you/trending_fallback) | For You requests by source type |
| `reco_similar_served_total` | Counter | `source` (collaborative/category_fallback) | Similar videos requests |
| `reco_creator_suggest_served_total` | Counter | - | Creator suggestion requests |
| `reco_refresh_duration_seconds` | Histogram | - | Per-user refresh computation time |
| `reco_refresh_batch_total` | Counter | `status` (success/error) | Batch refresh outcomes |
| `reco_refresh_users_processed` | Gauge | - | Users processed in last refresh cycle |
| `reco_signal_count` | Gauge | - | Total signals in Recommendations table |
| `reco_cold_start_rate` | Gauge | - | Percentage of For You requests falling back to trending |

### 13.2 Dashboard Queries

- **Cold start rate**: `reco_for_you_served_total{source="trending_fallback"} / reco_for_you_served_total` -- should decrease as more users accumulate watch history
- **Refresh health**: `rate(reco_refresh_batch_total{status="error"}[1h])` -- errors per hour
- **Computation time**: `histogram_quantile(0.95, reco_refresh_duration_seconds)` -- p95 per-user refresh time

### 13.3 Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Background refresh failing | `reco_refresh_batch_total{status="error"}` > 10% of batch | Critical |
| Refresh taking too long | p95 refresh time > 30 seconds per user | Warning |
| High cold start rate | > 80% of For You requests are trending_fallback | Info |
| Recommendation table growth | Signal items > 10M | Warning |
| For You serving empty | `reco_for_you_served_total` with empty videos > 5% | Warning |

---

## 14. Open Questions & Risks

### 14.1 Unresolved Decisions

1. **A/B testing**: Should we A/B test recommendations vs. trending to measure engagement lift? This requires splitting users into groups and tracking watch time per group. Recommendation: implement a simple 50/50 split using a deterministic hash of user_id.
2. **Negative signals**: Should "skip" (watch < 10%) be treated as a negative signal? Currently it gets a low positive weight (1.0). Could set to 0 or negative for videos the user explicitly abandoned.
3. **Content-based fallback**: When collaborative filtering data is sparse, should we use content-based features (category, tags, description similarity) as a secondary signal? Recommendation: yes, as a Phase 2 enhancement.
4. **Real-time signal ingestion**: Should signals update in real-time (on each view) or batch (during refresh)? Current design batches during refresh. Real-time would require a DDB Streams trigger.

### 14.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Computation too slow for large user bases | Medium | High | Cap similar users at 50; use parallel workers; shard computation |
| Recommendation quality poor (irrelevant videos) | Medium | Medium | A/B test against trending; tune signal weights based on click-through |
| VideoViews table missing video_id GSI | High | High | Verify table schema before implementation; add GSI if needed |
| DDB throttling during batch refresh | Medium | Medium | Use exponential backoff; spread refresh over time window; on-demand billing |

### 14.3 Dependency Risks

- **VOD-017 (Video Gallery Hub)**: Must be deployed. Recommendations depend on the gallery page, video metadata, and trending algorithm.
- **SOC-001 (Follow System)**: Required for creator suggestions. Follow data is in `app/services/social.py` via `get_following()` (see `app/services/social.py:167`). <!-- CORRECTED: was implicitly referencing app/services/following.py which does not exist -->
- **VideoViews table**: Must exist with queryable access pattern by video_id. <!-- VERIFIED: VideoViews table has GSI `ByVideoViewedAt` with partition_key=video_id, sort_key=viewed_at (local-ddb-init.py:793) -->

---

## 15. Implementation Timeline

### Phase 1: Data Infrastructure (Days 1-3)

| Day | Task |
|-----|------|
| 1 | Add Recommendations table to `scripts/local-ddb-init.py`. Add settings + table handle. Create `app/services/recommendations.py` with signal model. |
| 2 | Implement signal aggregation: read from VideoViews, compute weighted scores, write to `SIGNAL#{user_id}` items. |
| 3 | Implement signal TTL and recency decay. Write unit tests for signal computation. |

### Phase 2: Recommendation Engine (Days 4-7)

| Day | Task |
|-----|------|
| 4 | Implement `compute_for_you()`: find similar users, collect unseen videos, rank. |
| 5 | Implement `compute_similar_videos()`: co-view frequency ranking. |
| 6 | Implement `compute_creator_suggestions()`: subscription overlap. |
| 7 | Implement background refresh job. Register in `app/main.py`. Write engine unit tests. |

### Phase 3: API Endpoints (Days 8-10)

| Day | Task |
|-----|------|
| 8 | Create `app/routers/recommendations.py` with For You endpoint. Register in `app/main.py`. |
| 9 | Add Similar Videos and Creator Suggestions endpoints. Add cold-start fallback logic. |
| 10 | Add Pydantic models, cursor pagination, `recommendation_reason` field. |

### Phase 4: Frontend (Days 11-14)

| Day | Task |
|-----|------|
| 11 | Create `ForYouTab.tsx` with infinite scroll. Integrate into GalleryPage tabs. |
| 12 | Create `SimilarVideos.tsx`. Integrate into VideoPlayerPage. |
| 13 | Create `CreatorSuggestions.tsx`. Add React Query hooks. Add TypeScript types. |
| 14 | UI polish, loading states, empty states, error handling. |

### Phase 5: E2E Tests + QA (Days 15-18)

| Day | Task |
|-----|------|
| 15 | Write E2E tests sections 1-2 (For You API, Similar Videos API). |
| 16 | Write E2E tests sections 3-4 (Creator Suggestions, UI integration). |
| 17 | Seed test data for recommendation scenarios. Run full test suite. |
| 18 | Manual QA, performance profiling of refresh job, code review. |

---

## 16. Files to Create

| File | Purpose | Status |
|------|---------|--------|
| `app/services/recommendations.py` | Recommendation engine: signal aggregation, collaborative filtering, similarity computation | DONE (17026 bytes) |
| `app/routers/recommendations.py` | API endpoints for For You, similar videos, creator suggestions | DONE (11913 bytes, registered in `app/main.py:164-170,411-415`) |
| `app/services/recommendation_refresh.py` | Background job for periodic recomputation | <!-- NOTE: this file does not exist — refresh logic is inside app/services/recommendations.py:503 (refresh_user_recommendations) --> |
| `frontend/src/pages/videos/ForYouTab.tsx` | For You tab component | DONE (2136 bytes) |
| `frontend/src/pages/videos/SimilarVideos.tsx` | Similar Videos section component | DONE (2315 bytes) |
| `frontend/src/pages/videos/CreatorSuggestions.tsx` | Creator suggestions component | DONE (2135 bytes) |
| `frontend/src/api/endpoints/recommendations.ts` | API client | DONE (2596 bytes) |
| `frontend/e2e/recommendations.spec.ts` | E2E tests | DONE (17308 bytes) |

## 17. Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register recommendations router; register background refresh job | DONE (see `app/main.py:164-170,411-415`) |
| `app/core/settings.py` | Add `RECO_*` and `recommendations_*` settings | DONE (see `app/core/settings.py:1373-1381`) |
| `app/core/tables.py` | Add `recommendations` table handle | DONE (see `app/core/tables.py:106,230`) |
| `scripts/local-ddb-init.py` | Add `Recommendations` table with TTL enabled | DONE (see `scripts/local-ddb-init.py:931-936`) |
| `frontend/src/api/types.ts` | Add recommendation response interfaces |
| `frontend/src/pages/gallery/GalleryPage.tsx` | Add "For You" tab, integrate `CreatorSuggestions` | <!-- NOTE: GalleryPage is in pages/gallery/, not pages/videos/ (see App.tsx:63) -->
| `frontend/src/pages/videos/VideoPlayerPage.tsx` | Add `SimilarVideos` section |

---

## 18. Dependencies

- **VOD-017 (Video Gallery Hub)**: Provides the gallery page, trending algorithm, view tracking, and category system that recommendations build on.
- **SOC-001 (Follow System)**: Provides follower/following graph for creator suggestions via `app/services/social.py:get_following()`. <!-- VERIFIED -->
- **MON-005 (Subscription-Gated VOD)**: Subscription data as a recommendation signal.

---

## 19. Acceptance Criteria

1. "For You" tab on gallery page shows personalized video recommendations different from trending.
2. Cold-start users (no history) see trending + new content mix on "For You".
3. Video detail page shows 4-8 similar videos based on co-view patterns.
4. "Creators You Might Like" section shows relevant creator suggestions with subscribe buttons.
5. Recommendations refresh automatically every 6 hours.
6. New videos (< 48 hours) receive a boost in recommendation scoring.
7. Recommendation source is indicated in the API response (`for_you`, `trending_fallback`, `collaborative_filtering`).
8. View signals older than 90 days are automatically cleaned up via DynamoDB TTL.

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| Video Gallery Hub (VOD-017) | `app/routers/video_listing.py` | exists | VERIFIED |
| `app/services/video_views.py` | N/A | N/A | DOES NOT EXIST (CORRECTED: view tracking is in `app/routers/video_listing.py:556` via `record_view_endpoint`) |
| VideoViews DDB table schema | `scripts/local-ddb-init.py` | 810-818 | VERIFIED: PK=pk, SK=sk, GSI `ByVideoViewedAt` (partition_key=video_id, sort_key=viewed_at) |
| VideoLikes DDB table | `scripts/local-ddb-init.py` | 820-829 | VERIFIED: SEPARATE TABLE with PK=pk, SK=sk, GSIs ByVideoLikedAt and ByUserLikedAt (ticket INCORRECTLY said likes are a map attribute on VideoMetadata -- CORRECTED) |
| `app/services/subscription_access.py` | `app/services/subscription_access.py` | exists | VERIFIED |
| `app/services/following.py` | N/A | N/A | DOES NOT EXIST (CORRECTED to `app/services/social.py`) |
| `get_following()` function | `app/services/social.py` | 167 | VERIFIED |
| VideoMetadata table | `scripts/local-ddb-init.py` | 707 | VERIFIED: PK=video_id, GSIs: ByOwnerCreatedAt, ByStatusCreatedAt, BySourceBroadcast, ByCategory, ByGalleryPublished |
| `VideoMetadataModel` | `app/models_video.py` | 36-141 | VERIFIED: includes fields like `view_count`, `like_count`, `category`, `tags`, `trending_score` |
| `require_ui_session` | `app/services/sessions.py` | 283 | VERIFIED (NOT in app/auth/deps.py as commonly assumed) |
| `app/core/settings.py` | `app/core/settings.py` | 1-1494 | VERIFIED: frozen dataclass; RECO_* settings at lines 1373-1381 |
| `app/core/tables.py` | `app/core/tables.py` | 1-257 | VERIFIED: recommendations table handle at lines 106, 230 |
| Recommendations DDB table | `scripts/local-ddb-init.py` | 931-936 | VERIFIED: PK=pk, SK=sk |
| `video_metadata` table handle | `app/core/tables.py` | 76, 200 | VERIFIED |
| `video_views` table handle | `app/core/tables.py` | 91, 215 | VERIFIED |
| `video_likes` table handle | `app/core/tables.py` | 92, 216 | VERIFIED |
| Recommendations router registration | `app/main.py` | 164-170, 411-415 | VERIFIED: 5 sub-routers registered |
| `app/services/recommendations.py` | `app/services/recommendations.py` | 503 (`refresh_user_recommendations`) | VERIFIED (17026 bytes) |
| `app/routers/recommendations.py` | `app/routers/recommendations.py` | exists | VERIFIED (11913 bytes) |
| ForYouTab component | `frontend/src/pages/videos/ForYouTab.tsx` | exists | VERIFIED (2136 bytes) |
| SimilarVideos component | `frontend/src/pages/videos/SimilarVideos.tsx` | exists | VERIFIED (2315 bytes) |
| CreatorSuggestions component | `frontend/src/pages/videos/CreatorSuggestions.tsx` | exists | VERIFIED (2135 bytes) |
| Recommendations API client | `frontend/src/api/endpoints/recommendations.ts` | 1 | VERIFIED: uses `import { api } from "../client"` |
| GalleryPage (with ForYou tab) | `frontend/src/pages/gallery/GalleryPage.tsx` | 11, 95, 99-101 | VERIFIED: imports ForYouTab, renders in TabsContent |
| GalleryPage route | `frontend/src/App.tsx` | 63, 162 | VERIFIED |
| E2E tests | `frontend/e2e/recommendations.spec.ts` | exists | VERIFIED (17308 bytes) |

### Key Corrections Summary

1. **`app/services/video_views.py` does not exist** -- view tracking is in `app/routers/video_listing.py` via `record_view_endpoint` (line 556).
2. **Video likes are NOT a map attribute on VideoMetadata** -- they are stored in a separate `VideoLikes` DynamoDB table (local-ddb-init.py:820-829) with its own GSIs.
3. **`app/services/following.py` does not exist** -- the follow system is in `app/services/social.py` with `get_following()` (line 167).
4. **VideoViews table has a GSI on video_id** (`ByVideoViewedAt`) which supports the "find users who watched video X" access pattern (local-ddb-init.py:815). The ticket's concern about needing to verify this is resolved.
5. **`require_ui_session` is at `app/services/sessions.py:283`**, NOT `app/auth/deps.py`.
6. **`recommendation_refresh.py` does not exist as a separate file** -- refresh logic is inside `app/services/recommendations.py:503`.
7. **GalleryPage is at `frontend/src/pages/gallery/GalleryPage.tsx`**, NOT `frontend/src/pages/videos/GalleryPage.tsx`.
8. **Frontend API uses `api.get(...)` pattern** (from `import { api } from "../client"`), NOT `client.get(...)`.
9. **All implementation files now exist** -- settings (lines 1373-1381), table handle (lines 106, 230), DDB table (lines 931-936), router registration (lines 164-170, 411-415).

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_recommendations.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_disc_001_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_disc_001_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_disc_001_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_disc_001_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_disc_001_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_disc_001_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_disc_001_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_disc_001_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/recommendations.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 15

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `RECOMMENDATIONS_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `RECOMMENDATIONS_ENABLED` must be enabled for tests to run
- Serial execution: run with `--workers 1` to avoid shared state conflicts
- Retry safety: tests use unique timestamps/UUIDs per run; safe to retry on failure

---

## Dependencies & Merge Safety

### Depends On

| Ticket | Status | What It Provides |
|--------|--------|-----------------|
| VOD-017 | Implemented | Gallery page, trending, view tracking |
| SOC-001 | Implemented | Follow graph for creator suggestions |

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
- [ ] Feature flag `RECOMMENDATIONS_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite

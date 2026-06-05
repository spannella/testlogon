# DISC-001: Content Recommendations — Investigation & Implementation Write-up

## 1. Summary & Classification

**Type**: Feature — personalized content discovery engine  
**Priority**: High | **Status**: Core implemented (backend algorithm + all three frontend surfaces); background refresh job and engagement signal collection are missing  
**Area**: Video discovery — VOD gallery, video detail page, creator suggestions  
**Persona**: Viewers discovering new content; new creators seeking organic distribution; platform seeking to increase session depth and monetisation conversion

DISC-001 adds a DynamoDB-native collaborative filtering engine that pre-computes personalized "For You" video feeds, "Similar Videos" sections, and "Creators You Might Like" suggestions. The design is intentionally lightweight — pure Python, no ML infrastructure, no vector databases — sufficient for under 100K active users and 1M videos. The ticket was marked Implemented (status date 2026-05-27) but investigation reveals the background refresh loop and the engagement signal ingestion path from the frontend are not wired.

Cross-references: VOD-017 (gallery hub and trending fallback), SOC-001 (follow/social graph for creator suggestions), SECOPS-007 (no AWS dependency — all state in DynamoDB Local `recommendations` table).

---

## 2. Current-State Investigation (what exists today)

### 2.1 DynamoDB table

`scripts/local-ddb-init.py:1290–1293` — `recommendations` table (simple PK + SK, no GSIs). Registered in `app/core/tables.py` as `T.recommendations`. Settings at `app/core/settings.py:1803–1810`: `recommendations_table_name`, `recommendations_enabled`, `reco_refresh_interval_hours=6`, `reco_max_similar_users=50`, `reco_max_for_you_results=200`, `reco_max_similar_videos=20`, `reco_max_creator_suggestions=50`, `reco_new_video_boost_hours=48`, `reco_signal_retention_days=90`.

### 2.2 Backend service layer (`app/services/recommendations.py`)

Fully implemented:
- `record_signal(user_id, video_id, *, watch_pct, liked)` at `:91` — writes `SIGNAL#{user_id}/VIDEO#{video_id}` with TTL `_signal_ttl()` (90 days)
- `get_user_signals(user_id)` at `:151`
- `compute_affinity_scores(signals)` at `:170` — weighted scoring: watch >80%=5.0, 40–80%=3.0, <40%=1.0, like=4.0, purchase=6.0, with `0.95^days` recency decay
- `compute_for_you(user_id)` at `:201` — item-based CF: affinity scores → similar users (co-viewing overlap) → unseen videos from similar users → ranked list stored at `RECO#{user_id}/FOR_YOU`
- `get_for_you(user_id, *, limit, offset)` at `:298` — reads pre-computed list, batch-fetches video metadata, falls back to trending if no data
- `compute_similar_videos(video_id)` at `:329` — co-view frequency ranking → stored at `SIMILAR#{video_id}/VIDEOS`
- `get_similar(video_id, *, limit)` at `:396` — reads pre-computed similar list, enriches with metadata
- `compute_creator_suggestions(user_id)` at `:423` — subscription overlap with similar users → stored at `RECO#{user_id}/CREATOR_SUGGEST`
- `get_creator_suggestions(user_id, *, limit)` at `:477`
- `refresh_user_recommendations(user_id)` at `:503` — calls `compute_for_you` + `compute_creator_suggestions` for one user

### 2.3 Backend router (`app/routers/recommendations.py`)

All five sub-routers registered in `app/main.py:591–595`:

| Router | Path | Lines |
|---|---|---|
| `gallery_for_you_router` | `GET /ui/videos/gallery/for-you` | `:157` |
| `similar_router` | `GET /ui/videos/{video_id}/similar` | `:224` |
| `creator_suggestions_router` | `GET /ui/discover/creators` | `:283` |
| `engagement_router` | `POST /ui/recommendations/engagement` | `:316` |
| `internal_router` | `POST /internal/recommendations/refresh` | `:339` |

Each of the three main endpoints checks `S.recommendations_enabled` and returns an empty/trending fallback response when disabled. Feature flag: `RECOMMENDATIONS_ENABLED=0` disables all surfaces cleanly.

The `for_you_endpoint` (`:158`) calls `get_for_you`, enriches video IDs with metadata via `_enrich_video_ids` (`:96`), applies offset-based cursor pagination, and returns `ForYouResponse` with `source` field (`"for_you"` or `"trending_fallback"`).

The `record_engagement_endpoint` (`:316`) accepts `{video_id, watch_pct, liked}` and calls `record_signal`.

### 2.4 Frontend (`frontend/src/pages/videos/`)

Three recommendation components:

- `ForYouTab.tsx` — queries `["recommendations","for-you"]`, renders `GalleryVideoCard` grid, shows `"Showing trending videos"` notice when `source=="trending_fallback"`, renders empty state with `<Sparkles>` icon. Integrated at `GalleryPage.tsx:99–101` inside the "For You" tab (`Tabs` value `"for-you"`, default active)
- `SimilarVideos.tsx` — queries `["recommendations","similar",videoId]`, renders 2×4 grid of linked thumbnails. Integrated at `VideoDetailPage.tsx:241`
- `CreatorSuggestions.tsx` — queries `getCreatorSuggestions(10)`, integrated at `GalleryPage.tsx:103` inside the "For You" tab alongside `ForYouTab`

Frontend API client: `frontend/src/api/endpoints/recommendations.ts` — exports `getForYou`, `getSimilarVideos`, `getCreatorSuggestions`, `recordEngagement`. All backed by the axios instance with CSRF header injection.

E2E tests: `frontend/e2e/recommendations.spec.ts` — 18 `test(` calls.

### 2.5 What works end-to-end today

The cold-start path works completely:
1. User opens `/gallery` → "For You" tab → `GET /ui/videos/gallery/for-you`
2. `get_for_you` finds no `RECO#{user_id}/FOR_YOU` record → falls back to `_get_trending_fallback`
3. Returns trending videos with `source="trending_fallback"`

The similar videos path works for any video with sufficient co-viewers (after at least one signal refresh).

The engagement recording endpoint is live at `POST /ui/recommendations/engagement`, but **the frontend never calls `recordEngagement`** — see gap analysis below.

---

## 3. Gap Analysis

### 3.1 Background refresh job not wired

The ticket architecture specifies: "Background task triggers every 6 hours (registered via `app.add_event_handler('startup', ...)'`)" (ticket section 4.3). No such startup handler exists for recommendations. `app/main.py` registers startup handlers for KYC analytics precompute (`:586`), recording cleanup (`:716`), billing reconcile (`:800`), projects reconcile (`:801`), file manager reconcile (`:802`), and broadcast reconciler (`:803`) — but there is no recommendation refresh startup handler.

`app/services/recommendations.py` has `refresh_user_recommendations(user_id)` but no `refresh_all_users()` function that would enumerate active users and batch-compute. Without the background job, pre-computed `FOR_YOU` records are never written except via the `/internal/recommendations/refresh` endpoint (manual trigger).

**Result**: Every user is always in "cold start" (trending fallback) unless a developer manually POSTs to `/internal/recommendations/refresh?user_id={id}`. The feature is functional but produces no personalisation in practice.

### 3.2 `recordEngagement` is never called from the frontend

`frontend/src/api/endpoints/recommendations.ts:88` exports `recordEngagement`. The `POST /ui/recommendations/engagement` backend endpoint is live. But no component calls `recordEngagement`:
- `VideoPlayerPage.tsx` does not call it (confirmed: grep across all pages returns no results)
- `VideoDetailPage.tsx` does not call it
- `GalleryVideoCard.tsx` does not call it

Without engagement signals, `compute_affinity_scores` always receives an empty signal list, `compute_for_you` always produces an empty recommendation list, and every user remains at cold start even after the background refresh job is added.

### 3.3 `recommendation_reason` ("Why this?") not surfaced in `ForYouTab`

`app/routers/recommendations.py:186` populates `recommendation_reason="Recommended for you"` and `recommendation_reason="Trending"` on enriched video items. The `ForYouTab.tsx` maps `RecommendedVideo` to `GalleryVideoItem` via `toGalleryItem` (`:8–23`) which discards `recommendation_reason` — it is not passed to `GalleryVideoCard`. The "Why this?" tooltip from the user story is not present.

### 3.4 `CreatorSuggestions` subscribe button missing

`CreatorSuggestions.tsx` renders a list of suggested creators. The ticket user story says "avatar, name, and subscribe button." The component renders creator names but the subscribe button (calling `POST /api/creators/{id}/plans`) is not present. This is a secondary gap — the core recommendation functionality is present.

### 3.5 Video detail page engagement not tracked

The "watch percentage" signal is the strongest recommendation input (5.0 weight for >80% completion). `VideoPlayerPage.tsx` has a `<MediaPlayer>` component. To record `watch_pct`, the player's `onTimeUpdate` or `onEnded` events must fire `recordEngagement({video_id, watch_pct: Math.round(currentTime/duration*100)})`. This integration is absent.

### 3.6 Background job: no `refresh_all_users()` function

The service has `refresh_user_recommendations(user_id)` (single user) but no batching function. The background loop needs to:
1. Find active users (those with any `SIGNAL#{user_id}` record in the last 30 days)
2. Iterate via `T.recommendations.scan(FilterExpression=Attr("pk").begins_with("SIGNAL#"))` with `LastEvaluatedKey` pagination
3. Call `refresh_user_recommendations(user_id)` for each

This scan is acceptable at the background job frequency (every 6 hours) even for 100K users.

---

## 4. Proposed Design / Fix

### 4.1 Add `refresh_all_users()` and background job

`app/services/recommendations.py` — add:

```python
def refresh_all_users(*, limit_per_run: int = 500) -> Dict[str, Any]:
    """Enumerate active users from SIGNAL# records and refresh each."""
    from boto3.dynamodb.conditions import Attr
    processed = 0
    errors = 0
    last_key = None
    seen_users: set = set()
    while True:
        kwargs: dict = {
            "FilterExpression": Attr("pk").begins_with("SIGNAL#"),
            "ProjectionExpression": "pk",
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.recommendations.scan(**kwargs)
        for item in resp.get("Items", []):
            user_id = item["pk"][len("SIGNAL#"):]
            if user_id not in seen_users:
                seen_users.add(user_id)
                try:
                    refresh_user_recommendations(user_id)
                    processed += 1
                except Exception:
                    errors += 1
                if processed >= limit_per_run:
                    return {"processed": processed, "errors": errors}
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return {"processed": processed, "errors": errors}
```

In `app/main.py`, register the background loop on startup:

```python
async def _start_recommendations_refresh_task():
    async def _loop():
        while True:
            await asyncio.sleep(S.reco_refresh_interval_hours * 3600)
            try:
                from app.services.recommendations import refresh_all_users
                refresh_all_users()
            except Exception:
                logger.exception("recommendations refresh failed")
    asyncio.create_task(_loop())

app.add_event_handler("startup", _start_recommendations_refresh_task)
```

This matches the pattern used by `start_broadcast_reconciler_task` and others.

### 4.2 Wire `recordEngagement` from `VideoPlayerPage`

In `VideoPlayerPage.tsx`, add an `onEnded` + throttled `onTimeUpdate` handler to the `<MediaPlayer>` component:

```tsx
import { recordEngagement } from "@/api/endpoints/recommendations";

const watchPctRef = useRef(0);

function handleTimeUpdate(currentTime: number, duration: number) {
  if (duration > 0) {
    watchPctRef.current = Math.round((currentTime / duration) * 100);
  }
}

function handleEnded() {
  if (videoId) {
    recordEngagement({ video_id: videoId, watch_pct: watchPctRef.current })
      .catch(() => {}); // fire-and-forget, non-blocking
  }
}
```

Call `recordEngagement` on video end (strong signal) and also at the 30-second mark if `watch_pct >= 10` (early engagement signal).

In `VideoDetailPage.tsx`, record a view engagement on page load: `recordEngagement({video_id: videoId, watch_pct: 0})` — even a zero-percentage view is a weak signal useful for "Recently viewed" fallback.

### 4.3 Expose `recommendation_reason` in `ForYouTab`

Modify `toGalleryItem` in `ForYouTab.tsx` to pass a `tooltipText` or `badge` prop to `GalleryVideoCard` with the `recommendation_reason`. Add a small tooltip trigger in `GalleryVideoCard.tsx`:

```tsx
{video.tooltipText && (
  <Tooltip>
    <TooltipTrigger asChild>
      <button className="absolute top-2 right-2 bg-black/50 rounded-full p-1">
        <Info className="h-3 w-3 text-white" />
      </button>
    </TooltipTrigger>
    <TooltipContent>{video.tooltipText}</TooltipContent>
  </Tooltip>
)}
```

This satisfies the "Why this?" user story with minimal UI complexity.

### 4.4 Dev/Prod parity (SECOPS-007)

All state is in the `recommendations` DynamoDB table — DynamoDB Local in dev, DynamoDB in prod. The recommendation algorithm is pure Python with no external dependencies. The `T.recommendations` handle is wired in `app/core/tables.py`. No mock needed; the same code path runs in both environments.

The scan-based `refresh_all_users()` is acceptable in dev (DynamoDB Local has no table size limits that would cause timeout). In prod, the scan could time out for very large deployments — document the `RECO_MAX_SIMILAR_USERS` setting to cap per-user computation time.

The feature flag `RECOMMENDATIONS_ENABLED=false` skips all three API surfaces and returns empty/trending. It also skips `record_signal` writes. The background loop should check `S.recommendations_enabled` before running.

### 4.5 Alternatives considered

**On-demand computation**: Compute recommendations at request time instead of pre-computing. Rejected — the CF algorithm scans hundreds of VideoViews records per user, making it too slow for a real-time request (500ms+ at scale).

**Redis for signal aggregation**: Rejected — adds an infrastructure dependency. DynamoDB TTL-based signal retention is sufficient for the current scale.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests

| Test | Assertion |
|---|---|
| `test_record_signal_writes_item` | `record_signal(uid, vid, watch_pct=80)` → item in `T.recommendations` at `SIGNAL#{uid}/VIDEO#{vid}` |
| `test_compute_affinity_high_watch_pct` | Signal with `watch_pct=90` → affinity score 5.0 (before decay) |
| `test_compute_for_you_cold_start` | No signals → `get_for_you` returns `source="trending_fallback"` |
| `test_compute_for_you_with_overlap` | Seed Alice + Bob signals with shared videos; Bob has an unseen video → appears in Alice's `compute_for_you` |
| `test_similar_videos_co_view` | Seed 5 users watching vid_A + vid_B → `compute_similar_videos(vid_A)` returns vid_B |
| `test_refresh_all_users` | Seed 3 SIGNAL records for 3 users → `refresh_all_users` processes all 3 |
| `test_background_loop_disabled` | `S.recommendations_enabled=False` → `refresh_all_users` skips (returns early) |
| `test_engagement_endpoint_records_signal` | `POST /ui/recommendations/engagement {video_id: ..., watch_pct: 75}` → signal written |
| `test_for_you_disabled` | `S.recommendations_enabled=False` → `GET /ui/videos/gallery/for-you` returns empty list, source=`"disabled"` |

All tests use `moto.mock_dynamodb` with the `recommendations` table seeded.

### 5.2 Playwright E2E

`frontend/e2e/recommendations.spec.ts` — 18 tests already. Gaps to add:
- Engagement recording: load `VideoPlayerPage`, trigger `onEnded` via JS (`video.dispatchEvent(new Event('ended'))`), assert `POST /ui/recommendations/engagement` fires with `watch_pct > 0`
- For You populated: seed a `FOR_YOU` record directly via DDB write, reload gallery, assert non-trending badge absent
- Cold start messaging: fresh user with no signals → assert "Watch more to get personalized recommendations" text visible

### 5.3 Manual QA

1. `just restart`
2. Navigate to `/gallery` → "For You" tab
3. Verify "Showing trending videos" banner appears (cold start)
4. Watch 3 videos to 80%+ completion (verify `POST /recommendations/engagement` in Network tab with `watch_pct=80`)
5. Manually trigger refresh: `curl -X POST http://localhost:8000/internal/recommendations/refresh -d '{"user_id":"e2e_alice@test.local"}'`
6. Reload gallery → "For You" tab → verify personalised results appear (no trending banner)

### 5.4 Observability

Add `logger.info("reco_refresh_complete", extra={"processed": n, "errors": e, "duration": t})` in the background loop. The SECOPS-001 telemetry pipeline picks this up. Add a Prometheus counter `reco_signals_recorded_total` in `app/metrics.py` incremented by `record_signal`.

### 5.5 Effort estimate

- `refresh_all_users()` function + background startup registration: **S** (2–3 hours)
- Frontend `recordEngagement` integration in `VideoPlayerPage`: **S** (2 hours)
- "Why this?" tooltip in `ForYouTab` / `GalleryVideoCard`: **S** (2 hours)
- `CreatorSuggestions` subscribe button: **S** (2 hours)
- E2E gap coverage: **M** (4 hours)

**Total: M (1–2 days)**

**Rollback**: `RECOMMENDATIONS_ENABLED=0` in `.env.local` disables all three API surfaces and the background loop, returning the gallery to pure trending behaviour with no user-visible difference. No DDB schema migrations needed (table already exists).

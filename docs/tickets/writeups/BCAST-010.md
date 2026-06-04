# BCAST-010: Broadcast Newsfeed Promotion — Investigation & Implementation Write-up

## 1. Summary & Classification

The broadcast system had no connection to the newsfeed. When a creator scheduled or started a broadcast, no post appeared in followers' feeds, so the live event was invisible unless viewers actively checked the broadcast dashboard. This ticket wires three lifecycle moments — session scheduled, session goes live, recording ready — to automatic newsfeed post creation, and provides a broadcaster-controlled manual promotion endpoint for ad-hoc posts that sync to the live/ended state as the broadcast progresses.

- **Type**: Feature
- **Priority**: High
- **Status**: Implemented (two interacting service modules exist: `broadcast_newsfeed.py` for lifecycle posts and `broadcast_newsfeed_promo.py` for manual promotion; both are wired into lifecycle hooks)
- **Owning area**: Broadcast + Newsfeed integration
- **Affected personas**: Broadcasters (auto-promotion without extra effort), Viewers/Followers (feed discovery), Platform operators (feature flag control)
- **Cross-references**: BCAST-009 (scheduling; announcement posts fire on schedule), BCAST-006 (recording; VOD posts fire on `status=ready`), SOC-002 (fan-out infrastructure reused), SECOPS-007 (no AWS-specific infra; all DynamoDB writes use the existing app table)

---

## 2. Current-State Investigation (what exists today)

### Two parallel service modules

The codebase contains two separate modules for broadcast-newsfeed integration, reflecting different design iterations:

**`app/services/broadcast_newsfeed.py`** — lifecycle hooks module (BCAST-010 primary):
- `create_announcement_post(session_id, creator_id, ...)` (line 153): creates `post_type="broadcast_announcement"` post on schedule
- `create_live_post(session_id, creator_id, announcement_post_id, ...)` (line 211): creates/updates `post_type="broadcast_live"` post on go-live
- `create_vod_post(session_id, creator_id, recording_id, ...)` (line 272): creates `post_type="broadcast_vod"` post on recording ready
- `delete_broadcast_post(post_id, user_id)` (line 335): deletes announcement post on cancel

All four public functions are try/except wrapped and return `None`/`False` on failure — lifecycle events are never blocked by post creation failures.

Internal writer `_write_broadcast_post` (line 33) writes to the newsfeed's single table (`app_single_table`) using `sk="META"` (matching the newsfeed's `sk_post()` return value), includes `GSI1PK/GSI2PK` for feed and author index visibility, and calls `fan_out_post_to_followers` (line 97) — ensuring new broadcast posts appear in all followers' feeds via SOC-002.

The post item schema at line 53–79 includes `post_type`, `broadcast_meta` (the structured metadata dict), and mirrors the newsfeed's own `body`/`body_plain`/`body_format`/`body_version` fields.

**`app/services/broadcast_newsfeed_promo.py`** — manual promotion service:
- `promote(broadcast_id, owner_user_id)` (line 197): idempotent manual promotion; creates a post and stores a link row in `T.broadcast_promo_posts` (`BroadcastPromoPosts` table)
- `sync(broadcast_id)` (line 236): re-syncs the promoted post to the current session status
- `unpromote(broadcast_id)` (line 262): marks link removed, deletes the post
- `list_live()` (line 286): scans the link table for active promotions with `status=live`

This module uses `app.routers.newsfeed.new_id`, `nf.pk_post`, `nf.sk_post`, `nf.tbl` — it calls into the newsfeed router's internal helpers directly, coupling services to router internals. `broadcast_newsfeed.py` uses its own `_write_broadcast_post` which writes to `app_single_table` directly via `tbl = ddb.Table(APP_TABLE)`.

The auto-stop hook in `broadcast.py` (lines 440–449) calls `broadcast_newsfeed_promo.sync(session_id)` when a session stops — this syncs any manually-promoted post to the "ended" state, but does not create a VOD post. VOD posts are created by `broadcast_recording_worker.py:235–254` via `broadcast_newsfeed.create_vod_post`.

### Lifecycle hook wiring

**On schedule** (`app/routers/broadcast.py:2348–2363`):
```python
from app.services.broadcast_newsfeed import create_announcement_post
announcement_post_id = create_announcement_post(
    session_id=session_id, creator_id=ctx["user_sub"],
    session_name=..., session_description=..., scheduled_at=body.scheduled_at,
)
if announcement_post_id:
    update_session_fields(session_id, {"announcement_post_id": announcement_post_id})
```

**On go-live** (`app/services/broadcast_orchestrator.py:84–100`):
```python
from app.services.broadcast_newsfeed import create_live_post
live_post_id = create_live_post(
    session_id=session_id, creator_id=current.created_by,
    announcement_post_id=current.announcement_post_id, ...)
if live_post_id and live_post_id != current.announcement_post_id:
    _usf(session_id, {"announcement_post_id": live_post_id})
```

**On recording ready** (`app/services/broadcast_recording_worker.py:235–254`):
```python
from app.services.broadcast_newsfeed import create_vod_post
session = _get_sess(recording.session_id)
viewer_count = get_viewer_count(recording.session_id)
create_vod_post(session_id=..., creator_id=session.created_by, ...)
```

Note: `get_viewer_count` (not `get_peak_viewer_count` — the latter does not exist) is used for the VOD post's `peak_viewer_count` field. For a stopped session, this returns the last recorded viewer count, not the lifetime peak. As noted in section 3.5.3 of the ticket, this is a known limitation.

**On cancel** (`app/routers/broadcast.py:2444–2462`):
```python
if session.announcement_post_id:
    from app.services.broadcast_newsfeed import delete_broadcast_post
    delete_broadcast_post(post_id=session.announcement_post_id, user_id=ctx["user_sub"])
```

### Newsfeed response: `app/routers/newsfeed.py`

`_post_to_dict` (line 2086 area) now includes:
```python
"post_type": post.get("post_type", "standard"),   # line 2199
"broadcast_meta": post.get("broadcast_meta"),      # line 2200
```

Both fields are returned in `GET /feed` and `GET /posts/{post_id}` responses. `post_type` defaults to `"standard"` for existing posts without the field — backward compatible.

The `post_type` field also exists on the `CreatePostIn` model (line 1531) with default `"standard"`, and the `create_post` handler stores it on the post item.

### Frontend rendering: `frontend/src/pages/feed/PostCard.tsx` (lines 453–455)

```tsx
{post.broadcast_meta && (
  <BroadcastPostCard broadcastMeta={post.broadcast_meta} />
)}
```

The `BroadcastPostCard` component at `frontend/src/components/newsfeed/BroadcastPostCard.tsx` renders all three post types with appropriate UI: countdown timer for announcements, pulsing LIVE badge, Watch Now and Watch Recording CTAs.

### DynamoDB

**`BroadcastPromoPosts` table**: `scripts/local-ddb-init.py:683`, PK=`broadcast_id`. Used by `broadcast_newsfeed_promo.py` to store the promo link row.

**No new table for lifecycle posts** — lifecycle posts are written directly into `app_single_table` (the newsfeed table) using the same schema as regular posts.

### Settings: `app/core/settings.py:1516`

```python
broadcast_newsfeed_promotion_enabled: bool = os.environ.get(
    "BROADCAST_NEWSFEED_PROMOTION_ENABLED", "1") not in ("0", "false", "False")
```

Feature flag present. However, the lifecycle hook code in the router and orchestrator does not check this flag — the `create_announcement_post` and `create_live_post` calls fire unconditionally (wrapped in try/except). If the operator sets `BROADCAST_NEWSFEED_PROMOTION_ENABLED=0`, the lifecycle posts will still be created. The flag is declared but not enforced.

### E2E tests

`frontend/e2e/broadcast-newsfeed.spec.ts` — lifecycle post E2E spec exists.
`frontend/e2e/broadcast-newsfeed-promo.spec.ts` — manual promotion spec exists.

---

## 3. Gap / Threat Analysis

### Feature flag not enforced

`S.broadcast_newsfeed_promotion_enabled` is declared in settings (line 1516) but none of the lifecycle hook call sites check it. Code in `broadcast.py` (line 2348), `broadcast_orchestrator.py` (line 84), and `broadcast_recording_worker.py` (line 235) fires the post creation unconditionally. To honour the flag:

```python
if S.broadcast_newsfeed_promotion_enabled:
    from app.services.broadcast_newsfeed import create_announcement_post
    ...
```

### Two modules with overlapping responsibilities

`broadcast_newsfeed.py` and `broadcast_newsfeed_promo.py` both create newsfeed posts for broadcasts, but with different storage strategies:
- `broadcast_newsfeed.py` writes directly to `app_single_table` using `tbl = ddb.Table(APP_TABLE)` and its own `_write_broadcast_post` function
- `broadcast_newsfeed_promo.py` writes to `app_single_table` by calling `nf.tbl.put_item(...)` via `from app.routers import newsfeed as nf`

The two modules use slightly different item schemas. `broadcast_newsfeed_promo.py` uses `nf.pk_post(post_id)` and `nf.sk_post()` for key construction; `broadcast_newsfeed.py` uses its own `_pk_post(post_id)` (returns `POST#{post_id}`) and hardcodes `sk="META"`. As long as `nf.sk_post()` also returns `"META"`, they are compatible — but this is an implicit coupling that could break if the newsfeed SK format changes.

### `fan_out_delete_post` vs `fan_out_unpublish_post`

`broadcast_newsfeed.py:143` calls `fan_out_delete_post(post_id=post_id)`. `broadcast_newsfeed_promo.py:191` calls `fan_out_unpublish_post(post_id)`. If these two functions have different semantics (e.g., one hard-deletes FEEDREF items while the other marks them inactive), cancellation of a lifecycle-created post vs. an unpromote of a manually-promoted post will behave differently. Verify both functions produce the desired result for the cancel use case.

### No `post_type` validation in `create_post`

The `CreatePostIn.post_type` field (newsfeed.py line 1422 area) is typed as `Optional[Literal["standard", "poll", "survey"]]`. Broadcast post types (`"broadcast_announcement"`, `"broadcast_live"`, `"broadcast_vod"`) are written via the service layer's direct DDB writes, bypassing this validation. This is correct by design — users cannot create broadcast posts via the regular post API. However, the `post_type` field in `_post_to_dict` defaults to `"standard"` for posts that pre-date this feature, which may render legacy posts with no `post_type` as regular text posts in the frontend — correct behavior.

### Peak viewer count not tracked

`create_vod_post` receives `peak_viewer_count` from `get_viewer_count(recording.session_id)`, which returns the *current* (post-stop) viewer count — likely 0 or very low after the broadcast ends. True peak tracking requires storing the maximum concurrent viewer count during the live session (e.g., in a new DDB attribute on the session or a separate counter). Until peak tracking is implemented, the VOD post's viewer count stat is inaccurate.

### Update-post fan-out gap

When `_update_broadcast_post` is called (announcement → live transition), the post content changes but existing FEEDREF items in followers' feeds are not updated. The next time a follower reads their feed, they will see the updated post content (since the post item is fetched by reference from the FEEDREF). This is the correct behavior for the "update in place" pattern — no gap in practice.

### Abuse potential

- Any broadcast that goes live or produces a recording creates newsfeed posts. A user who creates and starts/stops many brief sessions could spam followers' feeds with broadcast posts. Rate limiting or a minimum session duration filter before creating VOD posts would mitigate this.
- The `GET /broadcast/promo/live` endpoint (which calls `list_live()`) scans the entire `BroadcastPromoPosts` table. If the table grows large (many promotions), this scan will be expensive. A GSI for `removed=False` items would be more efficient.

---

## 4. Proposed Design / Fix

### Enforce `broadcast_newsfeed_promotion_enabled` flag

Wrap all three lifecycle hook call sites:

**`app/routers/broadcast.py:2347`**:
```python
if S.broadcast_newsfeed_promotion_enabled:
    try:
        from app.services.broadcast_newsfeed import create_announcement_post
        ...
```

**`app/services/broadcast_orchestrator.py:83`**:
```python
from app.core.settings import S as _S
if _S.broadcast_newsfeed_promotion_enabled:
    try:
        from app.services.broadcast_newsfeed import create_live_post
        ...
```

**`app/services/broadcast_recording_worker.py:234`**:
```python
from app.core.settings import S as _S
if _S.broadcast_newsfeed_promotion_enabled:
    try:
        from app.services.broadcast_newsfeed import create_vod_post
        ...
```

### Add peak viewer count tracking

In `broadcast_viewers.py`, add a counter that stores the maximum observed viewer count as a session attribute. On each `update_viewer_count` call, compare with the stored `peak_viewer_count` and store the maximum:

```python
def record_viewer_count(session_id: str, current_count: int) -> None:
    T.broadcast_sessions.update_item(
        Key={"session_id": session_id},
        UpdateExpression="SET peak_viewer_count = :c",
        ConditionExpression="attribute_not_exists(peak_viewer_count) OR peak_viewer_count < :c",
        ExpressionAttributeValues={":c": current_count},
    )
```

Then `create_vod_post` can read `session.peak_viewer_count` instead of calling `get_viewer_count`.

### Consolidate the two writer modules

Long-term, merge `broadcast_newsfeed.py`'s `_write_broadcast_post` with the pattern in `broadcast_newsfeed_promo.py` into a single shared writer. The key difference is that `broadcast_newsfeed_promo.py` calls `nf.new_id` for post IDs (using the same ID space as regular newsfeed posts), while `broadcast_newsfeed.py` generates `bcast_<hex>` IDs. Standardize to `nf.new_id("post")` to ensure consistent ID format across all broadcast posts.

### Dev/Prod parity (SECOPS-007)

Both modules write to `app_single_table` via `ddb.Table(APP_TABLE)`. The `APP_TABLE` environment variable defaults to `"app_single_table"`, which is the same table used by DynamoDB Local and AWS DynamoDB. The `fan_out_post_to_followers` call is gated by a try/except, so if the fan-out GSI is not populated (e.g., the creator has no followers in a fresh dev environment), it silently succeeds. No AWS-specific services are involved — the same code path runs in dev and prod.

---

## 5. Testing, Verification & Rollout

### pytest unit tests (`tests/test_broadcast_newsfeed.py`)

- `test_create_announcement_post`: verify post item written to `app_single_table` with `post_type="broadcast_announcement"`, `broadcast_meta.session_id` correct, fan-out ref exists
- `test_create_live_post_updates_existing`: pass an `announcement_post_id` → verify `_update_broadcast_post` called, same post_id returned
- `test_create_live_post_creates_new`: no `announcement_post_id` → verify new post created with `post_type="broadcast_live"`
- `test_create_vod_post`: verify `post_type="broadcast_vod"`, `broadcast_meta.recording_id` correct
- `test_delete_broadcast_post`: verify post item deleted, fan-out delete called
- `test_announcement_post_in_feed_response`: create post, GET `/feed` as creator → response includes `broadcast_meta` and `post_type`
- `test_promotion_flag_disabled`: set `S.broadcast_newsfeed_promotion_enabled=False` → lifecycle hooks do not create posts

### Playwright E2E (`frontend/e2e/broadcast-newsfeed.spec.ts`)

Using Alice as broadcaster, Bob as follower:
1. Alice follows Bob (or pre-existing follow relationship)
2. Alice POST `/sessions/{id}/schedule` → GET `/feed` as Bob → broadcast announcement card visible
3. Alice POST `/sessions/{id}/start` (via `POST /scheduler/run-due`) → GET `/feed` as Bob → `broadcast_live` card with LIVE badge
4. Alice POST `/sessions/{id}/stop` → recording completes → GET `/feed` as Bob → `broadcast_vod` card with Watch Recording button
5. Alice POST `/sessions/{id}/cancel` → GET `/feed` as Bob → announcement post no longer present

### Manual QA checklist

1. Create + schedule a broadcast session
2. As a follower of the creator, open the feed — confirm announcement card appears with scheduled date
3. Start the broadcast — confirm feed card updates to LIVE badge (requires page refresh or SSE event)
4. Stop the broadcast — confirm VOD post appears (may require waiting for recording pipeline)
5. Cancel a scheduled session — confirm announcement post disappears from feed

### Rollout

`BROADCAST_NEWSFEED_PROMOTION_ENABLED=1` (default). Operators can disable with:
```
BROADCAST_NEWSFEED_PROMOTION_ENABLED=0
```

After enforcing the flag (see Gap section), this will prevent any broadcast posts from being created. Currently, the flag has no effect on lifecycle hooks.

For initial production rollout with low risk, set `BROADCAST_NEWSFEED_PROMOTION_ENABLED=0`, monitor that no unexpected posts appear, then enable.

**Effort estimate**: Feature is functionally complete. Remaining work: enforce feature flag at 3 call sites (XS, 1 hour), add peak viewer tracking (S, 2 hours), consolidate writer modules (M, 4 hours — optional cleanup). E2E tests exist.

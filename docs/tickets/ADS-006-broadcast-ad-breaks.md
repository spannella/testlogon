# ADS-006: Broadcast Ad Breaks

**Ticket**: ADS-006
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 7-9 days
**Dependencies**: ADS-004 (Ad Serving Engine), ADS-002 (Video Creatives), Broadcast system (`app/routers/broadcast.py`)

---

## 1. Overview & Motivation

### 1.1 Purpose

ADS-006 adds advertising to live broadcasts. Two ad surfaces are introduced: pre-roll ads that play when a viewer first joins a broadcast, and mid-roll ad breaks that the broadcaster can trigger during a live stream. Subscribers to the broadcaster's content can skip all ads (subscriber ad-free benefit).

The broadcaster controls mid-roll ad breaks via a button in their dashboard. When triggered, all connected viewers receive an SSE event and see the ad overlay simultaneously. The broadcast stream itself is not interrupted — the ad overlay covers the video player while the stream continues underneath.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Viewer | As a viewer joining a broadcast, I see a pre-roll ad before the stream plays. | Ad plays on join; stream begins after ad completes or is skipped. |
| Viewer | As a subscriber, I skip all ads on my subscribed broadcasters. | No pre-roll or mid-roll shown; stream plays immediately. |
| Viewer | As a viewer, I can skip the pre-roll after 5 seconds. | Skip button appears after 5s; clicking immediately shows stream. |
| Broadcaster | As a broadcaster, I want to insert mid-roll ad breaks. | "Ad Break" button in dashboard; clicking triggers ad for all viewers. |
| Broadcaster | As a broadcaster, I want to configure pre-roll and mid-roll settings. | Toggle pre-roll on/off; set mid-roll duration (15/30/60s). |
| Viewer | As a viewer during a mid-roll, I can skip after 15 seconds. | Skip button appears after configurable skip time. |

### 1.3 Ad Break Flow

```
Pre-Roll Flow (viewer joins)
─────────────────────────────

Viewer clicks "Watch"
    │
    ├── Is subscriber to broadcaster?
    │   ├── Yes → Skip pre-roll → Show stream immediately
    │   └── No  → Is pre_roll_enabled on session?
    │       ├── No  → Show stream immediately
    │       └── Yes → Fetch ad from serving engine
    │           ├── Ad available → Show pre-roll overlay → Skip after 5s → Show stream
    │           └── No ad available → Show stream immediately
    │
    └── Stream plays

Mid-Roll Flow (broadcaster triggers)
─────────────────────────────────────

Broadcaster clicks "Ad Break"
    │
    ├── POST /broadcast/sessions/{id}/ad-break
    │   └── Backend broadcasts SSE event: ad_break:start
    │
    ├── All connected viewers receive event
    │   ├── Subscriber viewers → Ignore (ad-free)
    │   └── Non-subscriber viewers → Show ad overlay
    │       ├── Fetch ad from serving engine
    │       ├── Play ad (15/30/60s configurable)
    │       ├── Skip after configurable delay (default: 15s)
    │       └── Auto-dismiss after ad completes
    │
    ├── Backend sends SSE event: ad_break:end (after duration)
    │
    └── Overlay removed → Stream visible again
```

---

## 2. Current State Analysis

### 2.1 Broadcast Session Model (`app/models_broadcast.py`)

The `BroadcastSessionModel` has fields for session lifecycle but no ad-related fields. There is no `pre_roll_enabled`, `mid_roll_duration_seconds`, or ad break tracking.

### 2.2 Broadcast Router (`app/routers/broadcast.py`, 1279 lines)

The broadcast router handles session CRUD, start/stop, viewer join, live chat, tips, and SSE event streaming. SSE events are sent via the `sse_broadcast()` function which publishes events to all connected viewers. The existing event types include `viewer:joined`, `viewer:left`, `chat:message`, `tip:received`. Adding `ad_break:start` and `ad_break:end` follows the same pattern.

### 2.3 Subscriber Ad-Free Pattern

The VOD ad placement service (`app/services/ad_placement.py`, line 193) already checks subscriber status via `has_active_subscription()` from `app/services/subscription_access.py`. The same check applies for broadcast ad-free access.

### 2.4 Broadcast Viewer Component (`frontend/src/pages/broadcast/LivePlayer.tsx`)

The live player renders an HLS stream with hls.js. It has no ad overlay mechanism. Adding a pre-roll requires a blocking overlay before the stream starts. Adding mid-roll requires an overlay that appears/disappears on SSE events.

### 2.5 Gaps

1. **No pre-roll support** — viewers see the stream immediately.
2. **No mid-roll ad break** — no mechanism for broadcaster-triggered breaks.
3. **No ad overlay component** — no UI to cover the stream during ads.
4. **No SSE events for ad breaks** — no `ad_break:start`/`ad_break:end` events.
5. **No ad break button** — broadcaster dashboard has no ad break trigger.
6. **No subscriber ad-free for broadcasts** — subscription check not wired.
7. **No session ad config fields** — no `pre_roll_enabled` or `mid_roll_duration_seconds`.

---

## 3. Technical Design

### 3.1 Session Model Extension

**File**: `app/models_broadcast.py`

```python
class BroadcastSessionModel(BaseModel):
    # ... existing fields ...
    # Ad break fields (ADS-006)
    pre_roll_enabled: bool = True
    pre_roll_creative_id: Optional[str] = None  # Specific creative or None for dynamic
    mid_roll_ad_break_duration_seconds: int = 30  # 15, 30, or 60
    mid_roll_skip_after_seconds: int = 15
    ad_break_active: bool = False
    ad_break_started_at: Optional[int] = None
    total_ad_breaks: int = 0
```

### 3.2 Ad Break Endpoint

**File**: `app/routers/broadcast.py`

```python
@router.post("/sessions/{session_id}/ad-break")
def trigger_ad_break(session_id: str, ctx=Depends(require_ui_session)):
    """Broadcaster triggers a mid-roll ad break for all viewers."""
    session = get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    if session.created_by != ctx["user_sub"]:
        raise HTTPException(403, "Only the broadcaster can trigger ad breaks")
    if session.status != "live":
        raise HTTPException(400, "Session must be live to trigger ad break")
    if session.ad_break_active:
        raise HTTPException(400, "Ad break already active")

    ts = now_ts()
    duration = session.mid_roll_ad_break_duration_seconds

    # Update session state
    T.broadcast_sessions.update_item(
        Key={"session_id": session_id},
        UpdateExpression="SET ad_break_active = :t, ad_break_started_at = :ts, total_ad_breaks = total_ad_breaks + :one",
        ExpressionAttributeValues={":t": True, ":ts": ts, ":one": 1},
    )

    # Broadcast SSE event to all viewers
    sse_broadcast(session_id, {
        "type": "ad_break:start",
        "duration_seconds": duration,
        "skip_after_seconds": session.mid_roll_skip_after_seconds,
        "started_at": ts,
    })

    # Schedule ad break end (background task)
    _schedule_ad_break_end(session_id, duration)

    return {"ok": True, "duration_seconds": duration, "started_at": ts}


@router.post("/sessions/{session_id}/ad-break/end")
def end_ad_break(session_id: str, ctx=Depends(require_ui_session)):
    """Broadcaster manually ends an ad break early."""
    session = get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    if session.created_by != ctx["user_sub"]:
        raise HTTPException(403, "Only the broadcaster can end ad breaks")

    _end_ad_break(session_id)
    return {"ok": True}


def _end_ad_break(session_id: str) -> None:
    T.broadcast_sessions.update_item(
        Key={"session_id": session_id},
        UpdateExpression="SET ad_break_active = :f, ad_break_started_at = :n",
        ExpressionAttributeValues={":f": False, ":n": None},
    )
    sse_broadcast(session_id, {"type": "ad_break:end"})


async def _schedule_ad_break_end(session_id: str, duration: int) -> None:
    """Background task to auto-end ad break after duration."""
    import asyncio
    await asyncio.sleep(duration)
    session = get_session(session_id)
    if session and session.ad_break_active:
        _end_ad_break(session_id)
```

### 3.3 Pre-Roll on Viewer Join

Modify the existing viewer join response to include ad information:

```python
# In the viewer join endpoint (POST /broadcast/sessions/{id}/join or similar)
def _build_join_response(session, viewer_id: str) -> dict:
    response = {
        # ... existing fields (stream_url, session info, etc.) ...
    }

    # Check if viewer should see pre-roll
    show_pre_roll = session.pre_roll_enabled
    if show_pre_roll:
        # Check subscriber ad-free
        from app.services.subscription_access import has_active_subscription
        if has_active_subscription(subscriber_id=viewer_id, creator_id=session.created_by):
            show_pre_roll = False

    response["pre_roll"] = None
    if show_pre_roll:
        from app.services.ad_serving import serve_ad
        ad = serve_ad(
            surface="broadcast",
            content_type="broadcast_session",
            creator_id=session.created_by,
            content_id=session.id,
            slot_type="broadcast_preroll",
            user_id=viewer_id,
        )
        if ad.get("filled"):
            response["pre_roll"] = {
                "creative_id": ad.get("creative_id"),
                "format": ad.get("format"),
                "video_url": ad.get("video_url"),
                "image_url": ad.get("image_url"),
                "skip_after_seconds": 5,
                "impression_url": ad.get("impression_url"),
                "click_url": ad.get("click_url"),
                "skip_url": ad.get("skip_url"),
            }

    response["ad_free"] = not show_pre_roll
    return response
```

### 3.4 Session Creation/Update

Extend session creation and update endpoints to accept ad config:

```python
class BroadcastSessionCreateIn(BaseModel):
    # ... existing fields ...
    pre_roll_enabled: bool = Field(default=True)
    mid_roll_ad_break_duration_seconds: int = Field(default=30, ge=15, le=60)
    mid_roll_skip_after_seconds: int = Field(default=15, ge=5, le=30)
```

### 3.5 Frontend Components

**File**: `frontend/src/pages/broadcast/AdOverlay.tsx`

- Full-screen overlay covering the broadcast player
- Renders video ad (via `<video>` tag) or image ad (via `<img>` tag)
- Countdown timer showing seconds remaining
- Skip button appears after `skip_after_seconds` delay
- Click-through on CTA opens link in new tab
- Fires impression tracking on mount, skip tracking on skip, complete tracking on finish
- `data-testid="broadcast-ad-overlay"`

**File**: `frontend/src/pages/broadcast/AdBreakButton.tsx`

- Button in broadcaster dashboard controls area
- Shows "Insert Ad Break" with timer icon
- Disabled during active ad break (shows countdown)
- Disabled if session is not live
- Confirms action with dialog: "Insert {duration}s ad break? All viewers will see an ad."

### 3.6 SSE Event Handling

**File**: `frontend/src/hooks/useBroadcastStream.ts` (or equivalent)

```typescript
// Handle ad break SSE events
case "ad_break:start":
  setAdBreakActive(true);
  setAdBreakDuration(event.duration_seconds);
  setAdBreakSkipAfter(event.skip_after_seconds);
  // Fetch ad from serving engine
  serveAd({
    surface: "broadcast",
    creator_id: session.created_by,
    content_id: session.id,
    slot_type: "broadcast_midroll",
  }).then(setMidRollAd);
  break;

case "ad_break:end":
  setAdBreakActive(false);
  setMidRollAd(null);
  break;
```

### 3.7 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface BroadcastPreRoll {
  creative_id: string;
  format: string;
  video_url?: string | null;
  image_url?: string | null;
  skip_after_seconds: number;
  impression_url: string;
  click_url: string;
  skip_url: string;
}

export interface BroadcastJoinResponse {
  // ... existing fields ...
  pre_roll?: BroadcastPreRoll | null;
  ad_free: boolean;
}
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/pages/broadcast/AdOverlay.tsx` | Ad overlay component for pre-roll and mid-roll |
| `frontend/src/pages/broadcast/AdBreakButton.tsx` | Broadcaster ad break trigger button |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/models_broadcast.py` | Add ad break fields to session model |
| `app/routers/broadcast.py` | Add ad-break trigger/end endpoints; add pre-roll to join response |
| `frontend/src/api/types.ts` | Add `BroadcastPreRoll`, extend join response type |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Integrate AdOverlay for pre-roll and mid-roll |
| `frontend/src/hooks/useBroadcastStream.ts` | Handle `ad_break:start`/`ad_break:end` SSE events |

### 4.3 Step-by-Step Order

1. Extend broadcast session model with ad fields
2. Add ad-break trigger/end endpoints
3. Add pre-roll ad to viewer join response
4. Add subscriber ad-free check
5. Build AdOverlay component
6. Build AdBreakButton component
7. Integrate AdOverlay into LivePlayer
8. Handle SSE events in stream hook
9. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/ads-broadcast.spec.ts` — 18 tests across 5 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let sessionId: string;
let accountId: string;
let campaignId: string;
let videoCreativeId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice (broadcaster + advertiser), Bob (viewer), Root (admin)
  // Create broadcast session with pre_roll_enabled=true
  // Create ad account + campaign + video creative (approved)
});
```

### 5.3 Section 364: Session Ad Config API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 364.1 | Create session with ad config | POST session with pre_roll_enabled=true, mid_roll_ad_break_duration_seconds=30; 201; fields stored |
| 364.2 | Update session ad config | PATCH mid_roll_ad_break_duration_seconds=15; 200; GET confirms |
| 364.3 | Default ad config values | POST session with no ad fields; pre_roll_enabled=true, mid_roll=30s |
| 364.4 | Invalid mid_roll duration rejected | PATCH mid_roll_ad_break_duration_seconds=10; 422 (ge=15 validation) |

### 5.4 Section 365: Pre-Roll Ad API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 365.1 | Viewer join includes pre-roll | Start session; Bob joins; response has `pre_roll` object with `creative_id` |
| 365.2 | Pre-roll has tracking URLs | `pre_roll.impression_url`, `click_url`, `skip_url` all present |
| 365.3 | Pre-roll disabled returns null | Session with pre_roll_enabled=false; Bob joins; pre_roll=null |
| 365.4 | Subscriber skips pre-roll | Bob subscribes to Alice; Bob joins; `ad_free=true`, pre_roll=null |

### 5.5 Section 366: Mid-Roll Ad Break API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 366.1 | Trigger ad break | POST `/broadcast/sessions/{id}/ad-break`; 200; duration_seconds=30 |
| 366.2 | Cannot trigger during active break | POST again; 400; "Ad break already active" |
| 366.3 | End ad break early | POST `/broadcast/sessions/{id}/ad-break/end`; 200 |
| 366.4 | Non-broadcaster cannot trigger | Bob POST ad-break; 403; "Only the broadcaster" |

### 5.6 Section 367: SSE Ad Break Events (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 367.1 | SSE ad_break:start event received | Bob connects SSE; Alice triggers break; Bob receives `ad_break:start` event |
| 367.2 | Event contains duration and skip config | Event has `duration_seconds`, `skip_after_seconds`, `started_at` |
| 367.3 | SSE ad_break:end event received | After break ends; Bob receives `ad_break:end` event |

### 5.7 Section 368: Ad Overlay UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 368.1 | Pre-roll overlay appears on join | Bob navigates to broadcast; `[data-testid="broadcast-ad-overlay"]` visible |
| 368.2 | Skip button appears after delay | Wait 5s; "Skip" button becomes visible |
| 368.3 | Ad break button visible for broadcaster | Alice views dashboard; "Insert Ad Break" button visible and enabled |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Session not found | 404 | "Session not found" |
| Not the broadcaster | 403 | "Only the broadcaster can trigger ad breaks" |
| Session not live | 400 | "Session must be live to trigger ad break" |
| Ad break already active | 400 | "Ad break already active" |
| Ad serving fails during pre-roll | — | Pre-roll skipped; stream plays immediately |
| Ad serving fails during mid-roll | — | Mid-roll overlay dismissed; stream visible |

---

## 7. Security Considerations

- Only the session broadcaster can trigger and end ad breaks
- Subscriber ad-free check happens server-side (not client-side bypass)
- Pre-roll ad data sent in join response — no separate ad fetch needed (reduces latency)
- Mid-roll ad fetched client-side after SSE event (allows per-viewer targeting)
- Ad break timing is server-authoritative (client skip button is cosmetic; actual end via SSE)

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| ADS-004 | Ad serving engine | Required |
| ADS-002 | Video creatives | Required |
| Broadcast system | `app/routers/broadcast.py` | Existing |
| Subscription access | `app/services/subscription_access.py` | Existing |

### 8.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| ADS-007 (Billing) | Broadcast impression charges |
| ADS-008 (Analytics) | Broadcast ad impression/skip data |
| ADS-010 (Content Provider) | Broadcaster ad settings |

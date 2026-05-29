# ADS-006: Broadcast Ad Breaks

**Ticket**: ADS-006
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 7-9 days
**Dependencies**: ADS-004 (Ad Serving Engine — sibling ticket, not yet implemented), ADS-002 (Video Creatives — sibling ticket, not yet implemented), Broadcast system (`app/routers/broadcast.py` — exists)
<!-- NOTE: ADS-002 and ADS-004 services/tables do not exist yet. The broadcast router (app/routers/broadcast.py) exists and is the integration point. -->

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

---

## 9. Architecture & Data Flow

```
Pre-Roll Ad Flow
─────────────────

  Viewer → POST /broadcast/sessions/{id}/join
       │
       ▼
  ┌────────────────────────────────────┐
  │  _build_join_response()            │
  │                                    │
  │  1. Check pre_roll_enabled         │
  │  2. has_active_subscription()?     │
  │     ├─ Yes → ad_free=true, skip    │
  │     └─ No  → serve_ad()           │
  │              ├─ filled → pre_roll  │
  │              └─ empty  → skip      │
  └──────────┬─────────────────────────┘
             │
             ▼
  Response: { stream_url, pre_roll: {...} | null, ad_free: bool }


Mid-Roll Ad Break Flow
──────────────────────

  Broadcaster → POST /broadcast/sessions/{id}/ad-break
       │
       ▼
  ┌────────────────────────────────────┐
  │  1. Validate broadcaster owns session   │
  │  2. Validate session is live            │
  │  3. Validate no active ad break         │
  │  4. Update DDB: ad_break_active=true    │
  │  5. SSE broadcast: ad_break:start       │
  │  6. Schedule auto-end (asyncio.sleep)   │
  └──────────┬─────────────────────────┘
             │
             ▼ (to all connected viewers)
  ┌────────────────────────────────────┐
  │  SSE Event: ad_break:start         │
  │  {                                 │
  │    type: "ad_break:start",         │
  │    duration_seconds: 30,           │
  │    skip_after_seconds: 15,         │
  │    started_at: 1748534400          │
  │  }                                 │
  └──────────┬─────────────────────────┘
             │
             ▼ (viewer client)
  ┌────────────────────────────────────┐
  │  Viewer Client Processing          │
  │                                    │
  │  Is subscriber?                    │
  │  ├─ Yes → Ignore event (ad-free)  │
  │  └─ No  → Show AdOverlay          │
  │           serve_ad(midroll)        │
  │           Start skip countdown     │
  └────────────────────────────────────┘
             │
             ▼ (after duration or manual end)
  ┌────────────────────────────────────┐
  │  SSE Event: ad_break:end           │
  │  AdOverlay dismissed               │
  │  Stream visible again              │
  └────────────────────────────────────┘
```

---

## 10. Detailed DynamoDB Access Patterns

| # | Access Pattern | Table | Key Condition | Notes |
|---|---------------|-------|---------------|-------|
| 1 | Get session by ID | `broadcast_sessions` | `session_id=X` | GetItem, includes ad config fields |
| 2 | Update session ad config | `broadcast_sessions` | `session_id=X` | UpdateItem: pre_roll_enabled, mid_roll settings |
| 3 | Set ad_break_active=true | `broadcast_sessions` | `session_id=X` | UpdateItem with SET + increment total_ad_breaks |
| 4 | Clear ad_break_active | `broadcast_sessions` | `session_id=X` | UpdateItem: ad_break_active=false, ad_break_started_at=null |
| 5 | Check subscriber status | `billing` | `pk=USER#{viewer}, sk=SUB#{creator}` | GetItem for ad-free check |

---

## 11. API Request/Response Examples

### 11.1 Create Session with Ad Config

```bash
curl -X POST http://localhost:8000/ui/broadcast/sessions \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_tok; ui_access_token=jwt_tok" \
  -H "x-csrf-token: csrf_tok" \
  -d '{
    "title": "Friday Night Stream",
    "pre_roll_enabled": true,
    "mid_roll_ad_break_duration_seconds": 30,
    "mid_roll_skip_after_seconds": 15
  }'
```

**Response (201)**:
```json
{
  "session_id": "bcast_abc123",
  "title": "Friday Night Stream",
  "status": "created",
  "pre_roll_enabled": true,
  "mid_roll_ad_break_duration_seconds": 30,
  "mid_roll_skip_after_seconds": 15,
  "ad_break_active": false,
  "total_ad_breaks": 0,
  "created_at": 1748534400
}
```

### 11.2 Trigger Mid-Roll Ad Break

```bash
curl -X POST http://localhost:8000/ui/broadcast/sessions/bcast_abc123/ad-break \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_tok; ui_access_token=jwt_tok" \
  -H "x-csrf-token: csrf_tok"
```

**Response (200)**:
```json
{
  "ok": true,
  "duration_seconds": 30,
  "started_at": 1748534500
}
```

### 11.3 End Ad Break Early

```bash
curl -X POST http://localhost:8000/ui/broadcast/sessions/bcast_abc123/ad-break/end \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_tok; ui_access_token=jwt_tok" \
  -H "x-csrf-token: csrf_tok"
```

**Response (200)**:
```json
{"ok": true}
```

### 11.4 Viewer Join with Pre-Roll

```bash
curl -X POST http://localhost:8000/ui/broadcast/sessions/bcast_abc123/join \
  -H "Cookie: ui_session=sess_bob; ui_csrf=csrf_tok; ui_access_token=jwt_tok" \
  -H "x-csrf-token: csrf_tok"
```

**Response (200)**:
```json
{
  "session_id": "bcast_abc123",
  "stream_url": "https://stream.example.com/bcast_abc123/live.m3u8",
  "pre_roll": {
    "creative_id": "cre_video_001",
    "format": "video",
    "video_url": "/mock/s3/ad-creatives/cre_video_001.mp4",
    "skip_after_seconds": 5,
    "impression_url": "/ui/ads/impressions/cre_video_001/track",
    "click_url": "/ui/ads/clicks/cre_video_001/track",
    "skip_url": "/ui/ads/skips/cre_video_001/track"
  },
  "ad_free": false
}
```

---

## 12. Error Handling Matrix

| # | Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|----------------|-------------|------------|---------------------|-----------------|
| 1 | Session not found | 404 | `SESSION_NOT_FOUND` | "Session not found." | Verify session_id |
| 2 | Not the broadcaster | 403 | `NOT_BROADCASTER` | "Only the broadcaster can trigger ad breaks." | Use broadcaster's session |
| 3 | Session not live | 400 | `SESSION_NOT_LIVE` | "Session must be live to trigger ad break." | Start the session first |
| 4 | Ad break already active | 400 | `AD_BREAK_ACTIVE` | "Ad break already active." | Wait for current break to end |
| 5 | Invalid mid_roll duration | 422 | `INVALID_DURATION` | "Duration must be between 15 and 60 seconds." | Use 15, 30, or 60 |
| 6 | Invalid skip_after value | 422 | `INVALID_SKIP` | "Skip delay must be between 5 and 30 seconds." | Use valid range |
| 7 | Ad serving fails during pre-roll | -- | -- | Pre-roll skipped; stream plays immediately | Automatic |
| 8 | Ad serving fails during mid-roll | -- | -- | Overlay dismissed; stream visible | Automatic |
| 9 | SSE connection drops during break | -- | -- | Client reconnects; checks ad_break_active | Auto-reconnect |

---

## 13. Expanded Pydantic Models

```python
from pydantic import BaseModel, Field, field_validator

class BroadcastAdConfigIn(BaseModel):
    pre_roll_enabled: bool = Field(default=True)
    mid_roll_ad_break_duration_seconds: int = Field(default=30, ge=15, le=60)
    mid_roll_skip_after_seconds: int = Field(default=15, ge=5, le=30)

    @field_validator("mid_roll_ad_break_duration_seconds")
    @classmethod
    def validate_duration(cls, v):
        if v not in (15, 30, 60):
            raise ValueError("mid_roll_ad_break_duration_seconds must be 15, 30, or 60")
        return v

class AdBreakOut(BaseModel):
    ok: bool = True
    duration_seconds: int
    started_at: int

class PreRollOut(BaseModel):
    creative_id: str
    format: str
    video_url: str | None = None
    image_url: str | None = None
    skip_after_seconds: int = 5
    impression_url: str
    click_url: str
    skip_url: str

class BroadcastJoinOut(BaseModel):
    session_id: str
    stream_url: str
    pre_roll: PreRollOut | None = None
    ad_free: bool = False
```

---

## 14. Frontend Component Tree

```
LivePlayer
├── PreRollOverlay (shown on join if pre_roll != null)
│   └── AdOverlay (data-testid="broadcast-ad-overlay")
│       ├── VideoAdPlayer / ImageAdDisplay
│       ├── CountdownTimer ("Ad ends in {N}s")
│       ├── SkipButton (appears after skip_after_seconds)
│       ├── CTAOverlayButton (optional)
│       └── ImpressionTracker (fires on mount)
│
├── MidRollOverlay (shown on ad_break:start SSE event)
│   └── AdOverlay (reuses same component)
│       ├── Fetches ad from serve_ad(midroll) on mount
│       └── Auto-dismisses on ad_break:end SSE event
│
└── BroadcasterControls (shown only to session owner)
    └── AdBreakButton (data-testid="ad-break-button")
        ├── "Insert Ad Break" label + Timer icon
        ├── ConfirmDialog ("Insert {duration}s ad break?")
        ├── disabled during active break (shows countdown)
        └── disabled if session not live
```

### Props Interfaces

```typescript
interface AdOverlayProps {
  ad: BroadcastPreRoll | MidRollAd;
  skipAfterSeconds: number;
  onSkip: () => void;
  onComplete: () => void;
  onCtaClick: (url: string) => void;
}

interface AdBreakButtonProps {
  sessionId: string;
  isLive: boolean;
  adBreakActive: boolean;
  durationSeconds: number;
  onTrigger: () => void;
}
```

---

## 15. Observability

### 15.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `broadcast_preroll_shown_total` | Counter | `session_id` | Pre-roll ads shown to viewers |
| `broadcast_preroll_skipped_total` | Counter | `session_id` | Pre-rolls skipped by viewers |
| `broadcast_midroll_triggered_total` | Counter | `session_id` | Mid-roll breaks triggered by broadcasters |
| `broadcast_midroll_ended_early_total` | Counter | `session_id` | Mid-roll breaks ended early by broadcaster |
| `broadcast_ad_free_joins_total` | Counter | -- | Subscribers who joined ad-free |
| `broadcast_ad_break_duration_seconds` | Histogram | -- | Actual ad break duration |

### 15.2 Log Events

| Event | Level | Fields |
|-------|-------|--------|
| `preroll_served` | INFO | session_id, viewer_id, creative_id |
| `preroll_skipped` | INFO | session_id, viewer_id, skip_after_seconds |
| `preroll_ad_free` | DEBUG | session_id, viewer_id, subscription_id |
| `midroll_triggered` | INFO | session_id, broadcaster_id, duration_seconds |
| `midroll_ended` | INFO | session_id, ended_by (auto/manual), actual_duration |
| `midroll_sse_sent` | DEBUG | session_id, event_type, viewer_count |

### 15.3 Alerting Rules

| Alert | Condition | Severity |
|-------|-----------|----------|
| Pre-roll failures spike | >10% pre-roll serve failures in 15 min | P3 |
| Ad break stuck | ad_break_active=true for >3x configured duration | P2 |
| SSE delivery failures | >5% SSE events undelivered in 1 hour | P2 |

---

## 16. Rollout Plan

### 16.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `BROADCAST_PREROLL_ENABLED` | `false` | Enable pre-roll ads on broadcast join |
| `BROADCAST_MIDROLL_ENABLED` | `false` | Enable mid-roll ad break button |

### 16.2 Phased Deployment

| Phase | Scope | Duration | Details |
|-------|-------|----------|---------|
| Phase 1: Backend + Session Model | Internal | Week 1 | Deploy session model extensions, ad-break endpoints, pre-roll in join response. Both flags off. |
| Phase 2: Pre-Roll Only | All users | Week 2 | `BROADCAST_PREROLL_ENABLED=true`. Viewers see pre-roll on join. Monitor skip rates and subscriber bypass. |
| Phase 3: Mid-Roll + UI | All users | Week 3 | `BROADCAST_MIDROLL_ENABLED=true`. AdBreakButton visible. AdOverlay deployed. Full SSE integration. |

---

## 17. Performance Considerations

### 17.1 Latency Targets

| Endpoint | Target p50 | Target p99 |
|----------|-----------|-----------|
| POST /join (with pre-roll) | 80ms | 300ms |
| POST /ad-break (trigger) | 50ms | 200ms |
| POST /ad-break/end | 30ms | 100ms |
| SSE event delivery | 50ms | 200ms |

### 17.2 SSE Scalability

Each broadcast session maintains a set of SSE connections for all connected viewers. `ad_break:start` and `ad_break:end` events are broadcast to all viewers simultaneously. For sessions with 1000+ concurrent viewers, the SSE publish loop iterates through all connections sequentially. Future optimization: batch SSE publish with fan-out.

### 17.3 Ad Break Auto-End

The `_schedule_ad_break_end()` function uses `asyncio.sleep(duration)` to auto-end breaks. This runs in the uvicorn event loop. For reliability, a secondary check runs every 60s scanning for sessions with `ad_break_active=true` and `ad_break_started_at + duration < now_ts()`, ending any stuck breaks.

---

## 18. Expanded E2E Tests

### 18.1 Section 369: Input Validation (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 369.1 | Invalid mid_roll duration (10s) | PATCH session with 10; 422; "must be between 15 and 60" |
| 369.2 | Invalid mid_roll duration (90s) | PATCH session with 90; 422 |
| 369.3 | Invalid skip_after (2s) | PATCH skip_after=2; 422; "must be between 5 and 30" |
| 369.4 | Valid extreme values accepted | PATCH duration=60, skip_after=30; 200 |

### 18.2 Section 370: Authorization Boundary (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 370.1 | Non-broadcaster cannot trigger ad break | Bob POST ad-break on Alice's session; 403 |
| 370.2 | Non-broadcaster cannot end ad break | Bob POST ad-break/end on Alice's session; 403 |
| 370.3 | Non-broadcaster cannot update ad config | Bob PATCH ad config on Alice's session; 403 |
| 370.4 | Viewer can join session (ad shows) | Bob POST join; 200; pre_roll present |

### 18.3 Section 371: Ad Break Lifecycle (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 371.1 | Trigger → End → Trigger again | POST ad-break; POST end; POST ad-break again; 200 |
| 371.2 | Total ad breaks increments | After 2 ad breaks, GET session; total_ad_breaks=2 |
| 371.3 | Ad break on non-live session | Stop session; POST ad-break; 400 "must be live" |
| 371.4 | Pre-roll disabled returns null | Create session with pre_roll_enabled=false; Bob joins; pre_roll=null |

### 18.4 Section 372: Subscriber Ad-Free (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 372.1 | Subscriber joins ad-free | Subscribe Bob to Alice; Bob joins; ad_free=true, pre_roll=null |
| 372.2 | Non-subscriber sees pre-roll | Unsubscribed viewer joins; pre_roll != null |
| 372.3 | Subscriber ignores mid-roll SSE | Subscriber connected; ad_break:start received; client should not show overlay |
| 372.4 | Expired subscription sees ads | Expire Bob's sub; Bob joins; ad_free=false, pre_roll present |

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/routers/broadcast.py` | — | Existing broadcast router — integration point for ad breaks |
| `app/services/ad_placement.py` | 222 | Existing `record_ad_impression` — reused for broadcast ad impressions |
| `app/services/subscription_access.py` | 55 | `has_active_subscription` — used for ad-free subscriber checks |
| `app/services/ad_serving.py` | — | Does not exist yet (ADS-004) — required for broadcast ad selection |

---

## Testing Strategy


### Unit Tests (pytest)


**Test file**: `tests/test_broadcast_ads.py`


**Mock setup**: moto for DynamoDB tables, `unittest.mock.patch` for external services (S3, Cognito, Stripe mock). All DDB tables created in-memory via moto `@mock_dynamodb` decorator.


| Test Function | Verifies |
|---|---|
| `test_create_broadcast_ads` | Creates record with correct fields and generated ID |
| `test_create_broadcast_ads_validation` | Rejects invalid input (missing required fields, out-of-range values) |
| `test_get_broadcast_ads_found` | Returns correct record by ID |
| `test_get_broadcast_ads_not_found` | Returns None for non-existent ID |
| `test_list_broadcast_ads` | Returns all records for the given scope/owner |
| `test_update_broadcast_ads` | Updates mutable fields and sets updated_at |
| `test_delete_broadcast_ads` | Removes record; subsequent get returns None |
| `test_broadcast_ads_owner_check` | Rejects operations from non-owner users |
| `test_broadcast_ads_admin_only` | Admin/root endpoints reject USER role with 403 |
| `test_broadcast_ads_concurrent_write` | Conditional update prevents stale overwrites |

### Integration Tests


Cross-service tests with real DDB (moto), verifying end-to-end flows:


1. Full CRUD lifecycle: create -> read -> update -> delete with real DDB (moto)
2. Authorization enforcement: non-owner access returns 403/404
3. Admin review/approval workflow with role-gated endpoints
4. Concurrent write safety: conditional updates prevent stale overwrites
5. Edge case: empty list returns `[]` not error; missing optional fields use defaults

### E2E Tests (Playwright)


**Test file**: `frontend/e2e/ads-broadcast.spec.ts`


**Auth setup**:
- Cookie auth: `injectAuth(page, "alice")` for UI session tests
- CSRF header: `headers: { "x-csrf-token": sessions[identity].csrf_token }`
- Bearer auth: global `request` fixture for API-only tests (bypasses CSRF)
- Admin auth: `injectAuth(page, "root")` for admin endpoints

| # | Test | Key Assertion |
|---|------|--------------|
| 1 | Create resource via API | `expect(response.status()).toBe(201)` with correct fields |
| 2 | List resources returns array | `expect(response.status()).toBe(200)`; array length > 0 |
| 3 | Get single resource by ID | `expect(response.status()).toBe(200)`; fields match |
| 4 | Update resource | `expect(response.status()).toBe(200)`; GET confirms change |
| 5 | Delete resource | `expect(response.status()).toBe(200)`; subsequent GET 404 |
| 6 | Non-owner access blocked | `expect(response.status()).toBe(403)` or `toBe(404)` |
| 7 | Admin endpoint blocked for USER | `expect(response.status()).toBe(403)` |
| 8 | Unauthenticated request | `expect(response.status()).toBe(401)` |
| 9 | Invalid input rejected | `expect(response.status()).toBe(422)` |
| 10 | Duplicate/conflict handled | `expect(response.status()).toBe(409)` or idempotent 200 |
| 11 | UI page loads correctly | `page.getByRole("heading", { name: expectedTitle })` visible |
| 12 | UI create flow works | Click create -> fill form -> submit -> new item in list |
| 13 | UI status badges display | `page.getByText("Active")` or `page.getByText("Pending")` |
| 14 | Concurrent operations safe | Parallel requests both succeed or one gets 409 |
| 15 | Edge case: empty state | Empty list shows placeholder text, not error |

### Test Data Requirements


**Test users**: Alice = USER (primary actor), Bob = USER (secondary/viewer), Root = ROOT (admin reviewer), Charlie = ADMIN (scoped admin)


**DDB seed data**: Uses existing tables; no new tables required. See DDB access patterns in technical design section.


### CI/Pipeline


- **Feature flags**: `BROADCAST_PREROLL_ENABLED`, `BROADCAST_MIDROLL_ENABLED` must be `true` in `.env.local`
- **Execution**: E2E tests run serially (1 worker, Chromium only) per `playwright.config.ts`; pytest can run in parallel
- **Retry safety**: All tests are idempotent; unique `TS = Date.now()` suffixed identifiers prevent cross-run collisions
- **Prerequisite**: `just restart` to create DDB tables and seed E2E sessions before running

## Dependencies & Merge Safety


### Depends On


| Ticket | What's Needed | Status | Can Overlap? |
|--------|--------------|--------|-------------|
| ADS-004 | Ad serving engine for pre-roll/mid-roll | Pending | No |
| ADS-002 | Video creatives for ads | Pending | No |
| Broadcast system | `app/routers/broadcast.py` | Implemented | N/A |
| Subscriptions | `subscription_access.py` | Implemented | N/A |

### Depended On By


| Ticket | What It Needs From This |
|--------|------------------------|
| ADS-007 | Broadcast impression charges |
| ADS-008 | Broadcast ad analytics |
| ADS-010 | Broadcaster ad settings |

### Merge Strategy


**Sequential (after ADS-004)**


- Must merge after: ADS-004, ADS-002
- Branch from `main` after dependencies are merged
- Can begin development in parallel but must rebase before merge
- DDB table creation is additive (no migration needed for new tables)

### Merge Checklist


- [ ] DDB tables verified (uses existing tables only)
- [ ] `.env.local` updated with any new environment variables
- [ ] Router registered in `app/main.py` (from `app/routers/broadcast.py`)
- [ ] All E2E tests passing (`just e2e` or targeted spec file)
- [ ] No breaking changes to existing endpoints or UI components
- [ ] `just restart` succeeds with new table definitions

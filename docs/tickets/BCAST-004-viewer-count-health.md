# BCAST-004: Real-Time Viewer Count and Stream Health Metrics

## 1. Overview & Motivation

### Problem Statement

Live broadcasts provide value only when the broadcaster understands their audience and
stream quality in real time. The current broadcast infrastructure (`app/routers/broadcast.py`,
`app/services/broadcast_orchestrator.py`) manages the full session lifecycle (draft through
stopped) and provisions playback URLs, but provides **zero observability** into:
<!-- NOTE: This claim is NOW OUTDATED. Viewer count and health services exist:
  `app/services/broadcast_viewers.py`, `app/services/broadcast_health.py`,
  `frontend/src/pages/broadcast/ViewerCountBadge.tsx`, `StreamHealthIndicator.tsx`,
  `frontend/e2e/broadcast-health.spec.ts` -->

1. How many viewers are currently watching a live session.
2. Whether the ingest stream is healthy (bitrate stability, dropped frames, connection state).
3. Whether the delivery pipeline is degraded (output errors, MediaLive input loss).

Without these signals, a broadcaster cannot tell if their stream is reaching anyone or if
quality has degraded to the point of viewer churn. The broadcaster dashboard (BCAST-001)
already has a "viewer count placeholder" and "health panel" in its wireframe -- this ticket
fills those placeholders with real data.

### Why Real-Time Metrics Matter

- **Engagement insight**: Viewer count spikes/drops correlate with content decisions. A
  broadcaster who sees viewership halve after a bitrate collapse can switch to a lower
  rendition preset or restart the stream.
- **Quality assurance**: Stream health indicators prevent silent failures. If the RTMP
  ingest drops to 0 kbps or frame loss exceeds 5%, the broadcaster needs an immediate
  visual alert -- not a post-mortem from CloudWatch 10 minutes later.
- **Viewer trust**: Showing "X viewers watching" gives social proof to new viewers. Hiding
  this (or showing stale data) undermines perceived liveness.

### User Stories

1. **As a broadcaster**, I want to see a real-time viewer count on my dashboard so I know
   how many people are watching my live stream right now.
2. **As a broadcaster**, I want a health indicator (green/yellow/red) that reflects my
   stream's ingest quality (bitrate, dropped frames) so I can react to problems before
   viewers notice.
3. **As a viewer**, I want to see the viewer count on the live player page so I know how
   popular the stream is.
4. **As the platform**, I want viewer count to automatically decrement when a viewer closes
   the tab or their playback token expires, so counts never grow stale.
5. **As the platform**, I want health metrics persisted to DynamoDB so I can build
   historical dashboards and trigger automated alerts.
6. **As an admin**, I want to see health history for a session so I can diagnose past
   quality incidents during post-broadcast review.

---

## 2. Current State Analysis

### 2.1 Existing Broadcast Infrastructure

The broadcast system is organized across multiple service files:

| File | Responsibility |
|------|---------------|
| `app/routers/broadcast.py` | HTTP endpoints: create/start/stop/delete sessions, mint playback URLs, audit log |
| `app/services/broadcast_store.py` | DynamoDB CRUD for profiles, sessions, outputs, transition audits |
| `app/services/broadcast_orchestrator.py` | Coordinates provider calls with state transitions |
| `app/services/broadcast_provider.py` | Provider protocol + `LocalBroadcastProvider` / `AwsBroadcastProvider` |
| `app/services/broadcast_playback.py` | Mints signed HLS playback URLs (local mode via MD5 token) |
| `app/services/broadcast_cloudfront.py` | CloudFront signed URL minting + token validation |
| `app/services/broadcast_state_machine.py` | Validates session status transitions |
| `app/models_broadcast.py` | Pydantic models for all broadcast domain objects |
| `app/metrics.py` | Prometheus-style counters: provision latency, session actions, input loss, output errors |

**DynamoDB Tables** (from `scripts/local-ddb-init.py`):

| Table | Key Schema | GSIs |
|-------|-----------|------|
| `BroadcastSessions` | PK: `session_id` | `ByStatusCreatedAt`, `ByCreatorCreatedAt` |
| `BroadcastOutputs` | PK: `session_id`, SK: `scope` | (none) |
| `BroadcastProfiles` | PK: `profile_id` | (none) |
| `BroadcastSessionTransitions` | PK: `transition_id`, SK: `session_id` | (none) |
| `BroadcastActionAudit` | PK: `audit_id` | `ByActorCreatedAt`, `ByCreatedAt` |

**No viewer or health data is currently stored anywhere.** The `BroadcastOutputs` table
stores static infrastructure details (ARNs, playback URLs) but has no fields for dynamic
metrics.

### 2.2 Existing SSE Patterns

The codebase uses two distinct SSE delivery approaches:

**Pattern A: Long-poll DynamoDB scan (Messaging)**

In `app/routers/messaging.py` (line 11036), the `/messaging/events/stream` endpoint:
- Opens a `StreamingResponse` with `media_type="text/event-stream"`
- Polls DynamoDB every `poll_ms` milliseconds for new events after a cursor
- Sends typed events via `_sse_pack(data, event=type)` which formats as `event: <type>\ndata: <json>\n\n`
- Sends `: ping\n\n` heartbeat every 15 seconds
- Frontend (`frontend/src/hooks/useMessagingStream.ts`) connects via native `EventSource` with named event listeners

**Pattern B: In-memory pub/sub queue (Alerts)**

In `app/services/alerts.py` (line 55), an in-memory pub/sub system:
- `_SSE_SUBSCRIBERS: Dict[str, Set[asyncio.Queue]]` maps user IDs to subscriber queues
- `sse_subscribe(user_sub)` creates an `asyncio.Queue(maxsize=200)` and adds it to the set
- `sse_publish_alert(user_sub, alert_obj)` pushes to all subscriber queues for that user
- `sse_unsubscribe(user_sub, q)` removes the queue on disconnect
- The `/alerts/stream` endpoint (line 382) awaits `q.get()` in an async generator

**Pattern B is better suited for broadcast viewer metrics** because:
1. Viewer count changes are session-scoped (not user-scoped) -- all viewers of session X
   need the same update.
2. DynamoDB polling adds unnecessary latency and read cost for high-frequency updates.
3. The in-memory queue pattern can fan out a single viewer-count update to all connected
   SSE clients for that session.

### 2.3 Existing Metrics Infrastructure

`app/metrics.py` already defines broadcast-specific counters (lines 899-920):
- `broadcast_provision_latency_seconds` (histogram)
- `broadcast_session_actions_total` (counter, labels: provider, action, result)
- `broadcast_input_loss_total` (counter, labels: provider, reason)
- `broadcast_output_errors_total` (counter, labels: provider, reason)
- `broadcast_drift_incidents_total` (counter, labels: provider, incident_type)

Recording functions exist (`record_broadcast_input_loss`, `record_broadcast_output_error`)
but are only called from `broadcast_provider.py` and `broadcast.py` on error paths. They
are never populated with live streaming data from CloudWatch or ingest probes.

### 2.4 Playback URL as Viewer Registration Point

The existing `POST /broadcast/sessions/{id}/playback-url` endpoint (line 313 in
`app/routers/broadcast.py`) is the natural viewer entry point. Every viewer must call this
to obtain a signed HLS URL before playback begins. This can serve as the "viewer join"
signal without requiring a separate registration endpoint.

### 2.5 Frontend State

There is currently **no frontend broadcast page** in the repository (BCAST-001 is still a
spec). The frontend API endpoint file (`frontend/src/api/endpoints/broadcast.ts`) and page
components (`frontend/src/pages/broadcaster/`) do not yet exist. This ticket's frontend
work will be integrated alongside or after BCAST-001's implementation.

---

## 3. Technical Design

### 3.1 Architecture Overview

```
+-------------------+         +---------------------+         +------------------+
| Viewer Browser    |         | Backend (FastAPI)    |         | Broadcaster UI   |
|                   |         |                     |         |                  |
| 1. POST playback  |-------->| register_viewer()   |         |                  |
|    -url           |         | DDB: viewers++      |-------->| SSE: viewer_count|
|                   |         |                     |         |                  |
| 2. GET .../       |-------->| SSE: broadcast/     |         | GET health       |
|    viewer-stream  |<--------| sessions/{id}/      |<--------| endpoint         |
|                   |         | viewer-stream       |         |                  |
| 3. Heartbeat      |-------->| touch_viewer()      |         |                  |
|    POST /heartbeat|         | reset TTL           |         |                  |
|                   |         |                     |         |                  |
| 4. Leave / close  |-------->| unregister_viewer() |         |                  |
|                   |         | DDB: viewers--      |-------->| SSE: viewer_count|
+-------------------+         +---------------------+         +------------------+
                                       |
                              +--------v---------+
                              | Health Collector  |
                              | (background task) |
                              | - CloudWatch poll |
                              | - Ingest probe    |
                              | - Store to DDB    |
                              | - Publish SSE     |
                              +------------------+
```

### 3.2 Viewer Count Tracking

#### 3.2.1 DynamoDB Table: `BroadcastViewers`

**Purpose**: Track active viewer sessions with TTL-based expiry.

| Attribute | Type | Description |
|-----------|------|-------------|
| `session_id` | S (PK) | Broadcast session ID |
| `viewer_id` | S (SK) | Unique viewer identifier (`{user_sub}#{connection_id}`) |
| `user_sub` | S | Authenticated user |
| `joined_at` | N | Unix timestamp when viewer joined |
| `last_heartbeat` | N | Unix timestamp of last heartbeat |
| `expires_at` | N | TTL attribute -- auto-deleted by DynamoDB after this time |
| `user_agent` | S | Browser user-agent (for analytics) |

**Key design decisions**:
- `viewer_id` combines user sub + a unique connection ID to support the same user watching
  on multiple tabs/devices.
- `expires_at` is set to `last_heartbeat + 60` seconds. If no heartbeat arrives within 60s,
  DynamoDB TTL deletes the record automatically.
- Viewer count = `COUNT` query on `session_id` PK.

**GSI**: `BySessionJoinedAt` (PK: `session_id`, SK: `joined_at`) for listing viewers
ordered by join time.

#### 3.2.2 DynamoDB Table: `BroadcastHealthSnapshots`

**Purpose**: Store periodic health metric snapshots for each live session.

| Attribute | Type | Description |
|-----------|------|-------------|
| `session_id` | S (PK) | Broadcast session ID |
| `snapshot_ts` | N (SK) | Unix timestamp of this snapshot |
| `viewer_count` | N | Concurrent viewer count at this moment |
| `ingest_bitrate_kbps` | N | Current ingest bitrate in kbps |
| `ingest_framerate` | N | Current ingest frame rate (fps) |
| `dropped_frames` | N | Cumulative dropped frames since session start |
| `dropped_frames_pct` | N | Dropped frame percentage (last 30s window) |
| `connection_quality` | S | One of: `excellent`, `good`, `fair`, `poor`, `critical` |
| `output_errors` | N | Output error count in last 30s window |
| `input_loss_seconds` | N | Seconds of input loss in last 30s window |
| `ttl` | N | DynamoDB TTL -- expire snapshots after 7 days |

**Note**: `attr_types={"snapshot_ts": "N", "viewer_count": "N", ...}` must be specified in
`scripts/local-ddb-init.py` for numeric sort key.

#### 3.2.3 In-Memory Pub/Sub for Broadcast Events

Following the alerts SSE pattern, create a session-scoped pub/sub system:

```python
# app/services/broadcast_sse.py

import asyncio
from typing import Any, Dict, Set

_BROADCAST_SUBSCRIBERS: Dict[str, Set[asyncio.Queue]] = {}

def broadcast_sse_subscribe(session_id: str) -> asyncio.Queue:
    """Subscribe to real-time events for a broadcast session."""
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    subs = _BROADCAST_SUBSCRIBERS.setdefault(session_id, set())
    subs.add(q)
    return q

def broadcast_sse_unsubscribe(session_id: str, q: asyncio.Queue) -> None:
    """Unsubscribe from a broadcast session's event stream."""
    subs = _BROADCAST_SUBSCRIBERS.get(session_id)
    if not subs:
        return
    subs.discard(q)
    if not subs:
        _BROADCAST_SUBSCRIBERS.pop(session_id, None)

def broadcast_sse_publish(session_id: str, event: Dict[str, Any]) -> None:
    """Publish an event to all subscribers of a broadcast session."""
    subs = _BROADCAST_SUBSCRIBERS.get(session_id)
    if not subs:
        return
    dead = []
    for q in list(subs):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        broadcast_sse_unsubscribe(session_id, q)

def broadcast_sse_subscriber_count(session_id: str) -> int:
    """Return number of active SSE subscribers for a session."""
    subs = _BROADCAST_SUBSCRIBERS.get(session_id)
    return len(subs) if subs else 0
```

### 3.3 API Endpoints

#### 3.3.1 Viewer Registration (join/leave/heartbeat)

Add to `app/routers/broadcast.py`:

```python
# --- Viewer Count Endpoints ---

class ViewerJoinOut(BaseModel):
    viewer_id: str
    session_id: str
    viewer_count: int

class ViewerHeartbeatOut(BaseModel):
    ok: bool
    viewer_count: int

class ViewerCountOut(BaseModel):
    session_id: str
    viewer_count: int

@router.post("/sessions/{session_id}/viewers/join", response_model=ViewerJoinOut)
def viewer_join(session_id: str, ctx: dict = Depends(_ctx)):
    """Register as a viewer. Called when playback begins."""
    ...

@router.post("/sessions/{session_id}/viewers/heartbeat", response_model=ViewerHeartbeatOut)
def viewer_heartbeat(session_id: str, viewer_id: str = Query(...), ctx: dict = Depends(_ctx)):
    """Heartbeat to keep viewer session alive. Call every 30s."""
    ...

@router.post("/sessions/{session_id}/viewers/leave")
def viewer_leave(session_id: str, viewer_id: str = Query(...), ctx: dict = Depends(_ctx)):
    """Explicit leave signal. Called on page unload via sendBeacon."""
    ...

@router.get("/sessions/{session_id}/viewers/count", response_model=ViewerCountOut)
def viewer_count(session_id: str, ctx: dict = Depends(_ctx)):
    """Get current viewer count for a session."""
    ...
```

#### 3.3.2 Health Metrics Endpoints

```python
class BroadcastHealthOut(BaseModel):
    session_id: str
    viewer_count: int
    ingest_bitrate_kbps: int
    ingest_framerate: float
    dropped_frames: int
    dropped_frames_pct: float
    connection_quality: str  # excellent|good|fair|poor|critical
    output_errors: int
    input_loss_seconds: float
    updated_at: int  # Unix timestamp

class BroadcastHealthHistoryOut(BaseModel):
    session_id: str
    snapshots: List[BroadcastHealthOut]

@router.get("/sessions/{session_id}/health", response_model=BroadcastHealthOut)
def get_session_health(session_id: str, ctx: dict = Depends(_ctx)):
    """Get current health metrics for a live session."""
    ...

@router.get("/sessions/{session_id}/health/history", response_model=BroadcastHealthHistoryOut)
def get_session_health_history(
    session_id: str,
    from_ts: Optional[int] = Query(default=None),
    to_ts: Optional[int] = Query(default=None),
    limit: int = Query(default=60, ge=1, le=360),
    ctx: dict = Depends(_ctx),
):
    """Get health metric history (for charts). Admin/broadcaster only."""
    ...
```

#### 3.3.3 Broadcast SSE Stream Endpoint

```python
@router.get("/sessions/{session_id}/stream")
async def broadcast_event_stream(session_id: str, ctx: dict = Depends(_ctx)):
    """SSE stream for real-time broadcast events (viewer count, health updates)."""
    from app.services.broadcast_sse import broadcast_sse_subscribe, broadcast_sse_unsubscribe

    _ = get_session(session_id)  # 404 if session doesn't exist
    q = broadcast_sse_subscribe(session_id)

    async def gen():
        try:
            yield "event: hello\ndata: {}\n\n"
            while True:
                item = await q.get()
                event_type = item.pop("_type", "update")
                yield f"event: {event_type}\ndata: {json.dumps(item, separators=(',', ':'))}\n\n"
        finally:
            broadcast_sse_unsubscribe(session_id, q)

    return StreamingResponse(gen(), media_type="text/event-stream")
```

**SSE Event Types**:
- `viewer_count` -- `{ session_id, viewer_count, delta: +1|-1 }`
- `health_update` -- `{ session_id, ingest_bitrate_kbps, dropped_frames_pct, connection_quality, ... }`
- `session_status` -- `{ session_id, status, updated_at }` (piggyback on status transitions)

#### 3.3.4 Health Reporting Endpoint (from broadcaster/ingest)

```python
class BroadcastHealthReportIn(BaseModel):
    ingest_bitrate_kbps: int = Field(ge=0, le=100_000)
    ingest_framerate: float = Field(ge=0, le=240)
    dropped_frames: int = Field(ge=0)
    dropped_frames_pct: float = Field(ge=0, le=100)
    output_errors: int = Field(ge=0, default=0)
    input_loss_seconds: float = Field(ge=0, default=0)

@router.post("/sessions/{session_id}/health/report")
def report_session_health(
    session_id: str,
    body: BroadcastHealthReportIn,
    ctx: dict = Depends(_ctx),
):
    """
    Accept health metrics from the broadcaster client or ingest probe.
    Stores snapshot and publishes via SSE to all connected clients.
    """
    ...
```

### 3.4 Service Layer: `app/services/broadcast_viewers.py`

```python
"""Viewer count tracking for live broadcast sessions."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish


VIEWER_TTL_SECONDS = 60  # Viewer record expires 60s after last heartbeat
HEARTBEAT_INTERVAL_SECONDS = 30  # Client should heartbeat every 30s


def register_viewer(session_id: str, user_sub: str, user_agent: str = "") -> Dict[str, Any]:
    """Register a new viewer for a broadcast session. Returns viewer record."""
    connection_id = uuid4().hex[:12]
    viewer_id = f"{user_sub}#{connection_id}"
    now = now_ts()

    item = {
        "session_id": session_id,
        "viewer_id": viewer_id,
        "user_sub": user_sub,
        "joined_at": now,
        "last_heartbeat": now,
        "expires_at": now + VIEWER_TTL_SECONDS,
        "user_agent": user_agent,
    }
    T.broadcast_viewers.put_item(Item=item)

    count = get_viewer_count(session_id)
    broadcast_sse_publish(session_id, {
        "_type": "viewer_count",
        "session_id": session_id,
        "viewer_count": count,
        "delta": 1,
    })
    return {"viewer_id": viewer_id, "session_id": session_id, "viewer_count": count}


def touch_viewer(session_id: str, viewer_id: str) -> int:
    """Update heartbeat timestamp and extend TTL. Returns current viewer count."""
    now = now_ts()
    T.broadcast_viewers.update_item(
        Key={"session_id": session_id, "viewer_id": viewer_id},
        UpdateExpression="SET last_heartbeat = :hb, expires_at = :exp",
        ExpressionAttributeValues={":hb": now, ":exp": now + VIEWER_TTL_SECONDS},
        ConditionExpression="attribute_exists(viewer_id)",
    )
    return get_viewer_count(session_id)


def unregister_viewer(session_id: str, viewer_id: str) -> int:
    """Remove viewer record explicitly. Returns updated viewer count."""
    T.broadcast_viewers.delete_item(
        Key={"session_id": session_id, "viewer_id": viewer_id}
    )
    count = get_viewer_count(session_id)
    broadcast_sse_publish(session_id, {
        "_type": "viewer_count",
        "session_id": session_id,
        "viewer_count": count,
        "delta": -1,
    })
    return count


def get_viewer_count(session_id: str) -> int:
    """Count active viewers for a session (DDB Select=COUNT query)."""
    resp = T.broadcast_viewers.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
        Select="COUNT",
    )
    return resp.get("Count", 0)


def list_viewers(session_id: str, limit: int = 100) -> list:
    """List active viewers for a session (for admin display)."""
    resp = T.broadcast_viewers.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
        Limit=limit,
        ScanIndexForward=False,
    )
    return resp.get("Items", [])
```

### 3.5 Service Layer: `app/services/broadcast_health.py`

```python
"""Stream health metrics collection, storage, and classification."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish
from app.services.broadcast_viewers import get_viewer_count


SNAPSHOT_TTL_DAYS = 7

# Connection quality thresholds
QUALITY_THRESHOLDS = {
    # (dropped_frames_pct, min_bitrate_kbps, input_loss_seconds)
    "excellent": (0.1, 4000, 0),
    "good": (0.5, 2000, 0),
    "fair": (2.0, 1000, 2),
    "poor": (5.0, 500, 5),
    # anything worse = "critical"
}


def classify_connection_quality(
    dropped_frames_pct: float,
    ingest_bitrate_kbps: int,
    input_loss_seconds: float,
) -> str:
    """Classify stream quality into a color-coded tier."""
    for level, (max_drop, min_bitrate, max_loss) in QUALITY_THRESHOLDS.items():
        if (
            dropped_frames_pct <= max_drop
            and ingest_bitrate_kbps >= min_bitrate
            and input_loss_seconds <= max_loss
        ):
            return level
    return "critical"


def store_health_snapshot(
    session_id: str,
    *,
    ingest_bitrate_kbps: int,
    ingest_framerate: float,
    dropped_frames: int,
    dropped_frames_pct: float,
    output_errors: int = 0,
    input_loss_seconds: float = 0,
) -> Dict[str, Any]:
    """Store a health snapshot and publish via SSE."""
    now = now_ts()
    viewer_count = get_viewer_count(session_id)
    quality = classify_connection_quality(dropped_frames_pct, ingest_bitrate_kbps, input_loss_seconds)

    item = {
        "session_id": session_id,
        "snapshot_ts": now,
        "viewer_count": viewer_count,
        "ingest_bitrate_kbps": ingest_bitrate_kbps,
        "ingest_framerate": ingest_framerate,
        "dropped_frames": dropped_frames,
        "dropped_frames_pct": dropped_frames_pct,
        "connection_quality": quality,
        "output_errors": output_errors,
        "input_loss_seconds": input_loss_seconds,
        "ttl": now + (SNAPSHOT_TTL_DAYS * 86400),
    }
    T.broadcast_health_snapshots.put_item(Item=item)

    # Publish health update to all SSE subscribers
    broadcast_sse_publish(session_id, {
        "_type": "health_update",
        "session_id": session_id,
        "viewer_count": viewer_count,
        "ingest_bitrate_kbps": ingest_bitrate_kbps,
        "ingest_framerate": ingest_framerate,
        "dropped_frames": dropped_frames,
        "dropped_frames_pct": dropped_frames_pct,
        "connection_quality": quality,
        "output_errors": output_errors,
        "input_loss_seconds": input_loss_seconds,
        "updated_at": now,
    })

    return item


def get_latest_health(session_id: str) -> Optional[Dict[str, Any]]:
    """Get the most recent health snapshot for a session."""
    resp = T.broadcast_health_snapshots.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
        ScanIndexForward=False,
        Limit=1,
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def get_health_history(
    session_id: str,
    from_ts: Optional[int] = None,
    to_ts: Optional[int] = None,
    limit: int = 60,
) -> List[Dict[str, Any]]:
    """Get health snapshot history for a session within a time range."""
    kce = Key("session_id").eq(session_id)
    if from_ts and to_ts:
        kce = kce & Key("snapshot_ts").between(from_ts, to_ts)
    elif from_ts:
        kce = kce & Key("snapshot_ts").gte(from_ts)
    elif to_ts:
        kce = kce & Key("snapshot_ts").lte(to_ts)

    resp = T.broadcast_health_snapshots.query(
        KeyConditionExpression=kce,
        ScanIndexForward=False,
        Limit=limit,
    )
    return resp.get("Items", [])
```

### 3.6 Connection Quality Indicator Logic

The `connection_quality` field maps to a visual indicator:

| Quality | Color | Criteria |
|---------|-------|----------|
| `excellent` | Green (bright) | Drop <0.1%, bitrate >4000kbps, no input loss |
| `good` | Green | Drop <0.5%, bitrate >2000kbps, no input loss |
| `fair` | Yellow | Drop <2%, bitrate >1000kbps, loss <2s |
| `poor` | Orange | Drop <5%, bitrate >500kbps, loss <5s |
| `critical` | Red | Anything worse than "poor" |

### 3.7 Frontend Components

#### 3.7.1 Hook: `useBroadcastStream`

```typescript
// frontend/src/hooks/useBroadcastStream.ts

import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";

export interface BroadcastHealthData {
  session_id: string;
  viewer_count: number;
  ingest_bitrate_kbps: number;
  ingest_framerate: number;
  dropped_frames: number;
  dropped_frames_pct: number;
  connection_quality: "excellent" | "good" | "fair" | "poor" | "critical";
  output_errors: number;
  input_loss_seconds: number;
  updated_at: number;
}

/**
 * SSE hook for real-time broadcast session events.
 * Provides viewer count and health metrics via EventSource.
 */
export function useBroadcastStream(sessionId: string | null, enabled = true) {
  const queryClient = useQueryClient();
  const [viewerCount, setViewerCount] = React.useState(0);
  const [health, setHealth] = React.useState<BroadcastHealthData | null>(null);
  const retryCount = React.useRef(0);

  React.useEffect(() => {
    if (!enabled || !sessionId) return;

    let es: EventSource | null = null;
    let retryTimer: ReturnType<typeof setTimeout>;

    function connect() {
      es = new EventSource(`/broadcast/sessions/${sessionId}/stream`, {
        withCredentials: true,
      });

      es.onopen = () => { retryCount.current = 0; };

      es.addEventListener("viewer_count", (event: MessageEvent) => {
        const data = JSON.parse(event.data);
        setViewerCount(data.viewer_count);
      });

      es.addEventListener("health_update", (event: MessageEvent) => {
        const data = JSON.parse(event.data) as BroadcastHealthData;
        setHealth(data);
        setViewerCount(data.viewer_count);
      });

      es.addEventListener("session_status", (event: MessageEvent) => {
        queryClient.invalidateQueries({ queryKey: ["broadcast", "sessions", sessionId] });
      });

      es.onerror = () => {
        es?.close();
        es = null;
        const delay = Math.min(1000 * Math.pow(2, retryCount.current), 30_000);
        retryCount.current++;
        retryTimer = setTimeout(connect, delay);
      };
    }

    connect();
    return () => { es?.close(); clearTimeout(retryTimer); };
  }, [sessionId, enabled, queryClient]);

  return { viewerCount, health };
}
```

#### 3.7.2 Hook: `useViewerHeartbeat`

```typescript
// frontend/src/hooks/useViewerHeartbeat.ts

import * as React from "react";
import { api } from "@/api/client";

const HEARTBEAT_INTERVAL = 30_000; // 30 seconds

/**
 * Manages viewer lifecycle: join on mount, heartbeat every 30s, leave on unmount.
 * Uses sendBeacon for reliable leave signal on page close.
 */
export function useViewerHeartbeat(sessionId: string | null, enabled = true) {
  const viewerIdRef = React.useRef<string | null>(null);

  React.useEffect(() => {
    if (!enabled || !sessionId) return;

    let heartbeatTimer: ReturnType<typeof setInterval>;

    // Join
    api.post(`/broadcast/sessions/${sessionId}/viewers/join`)
      .then((resp) => {
        viewerIdRef.current = resp.data.viewer_id;
        // Start heartbeat
        heartbeatTimer = setInterval(() => {
          if (viewerIdRef.current) {
            api.post(`/broadcast/sessions/${sessionId}/viewers/heartbeat`, null, {
              params: { viewer_id: viewerIdRef.current },
            }).catch(() => {});
          }
        }, HEARTBEAT_INTERVAL);
      });

    // Leave on page unload (sendBeacon for reliability)
    const handleUnload = () => {
      if (viewerIdRef.current) {
        const url = `/broadcast/sessions/${sessionId}/viewers/leave?viewer_id=${viewerIdRef.current}`;
        navigator.sendBeacon(url);
      }
    };
    window.addEventListener("beforeunload", handleUnload);

    return () => {
      clearInterval(heartbeatTimer);
      window.removeEventListener("beforeunload", handleUnload);
      // Explicit leave on React unmount (e.g. navigating away)
      if (viewerIdRef.current) {
        api.post(`/broadcast/sessions/${sessionId}/viewers/leave`, null, {
          params: { viewer_id: viewerIdRef.current },
        }).catch(() => {});
      }
    };
  }, [sessionId, enabled]);
}
```

#### 3.7.3 Component: `ViewerCountBadge`

```typescript
// frontend/src/pages/broadcaster/ViewerCountBadge.tsx

import { Users } from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface ViewerCountBadgeProps {
  count: number;
  className?: string;
}

export function ViewerCountBadge({ count, className }: ViewerCountBadgeProps) {
  return (
    <Badge variant="secondary" className={className}>
      <Users className="h-3 w-3 mr-1" />
      {count.toLocaleString()} {count === 1 ? "viewer" : "viewers"}
    </Badge>
  );
}
```

#### 3.7.4 Component: `StreamHealthIndicator`

```typescript
// frontend/src/pages/broadcaster/StreamHealthIndicator.tsx

import { Activity, AlertTriangle, XCircle } from "lucide-react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

type Quality = "excellent" | "good" | "fair" | "poor" | "critical";

const QUALITY_CONFIG: Record<Quality, { color: string; icon: typeof Activity; label: string }> = {
  excellent: { color: "text-green-500", icon: Activity, label: "Excellent" },
  good: { color: "text-green-400", icon: Activity, label: "Good" },
  fair: { color: "text-yellow-500", icon: AlertTriangle, label: "Fair" },
  poor: { color: "text-orange-500", icon: AlertTriangle, label: "Poor" },
  critical: { color: "text-red-500", icon: XCircle, label: "Critical" },
};

interface StreamHealthIndicatorProps {
  quality: Quality;
  bitrateKbps: number;
  droppedFramesPct: number;
  className?: string;
}

export function StreamHealthIndicator({
  quality,
  bitrateKbps,
  droppedFramesPct,
  className,
}: StreamHealthIndicatorProps) {
  const config = QUALITY_CONFIG[quality];
  const Icon = config.icon;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div className={`flex items-center gap-1 ${className}`}>
          <Icon className={`h-4 w-4 ${config.color}`} />
          <span className={`text-sm font-medium ${config.color}`}>{config.label}</span>
        </div>
      </TooltipTrigger>
      <TooltipContent>
        <div className="text-xs space-y-1">
          <div>Bitrate: {bitrateKbps.toLocaleString()} kbps</div>
          <div>Dropped frames: {droppedFramesPct.toFixed(1)}%</div>
          <div>Quality: {quality}</div>
        </div>
      </TooltipContent>
    </Tooltip>
  );
}
```

#### 3.7.5 Component: `HealthMetricsPanel`

A collapsible panel for the broadcaster dashboard showing detailed metrics + mini chart:

```typescript
// frontend/src/pages/broadcaster/HealthMetricsPanel.tsx

interface HealthMetricsPanelProps {
  sessionId: string;
  health: BroadcastHealthData | null;
}

export function HealthMetricsPanel({ sessionId, health }: HealthMetricsPanelProps) {
  // Uses useQuery to fetch health history for sparkline chart
  // Displays: bitrate graph, frame rate, dropped %, viewer count over time
  // Updates in real-time via useBroadcastStream hook
}
```

### 3.8 Polling Fallback (Non-SSE Clients)

For clients that cannot maintain SSE connections (mobile webviews, degraded networks),
the `GET /broadcast/sessions/{id}/health` endpoint serves the same data via polling.
Recommended poll interval: 10 seconds. The broadcaster dashboard already uses 10s polling
for session status (per BCAST-001 design) -- health data piggybacks on that interval.

### 3.9 Interaction with Existing Broadcast Lifecycle

**On session start** (`start_session_with_provider`):
- Publish `session_status: live` via `broadcast_sse_publish`
- Health collector background task begins (if AWS mode, polls CloudWatch every 10s)

**On session stop** (`stop_session_with_provider`):
- All viewer records for the session are batch-deleted
- Publish `session_status: stopped` via `broadcast_sse_publish`
- Final health snapshot stored with `viewer_count: 0`
- SSE subscribers receive the event, then the generator returns (stream closed)

**On viewer count change**:
- Both `register_viewer` and `unregister_viewer` publish `viewer_count` events
- The broadcaster's SSE connection (dashboard) and all viewer SSE connections receive the update

### 3.10 Production Mode: CloudWatch Metrics Integration

In production (AWS provider), health metrics come from CloudWatch rather than client
reports:

```python
# app/services/broadcast_health_collector.py (production extension)

import boto3

def poll_cloudwatch_metrics(session_id: str, channel_id: str) -> dict:
    """Poll MediaLive CloudWatch metrics for a live channel."""
    cw = boto3.client("cloudwatch")
    # Metrics: AWS/MediaLive NetworkIn, DroppedFrames, InputVideoFrameRate
    # Period: 10 seconds
    # This runs in a background asyncio task every 10s while session is live
    ...
```

In dev/local mode, health metrics come from the broadcaster client via the
`POST /sessions/{id}/health/report` endpoint (the OBS stats plugin or a browser-based
ingest UI can POST metrics).

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/broadcast_sse.py` | In-memory pub/sub for broadcast session events |
| `app/services/broadcast_viewers.py` | Viewer registration, heartbeat, count, unregister |
| `app/services/broadcast_health.py` | Health snapshot storage, classification, history |
| `frontend/src/hooks/useBroadcastStream.ts` | SSE hook for broadcast events |
| `frontend/src/hooks/useViewerHeartbeat.ts` | Viewer lifecycle management hook |
| `frontend/src/pages/broadcaster/ViewerCountBadge.tsx` | Viewer count display component |
| `frontend/src/pages/broadcaster/StreamHealthIndicator.tsx` | Health quality indicator |
| `frontend/src/pages/broadcaster/HealthMetricsPanel.tsx` | Detailed health panel |
| `frontend/e2e/broadcast-health.spec.ts` | E2E tests for viewer count + health |
| `tests/test_broadcast_viewers.py` | Unit tests for viewer service |
| `tests/test_broadcast_health.py` | Unit tests for health service |

### 4.2 Files to Modify

| File | Change |
|------|--------|
| `app/routers/broadcast.py` | Add 7 new endpoints (viewer join/heartbeat/leave/count, health get/history/report, SSE stream) |
| `app/core/settings.py` | Add `broadcast_viewers_table_name`, `broadcast_health_snapshots_table_name`, `broadcast_health_poll_interval_seconds` settings |
| `app/core/tables.py` | Add `broadcast_viewers` and `broadcast_health_snapshots` table handles |
| `scripts/local-ddb-init.py` | Add `BroadcastViewers` and `BroadcastHealthSnapshots` table definitions (with `attr_types` for numeric keys) |
| `app/models_broadcast.py` | Add `BroadcastViewerModel` and `BroadcastHealthSnapshotModel` Pydantic models |
| `app/metrics.py` | Add `broadcast_viewer_joins_total`, `broadcast_viewer_leaves_total`, `broadcast_health_reports_total` counters |
| `frontend/src/api/endpoints/broadcast.ts` | Add viewer and health API functions (when BCAST-001 creates this file) |
| `frontend/vite.config.ts` | Ensure `/broadcast` proxy entry exists (may already be added by BCAST-001) |

### 4.3 Step-by-Step Implementation Order

**Phase 1: Backend Infrastructure (2-3 hours)**

1. Add settings to `app/core/settings.py`:
   ```python
   broadcast_viewers_table_name: str = os.environ.get("DDB_BROADCAST_VIEWERS", "BroadcastViewers")
   broadcast_health_snapshots_table_name: str = os.environ.get("DDB_BROADCAST_HEALTH_SNAPSHOTS", "BroadcastHealthSnapshots")
   broadcast_health_poll_interval_seconds: int = int(os.environ.get("BROADCAST_HEALTH_POLL_INTERVAL_SECONDS", "10"))
   broadcast_viewer_ttl_seconds: int = int(os.environ.get("BROADCAST_VIEWER_TTL_SECONDS", "60"))
   ```

2. Add table handles to `app/core/tables.py`:
   ```python
   broadcast_viewers: Any
   broadcast_health_snapshots: Any
   ```

3. Add DynamoDB table definitions to `scripts/local-ddb-init.py`:
   ```python
   TableDef(
       _resolve_table_name(S.broadcast_viewers_table_name, "BroadcastViewers"),
       "session_id", "viewer_id",
       attr_types={"joined_at": "N", "expires_at": "N"},
   ),
   TableDef(
       _resolve_table_name(S.broadcast_health_snapshots_table_name, "BroadcastHealthSnapshots"),
       "session_id", "snapshot_ts",
       attr_types={"snapshot_ts": "N"},
   ),
   ```

4. Add Pydantic models to `app/models_broadcast.py`.

5. Create `app/services/broadcast_sse.py` (pub/sub module).

6. Create `app/services/broadcast_viewers.py` (viewer tracking).

7. Create `app/services/broadcast_health.py` (health metrics).

**Phase 2: API Endpoints (2-3 hours)**

8. Add viewer endpoints to `app/routers/broadcast.py`:
   - `POST /sessions/{id}/viewers/join`
   - `POST /sessions/{id}/viewers/heartbeat`
   - `POST /sessions/{id}/viewers/leave`
   - `GET /sessions/{id}/viewers/count`

9. Add health endpoints:
   - `GET /sessions/{id}/health`
   - `GET /sessions/{id}/health/history`
   - `POST /sessions/{id}/health/report`

10. Add SSE stream endpoint:
    - `GET /sessions/{id}/stream`

11. Hook into existing lifecycle: publish `session_status` events from
    `start_session_route` and `stop_session_route`.

**Phase 3: Frontend Hooks + Components (2-3 hours)**

12. Create `frontend/src/hooks/useBroadcastStream.ts`.

13. Create `frontend/src/hooks/useViewerHeartbeat.ts`.

14. Create `frontend/src/pages/broadcaster/ViewerCountBadge.tsx`.

15. Create `frontend/src/pages/broadcaster/StreamHealthIndicator.tsx`.

16. Create `frontend/src/pages/broadcaster/HealthMetricsPanel.tsx`.

17. Add API endpoint wrappers to `frontend/src/api/endpoints/broadcast.ts`
    (viewer join/leave/heartbeat, health get/report).

**Phase 4: Integration (1-2 hours)**

18. Wire `useBroadcastStream` into `BroadcasterPage.tsx` session detail view
    (created by BCAST-001).

19. Wire `useViewerHeartbeat` into `LivePlayer.tsx` (created by BCAST-002).

20. Wire `ViewerCountBadge` into both broadcaster dashboard and viewer player page.

21. Wire `StreamHealthIndicator` + `HealthMetricsPanel` into broadcaster session
    detail dialog.

### 4.4 Dependencies

| Dependency | Impact | Mitigation |
|-----------|--------|------------|
| BCAST-001 (dashboard page) | Health panel needs a page to live in | Frontend components can be built standalone; integration is a single import |
| BCAST-002 (viewer page) | Heartbeat hook needs a viewer page | Hook works independently; wire in when LivePlayer exists |
| BCAST-003 (AWS execution) | Production CloudWatch metrics need real MediaLive | Local mode uses client-reported metrics; AWS collector is additive |
| DynamoDB tables | Must exist before service layer works | Add to `local-ddb-init.py` early; tables auto-create on `just up` |

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_broadcast_viewers_health.py`

**Mock setup**: moto mock for DynamoDB (`BroadcastViewers`, `BroadcastHealthSnapshots` tables). Patch `now_ts()` for TTL testing.

| Test Function | Description |
|---|---|
| `test_heartbeat_increments_viewer_count` | POST heartbeat; GET count returns 1 |
| `test_heartbeat_dedup_same_device` | Two heartbeats same device_id; count still 1 |
| `test_expired_viewers_decremented` | Heartbeat TTL expires; count drops to 0 |
| `test_health_snapshot_persisted` | POST health metrics; snapshot stored in DDB with correct fields |
| `test_health_history_returns_sorted` | Seed 5 snapshots; GET returns newest first |
| `test_health_status_green_yellow_red` | Bitrate thresholds classify as good/degraded/critical |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Heartbeat -> viewer count increment -> TTL expiry -> count decrement
2. Health snapshot write -> query history -> verify sorted by timestamp
3. Concurrent heartbeats from different devices -> count equals unique device count

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/broadcast-health.spec.ts`

**Auth pattern**: `injectAuth(page, "alice")` for viewer; `injectAuth(page, "root")` for broadcaster

| # | Test Name | Assertion |
|---|---|---|
| 1 | Viewer count badge shows on player page | Navigate to watch page; ViewerCountBadge visible with count >= 0 |
| 2 | Heartbeat endpoint accepts valid payload | POST heartbeat -> 200 |
| 3 | Health indicator shows green for good stream | Seed healthy metrics; green indicator visible |
| 4 | Health indicator shows red for critical stream | Seed 0 bitrate; red indicator visible |
| 5 | Health history returns snapshots | GET health history returns array of snapshot objects |
| 6 | Viewer count decrements after disconnect | Send heartbeat, wait TTL, verify count drops |
| 7 | Unauthenticated heartbeat returns 401 | No session -> 401 |
| 8 | Health endpoint requires session owner | Non-owner GET health -> 403 |

**Negative tests**: 401 unauthenticated, 403 non-owner health access, 404 non-existent session

**Edge cases**: TTL-based viewer expiry, concurrent heartbeats, zero-bitrate health snapshot, rapid heartbeat dedup

### Test Data Requirements

Create live broadcast session in `beforeAll`. Seed viewer heartbeats via API.

**Test users**: Alice (USER, viewer), Root (ROOT, broadcaster/session owner)

### CI/Pipeline

Serial execution. `BROADCAST_PROVIDER=local`. Retry-safe.

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|---|---|---|---|
| BCAST-001 | Broadcast session endpoints | Implemented | Yes |
| BCAST-002 | Viewer player page for badge display | Implemented | Yes |

### Depended On By

| Ticket | What It Needs |
|---|---|
| BCAST-005 | Viewer count context for chat rate limiting |

### Merge Strategy

Parallel-safe with BCAST-005. New DDB tables (`BroadcastViewers`, `BroadcastHealthSnapshots`), new services, new frontend components.

### Merge Checklist

- [ ] DDB tables added to `scripts/local-ddb-init.py`
- [ ] Table handles `T.broadcast_viewers`, `T.broadcast_health_snapshots` in `tables.py`
- [ ] ViewerCountBadge and StreamHealthIndicator components created
- [ ] E2E test passes in CI
- [ ] No breaking changes to existing broadcast endpoints

---

## Codebase References

| File | Line(s) | Status | Notes |
|------|---------|--------|-------|
| `app/services/broadcast_viewers.py` | — | EXISTS | Viewer count tracking service |
| `app/services/broadcast_health.py` | — | EXISTS | Stream health metrics service |
| `app/services/broadcast_sse.py` | — | EXISTS | SSE event streaming |
| `app/routers/broadcast.py` | 505+ | EXISTS | Viewer join endpoint (`/sessions/{id}/viewers/join`) |
| `app/core/settings.py` | 490-491 | EXISTS | `broadcast_viewers_table_name`, `broadcast_health_snapshots_table_name` |
| `app/core/settings.py` | 498 | EXISTS | `broadcast_health_poll_interval_seconds` |
| `app/core/tables.py` | 78-79 | EXISTS | `T.broadcast_viewers`, `T.broadcast_health_snapshots` |
| `scripts/local-ddb-init.py` | 545-550 | EXISTS | BroadcastViewers, BroadcastHealthSnapshots tables |
| `frontend/src/pages/broadcast/ViewerCountBadge.tsx` | — | EXISTS | Viewer count UI component |
| `frontend/src/pages/broadcast/StreamHealthIndicator.tsx` | — | EXISTS | Stream health UI component |
| `frontend/e2e/broadcast-health.spec.ts` | — | EXISTS | E2E tests for health metrics |
| `app/main.py` | 396 | EXISTS | `broadcast_router` registered |
| `app/metrics.py` | — | EXISTS | Prometheus-style metrics framework |

# BCAST-009: Broadcast Scheduling — Schedule Broadcasts for Future Date/Time

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-27  
**Priority**: High  
**Estimated effort**: 7-10 days

---

## 1. Overview & Motivation

### The Gap

The broadcast system (`app/routers/broadcast.py`, 1279 lines) currently supports a linear session lifecycle: `draft -> provisioning -> ready -> live -> stopping -> stopped`. A broadcaster creates a session via `POST /broadcast/sessions`, which initializes it in `draft` status. Starting requires an explicit `POST /broadcast/sessions/{id}/start` call, which provisions infrastructure and transitions to `live` immediately.

There is **no mechanism to schedule a broadcast for a future date/time**. Broadcasters cannot:
<!-- NOTE: This claim is NOW OUTDATED. Scheduling infrastructure exists:
  `app/services/broadcast_scheduler.py` (background loop, auto-starts at scheduled_at),
  `app/services/broadcast_reminders.py` (reminder dispatch),
  `app/main.py:131,378-379` (scheduler + reminder tasks registered at startup),
  `app/routers/broadcast.py:300` (GET /sessions/scheduled endpoint),
  `scripts/local-ddb-init.py:517` (BroadcastSessions ByScheduledAt GSI),
  `scripts/local-ddb-init.py:771` (BroadcastReminders table),
  `frontend/src/api/endpoints/broadcastSchedule.ts`,
  `frontend/e2e/broadcast-scheduling.spec.ts` -->

1. Announce an upcoming broadcast in advance so viewers can plan to attend
2. Have the system automatically start a broadcast at the scheduled time
3. Display a countdown to viewers who navigate to the session before it goes live
4. Send reminder notifications to followers before the broadcast starts
5. Generate downloadable calendar invites (`.ics`) for the event

### Why This Is Needed

1. **Viewer discovery**: Scheduled broadcasts give viewers a reason to return at a specific time, improving engagement and live viewer counts.
2. **Creator workflow**: Creators need to prepare content, set up product shelves (LCOM-001), and configure settings before going live. A scheduled start decouples preparation from the go-live moment.
3. **Cross-promotion**: Scheduled broadcasts can be shared as calendar events, embedded in social media, and promoted through the newsfeed (BCAST-010).
4. **Reminder-driven retention**: Push/email/in-app reminders at configurable intervals drive return visits and reduce missed broadcasts.
5. **Parity with competitors**: YouTube, Twitch, and Instagram all support scheduled live streams. This is table-stakes for creator adoption.

### Architecture After This Change

```
Broadcast Lifecycle (Extended with Scheduling)

  POST /broadcast/sessions                POST /broadcast/sessions/{id}/start
  { profile_id, scheduled_at? }           (manual early start)
       |                                        |
       v                                        |
  +--------+     +-----------+     +-------+    |    +------+     +--------+     +---------+
  | draft  |---->| scheduled |---->| draft |----+---->| prov |---->| ready  |---->| live    |
  +--------+     +-----------+     +-------+         +------+     +--------+     +---------+
       |               |                                                              |
       |               |                                                              v
       |               |         Background Scheduler (every 30s)               +---------+
       |               |           scheduled_at <= now()                        | stopping |
       |               +- auto-start ──────────────────────> start_session()    +---------+
       |                                                                              |
       |                                                                              v
       |                                                                        +---------+
       +- (no scheduled_at) ───> immediate start path (unchanged)               | stopped |
                                                                                +---------+

  Reminder System (parallel)

  scheduled_at - 24h  ──> alert: "Starting in 24 hours"
  scheduled_at - 1h   ──> alert: "Starting in 1 hour"
  scheduled_at - 15m  ──> alert: "Starting in 15 minutes"
```

---

## 2. Current State Analysis

### 2.1 Session Model (`app/models_broadcast.py`)

The `BroadcastSessionModel` (line 34) has these fields:

```python
class BroadcastSessionModel(BaseModel):
    id: str
    profile_id: str
    status: BroadcastSessionStatus = "draft"
    ingest_url: Optional[str] = None
    stream_key_ref: Optional[str] = None
    stream_key_last_rotated_at: Optional[str] = None
    stream_key_rotation_interval_seconds: int = 86400
    started_at: Optional[str] = None
    stopped_at: Optional[str] = None
    created_by: str
    created_at: str = ""
    updated_at: str = ""
```

No `scheduled_at`, `name`, or `description` fields exist. The `status` type is a `Literal` union of `"draft" | "provisioning" | "ready" | "live" | "stopping" | "stopped" | "error"`. The `"scheduled"` status does not exist.

### 2.2 State Machine (`app/services/broadcast_state_machine.py`)

The allowed transitions are:

```python
_ALLOWED_TRANSITIONS = {
    "draft": {"provisioning", "error"},
    "provisioning": {"ready", "error"},
    "ready": {"live", "stopping", "error"},
    "live": {"stopping", "error"},
    "stopping": {"stopped", "error"},
    "stopped": set(),
    "error": {"provisioning", "stopped"},
}
```

No `"scheduled"` status exists. Adding it requires a new transition `"draft" -> "scheduled"` and `"scheduled" -> "draft"` (for cancel) or `"scheduled" -> "provisioning"` (for auto-start).

### 2.3 Session Creation (`app/services/broadcast_store.py`, line 146)

`create_session()` creates a session in `"draft"` status unconditionally. There is no branch for scheduling. The `BroadcastSessionCreateIn` model (line 90 in `broadcast.py`) accepts `profile_id`, `ingest_url`, and `stream_key_ref` but not `scheduled_at`.

### 2.4 Session Storage (`app/services/broadcast_store.py`)

Sessions are stored in the `BroadcastSessions` table with:
- **PK**: `session_id`
- **GSI `ByStatusCreatedAt`**: partition key `status`, sort key `created_at`
- **GSI `ByCreatorCreatedAt`**: partition key `created_by`, sort key `created_at`

The `ByStatusCreatedAt` GSI is used by `list_sessions_by_status()` (line 323). A new query pattern is needed: "get all sessions with status=scheduled where scheduled_at <= now" for the auto-start scheduler. The existing `ByStatusCreatedAt` GSI with `sort_key=created_at` does not sort by `scheduled_at`.

### 2.5 Start Flow (`app/services/broadcast_orchestrator.py`)

`start_session_with_provider()` handles the `draft -> provisioning -> ready -> live` transition sequence. It accepts `session_id`, `actor`, `reason`, `correlation_id`, and `idempotency_key`. However, the function has a `if current.status == "draft":` guard at line 29 that restricts provisioning to sessions in `"draft"` status only. A session in `"scheduled"` status would NOT enter the provisioning branch. **The orchestrator must be modified to also accept `status == "scheduled"` as a valid starting state**, either by widening the guard to `if current.status in ("draft", "scheduled"):` or by first transitioning the session from `"scheduled"` to `"draft"` before calling the orchestrator.

> **Corrected**: The original text stated "no modification needed to the core start logic." This is wrong — `start_session_with_provider()` at `app/services/broadcast_orchestrator.py:29` has an explicit `if current.status == "draft":` guard that would skip provisioning for a `"scheduled"` session. The orchestrator must be updated to handle the `"scheduled"` status.

### 2.6 Alert System (`app/services/alerts.py`)

The alerts system supports creating in-app alerts with `write_alert(user_sub, *, event, outcome, title, details)` in `app/services/alerts.py` (line 265). Alerts are stored in the `alerts` table with `user_sub` as PK. The system supports multiple channels (in-app, push, email) and rate limiting per channel. This is the integration point for broadcast reminders.

> **Corrected**: The original text referenced `send_alert()` / `create_alert()`. The actual function is `write_alert(user_sub, *, event, outcome, title, details)`. The parameter names differ: `event` (not `event_type`), `outcome` (required, no equivalent in the spec's `create_alert` signature), `title`, and `details` (a dict, not separate `body`/`metadata` params). All code samples in this spec that call `create_alert()` must be updated to use `write_alert()` with the correct parameter names.

### 2.7 Newsfeed Scheduler Pattern (`app/services/newsfeed_scheduler.py`)

The newsfeed scheduler uses a background task that polls a GSI (`GSI_SCHEDULE_DUE`) for items with `GSI_SCHEDULE_PK="SCHEDULED"` and `GSI_SCHEDULE_SK <= now_iso()`. The function is `run_scheduler_loop` (not `run_newsfeed_scheduler_loop`) defined at `app/services/newsfeed_scheduler.py:369`. This is the same pattern the broadcast scheduler should follow — a background loop that queries for due scheduled broadcasts and transitions them to live.

> **Corrected**: The original text implied the function name is `run_newsfeed_scheduler_loop`. The actual name is `run_scheduler_loop` in `app/services/newsfeed_scheduler.py:369`.

### 2.8 Existing Background Tasks (`app/main.py`)

The app startup registers background tasks via `app.add_event_handler("startup", ...)` calls in `app/main.py` (lines 306-365). The newsfeed scheduler is started indirectly: `app.add_event_handler("startup", newsfeed_startup)` at line 321 calls the `startup()` function defined in `app/routers/newsfeed.py`. The broadcast scheduler should follow the same pattern — define a startup function that creates the async task, and register it with `add_event_handler`.

> **Corrected**: The original text said the app uses a lifespan context manager and that `run_newsfeed_scheduler_loop` is registered directly in `main.py`. The actual pattern uses `app.add_event_handler("startup", ...)` (not a lifespan context manager), and the newsfeed scheduler is started from `app/routers/newsfeed.py`'s `startup()` function (not directly from `main.py`). The function name is `run_scheduler_loop`, not `run_newsfeed_scheduler_loop`.

---

## 3. Technical Design

### 3.1 Extended Session Model

Add the following fields to `BroadcastSessionModel` in `app/models_broadcast.py`:

```python
class BroadcastSessionModel(BaseModel):
    # ... existing fields ...
    scheduled_at: Optional[int] = None       # Unix timestamp of scheduled start
    name: Optional[str] = None               # Human-readable session name/title
    description: Optional[str] = None        # Session description for announcements
    thumbnail_url: Optional[str] = None      # Thumbnail image URL for listings
    cancelled_at: Optional[str] = None       # ISO timestamp if session was cancelled
    announcement_post_id: Optional[str] = None  # Newsfeed post ID (BCAST-010)
```

### 3.2 Extended State Machine

Add `"scheduled"` to `BroadcastSessionStatus`:

```python
BroadcastSessionStatus = Literal[
    "draft",
    "scheduled",       # NEW
    "provisioning",
    "ready",
    "live",
    "stopping",
    "stopped",
    "error",
]
```

Updated transition map:

```python
_ALLOWED_TRANSITIONS = {
    "draft": {"scheduled", "provisioning", "error"},       # + scheduled
    "scheduled": {"draft", "provisioning", "error"},       # NEW: cancel (-> draft) or start (-> provisioning)
    "provisioning": {"ready", "error"},
    "ready": {"live", "stopping", "error"},
    "live": {"stopping", "error"},
    "stopping": {"stopped", "error"},
    "stopped": set(),
    "error": {"provisioning", "stopped"},
}
```

Transition semantics:
- `draft -> scheduled`: When `scheduled_at` is provided on create (or via `PATCH /sessions/{id}/schedule`)
- `scheduled -> draft`: When the creator cancels the schedule (clears `scheduled_at`)
- `scheduled -> provisioning`: When the auto-start scheduler fires or the creator starts early

### 3.3 DynamoDB Changes — New GSI for Scheduled Sessions

Add a new GSI `ByScheduledAt` to the `BroadcastSessions` table for efficient scheduled session queries:

```python
# scripts/local-ddb-init.py — add to BroadcastSessions GSI list
{"index_name": "ByScheduledAt", "partition_key": "status", "sort_key": "scheduled_at"},
```

**Access pattern**: Query `status="scheduled"` with `scheduled_at <= now_ts()` to find due sessions. The `ScanIndexForward=True` ordering ensures the oldest due sessions are processed first.

**`attr_types` addition**: `scheduled_at` is numeric (`"N"`) — must be declared in the `TableDef`:

```python
attr_types={"created_at": "S", "scheduled_at": "N"},
```

**DDB access pattern diagram**:

```
┌─────────────────────────────────────────────────────────────────┐
│ BroadcastSessions Table — ByScheduledAt GSI                     │
├───────────────────────┬─────────────────────────────────────────┤
│ Partition Key (GSI)   │ Sort Key (GSI)                           │
│ status (S)            │ scheduled_at (N)                         │
├───────────────────────┼─────────────────────────────────────────┤
│                       │                                          │
│  Access Patterns:     │                                          │
│                       │                                          │
│  1. Find due scheduled broadcasts:                               │
│     Query(PK="scheduled", SK <= now_ts())                        │
│     ScanIndexForward=True (oldest first)                         │
│     Limit=10 (process in batches)                                │
│                       │                                          │
│  2. List upcoming broadcasts:                                    │
│     Query(PK="scheduled", SK > now_ts())                         │
│     ScanIndexForward=True (soonest first)                        │
│     Used by GET /broadcast/sessions/upcoming                     │
│                       │                                          │
└───────────────────────┴─────────────────────────────────────────┘
```

### 3.4 Session Store Changes (`app/services/broadcast_store.py`)

Extend `session_to_item()` and `session_from_item()` to persist/read the new fields:

```python
def session_to_item(session: BroadcastSessionModel) -> Dict[str, Any]:
    item = {
        # ... existing fields ...
        "scheduled_at": session.scheduled_at,
        "name": session.name,
        "description": session.description,
        "thumbnail_url": session.thumbnail_url,
        "cancelled_at": session.cancelled_at,
        "announcement_post_id": session.announcement_post_id,
    }
    # Remove None values to avoid DynamoDB issues with GSI sort keys
    return {k: v for k, v in item.items() if v is not None}

def session_from_item(item: Dict[str, Any]) -> BroadcastSessionModel:
    return BroadcastSessionModel(
        # ... existing fields ...
        scheduled_at=int(item["scheduled_at"]) if item.get("scheduled_at") else None,
        name=item.get("name"),
        description=item.get("description"),
        thumbnail_url=item.get("thumbnail_url"),
        cancelled_at=item.get("cancelled_at"),
        announcement_post_id=item.get("announcement_post_id"),
    )
```

Add a new query function for upcoming broadcasts:

```python
def list_upcoming_sessions(*, limit: int = 50) -> Dict[str, Any]:
    """List all sessions with status=scheduled, ordered by scheduled_at ascending."""
    resp = T.broadcast_sessions.query(
        IndexName="ByScheduledAt",
        KeyConditionExpression=Key("status").eq("scheduled"),
        ScanIndexForward=True,
        Limit=limit,
    )
    items = [session_from_item(i) for i in resp.get("Items", [])]
    return {"items": items, "cursor": resp.get("LastEvaluatedKey")}


def list_due_scheduled_sessions(*, now: int, limit: int = 10) -> List[BroadcastSessionModel]:
    """Get scheduled sessions that are past their scheduled_at time."""
    resp = T.broadcast_sessions.query(
        IndexName="ByScheduledAt",
        KeyConditionExpression=Key("status").eq("scheduled") & Key("scheduled_at").lte(now),
        ScanIndexForward=True,
        Limit=limit,
    )
    return [session_from_item(i) for i in resp.get("Items", [])]
```

### 3.5 API Endpoints

#### 3.5.1 Create Session with Schedule

Modify existing `POST /broadcast/sessions` to accept optional scheduling fields:

```python
class BroadcastSessionCreateIn(BaseModel):
    profile_id: str = Field(..., min_length=1)
    ingest_url: Optional[str] = Field(default=None, max_length=1024)
    stream_key_ref: Optional[str] = Field(default=None, max_length=512)
    stream_key_last_rotated_at: Optional[str] = None
    stream_key_rotation_interval_seconds: int = Field(default=86400, ge=60)
    # New scheduling fields
    scheduled_at: Optional[int] = Field(
        default=None,
        description="Unix timestamp for scheduled start. Must be >= 15 minutes in the future.",
    )
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)
```

**Behavior changes in `create_session_route()`**:

1. If `scheduled_at` is provided, validate it is >= `now_ts() + 900` (15 minutes in the future). Return 400 if too soon.
2. Create session in `"draft"` status, then immediately transition to `"scheduled"` via `transition_session_status()`.
3. Store `scheduled_at`, `name`, and `description` on the session item.
4. Record audit action `"schedule_session"`. **Note**: The `BroadcastActionAuditModel.action` field in `app/models_broadcast.py` (line 81) is currently typed as `Literal["create_profile", "create_session", "start_session", "stop_session", "delete_session"]`. The new actions `"schedule_session"`, `"cancel_scheduled_session"`, and `"reschedule_session"` must be added to this Literal union.
5. If no `scheduled_at`, existing behavior is unchanged.

#### 3.5.2 List Upcoming Broadcasts

```
GET /broadcast/sessions/upcoming
```

**Auth**: `require_ui_session` — any authenticated user.

**Query params**: `limit` (int, default 50, max 200).

**Response model**:

```python
class BroadcastUpcomingListOut(BaseModel):
    items: List[BroadcastSessionOut] = Field(default_factory=list)
    count: int = 0
```

**Behavior**: Query `ByScheduledAt` GSI with `status="scheduled"` and `scheduled_at > now_ts()`, ordered ascending. Returns sessions visible to all authenticated users for viewer discovery.

#### 3.5.3 Cancel Scheduled Broadcast

```
POST /broadcast/sessions/{session_id}/cancel
```

**Auth**: `require_ui_session` — only session creator.

**Behavior**:

1. Validate session status is `"scheduled"` (409 otherwise).
2. Transition status from `"scheduled"` to `"draft"`.
3. Clear `scheduled_at` from the session item.
4. Set `cancelled_at` to current ISO timestamp.
5. Cancel any pending reminder jobs.
6. Record audit action `"cancel_scheduled_session"`.
7. Return updated session.

#### 3.5.4 Reschedule Broadcast

```
PATCH /broadcast/sessions/{session_id}/schedule
```

**Auth**: `require_ui_session` — only session creator.

**Request model**:

```python
class BroadcastRescheduleIn(BaseModel):
    scheduled_at: int = Field(
        ..., description="New Unix timestamp. Must be >= 15 minutes in the future."
    )
```

**Behavior**:

1. Validate session status is `"scheduled"` or `"draft"` (409 otherwise).
2. Validate `scheduled_at >= now_ts() + 900`.
3. Update `scheduled_at` on the session item.
4. If status was `"draft"`, transition to `"scheduled"`.
5. Re-schedule reminders for the new time.
6. Record audit action `"reschedule_session"`.

#### 3.5.5 Download Calendar Invite

```
GET /broadcast/sessions/{session_id}/ical
```

**Auth**: `require_ui_session` — any authenticated user.

**Behavior**:

1. Look up session; return 404 if not found.
2. Return 409 if `scheduled_at` is not set.
3. Generate `.ics` content with:
   - `DTSTART`: `scheduled_at` converted to UTC
   - `SUMMARY`: session `name` or `"Broadcast"`
   - `DESCRIPTION`: session `description` or empty
   - `URL`: `{frontend_base_url}/broadcast/{session_id}`
   - `VALARM`: 15-minute reminder
4. Return with `Content-Type: text/calendar` and `Content-Disposition: attachment; filename="broadcast.ics"`.

#### 3.5.6 Subscribe to Reminders

```
POST /broadcast/sessions/{session_id}/remind
```

**Auth**: `require_ui_session` — any authenticated user.

**Request model**:

```python
class BroadcastReminderIn(BaseModel):
    intervals: List[int] = Field(
        default=[900],
        description="Reminder intervals in seconds before scheduled_at. Allowed: 900 (15min), 3600 (1hr), 86400 (24hr).",
    )
```

**Behavior**:

1. Validate session is `"scheduled"`.
2. Validate intervals are from the allowed set `{900, 3600, 86400}`.
3. Write reminder subscription items to DDB (see 3.7).
4. Return `{"ok": True, "intervals": [...]}`.

### 3.6 Broadcast Scheduler — `app/services/broadcast_scheduler.py`

New file implementing the background auto-start loop:

```python
"""Background scheduler that auto-starts broadcast sessions at their scheduled_at time."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from app.core.time import now_ts
from app.services.broadcast_store import list_due_scheduled_sessions, get_session
from app.services.broadcast_orchestrator import start_session_with_provider

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 30
MAX_BATCH_SIZE = 10
SCHEDULER_ENABLED_ENV = "BROADCAST_SCHEDULER_ENABLED"


async def run_broadcast_scheduler_loop(*, poll_interval: int = POLL_INTERVAL_SECONDS):
    """Background coroutine that polls for due scheduled broadcasts and starts them.

    Runs every `poll_interval` seconds. For each due session:
    1. Fetch session details (consistent read to avoid stale status).
    2. Verify status is still "scheduled" (another worker may have started it).
    3. Call start_session_with_provider() to provision and go live.
    4. Log success or failure; never crash the loop.
    """
    import os
    if os.environ.get(SCHEDULER_ENABLED_ENV, "true").lower() != "true":
        logger.info("Broadcast scheduler disabled via %s", SCHEDULER_ENABLED_ENV)
        return

    logger.info("Broadcast scheduler started (poll_interval=%ds)", poll_interval)
    while True:
        try:
            now = now_ts()
            due_sessions = list_due_scheduled_sessions(now=now, limit=MAX_BATCH_SIZE)

            for session in due_sessions:
                try:
                    # Re-fetch with consistent read to avoid race
                    fresh = get_session(session.id)
                    if fresh.status != "scheduled":
                        logger.info("Session %s no longer scheduled (status=%s), skipping", session.id, fresh.status)
                        continue

                    logger.info("Auto-starting scheduled broadcast %s (scheduled_at=%d, now=%d)", session.id, session.scheduled_at, now)
                    start_session_with_provider(
                        session_id=session.id,
                        actor="system:broadcast-scheduler",
                        reason="scheduled-auto-start",
                        correlation_id=f"sched-{session.id}-{now}",
                    )
                    logger.info("Auto-start succeeded for session %s", session.id)
                except Exception:
                    logger.exception("Auto-start failed for session %s", session.id)
                    # Individual session failure should not block other sessions

        except Exception:
            logger.exception("Broadcast scheduler loop error")

        await asyncio.sleep(poll_interval)
```

### 3.7 Reminder System — `app/services/broadcast_reminders.py`

New file for managing reminder subscriptions and dispatching reminder alerts:

```python
"""Broadcast reminder system — subscriber management and reminder dispatch."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert

logger = logging.getLogger(__name__)

# Allowed reminder intervals (seconds before scheduled_at)
ALLOWED_INTERVALS: Set[int] = {900, 3600, 86400}  # 15min, 1hr, 24hr

# Human-readable labels
_INTERVAL_LABELS = {
    900: "15 minutes",
    3600: "1 hour",
    86400: "24 hours",
}


def subscribe_to_reminders(
    *,
    session_id: str,
    user_id: str,
    intervals: List[int],
) -> Dict[str, Any]:
    """Write reminder subscription items for the given user and intervals.

    Each reminder is stored as a separate DDB item in the broadcast_reminders table
    with a GSI for efficient "find all due reminders" queries.

    Item schema:
        PK: SESSION#{session_id}
        SK: REMINDER#{user_id}#{interval}
        GSI_REM_PK: "PENDING"
        GSI_REM_SK: {remind_at}  (Unix timestamp = scheduled_at - interval)
        user_id, session_id, interval, remind_at, sent: False
    """
    valid = [i for i in intervals if i in ALLOWED_INTERVALS]
    if not valid:
        return {"ok": False, "error": "No valid intervals"}

    # Look up session to get scheduled_at
    from app.services.broadcast_store import get_session
    session = get_session(session_id)
    if not session.scheduled_at:
        return {"ok": False, "error": "Session is not scheduled"}

    ts = now_ts()
    written = []
    for interval in valid:
        remind_at = session.scheduled_at - interval
        if remind_at <= ts:
            continue  # Reminder time already passed

        item = {
            "pk": f"SESSION#{session_id}",
            "sk": f"REMINDER#{user_id}#{interval}",
            "user_id": user_id,
            "session_id": session_id,
            "interval": interval,
            "remind_at": remind_at,
            "scheduled_at": session.scheduled_at,
            "session_name": session.name or "Broadcast",
            "sent": False,
            "created_at": ts,
            "GSI_REM_PK": "PENDING",
            "GSI_REM_SK": remind_at,
        }
        T.broadcast_reminders.put_item(Item=item)
        written.append(interval)

    return {"ok": True, "intervals": written}


def cancel_reminders_for_session(session_id: str) -> int:
    """Delete all reminder items for a cancelled/rescheduled session."""
    deleted = 0
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(f"SESSION#{session_id}"),
            "Limit": 500,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.broadcast_reminders.query(**kwargs)
        items = resp.get("Items", [])
        if items:
            with T.broadcast_reminders.batch_writer() as bw:
                for item in items:
                    bw.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
                    deleted += 1
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return deleted


def dispatch_due_reminders(*, now: int, limit: int = 50) -> int:
    """Find and send all due reminders.

    Queries the GSI_REM_PK="PENDING", GSI_REM_SK <= now index.
    For each due reminder, creates an in-app alert and marks it as sent.

    Returns the count of reminders dispatched.
    """
    resp = T.broadcast_reminders.query(
        IndexName="ByRemindAt",
        KeyConditionExpression=(
            Key("GSI_REM_PK").eq("PENDING") & Key("GSI_REM_SK").lte(now)
        ),
        Limit=limit,
    )
    items = resp.get("Items", [])
    dispatched = 0

    for item in items:
        if item.get("sent"):
            continue
        try:
            interval = int(item.get("interval", 900))
            label = _INTERVAL_LABELS.get(interval, f"{interval // 60} minutes")
            session_name = item.get("session_name", "Broadcast")

            write_alert(
                item["user_id"],
                event="broadcast_reminder",
                outcome="pending",
                title=f"Broadcast starting in {label}",
                details={
                    "body": f'"{session_name}" is starting in {label}. Don\'t miss it!',
                    "session_id": item["session_id"],
                    "scheduled_at": int(item.get("scheduled_at", 0)),
                    "interval": interval,
                },
            )

            # Mark as sent
            T.broadcast_reminders.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression="SET sent = :t REMOVE GSI_REM_PK, GSI_REM_SK",
                ExpressionAttributeValues={":t": True},
            )
            dispatched += 1
        except Exception:
            logger.exception("Failed to dispatch reminder pk=%s sk=%s", item["pk"], item["sk"])

    return dispatched
```

### 3.8 DynamoDB Table — `BroadcastReminders`

New table for reminder subscriptions:

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.broadcast_reminders_table_name, "BroadcastReminders"),
    "pk",       # SESSION#{session_id}
    "sk",       # REMINDER#{user_id}#{interval}
    gsis=[
        {"index_name": "ByRemindAt", "partition_key": "GSI_REM_PK", "sort_key": "GSI_REM_SK"},
    ],
    attr_types={"GSI_REM_SK": "N"},
),
```

| Attribute | Type | Value |
|-----------|------|-------|
| `pk` | S | `SESSION#{session_id}` |
| `sk` | S | `REMINDER#{user_id}#{interval}` |
| `user_id` | S | Subscriber user sub |
| `session_id` | S | Broadcast session ID |
| `interval` | N | Seconds before start (900, 3600, 86400) |
| `remind_at` | N | Unix timestamp when reminder should fire |
| `scheduled_at` | N | Session scheduled start time |
| `session_name` | S | Session name for alert text |
| `sent` | BOOL | Whether reminder has been dispatched |
| `created_at` | N | When the subscription was created |
| `GSI_REM_PK` | S | `"PENDING"` (removed after dispatch) |
| `GSI_REM_SK` | N | Same as `remind_at` (GSI sort key) |

### 3.9 iCal Generation

```python
def generate_ical(
    *,
    session_id: str,
    name: str,
    description: str,
    scheduled_at: int,
    frontend_base_url: str,
) -> str:
    """Generate RFC 5545 iCalendar content for a scheduled broadcast."""
    from datetime import datetime, timezone

    dt = datetime.fromtimestamp(scheduled_at, tz=timezone.utc)
    dtstart = dt.strftime("%Y%m%dT%H%M%SZ")
    # Assume 1-hour duration for the calendar event
    end_dt = datetime.fromtimestamp(scheduled_at + 3600, tz=timezone.utc)
    dtend = end_dt.strftime("%Y%m%dT%H%M%SZ")
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    url = f"{frontend_base_url}/broadcast/{session_id}"

    # Escape special characters per RFC 5545
    name_escaped = name.replace("\\", "\\\\").replace(",", "\\,").replace(";", "\\;").replace("\n", "\\n")
    desc_escaped = description.replace("\\", "\\\\").replace(",", "\\,").replace(";", "\\;").replace("\n", "\\n")

    return (
        "BEGIN:VCALENDAR\r\n"
        "VERSION:2.0\r\n"
        "PRODID:-//Platform//Broadcast//EN\r\n"
        "BEGIN:VEVENT\r\n"
        f"UID:broadcast-{session_id}@platform\r\n"
        f"DTSTAMP:{dtstamp}\r\n"
        f"DTSTART:{dtstart}\r\n"
        f"DTEND:{dtend}\r\n"
        f"SUMMARY:{name_escaped}\r\n"
        f"DESCRIPTION:{desc_escaped}\r\n"
        f"URL:{url}\r\n"
        "BEGIN:VALARM\r\n"
        "TRIGGER:-PT15M\r\n"
        "ACTION:DISPLAY\r\n"
        "DESCRIPTION:Broadcast starting in 15 minutes\r\n"
        "END:VALARM\r\n"
        "END:VEVENT\r\n"
        "END:VCALENDAR\r\n"
    )
```

### 3.10 Pydantic Models

```python
class BroadcastSessionCreateIn(BaseModel):
    profile_id: str = Field(..., min_length=1)
    ingest_url: Optional[str] = Field(default=None, max_length=1024)
    stream_key_ref: Optional[str] = Field(default=None, max_length=512)
    stream_key_last_rotated_at: Optional[str] = None
    stream_key_rotation_interval_seconds: int = Field(default=86400, ge=60)
    # Scheduling fields (BCAST-009)
    scheduled_at: Optional[int] = Field(default=None, description="Unix timestamp >= 15 min from now")
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)


class BroadcastRescheduleIn(BaseModel):
    scheduled_at: int = Field(..., description="New Unix timestamp, >= 15 min from now")


class BroadcastReminderIn(BaseModel):
    intervals: List[int] = Field(
        default=[900],
        description="Reminder intervals in seconds before start. Allowed: 900, 3600, 86400.",
    )


class BroadcastUpcomingListOut(BaseModel):
    items: List[BroadcastSessionOut] = Field(default_factory=list)
    count: int = 0
```

### 3.11 Frontend Types

```typescript
// frontend/src/api/types.ts — additions

interface BroadcastSession {
  // ... existing fields ...
  scheduled_at?: number | null;
  name?: string | null;
  description?: string | null;
  thumbnail_url?: string | null;
  cancelled_at?: string | null;
  announcement_post_id?: string | null;
}

interface BroadcastRescheduleIn {
  scheduled_at: number;
}

interface BroadcastReminderIn {
  intervals: number[];
}
```

### 3.12 Frontend Components

#### 3.12.1 ScheduleDialog

Modal for setting/editing `scheduled_at` with a date-time picker. Validates the 15-minute-minimum constraint client-side. Shows timezone context.

```typescript
// frontend/src/pages/broadcast/ScheduleDialog.tsx

interface ScheduleDialogProps {
  /** Whether the dialog is open */
  open: boolean;
  /** Callback when the dialog is dismissed or closed */
  onOpenChange: (open: boolean) => void;
  /** Current scheduled_at value (Unix seconds) if editing; undefined if creating */
  initialScheduledAt?: number | null;
  /** Session name for display in the dialog header */
  sessionName?: string;
  /** Called with the chosen Unix-seconds timestamp when user confirms */
  onConfirm: (scheduledAt: number) => void;
  /** Whether the confirm action is in progress (disables submit button) */
  isSubmitting?: boolean;
}

/**
 * Internal state managed by the component:
 *
 *   selectedDate: Date        — calendar date picker value (local timezone Date object)
 *   selectedTime: string      — time string in "HH:mm" format (24h, local timezone)
 *   selectedTimezone: string  — IANA timezone identifier (e.g., "America/New_York")
 *   validationError: string   — error message if selected time < now + 15 min
 *
 * The dialog computes the final Unix timestamp by:
 *   1. Combining selectedDate + selectedTime into a Date in selectedTimezone
 *   2. Converting to UTC Unix seconds via Math.floor(date.getTime() / 1000)
 *   3. Validating result >= now + 900 (15 minutes)
 *
 * Timezone selector:
 *   - Defaults to Intl.DateTimeFormat().resolvedOptions().timeZone (user's browser TZ)
 *   - Dropdown lists all IANA timezones from Intl.supportedValuesOf("timeZone")
 *     (fallback: hardcoded list of ~50 common timezones for older browsers)
 *   - Shows current UTC offset next to each option: "America/New_York (UTC-05:00)"
 *   - Offset is computed dynamically (accounts for DST at the selected date)
 *
 * Reminder toggles (optional sub-section):
 *   - Three checkboxes: "24 hours before", "1 hour before", "15 minutes before"
 *   - Default: "15 minutes before" checked
 *   - When user confirms, the dialog also calls POST /sessions/{id}/remind
 *     with the selected intervals
 */
```

**UI layout**:

```
┌─────────────────────────────────────────────┐
│ Schedule Broadcast                     [X]  │
│─────────────────────────────────────────────│
│                                             │
│  Session: "Friday Night Live"               │
│                                             │
│  Date:  [  May 30, 2026          ▼ ]       │
│  Time:  [  20:00                 ▼ ]       │
│  Zone:  [  America/New_York (UTC-04:00) ▼ ]│
│                                             │
│  ──── Scheduled for ────                    │
│  Sat May 30 2026 at 8:00 PM EDT            │
│  (in 3 days, 4 hours)                       │
│                                             │
│  ──── Reminders ────                        │
│  ☑ 24 hours before                          │
│  ☑ 1 hour before                            │
│  ☑ 15 minutes before                        │
│                                             │
│          [ Cancel ]  [ Schedule ]            │
└─────────────────────────────────────────────┘
```

#### 3.12.2 UpcomingBroadcastsList

Card layout listing all upcoming scheduled broadcasts with countdown timers, cancel/reschedule buttons.

```typescript
// frontend/src/pages/broadcast/UpcomingBroadcastsList.tsx

interface UpcomingBroadcastsListProps {
  /** Creator-only view: show cancel/reschedule actions */
  showActions?: boolean;
  /** Maximum items to display (default: 20) */
  limit?: number;
  /** Filter to only sessions by this creator (user_sub). Omit for global view. */
  creatorId?: string;
}

/**
 * Data fetching:
 *   useQuery(["broadcast", "upcoming"], () => getUpcomingSessions({ limit }))
 *   Refetch interval: 60_000ms (countdown is client-side; data refetch catches
 *   cancellations/reschedules by other tabs or the scheduler auto-starting)
 *
 * Each item renders a ScheduledBroadcastCard (see 3.12.3).
 *
 * Empty state: "No upcoming broadcasts scheduled." with a "Schedule One" CTA
 * button (visible only if showActions=true, links to ScheduleDialog).
 *
 * Sort order: ascending by scheduled_at (soonest first), matching the GSI
 * sort order returned by the backend.
 */
```

#### 3.12.3 ScheduledBroadcastCard

Card component for a single upcoming broadcast in the list.

```typescript
// frontend/src/pages/broadcast/ScheduledBroadcastCard.tsx

interface ScheduledBroadcastCardProps {
  session: BroadcastSession;
  /** Show creator actions (cancel, reschedule, start early) */
  showActions?: boolean;
  /** Callback when cancel is confirmed */
  onCancel?: (sessionId: string) => void;
  /** Callback when reschedule dialog is requested */
  onReschedule?: (sessionId: string) => void;
  /** Callback when early start is requested */
  onStartEarly?: (sessionId: string) => void;
}

/**
 * Card layout:
 *
 * ┌──────────────────────────────────────────────────┐
 * │ ┌──────────┐  Friday Night Live                  │
 * │ │thumbnail │  Sat May 30 at 8:00 PM EDT          │
 * │ │ or icon  │                                     │
 * │ └──────────┘  ⏱ 3d 4h 22m 15s                   │
 * │                                                  │
 * │  [ 🔔 Set Reminder ]  [ 📅 Add to Calendar ]    │
 * │                                                  │
 * │  --- creator actions (if showActions) ---         │
 * │  [ Start Early ]  [ Reschedule ]  [ Cancel ]     │
 * └──────────────────────────────────────────────────┘
 *
 * - Thumbnail: session.thumbnail_url or a default broadcast icon
 * - Countdown: rendered via BroadcastCountdown component
 * - "Set Reminder" opens a popover with interval checkboxes (calls POST /remind)
 * - "Add to Calendar" triggers download of GET /sessions/{id}/ical
 * - "Start Early" shows a confirmation dialog, then calls POST /sessions/{id}/start
 * - "Cancel" shows a confirmation dialog, then calls POST /sessions/{id}/cancel
 */
```

#### 3.12.4 BroadcastCountdown

Live countdown component with days/hours/minutes/seconds.

```typescript
// frontend/src/pages/broadcast/BroadcastCountdown.tsx

interface BroadcastCountdownProps {
  /** Target Unix timestamp (seconds) to count down to */
  scheduledAt: number;
  /** Variant: "full" shows d/h/m/s; "compact" shows largest two units only */
  variant?: "full" | "compact";
  /** Called when countdown reaches zero */
  onExpired?: () => void;
  /** CSS className override */
  className?: string;
}

interface CountdownState {
  days: number;
  hours: number;
  minutes: number;
  seconds: number;
  expired: boolean;
}

/**
 * Implementation notes:
 *
 * - Uses setInterval(1000) with useEffect cleanup on unmount
 * - Computes remaining = scheduledAt - Math.floor(Date.now() / 1000) each tick
 * - When remaining <= 0: sets expired=true, clears interval, calls onExpired()
 * - "full" variant: "3d 4h 22m 15s" (all four units)
 * - "compact" variant: "3 days, 4 hours" or "22 min, 15 sec" (two largest
 *   non-zero units — useful for sidebar/card contexts)
 * - When remaining < 60: shows only seconds with a pulsing animation
 * - When expired: displays "Starting now..." with a spinner
 * - Does NOT rely on server time; uses client Date.now(). This means the
 *   countdown may be off by up to the client's clock skew. This is acceptable
 *   for display purposes; the actual auto-start is server-controlled.
 *
 * Visual states:
 *   remaining > 24h:   neutral color (muted text)
 *   1h < remaining <= 24h: yellow/amber accent
 *   remaining <= 1h:   red accent with subtle pulse
 *   expired:           green "Starting now..." with spinner
 */
```

#### 3.12.5 BroadcastPage.tsx Changes

- Add "Upcoming" tab alongside "Sessions" and "Profiles" tabs
- "Upcoming" tab fetches `GET /broadcast/sessions/upcoming`
- Session detail view shows countdown for scheduled sessions
- "Start Early" button visible on scheduled sessions (calls existing start endpoint)
- "Cancel Schedule" button (calls `POST /sessions/{id}/cancel`)
- "Reschedule" button (opens ScheduleDialog, calls `PATCH /sessions/{id}/schedule`)

#### 3.12.6 LivePlayer.tsx Changes

- If session status is `"scheduled"`, show countdown overlay instead of video player
- "Set Reminder" button on the countdown overlay
- "Add to Calendar" download link

### 3.13 SSE Events

| Event Type | Payload | Trigger |
|------------|---------|---------|
| `session:scheduled` | `{session_id, scheduled_at, name}` | Session scheduled or rescheduled |
| `session:cancelled` | `{session_id}` | Scheduled session cancelled |
| `session:countdown` | `{session_id, seconds_remaining}` | Published every 60s when <5min remain |

---

## 4. Implementation Plan

### Phase 1: Backend Model + State Machine (1 day)

| File | Change |
|------|--------|
| `app/models_broadcast.py` | Add `scheduled_at`, `name`, `description`, `thumbnail_url`, `cancelled_at`, `announcement_post_id` to `BroadcastSessionModel`. Add `"scheduled"` to `BroadcastSessionStatus`. |
| `app/services/broadcast_state_machine.py` | Add `"scheduled"` to `_ALLOWED_TRANSITIONS`: `draft -> {scheduled, ...}`, `scheduled -> {draft, provisioning, error}`. |
| `app/services/broadcast_store.py` | Extend `session_to_item()`, `session_from_item()`. Add `list_upcoming_sessions()`, `list_due_scheduled_sessions()`. |
| `scripts/local-ddb-init.py` | Add `ByScheduledAt` GSI to `BroadcastSessions` table. Add `BroadcastReminders` table definition. |
| `app/core/settings.py` | Add **new** settings: `broadcast_reminders_table_name`, `broadcast_scheduler_enabled`, `broadcast_scheduler_poll_interval`. These do not currently exist in `Settings` and must be added as new fields. |
| `app/core/tables.py` | Add **new** `broadcast_reminders` table handle. `T.broadcast_reminders` does not currently exist and must be added alongside the new setting. |

### Phase 2: Scheduler + Reminders Service (2 days)

| File | Change |
|------|--------|
| `app/services/broadcast_scheduler.py` | New file: `run_broadcast_scheduler_loop()` background task. |
| `app/services/broadcast_reminders.py` | New file: `subscribe_to_reminders()`, `cancel_reminders_for_session()`, `dispatch_due_reminders()`, `generate_ical()`. |
| `app/main.py` | Register broadcast scheduler startup function via `app.add_event_handler("startup", ...)` (matching the existing pattern, NOT a lifespan context manager). Add reminder dispatch to scheduler loop or as separate task. |

### Phase 3: API Endpoints (1 day)

| File | Change |
|------|--------|
| `app/routers/broadcast.py` | Modify `create_session_route()` for scheduling. Add endpoints: `GET /sessions/upcoming`, `POST /sessions/{id}/cancel`, `PATCH /sessions/{id}/schedule`, `GET /sessions/{id}/ical`, `POST /sessions/{id}/remind`. Add Pydantic models. |

### Phase 4: Frontend (2-3 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add scheduling fields to `BroadcastSession`. |
| `frontend/src/api/endpoints/broadcast.ts` | Add `getUpcomingSessions()`, `cancelSchedule()`, `rescheduleSession()`, `downloadIcal()`, `subscribeReminder()`. |
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | Add "Upcoming" tab, schedule UI in session detail. |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Countdown overlay for scheduled sessions. |
| `frontend/src/pages/broadcast/ScheduleDialog.tsx` | New: date-time picker dialog. |
| `frontend/src/pages/broadcast/BroadcastCountdown.tsx` | New: countdown timer component. |
| `frontend/src/pages/broadcast/ScheduledBroadcastCard.tsx` | New: card for upcoming list. |

### Phase 5: E2E Tests (1 day)

| File | Change |
|------|--------|
| `frontend/e2e/broadcast-scheduling.spec.ts` | New: sections 119-120. |

### Summary of All Files

| File | Type | Estimated Lines |
|------|------|-----------------|
| `app/models_broadcast.py` | Modify | +10 |
| `app/services/broadcast_state_machine.py` | Modify | +5 |
| `app/services/broadcast_store.py` | Modify | +60 |
| `app/services/broadcast_scheduler.py` | Create | ~80 |
| `app/services/broadcast_reminders.py` | Create | ~200 |
| `app/routers/broadcast.py` | Modify | ~150 |
| `app/core/settings.py` | Modify | +5 |
| `app/core/tables.py` | Modify | +2 |
| `app/main.py` | Modify | +10 |
| `scripts/local-ddb-init.py` | Modify | +15 |
| `frontend/src/api/types.ts` | Modify | +15 |
| `frontend/src/api/endpoints/broadcast.ts` | Modify | +30 |
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | Modify | +80 |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Modify | +40 |
| `frontend/src/pages/broadcast/ScheduleDialog.tsx` | Create | ~120 |
| `frontend/src/pages/broadcast/BroadcastCountdown.tsx` | Create | ~60 |
| `frontend/src/pages/broadcast/ScheduledBroadcastCard.tsx` | Create | ~80 |
| `frontend/e2e/broadcast-scheduling.spec.ts` | Create | ~300 |
| **Total** | | **~1260** |

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_broadcast_scheduler.py`

**Mock setup**: moto mock for DynamoDB (broadcast tables). Mock broadcast provider for instant state transitions.

| Test Function | Description |
|---|---|
| `test_create_bcast009_resource` | Create primary resource; verify stored in DDB with correct fields |
| `test_get_bcast009_resource` | Get resource by ID; verify all fields returned |
| `test_list_bcast009_resources` | List resources; verify pagination and filtering |
| `test_update_bcast009_resource` | Update resource; verify changed fields persisted |
| `test_delete_bcast009_resource` | Delete resource; verify removed from DDB |
| `test_validation_rejects_invalid_input` | Missing required fields returns 422; invalid values return 400 |
| `test_authorization_enforced` | Non-owner/non-admin access returns 403 |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Full lifecycle: create -> read -> update -> delete through real DDB
2. Cross-service integration with broadcast session store
3. Concurrent operations do not corrupt shared state

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/broadcast-scheduling.spec.ts`

**Auth pattern**: `injectAuth(page, "root")` for admin operations; `injectAuth(page, "alice")` for viewer operations; CSRF header for mutations

| # | Test Name | Assertion |
|---|---|---|
| 1 | API creates resource successfully | POST returns 200/201 with resource ID |
| 2 | API returns resource by ID | GET returns full resource with all expected fields |
| 3 | API lists resources with pagination | GET list returns array; supports cursor pagination |
| 4 | API updates resource fields | PATCH/PUT returns updated resource |
| 5 | API deletes resource | DELETE returns 200; subsequent GET returns 404 |
| 6 | UI page loads with expected heading | Navigate to page; heading visible |
| 7 | UI form creates new resource | Fill form; submit; resource appears in list |
| 8 | UI shows error for invalid input | Submit empty form; validation messages visible |
| 9 | Unauthenticated request returns 401 | No session cookies -> 401 |
| 10 | Non-owner access returns 403 | Wrong user -> 403 |
| 11 | Non-existent resource returns 404 | GET invalid ID -> 404 |
| 12 | Duplicate creation returns 409 | Create same resource twice -> 409 or idempotent success |

**Negative tests**: 401 unauthenticated, 403 non-owner, 404 not found, 409 conflict/duplicate, 422 validation

**Edge cases**: Empty state (no resources), concurrent mutations, resource with max-length fields, Unicode content

### Test Data Requirements

Seed broadcast session in `beforeAll`. Create test resources via API with unique `Date.now()` suffixed names.

**Test users**: Root (ROOT, admin operations), Alice (USER, standard operations), Bob (USER, cross-user isolation)

### CI/Pipeline

Serial execution. `BROADCAST_PROVIDER=local`. Retry-safe with unique resource names.

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|---|---|---|---|
| BCAST-001 | Broadcast session CRUD and state machine | Implemented | Yes |

### Depended On By

| Ticket | What It Needs |
|---|---|
| BCAST-010 | Scheduled session events for newsfeed promotion |

### Merge Strategy

Independent. Adds `scheduled_at` field to session model, scheduler background task, and reminder service. Feature-flag-gated.

### Merge Checklist

- [ ] DDB table/fields added to `scripts/local-ddb-init.py` (if new table needed)
- [ ] Settings added to `app/core/settings.py`
- [ ] Service and router files created/modified
- [ ] Frontend components and API wrappers created
- [ ] E2E test passes in CI
- [ ] No breaking changes to existing endpoints

---

## Codebase References

| File | Line(s) | Status | Notes |
|------|---------|--------|-------|
| `app/services/broadcast_scheduler.py` | 1, 16, 25 | EXISTS | Background scheduler loop, `broadcast_scheduler_enabled` check |
| `app/services/broadcast_reminders.py` | — | EXISTS | Reminder dispatch service |
| `app/core/settings.py` | 1197 | EXISTS | `broadcast_reminders_table_name` |
| `app/core/tables.py` | 87 | EXISTS | `T.broadcast_reminders` handle |
| `scripts/local-ddb-init.py` | 771-779 | EXISTS | BroadcastReminders table |
| `scripts/local-ddb-init.py` | 517-525 | EXISTS | BroadcastSessions with `ByScheduledAt` GSI |
| `app/main.py` | 131, 378-379 | EXISTS | `start_broadcast_scheduler_task`, `start_broadcast_reminder_task` |
| `app/routers/broadcast.py` | 300 | EXISTS | `GET /sessions/scheduled` endpoint |
| `frontend/src/api/endpoints/broadcastSchedule.ts` | — | EXISTS | Schedule API endpoint wrappers |
| `frontend/e2e/broadcast-scheduling.spec.ts` | — | EXISTS | E2E tests |

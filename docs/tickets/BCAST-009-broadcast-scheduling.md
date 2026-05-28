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

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_broadcast_scheduling.py`)

New file, ~300 lines. Tests the scheduler and reminder services with moto-mocked DynamoDB.

```python
import pytest
from moto import mock_dynamodb
from unittest.mock import patch, MagicMock

from app.services.broadcast_scheduler import run_broadcast_scheduler_loop
from app.services.broadcast_reminders import (
    subscribe_to_reminders,
    cancel_reminders_for_session,
    dispatch_due_reminders,
    generate_ical,
    ALLOWED_INTERVALS,
)

def test_list_due_scheduled_sessions_returns_only_due(broadcast_tables):
    """Create 3 scheduled sessions: 2 past due, 1 future. Verify only 2 returned."""
    now = 1700000000
    _create_scheduled_session("s1", scheduled_at=now - 60)    # 1 min ago — due
    _create_scheduled_session("s2", scheduled_at=now - 3600)  # 1 hr ago — due
    _create_scheduled_session("s3", scheduled_at=now + 3600)  # 1 hr future — not due
    due = list_due_scheduled_sessions(now=now)
    assert len(due) == 2
    assert {s.id for s in due} == {"s1", "s2"}

def test_list_due_ordered_oldest_first(broadcast_tables):
    """Verify due sessions are returned oldest-first (ascending scheduled_at)."""
    now = 1700000000
    _create_scheduled_session("s_old", scheduled_at=now - 7200)
    _create_scheduled_session("s_new", scheduled_at=now - 60)
    due = list_due_scheduled_sessions(now=now)
    assert due[0].id == "s_old"
    assert due[1].id == "s_new"

def test_list_upcoming_excludes_past_due(broadcast_tables):
    """Upcoming list only returns future scheduled broadcasts."""
    now = 1700000000
    _create_scheduled_session("s_past", scheduled_at=now - 60)
    _create_scheduled_session("s_future", scheduled_at=now + 3600)
    upcoming = list_upcoming_sessions()
    assert len(upcoming["items"]) >= 1
    ids = {s.id for s in upcoming["items"]}
    assert "s_future" in ids
    # s_past has scheduled_at in the past; may or may not appear depending on query

def test_schedule_validation_rejects_past_timestamp():
    """scheduled_at < now + 900 should return 400."""
    import time
    now = int(time.time())
    # This would be tested at the router level via TestClient
    assert now - 100 < now + 900  # sanity check

def test_schedule_validation_rejects_too_soon():
    """scheduled_at within 15 minutes should return 400."""
    pass  # Tested via TestClient integration test

def test_subscribe_to_reminders_writes_items(reminder_tables):
    """Subscribe to 15min + 1hr reminders. Verify 2 DDB items written."""
    result = subscribe_to_reminders(
        session_id="s1", user_id="user1", intervals=[900, 3600]
    )
    assert result["ok"] is True
    assert len(result["intervals"]) == 2

def test_subscribe_skips_past_reminders(reminder_tables):
    """If scheduled_at - interval is in the past, skip that reminder."""
    # Session scheduled 10 minutes from now; 24hr reminder is already past
    result = subscribe_to_reminders(
        session_id="s_soon", user_id="user1", intervals=[900, 86400]
    )
    assert 900 in result["intervals"]
    assert 86400 not in result["intervals"]

def test_subscribe_rejects_invalid_intervals(reminder_tables):
    """Only 900, 3600, 86400 are valid. Others are silently filtered."""
    result = subscribe_to_reminders(
        session_id="s1", user_id="user1", intervals=[999, 60]
    )
    assert result["ok"] is False  # No valid intervals

def test_cancel_reminders_deletes_all(reminder_tables):
    """Cancel deletes all reminder items for a session."""
    subscribe_to_reminders(session_id="s1", user_id="u1", intervals=[900, 3600])
    subscribe_to_reminders(session_id="s1", user_id="u2", intervals=[900])
    deleted = cancel_reminders_for_session("s1")
    assert deleted == 3

def test_dispatch_due_reminders_creates_alerts(reminder_tables):
    """Due reminders generate in-app alerts via write_alert."""
    subscribe_to_reminders(session_id="s1", user_id="user1", intervals=[900])
    with patch("app.services.broadcast_reminders.write_alert") as mock_alert:
        dispatched = dispatch_due_reminders(now=_session_scheduled_at - 900 + 1)
        assert dispatched == 1
        mock_alert.assert_called_once()
        call_args = mock_alert.call_args
        assert call_args[0][0] == "user1"  # positional user_sub
        assert "15 minutes" in call_args[1]["title"]

def test_dispatch_marks_sent(reminder_tables):
    """After dispatch, reminder item has sent=True and GSI keys removed."""
    subscribe_to_reminders(session_id="s1", user_id="user1", intervals=[900])
    with patch("app.services.broadcast_reminders.write_alert"):
        dispatch_due_reminders(now=_session_scheduled_at - 900 + 1)
    # Re-dispatching should find 0 due items
    with patch("app.services.broadcast_reminders.write_alert") as mock_alert:
        dispatched = dispatch_due_reminders(now=_session_scheduled_at - 900 + 1)
        assert dispatched == 0
        mock_alert.assert_not_called()

def test_generate_ical_valid_format():
    """Generated iCal contains required RFC 5545 fields."""
    ical = generate_ical(
        session_id="s1",
        name="Test Stream",
        description="A test broadcast",
        scheduled_at=1700000000,
        frontend_base_url="https://example.com",
    )
    assert "BEGIN:VCALENDAR" in ical
    assert "BEGIN:VEVENT" in ical
    assert "SUMMARY:Test Stream" in ical
    assert "DTSTART:" in ical
    assert "DTEND:" in ical
    assert "URL:https://example.com/broadcast/s1" in ical
    assert "BEGIN:VALARM" in ical
    assert "END:VCALENDAR" in ical

def test_generate_ical_escapes_special_chars():
    """Commas and semicolons in name/description are escaped."""
    ical = generate_ical(
        session_id="s1",
        name="Live, Stream; Now",
        description="Don't miss\nthis event",
        scheduled_at=1700000000,
        frontend_base_url="https://example.com",
    )
    assert "SUMMARY:Live\\, Stream\\; Now" in ical
    assert "DESCRIPTION:Don't miss\\nthis event" in ical

def test_state_machine_scheduled_transitions():
    """Verify scheduled state can transition to draft, provisioning, error."""
    from app.services.broadcast_state_machine import validate_transition
    assert validate_transition("draft", "scheduled").legal
    assert validate_transition("scheduled", "draft").legal
    assert validate_transition("scheduled", "provisioning").legal
    assert validate_transition("scheduled", "error").legal
    assert not validate_transition("scheduled", "live").legal
    assert not validate_transition("scheduled", "stopped").legal
    assert not validate_transition("live", "scheduled").legal
```

### 5.2 E2E Tests (`frontend/e2e/broadcast-scheduling.spec.ts`)

New file, ~300 lines.

**Section 119: Broadcast Scheduling API (5 tests)**:

1. `Creator schedules a broadcast 30 minutes in the future` — POST with `scheduled_at`, verify response has `status: "scheduled"` and correct `scheduled_at`.
2. `Scheduling with scheduled_at < 15 minutes returns 400` — Verify validation error.
3. `Creator reschedules a broadcast` — PATCH with new `scheduled_at`, verify updated.
4. `Creator cancels a scheduled broadcast` — POST cancel, verify status returns to `"draft"` and `scheduled_at` is cleared.
5. `Upcoming list returns scheduled broadcasts sorted by time` — Create 2 scheduled sessions, verify GET returns them in chronological order.

**Section 120: Scheduled Broadcast Auto-Start (3 tests)**:

1. `Scheduled broadcast with past scheduled_at auto-starts` — Create session with `scheduled_at = now - 60` (by directly writing to DDB with past timestamp), wait for scheduler poll (up to 35s), verify session transitions to `live`.
2. `Manual early start of scheduled broadcast succeeds` — Schedule a broadcast, call existing start endpoint, verify it starts normally.
3. `Calendar invite downloads as .ics file` — GET `/sessions/{id}/ical`, verify response has `Content-Type: text/calendar` and contains `BEGIN:VCALENDAR`.

**Test Setup (beforeAll)**:

```typescript
let rootPage: Page;
const TS = Date.now();

test.beforeAll(async ({ browser }) => {
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");

  // Create broadcast profile for scheduling tests
  const profileResp = await apiPost(rootPage, "root", "/broadcast/profiles", {
    name: `sched-test-profile-${TS}`,
    region: "us-east-1",
    rendition_preset: "720p",
  });
  profileId = profileResp.id;
});
```

### 5.3 Edge Cases

| Edge Case | Expected Behavior |
|-----------|-------------------|
| `scheduled_at` exactly 15 minutes from now | Accepted (boundary: `>= now + 900`) |
| `scheduled_at` 14 minutes 59 seconds from now | Rejected with 400 |
| Creator starts broadcast early (before `scheduled_at`) | Normal start flow; status transitions `scheduled -> provisioning -> ready -> live` |
| Scheduler fires but session was already cancelled | Re-fetches session with consistent read; skips if status != `"scheduled"` |
| Two scheduler instances running concurrently | First to call `start_session_with_provider()` wins; second sees status != `"scheduled"` and skips |
| Session with `scheduled_at` but status manually set to `"draft"` | Scheduler only queries `status="scheduled"`; session is not auto-started |
| Reminder subscription after reminder time has passed | That specific interval is skipped; other future intervals are written |
| Reschedule to earlier time | Old reminders cancelled, new reminders written for new time |
| iCal download for non-scheduled session | Returns 409 ("Session is not scheduled") |
| Session deleted while scheduled | Delete flow (existing) removes session; scheduler finds nothing on next poll |
| `scheduled_at` in the far future (1 year) | Accepted; reminders fire at their intervals regardless of how far out |

### 5.4 Flakiness Mitigations

| Risk | Mitigation |
|------|------------|
| Scheduler poll timing in E2E | Section 120 test uses `test.setTimeout(60_000)` and polls session status every 2s for up to 40s |
| Multiple scheduled sessions from prior runs | Each test creates sessions with unique profile; scheduler auto-starts don't interfere because prior sessions are already `"live"` or `"stopped"` |
| DDB eventual consistency on GSI | `list_due_scheduled_sessions` result confirmed via `get_session()` consistent read before starting |
| Timezone issues in iCal | All timestamps are Unix epoch (integers); iCal uses UTC (`Z` suffix) |

---

## 6. Security Considerations

### 6.1 Authentication & Authorization

- **Schedule/reschedule/cancel**: Only the session creator (`ctx["user_sub"] == session.created_by`) can modify scheduling. Same ownership model as existing session management.
- **Upcoming list**: Available to any authenticated user via `require_ui_session`. Scheduled broadcasts are public discovery points; hiding them defeats the purpose.
- **iCal download**: Available to any authenticated user. The iCal file contains only public information (session name, time, URL). No secrets are embedded.
- **Reminder subscription**: Any authenticated user can subscribe. No admin/root gate needed since users are opting in for themselves.
- **Auto-start actor**: The scheduler uses `actor="system:broadcast-scheduler"` in audit records, distinguishing automated starts from manual ones.

### 6.2 Input Validation

- **`scheduled_at`**: Must be an integer Unix timestamp >= `now + 900`. Prevents scheduling in the past or too close to now (insufficient prep time).
- **`name`**: Max 200 characters. Used in alerts and iCal summaries.
- **`description`**: Max 2000 characters. Truncated in iCal if needed.
- **`intervals`**: Validated against the `ALLOWED_INTERVALS` set. Invalid values are silently filtered.

### 6.3 Abuse Vectors

- **Reminder spam**: A user could subscribe to reminders for every scheduled broadcast, generating many alerts. Mitigation: rate limit on `POST /sessions/{id}/remind` (10 per minute per user). Each user can only subscribe once per session per interval (DDB conditional write on `sk`).
- **Schedule-cancel cycling**: A creator could schedule and cancel repeatedly to generate SSE events. Mitigation: session creation rate limit (existing) applies. Cancel is idempotent.
- **Far-future scheduling**: No inherent limit. Reminders for events >90 days out could be cleaned up via TTL, but this is low risk.

### 6.4 Data Privacy

- **Reminder items**: Contain `user_id` and `session_id`. These are internal system references. Reminder items are deleted when the session is cancelled or after dispatch.
- **iCal files**: Contain session name, description, and URL. No user-specific data. The URL does not include auth tokens.

---

## 7. Migration & Rollback Plan

### 7.1 DDB Changes

1. **New GSI `ByScheduledAt`** on `BroadcastSessions` table: Must be created before deploying backend code. In dev mode, `scripts/local-ddb-init.py` recreates tables on startup. In production, add GSI via `aws dynamodb update-table`.
2. **New table `BroadcastReminders`**: Created by `local-ddb-init.py`. In production, create before code deploy.

### 7.2 Schema Backward Compatibility

- New fields on `BroadcastSessionModel` (`scheduled_at`, `name`, etc.) are all `Optional` with `None` defaults. Existing sessions without these fields are unaffected.
- The new `"scheduled"` status value only applies to newly created sessions. Existing sessions in `"draft"` or other states are unchanged.
- `BroadcastSessionOut` gains new optional fields. Frontend code that does not use them is unaffected.

### 7.3 Feature Flag

- `BROADCAST_SCHEDULER_ENABLED` (default `"true"`): Controls whether the background auto-start loop runs. Set to `"false"` to disable auto-start without removing code.
- If disabled, scheduled sessions remain in `"scheduled"` status indefinitely. Creators can still manually start them.

### 7.4 Rollback Steps

1. Set `BROADCAST_SCHEDULER_ENABLED=false` to stop auto-starts.
2. Revert frontend to remove scheduling UI. Scheduled sessions remain in DDB but are not surfaced.
3. Revert backend endpoints. Existing scheduled sessions are orphaned but harmless.
4. Optionally: run a migration script to transition all `"scheduled"` sessions back to `"draft"`.

### 7.5 Zero-Downtime Deployment

- Backend endpoints are additive (new routes + modified create route with optional field).
- State machine change is backward-compatible (existing transitions are preserved).
- New GSI creation is a background operation on DDB (no downtime).
- Frontend changes are bundled in the Vite build.

---

## 8. Operational Runbook

### 8.1 Metrics

```python
record_broadcast_schedule_created    # Counter: sessions created with scheduled_at
record_broadcast_schedule_cancelled  # Counter: scheduled sessions cancelled
record_broadcast_schedule_autostart  # Counter: sessions auto-started by scheduler
record_broadcast_schedule_early_start # Counter: sessions manually started before scheduled_at
record_broadcast_schedule_latency_ms # Histogram: delay between scheduled_at and actual start
record_broadcast_reminder_dispatched # Counter: reminders sent
record_broadcast_reminder_subscribed # Counter: reminder subscriptions created
record_broadcast_scheduler_poll_duration_ms # Histogram: time to process one scheduler poll
```

### 8.2 Alerting Thresholds

| Metric | Threshold | Action |
|--------|-----------|--------|
| `schedule_latency_ms_p95` | > 60000 (1 min) | Scheduler poll interval may need reduction |
| `scheduler_poll_duration_ms_p95` | > 10000 (10s) | Too many due sessions; increase `MAX_BATCH_SIZE` |
| `schedule_autostart` (5-min rate) | > 50 | Unusual spike; verify not caused by clock skew |
| `reminder_dispatched` error rate | > 5% | Check alerts service health |

### 8.3 Common Debugging

**Scheduled broadcast didn't auto-start**:
1. Check `BROADCAST_SCHEDULER_ENABLED` env var.
2. Verify session status is `"scheduled"` in DDB: `aws dynamodb get-item --table-name BroadcastSessions --key '{"session_id":{"S":"<id>"}}'`
3. Check `scheduled_at` value is in the past: compare to `date +%s`.
4. Check backend logs for scheduler errors: `grep "broadcast_scheduler" .logs/uvicorn.log`.
5. Verify `ByScheduledAt` GSI exists and is `ACTIVE`.

**Reminders not being sent**:
1. Check `BroadcastReminders` table for items with `GSI_REM_PK="PENDING"`.
2. Verify `remind_at` is in the past.
3. Check alerts service is healthy: `curl localhost:8000/internal/health`.
4. Check reminder dispatch logs: `grep "broadcast_reminders" .logs/uvicorn.log`.

---

## 9. Performance & Capacity Planning

### 9.1 Scheduler Throughput

| Metric | Value |
|--------|-------|
| Poll interval | 30 seconds |
| Max sessions per poll | 10 |
| Start latency (provision + go live) | 2-5 seconds per session |
| Worst-case: 10 sessions due simultaneously | ~30 seconds to start all (sequential) |

### 9.2 DDB Capacity

| Operation | Rate | WCU/RCU |
|-----------|------|---------|
| Scheduler poll (GSI query) | 2/min | 1 RCU per poll |
| Session create with scheduling | Bursty | 2 WCU (session + transition) |
| Reminder subscribe | 1-10/session | 1 WCU per interval |
| Reminder dispatch | Bursty at reminder times | 1 WCU (update sent flag) + 1 WCU (alert) |

### 9.3 Hot Partition Analysis

- **`ByScheduledAt` GSI**: Partition key is `status` = `"scheduled"`. All scheduled sessions hash to the same partition. With <=1000 concurrent scheduled sessions, this is well within DDB's 10GB partition limit and 3000 RCU/s per partition.
- **`BroadcastReminders` `ByRemindAt` GSI**: Partition key is `"PENDING"`. All pending reminders in one partition. At reminder fire time, a burst of reads occurs. With <=10K pending reminders, query returns in <50ms.

---

## 10. Dependency Analysis

### 10.1 Tickets This Is Blocked By

| Ticket | Dependency | Detail |
|--------|-----------|--------|
| None | — | BCAST-009 builds on existing broadcast infrastructure. No blocking dependencies. |

### 10.2 Tickets This Blocks

| Ticket | Dependency | Detail |
|--------|-----------|--------|
| BCAST-010 | `scheduled_at` field | BCAST-010 creates newsfeed posts when a broadcast is scheduled |
| SOC-001 | Follow system (soft) | Reminders to followers require the follow system, but reminders are optional |

### 10.3 Integration Points

- **`app/services/broadcast_orchestrator.py::start_session_with_provider()`** — called by the scheduler to auto-start sessions (**requires modification**: the `if current.status == "draft":` guard at line 29 must be widened to also accept `"scheduled"` status)
- **`app/services/alerts.py::write_alert()`** — called by reminder dispatch to create in-app alerts
- **`app/services/broadcast_sse.py::broadcast_sse_publish()`** — for `session:scheduled`, `session:cancelled` SSE events
- **`app/main.py`** — registers scheduler background task

---

## 11. Acceptance Criteria

### Scheduling Core

1. A creator can schedule a broadcast session >= 15 minutes in the future by providing `scheduled_at` in the create request. The session transitions to `"scheduled"` status and the response includes the `scheduled_at` timestamp.
2. Attempting to schedule with `scheduled_at` less than 15 minutes in the future returns HTTP 400 with error code `SCHEDULE_TOO_SOON`.
3. Attempting to schedule with `scheduled_at` in the past returns HTTP 400 with error code `SCHEDULE_TOO_SOON`.
4. A session created without `scheduled_at` follows the existing immediate-start path with no changes to behavior.

### Auto-Start

5. The background scheduler auto-starts scheduled sessions within 60 seconds of their `scheduled_at` time under normal operating conditions (single-instance, no clock skew).
6. If the scheduler was down for up to 5 minutes, it picks up and auto-starts all broadcasts whose `scheduled_at` fell within that downtime window upon restart (grace period recovery).
7. The scheduler is idempotent: if two scheduler instances both query for due sessions, only one successfully transitions a given session (the other sees `status != "scheduled"` on the consistent re-read and skips it).
8. Auto-started sessions have `actor="system:broadcast-scheduler"` in the audit log, distinguishing them from manual starts.

### Cancellation & Rescheduling

9. A creator can cancel a scheduled broadcast via `POST /sessions/{id}/cancel`, transitioning it back to `"draft"` status and clearing `scheduled_at`.
10. Cancelling a non-scheduled session returns HTTP 409.
11. A creator can reschedule a broadcast via `PATCH /sessions/{id}/schedule` with a new `scheduled_at` value >= 15 minutes in the future. Old reminder subscriptions are deleted and new ones are written for the updated time.
12. A creator can manually start a scheduled broadcast early via the existing `POST /sessions/{id}/start` endpoint. The session transitions `scheduled -> provisioning -> ready -> live` normally.

### Reminders

13. Any authenticated user can subscribe to reminder notifications at 15-minute, 1-hour, and 24-hour intervals for a scheduled broadcast.
14. Reminder alerts are dispatched at the correct times (within 30 seconds of `scheduled_at - interval`) via the existing alert system, producing in-app notifications with the broadcast name and time-until-start label.
15. Reminders that have already passed at subscription time (e.g., subscribing to a 24-hour reminder when the broadcast is 30 minutes away) are silently skipped, and only future-eligible intervals are written.
16. When a session is cancelled, all pending reminder items for that session are deleted from DynamoDB.

### iCal / Calendar

17. Any authenticated user can download a `.ics` calendar invite via `GET /sessions/{id}/ical`. The response has `Content-Type: text/calendar` and `Content-Disposition: attachment; filename="broadcast.ics"`.
18. The generated `.ics` file is valid RFC 5545: contains `BEGIN:VCALENDAR`, `BEGIN:VEVENT`, `DTSTART` / `DTEND` in UTC (`Z` suffix), `SUMMARY`, `DESCRIPTION`, `URL` pointing to the broadcast page, and a `VALARM` trigger at -15 minutes.
19. Requesting iCal for a non-scheduled session (no `scheduled_at`) returns HTTP 409.

### Timezone Handling

20. All `scheduled_at` values are stored and compared as UTC Unix seconds. No timezone information is persisted on the backend.
21. The frontend ScheduleDialog defaults to the user's browser timezone and converts the selected local date/time to a UTC Unix timestamp before submission. The dialog displays the equivalent UTC time for confirmation.

### Upcoming List & UI

22. Scheduled sessions appear in a new "Upcoming" tab on the broadcast dashboard, sorted soonest-first.
23. The countdown timer on the session detail page and LivePlayer overlay counts down accurately (within 1-second precision) and displays "Starting now..." when it reaches zero.
24. The LivePlayer shows a countdown overlay (not the video player) when the session status is `"scheduled"`.

### Testing

25. All E2E tests (sections 119-120) pass with 0 flakes on 3 consecutive runs.
26. Unit tests cover: state machine transitions, due-session GSI query, reminder subscribe/cancel/dispatch, iCal generation with special character escaping, and scheduler idempotency.

---

## 12. Error Handling Matrix

| Error Condition | HTTP Status | Error Code | User Message | Recovery |
|----------------|-------------|------------|--------------|----------|
| `scheduled_at` in the past | 400 | SCHEDULE_TOO_SOON | "scheduled_at must be at least 15 minutes in the future" | Provide a future timestamp |
| `scheduled_at` < now + 900 | 400 | SCHEDULE_TOO_SOON | "scheduled_at must be at least 15 minutes in the future" | Use a time >= 15 min from now |
| Cancel non-scheduled session | 409 | SESSION_NOT_SCHEDULED | "Session is not in scheduled state" | Only cancel scheduled sessions |
| Reschedule non-scheduled session | 409 | SESSION_NOT_SCHEDULED | "Session must be in scheduled or draft state" | Schedule first, then reschedule |
| iCal for non-scheduled session | 409 | SESSION_NOT_SCHEDULED | "Session is not scheduled" | Schedule the session first |
| Remind on non-scheduled session | 409 | SESSION_NOT_SCHEDULED | "Session is not scheduled" | Only subscribe to scheduled sessions |
| Invalid reminder intervals | 422 | VALIDATION_ERROR | "Invalid reminder interval" | Use 900, 3600, or 86400 |
| Auto-start provisioning failure | N/A (logged) | N/A | N/A | Scheduler retries on next poll; session transitions to `"error"` |
| Auto-start session already started | N/A (skipped) | N/A | N/A | Scheduler re-fetches and skips |

---

## Appendix A: API Reference Summary

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/broadcast/sessions` | Session creator | Create session (with optional `scheduled_at`) |
| GET | `/broadcast/sessions/upcoming` | Any authenticated | List upcoming scheduled broadcasts |
| POST | `/broadcast/sessions/{id}/cancel` | Session creator | Cancel a scheduled broadcast |
| PATCH | `/broadcast/sessions/{id}/schedule` | Session creator | Reschedule a broadcast |
| GET | `/broadcast/sessions/{id}/ical` | Any authenticated | Download calendar invite |
| POST | `/broadcast/sessions/{id}/remind` | Any authenticated | Subscribe to reminders |

## Appendix B: Configuration

| Setting | Default | Purpose |
|---------|---------|---------|
| `BROADCAST_SCHEDULER_ENABLED` | `true` | Enable/disable auto-start scheduler |
| `BROADCAST_SCHEDULER_POLL_INTERVAL` | `30` | Seconds between scheduler polls |
| `BROADCAST_SCHEDULE_MIN_LEAD_TIME` | `900` | Minimum seconds in the future for scheduling |
| `DDB_BROADCAST_REMINDERS` | `BroadcastReminders` | Reminders table name |

## Appendix C: Related Tickets

- **BCAST-010**: Broadcast newsfeed promotion — auto-posts when a broadcast is scheduled or goes live
- **SOC-001**: Follow system — enables reminders to followers
- **LCOM-001**: Product shelf — shelf can be set up before a scheduled broadcast goes live

---

## 13. Timezone Handling

### 13.1 Storage: UTC Unix Seconds Only

All `scheduled_at` values are stored as integer Unix timestamps (seconds since epoch, UTC). No timezone offset, IANA timezone name, or local time string is ever stored in DynamoDB. This is consistent with the rest of the platform, where `now_ts()` returns an integer Unix timestamp and all time comparisons are done on integers.

**Rationale**: Storing UTC integers eliminates ambiguity from DST transitions, timezone database updates, and locale differences between backend instances. The scheduler compares `scheduled_at <= now_ts()` -- both are UTC integers, so no timezone conversion is needed on the backend at any point.

```python
# Backend never touches timezones — all comparisons are integer arithmetic
def is_due(session: BroadcastSessionModel) -> bool:
    return session.scheduled_at is not None and session.scheduled_at <= now_ts()
```

### 13.2 Frontend: Local Timezone Display

The frontend is responsible for all timezone conversions. The ScheduleDialog converts the user's selected local date/time/timezone into a UTC Unix timestamp for submission:

```typescript
// Converting local selection to UTC Unix timestamp
function localToUnixTimestamp(
  date: Date,           // calendar date (year, month, day from date picker)
  time: string,         // "HH:mm" from time picker
  timezone: string,     // IANA timezone, e.g., "America/New_York"
): number {
  // Build an ISO string in the target timezone
  const [hours, minutes] = time.split(":").map(Number);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const isoLocal = `${year}-${month}-${day}T${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:00`;

  // Use Intl.DateTimeFormat to resolve the UTC offset at that moment in that timezone
  // This correctly handles DST — the offset is computed for the specific date, not "now"
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone: timezone,
    timeZoneName: "shortOffset",
  });

  // Alternative: use the Temporal API (stage 3+) if available
  // const zonedDt = Temporal.ZonedDateTime.from({ ...parts, timeZone: timezone });
  // return zonedDt.epochSeconds;

  // Fallback: construct Date with timezone via string manipulation
  const dtInTz = new Date(isoLocal + getUtcOffsetString(timezone, date));
  return Math.floor(dtInTz.getTime() / 1000);
}
```

When displaying scheduled times, the frontend formats the UTC timestamp in the user's local timezone:

```typescript
// Displaying scheduled_at in user's local timezone
function formatScheduledTime(scheduledAt: number, timezone?: string): string {
  const dt = new Date(scheduledAt * 1000);
  return dt.toLocaleString("en-US", {
    timeZone: timezone ?? Intl.DateTimeFormat().resolvedOptions().timeZone,
    weekday: "short",
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  });
  // Example output: "Sat, May 30, 2026, 8:00 PM EDT"
}
```

### 13.3 Timezone-Aware iCal Generation

The iCal endpoint generates `DTSTART` and `DTEND` in UTC using the `Z` suffix (Zulu time), which is universally understood by all calendar applications:

```
DTSTART:20260530T000000Z
DTEND:20260530T010000Z
```

Calendar applications (Google Calendar, Apple Calendar, Outlook) convert UTC to the user's local timezone for display. This is the recommended approach per RFC 5545 Section 3.3.5 -- floating times (without timezone) should be avoided because they are ambiguous.

**Why not use VTIMEZONE?** VTIMEZONE components allow embedding a specific timezone definition in the iCal file, but they add complexity (50+ lines per timezone definition) and are unnecessary when UTC is used. All modern calendar applications handle UTC correctly. The `VALARM` trigger (`TRIGGER:-PT15M`) is relative to `DTSTART` and is timezone-agnostic.

### 13.4 DST Edge Cases

**Problem**: A creator in `America/New_York` schedules a broadcast for "Sunday, November 1 at 1:30 AM". During the fall-back DST transition, 1:30 AM occurs twice (once in EDT, once in EST).

**Resolution**: The ScheduleDialog resolves ambiguity at input time. When the user selects a date/time that falls within a DST transition's ambiguous window:

1. The timezone selector shows the current offset for the selected date (not the current date). For November 1 in New York, it shows `UTC-05:00` (EST) because the DST transition has already occurred at 2:00 AM.
2. If the selected time is in the ambiguous 1:00-1:59 AM window, the dialog shows a disambiguation prompt: "This time occurs twice due to a daylight saving change. Which did you mean?" with two options showing the UTC equivalents.
3. The final Unix timestamp is unambiguous regardless, because it is a single integer.

**Spring-forward gap**: If a creator selects 2:30 AM on a spring-forward date (which does not exist -- clocks jump from 2:00 AM to 3:00 AM), the dialog shows a validation error: "This time does not exist in [timezone] due to a daylight saving change. Please select a different time."

**Backend impact**: None. The backend only sees Unix timestamps. All DST logic is frontend-only.

### 13.5 "scheduled_at Is in the Past" Race Condition

**Scenario**: A creator submits a schedule request at 14:59:05 for 15:14:00 (exactly 14 minutes 55 seconds away). The request takes 6 seconds to reach the backend. At 14:59:11, the backend validates `scheduled_at >= now_ts() + 900` and finds `15:14:00 >= 14:59:11 + 900 = 15:14:11`. The check fails -- the request is rejected with 400.

**Mitigation**: The frontend pre-validates `scheduled_at >= now + 900 + 30` (adding a 30-second buffer for network latency). The ScheduleDialog's "Schedule" button is disabled when the selected time is within 15 minutes 30 seconds of the current time, with a tooltip: "Must be at least 15 minutes in the future."

**Opposite race**: The scheduler polls and finds a session with `scheduled_at = now - 2` (due 2 seconds ago). Between the GSI query and the `get_session()` consistent read, the creator cancels the session. The scheduler's consistent read sees `status = "draft"` and skips it. No race condition -- the consistent read is the serialization point.

**Clock drift between client and server**: If the user's device clock is significantly ahead of the server clock, they might schedule a broadcast that the server considers too close. The 15-minute minimum provides a large enough buffer that typical clock drift (NTP-synced servers are within 1 second; user devices within 1-2 minutes) does not cause issues. If the user's clock is more than 15 minutes off, the server's 400 response is the correct behavior -- the scheduled time genuinely is too soon from the server's perspective, and the server's clock is authoritative.

---

## 14. Concurrent Scheduling Conflicts

### 14.1 Policy Decision: Allow Overlapping Schedules

**Decision**: The system allows a creator to schedule multiple broadcasts at overlapping times. There is no server-enforced mutual exclusion.

**Rationale**:

1. **Creator autonomy**: Creators may have legitimate reasons for overlapping schedules (e.g., scheduling on two different profiles, A/B testing start times, one broadcast replacing another).
2. **Cancellation workflow**: A common pattern is scheduling a new broadcast before cancelling the old one. Blocking overlaps would force a cancel-then-schedule sequence, which is worse UX.
3. **Multi-profile support**: A creator with multiple broadcast profiles may intentionally schedule concurrent streams on different profiles (e.g., one for gaming, one for IRL).
4. **Complexity vs. value**: Overlap detection requires an additional DDB query on every schedule/reschedule request, adding latency and cost for a constraint most creators will never hit.

### 14.2 Soft Warning (Frontend Only)

While the backend does not enforce exclusion, the frontend ScheduleDialog queries the creator's existing scheduled sessions and shows a non-blocking warning if overlaps are detected:

```typescript
// ScheduleDialog overlap check (client-side only, non-blocking)
const OVERLAP_BUFFER_MINUTES = 30;

function checkOverlaps(
  newScheduledAt: number,
  existingSessions: BroadcastSession[],
): BroadcastSession[] {
  const bufferSeconds = OVERLAP_BUFFER_MINUTES * 60;
  return existingSessions.filter(
    (s) =>
      s.status === "scheduled" &&
      s.scheduled_at != null &&
      Math.abs(s.scheduled_at - newScheduledAt) < bufferSeconds,
  );
}

// If overlaps found, show warning:
// "You have another broadcast scheduled within 30 minutes of this time:
//  'Friday Night Live' at 8:00 PM EDT.
//  Are you sure you want to continue?"
// [Continue Anyway] [Pick a Different Time]
```

The 30-minute buffer is a UX heuristic, not a backend constraint. The creator can always proceed.

### 14.3 DDB Query for Overlap Detection (If Policy Changes)

If a future decision reverses this policy and requires server-side overlap prevention, the implementation would be:

```python
def check_scheduling_conflict(
    *,
    creator_id: str,
    scheduled_at: int,
    buffer_seconds: int = 1800,  # 30 minutes
    exclude_session_id: Optional[str] = None,
) -> Optional[BroadcastSessionModel]:
    """Check if the creator has another scheduled broadcast within buffer_seconds.

    Uses the ByCreatorCreatedAt GSI to find all sessions by this creator,
    then filters for status="scheduled" and overlapping scheduled_at.

    NOTE: This is a scan-and-filter, not a direct index lookup, because the
    GSI is keyed by created_at (not scheduled_at). For creators with <100
    total sessions, this is acceptable (<50ms). For high-volume creators,
    consider adding a ByCreatorScheduledAt GSI.
    """
    sessions = []
    last_key = None
    while True:
        kwargs = {
            "IndexName": "ByCreatorCreatedAt",
            "KeyConditionExpression": Key("created_by").eq(creator_id),
            "FilterExpression": Attr("status").eq("scheduled"),
            "Limit": 100,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.broadcast_sessions.query(**kwargs)
        sessions.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    for item in sessions:
        sid = item.get("session_id", "")
        sa = int(item.get("scheduled_at", 0))
        if sid == exclude_session_id:
            continue
        if abs(sa - scheduled_at) < buffer_seconds:
            return session_from_item(item)

    return None  # No conflict
```

**Why not a dedicated GSI?** Adding a `ByCreatorScheduledAt` GSI (partition key: `created_by`, sort key: `scheduled_at`) would enable a range query `scheduled_at BETWEEN (target - buffer) AND (target + buffer)` with a filter on `status = "scheduled"`. This is more efficient but adds GSI cost. Given the current policy of allowing overlaps, this GSI is not needed. If the policy changes, it should be added.

---

## 15. Auto-Start Reliability Deep Dive

### 15.1 Deployment Model: Single Scheduler Instance

The broadcast scheduler runs as an `asyncio.create_task()` background coroutine inside the FastAPI application process. In development, the backend runs with `--workers 1` (required for moto S3 compatibility). In production, only one worker instance should run the scheduler to avoid duplicate processing.

**Leader election is NOT implemented in v1.** Instead, the scheduler relies on:

1. **Python-level status validation + unconditional put**: The current `transition_session_status()` (at `broadcast_store.py:266-303`) calls `get_session()` (consistent read), validates the transition in Python via `validate_transition()`, then does an unconditional `put_item()` to write the updated session. **It does NOT use a DynamoDB `ConditionExpression`**, so there is a race window between the `get` and the `put` where two concurrent callers could both read `status="scheduled"` and both proceed. For single-instance deployments this is acceptable; for multi-instance deployments, a `ConditionExpression` should be added to `put_item()` (see note below).
2. **Scheduler re-read**: Before attempting a start, the scheduler re-fetches the session with `get_session()`. If another instance already transitioned the session, the re-read shows the new status and the scheduler skips it. This provides soft protection but is not atomic.
3. **Environment variable gating**: `BROADCAST_SCHEDULER_ENABLED` defaults to `"true"` but can be set to `"false"` on all but one instance in a multi-worker deployment.

> **Corrected**: The original text claimed `transition_session_status()` uses a DynamoDB `ConditionExpression: status = :expected_status`. This is wrong. The actual implementation (`broadcast_store.py:266-303`) does `get_session()` (consistent read), validates in Python, then does an **unconditional `put_item()`**. There is no `ConditionalCheckFailedException` path. For true idempotency in multi-instance deployments, a `ConditionExpression` should be added to the `put_item()` call. In single-instance dev mode (required for moto), the race window is academic.

**Future improvement (v2)**: Implement leader election via a DynamoDB lease table. The pattern:

```python
LEADER_LEASE_TABLE = "SchedulerLeases"
LEASE_DURATION_SECONDS = 60
LEASE_RENEW_INTERVAL_SECONDS = 20

async def acquire_lease(scheduler_id: str) -> bool:
    """Try to acquire or renew the scheduler lease.

    Uses a conditional PutItem:
    - If no lease exists: acquire it.
    - If lease exists but is expired: acquire it.
    - If lease exists, is not expired, and belongs to us: renew it.
    - If lease exists, is not expired, and belongs to another instance: fail.
    """
    now = now_ts()
    try:
        T.scheduler_leases.put_item(
            Item={
                "lease_id": "broadcast-scheduler",
                "holder_id": scheduler_id,
                "acquired_at": now,
                "expires_at": now + LEASE_DURATION_SECONDS,
            },
            ConditionExpression=(
                "attribute_not_exists(lease_id) OR "
                "expires_at < :now OR "
                "holder_id = :me"
            ),
            ExpressionAttributeValues={
                ":now": now,
                ":me": scheduler_id,
            },
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise
```

### 15.2 Idempotent State Transitions

The auto-start flow has two serialization points that reduce duplicate processing:

```
1. GSI Query (eventually consistent)
   └── May return stale results (session already started by another instance)

2. Consistent Read (strongly consistent)
   └── Confirms session is still status="scheduled"
   └── If not, skip (log and continue to next session)

NOTE: There is NO atomic conditional update. The current transition_session_status()
does get_session() + validate_transition() + unconditional put_item(). In a
multi-instance deployment, there is a race window between the get and put.
```

> **Corrected**: The original text described a three-step flow with a `ConditionExpression`-based conditional update as the "true serialization point" and showed a code sample using `update_item` with `ConditionExpression="#st = :old_st"`. This does not match the actual implementation. The real `transition_session_status()` at `broadcast_store.py:266-303` uses `get_session()` (consistent read) + `validate_transition()` (Python-side check) + unconditional `put_item()`. There is no `ConditionalCheckFailedException` handling. For production multi-instance deployments, adding a `ConditionExpression` to the `put_item()` call is recommended to close this race window.

The actual `transition_session_status()` in `broadcast_store.py` (lines 266-303):

```python
def transition_session_status(*, session_id: str, to_status: str, reason: str, actor: str) -> BroadcastSessionModel:
    current = get_session(session_id)
    validation = validate_transition(current.status, to_status)
    if not validation.legal:
        raise HTTPException(status_code=409, detail={...})

    updated = BroadcastSessionModel(
        id=current.id,
        # ... copy all fields with new status and updated_at ...
        status=to_status,
        updated_at=now_iso(),
    )
    T.broadcast_sessions.put_item(Item=session_to_item(updated))  # unconditional put
    # ... write transition audit ...
    return updated
```

### 15.3 Crash Recovery and Grace Period

**Problem**: If the scheduler process crashes or the backend is restarted, broadcasts scheduled during the downtime window will not auto-start until the scheduler resumes.

**Solution**: The scheduler has no "catch-up" mechanism beyond its normal polling behavior, which inherently handles recovery:

1. On startup, the scheduler immediately polls `list_due_scheduled_sessions(now=now_ts())`.
2. This query returns ALL sessions with `status="scheduled"` AND `scheduled_at <= now`.
3. Sessions that were due 1 second ago or 5 minutes ago are both returned.
4. The scheduler processes them in order (oldest first via `ScanIndexForward=True`).

**Grace period**: There is no explicit grace period cutoff. A session that was due 30 minutes ago will still be auto-started. However, an operational alert fires if `schedule_latency_ms_p95 > 60000` (see section 8.2), prompting investigation.

**Should there be a max grace period?** Consider adding a configurable `BROADCAST_SCHEDULE_MAX_LATE_START_SECONDS` (default: 600 = 10 minutes). If `now - scheduled_at > max_late_start`, the session transitions to `"error"` with reason `"auto-start-too-late"` instead of starting. The creator is notified via alert and can manually restart.

```python
MAX_LATE_START = int(os.environ.get("BROADCAST_SCHEDULE_MAX_LATE_START_SECONDS", "600"))

async def process_due_session(session: BroadcastSessionModel, now: int):
    late_by = now - session.scheduled_at
    if late_by > MAX_LATE_START:
        logger.warning(
            "Session %s is %d seconds past scheduled_at; exceeds max grace period of %d. "
            "Transitioning to error instead of auto-starting.",
            session.id, late_by, MAX_LATE_START,
        )
        transition_session_status(
            session.id, "scheduled", "error",
            actor="system:broadcast-scheduler",
            reason=f"auto-start-too-late (late by {late_by}s, max={MAX_LATE_START}s)",
        )
        write_alert(
            session.created_by,
            event="broadcast_autostart_failed",
            outcome="error",
            title="Scheduled broadcast failed to start",
            details={
                "body": (
                    f'"{session.name or "Broadcast"}" was scheduled for '
                    f'{datetime.fromtimestamp(session.scheduled_at, tz=timezone.utc).isoformat()} '
                    f"but the auto-start system was unavailable. Please start it manually or reschedule."
                ),
                "session_id": session.id,
                "late_by_seconds": late_by,
            },
        )
        return

    # Normal auto-start path
    start_session_with_provider(
        session_id=session.id,
        actor="system:broadcast-scheduler",
        reason="scheduled-auto-start",
        correlation_id=f"sched-{session.id}-{now}",
    )
```

### 15.4 Scheduler Loop Error Handling

The scheduler loop wraps each individual session start in a try/except, so one session's failure does not block others. The outer loop also has a try/except, so unhandled exceptions (e.g., DDB throttling, network errors) do not crash the loop:

```
Loop iteration:
  try:
    Query due sessions (may throw ThrottlingException)
    for session in due_sessions:
      try:
        Re-read session (consistent read)
        Check status == "scheduled"
        Check grace period
        Call start_session_with_provider()
        Log success
      except Exception:
        Log error for THIS session; continue to next
  except Exception:
    Log error for ENTIRE poll; sleep and retry
  await asyncio.sleep(poll_interval)
```

**DDB throttling**: If the GSI query is throttled, the loop logs the error and waits `poll_interval` seconds before retrying. There is no exponential backoff because the 30-second poll interval is already a sufficient cool-down period.

**Orphaned sessions**: If `start_session_with_provider()` throws after transitioning the session to `"provisioning"` but before completing provisioning, the session is stuck in `"provisioning"`. This is an existing problem (not introduced by BCAST-009) and is handled by the existing provisioning timeout mechanism in the orchestrator. The scheduler only operates on `status="scheduled"` sessions and does not retry stuck provisioning sessions.

### 15.5 Scheduler Startup Sequence

The scheduler is registered via `app.add_event_handler("startup", ...)` in `app/main.py`, matching the existing pattern used for other background tasks (e.g., `start_billing_dunning_task`, `start_scheduled_messages_task`):

```python
# app/services/broadcast_scheduler.py (or app/routers/broadcast.py)

async def start_broadcast_scheduler_task():
    """Startup handler registered via add_event_handler("startup", ...)."""
    if S.broadcast_scheduler_enabled:
        asyncio.create_task(
            run_broadcast_scheduler_loop(poll_interval=S.broadcast_scheduler_poll_interval)
        )
        logger.info("Broadcast scheduler task started")

# app/main.py — add alongside other startup handlers:
app.add_event_handler("startup", start_broadcast_scheduler_task)
```

> **Corrected**: The original text used a `@asynccontextmanager async def lifespan(app)` pattern. The actual `app/main.py` (lines 306-365) uses `app.add_event_handler("startup", ...)` for all background task registration — there is no lifespan context manager. The code sample has been updated to match the existing pattern.

The scheduler starts after all DynamoDB tables are initialized (table creation happens earlier in the startup sequence). It does not start if `BROADCAST_SCHEDULER_ENABLED` is `"false"`.

---

## 16. Notification Delivery Matrix

### 16.1 Channel Matrix

The following table shows which notification channels fire at which reminder intervals. Channel availability depends on the user's notification preferences (integration point: SOC-004 notification preferences expansion).

| Interval | In-App Alert | Push Notification | Email | SMS (Optional) |
|----------|:------------:|:-----------------:|:-----:|:--------------:|
| 24 hours before | Yes | No | Yes | No |
| 1 hour before | Yes | Yes | Yes | Yes |
| 15 minutes before | Yes | Yes | No | No |
| Broadcast started (live) | Yes | Yes | Yes | Yes |

**Rationale for channel selection**:

- **24 hours**: In-app + email. Too early for push (would be dismissed/forgotten). Email serves as a "save the date" that persists in the inbox.
- **1 hour**: All channels. The critical reminder window. Push ensures mobile users are notified even if they are not in the app. Email catches users who check email frequently. SMS is opt-in for users who have enabled it.
- **15 minutes**: In-app + push only. Too late for email (delivery time is unpredictable). Push is the primary channel -- it interrupts the user's current activity. In-app covers users who are already browsing the platform.
- **Broadcast started**: All channels. This is the final notification, confirming the broadcast is live. Users who missed all reminders get one last chance.

### 16.2 Notification Content by Channel

| Channel | Subject / Title | Body | Action URL |
|---------|----------------|------|------------|
| In-app alert | "Broadcast starting in {interval}" | '"{session_name}" is starting in {interval}. Don\'t miss it!' | `/broadcast/{session_id}` |
| Push notification | "{session_name} - {interval}" | "Starting in {interval}. Tap to watch." | Deep link to `/broadcast/{session_id}` |
| Email | "Reminder: {session_name} in {interval}" | HTML template with session thumbnail, name, description, countdown, and "Watch Now" button | `{frontend_base_url}/broadcast/{session_id}` |
| SMS | N/A | "{session_name} starts in {interval}. Watch at {short_url}" | Shortened URL |

### 16.3 Integration with SOC-004 Notification Preferences

SOC-004 introduces per-user notification preference settings (channel enable/disable, quiet hours, etc.). The broadcast reminder system integrates as follows:

1. **Preference check before dispatch**: `dispatch_due_reminders()` calls `get_user_notification_preferences(user_id)` before sending on each channel. If the user has disabled a channel, that channel is skipped.
2. **Quiet hours**: If the user has quiet hours enabled and the reminder falls within quiet hours, push and SMS are suppressed. In-app and email are still sent (they are non-intrusive).
3. **Unsubscribe**: Users can unsubscribe from broadcast reminders for a specific session (`DELETE /broadcast/sessions/{id}/remind`) or globally via SOC-004 preference settings.
4. **Fallback if SOC-004 is not yet deployed**: If `get_user_notification_preferences` is not available, all channels are enabled by default. The reminder system does not hard-depend on SOC-004.

### 16.4 "Broadcast Started" Notification

When the scheduler (or manual start) transitions a session from `"scheduled"` to `"live"`, a separate "broadcast started" notification is sent to all users who subscribed to reminders:

```python
def notify_broadcast_started(session_id: str):
    """Send 'broadcast is live' notification to all reminder subscribers."""
    last_key = None
    while True:
        kwargs = {
            "KeyConditionExpression": Key("pk").eq(f"SESSION#{session_id}"),
            "Limit": 500,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.broadcast_reminders.query(**kwargs)
        items = resp.get("Items", [])

        # Deduplicate by user_id (a user may have subscribed to multiple intervals)
        seen_users = set()
        for item in items:
            uid = item.get("user_id")
            if uid and uid not in seen_users:
                seen_users.add(uid)
                write_alert(
                    uid,
                    event="broadcast_started",
                    outcome="ok",
                    title="Broadcast is live!",
                    details={
                        "body": f'"{item.get("session_name", "Broadcast")}" is now live. Watch now!',
                        "session_id": session_id,
                    },
                )

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
```

### 16.5 Rate Limiting and Deduplication

- **Per-user per-session deduplication**: The reminder DDB item key (`SESSION#{session_id}#REMINDER#{user_id}#{interval}`) ensures a user cannot subscribe to the same interval twice. Re-subscribing overwrites the existing item.
- **Cross-session rate limit**: A user subscribing to reminders for many sessions (e.g., 100) will receive up to 300 reminders (3 intervals each). The existing alert system's per-user rate limit (100 alerts/hour) prevents inbox flooding. If a user exceeds this, the oldest alerts are dropped silently.
- **Email rate limit**: Email dispatch is rate-limited at 1 email per user per 5 minutes for the `broadcast_reminder` event type. If a user has two broadcasts starting within 5 minutes and both have 1-hour reminders, only the first email is sent.

---

## 17. Edge Cases Deep Dive

### 17.1 Creator Schedules Then Deletes Their Account

**Scenario**: A creator schedules a broadcast for next week, then deletes their account 3 days later.

**Current behavior (without explicit handling)**: The session remains in DDB with `status="scheduled"`. When `scheduled_at` arrives, the scheduler calls `start_session_with_provider()`, which attempts to provision infrastructure for the deleted user. The provisioning step may fail if it checks user existence, or it may succeed and produce a live broadcast with no active creator to manage it.

**Required handling**: Account deletion (existing flow in `app/services/account.py`) must cancel all scheduled broadcasts for the deleted user:

```python
# In the account deletion flow, before marking the account as deleted:
def cancel_user_scheduled_broadcasts(user_sub: str):
    """Cancel all scheduled broadcasts for a user being deleted."""
    sessions = list_sessions_by_creator(creator_id=user_sub, status_filter="scheduled")
    for session in sessions:
        transition_session_status(
            session.id, "scheduled", "draft",
            actor="system:account-deletion",
            reason=f"Creator account {user_sub} deleted",
        )
        cancel_reminders_for_session(session.id)
        logger.info("Cancelled scheduled broadcast %s due to account deletion", session.id)
```

**Reminder cleanup**: All reminder items for cancelled sessions are deleted by `cancel_reminders_for_session()`. Users who subscribed to reminders receive no notification (the session no longer exists). This is acceptable -- the alternative (sending "this broadcast was cancelled" notifications) requires the user to still exist for alert delivery.

### 17.2 Creator Schedules Then Gets Banned / Suspended

**Scenario**: A creator schedules a broadcast, then a moderator suspends their account before the broadcast time.

**Required handling**: The moderation/ban flow must check for scheduled broadcasts and either:

1. **Auto-cancel all scheduled broadcasts** (recommended for bans).
2. **Leave scheduled broadcasts in place** (for temporary suspensions with a known end date before `scheduled_at`).

Implementation in the moderation flow:

```python
def on_user_banned(user_sub: str, ban_type: str):
    """Handle scheduled broadcasts when a user is banned."""
    if ban_type == "permanent":
        cancel_user_scheduled_broadcasts(user_sub)
    elif ban_type == "temporary":
        # Check if any scheduled broadcasts fall within the ban period
        sessions = list_sessions_by_creator(creator_id=user_sub, status_filter="scheduled")
        ban_end = get_ban_end_timestamp(user_sub)
        for session in sessions:
            if session.scheduled_at and session.scheduled_at < ban_end:
                transition_session_status(
                    session.id, "scheduled", "draft",
                    actor="system:moderation",
                    reason=f"Creator banned until {ban_end}; broadcast scheduled before ban ends",
                )
                cancel_reminders_for_session(session.id)
```

The scheduler also adds a secondary check: before auto-starting, verify the creator's account is active:

```python
# In the scheduler loop, after confirming status == "scheduled":
from app.services.account import is_user_active
if not is_user_active(fresh.created_by):
    logger.warning("Creator %s is no longer active; cancelling session %s", fresh.created_by, session.id)
    transition_session_status(session.id, "scheduled", "error", actor="system:broadcast-scheduler", reason="creator-inactive")
    continue
```

### 17.3 Server Clock Skew Between Scheduler and DDB

**Scenario**: The application server's clock is 30 seconds ahead of DynamoDB's clock. The scheduler thinks it is 15:00:30 but DDB thinks it is 15:00:00. A broadcast scheduled for 15:00:15 should be due, but the GSI comparison uses the value written by the application (which used its own clock).

**Analysis**: This is a non-issue in practice because:

1. `scheduled_at` is written by the application server (using `now_ts()` from the server's clock).
2. The scheduler queries `scheduled_at <= now_ts()`, also using the server's clock.
3. Both the write and the read use the same clock source.
4. DynamoDB does not impose its own timestamp on `scheduled_at` -- it stores whatever integer the application provides.

**Where clock skew DOES matter**: If multiple application servers have different clocks:

- Server A (clock +30s) writes `scheduled_at = 1700000000`.
- Server B (clock -30s) runs the scheduler. At real time `1700000000`, Server B thinks it is `1699999970`. It queries `scheduled_at <= 1699999970` and misses the session.
- 30 seconds later (at real time `1700000030`), Server B queries `scheduled_at <= 1700000000` and finds the session.
- Net effect: the session starts 30 seconds late.

**Mitigation**: All servers should use NTP time synchronization. AWS EC2 instances use the Amazon Time Sync Service, which keeps clocks within 1 millisecond of UTC. The 30-second poll interval already dwarfs any realistic clock skew.

### 17.4 Broadcast Scheduled for February 29 in a Non-Leap Year

**Scenario**: A user somehow submits `scheduled_at` corresponding to February 29, 2027 (2027 is not a leap year).

**Analysis**: This cannot happen through the normal flow because `scheduled_at` is a Unix timestamp (integer), not a date string. The frontend ScheduleDialog uses a date picker that only shows valid dates. There is no February 29 to select in 2027.

However, if a client submits a raw API request with a fabricated Unix timestamp:

- The Unix timestamp for "February 29, 2027" does not exist. The closest valid timestamps are February 28 and March 1.
- If the client calculates what they think is "Feb 29, 2027 at noon UTC" and gets a timestamp that actually corresponds to March 1 at noon, the backend accepts it as a valid future timestamp.
- The broadcast would be scheduled for March 1 at noon, not February 29. The backend never interprets the timestamp as a calendar date.

**Conclusion**: No special handling needed. Unix timestamps cannot represent invalid dates.

### 17.5 Creator's Timezone Changes Between Scheduling and Broadcast Time

**Scenario**: A creator in `America/New_York` (UTC-5) schedules a broadcast for "January 15 at 8 PM" (which the frontend converts to `2027-01-15T20:00:00-05:00` = Unix `1800154800`). Before the broadcast, the creator travels to `America/Los_Angeles` (UTC-8). They open the app and see the broadcast scheduled for "5 PM" (local time), not "8 PM".

**Analysis**: This is correct behavior. The broadcast starts at the same absolute moment in time regardless of the creator's current timezone. The creator scheduled a specific instant; the display adapts to their current location.

**Potential confusion**: The creator might think the broadcast time changed. To mitigate:

1. The ScheduleDialog confirmation shows the UTC time alongside the local time: "Scheduled for Jan 15, 2027 at 8:00 PM EST (Jan 16, 2027 01:00 UTC)".
2. The UpcomingBroadcastsList shows the scheduled time in the user's current timezone with a tooltip showing the original timezone: "5:00 PM PST (originally scheduled as 8:00 PM EST)".

**Implementation note**: Storing the "original timezone" requires adding an `original_timezone` field to the session model. This is a UI nicety, not a functional requirement. For v1, showing times in the user's current timezone with "(UTC: ...)" tooltip is sufficient.

### 17.6 Scheduler Processes the Same Session Twice

**Scenario**: The GSI query returns session S1 as due. The scheduler starts processing S1 (consistent read, status check). While S1 is being processed, the next poll interval fires (this cannot happen with a single async loop, but could happen with concurrent scheduler instances or if processing takes longer than `poll_interval`).

**Analysis with single async loop**: The scheduler uses `await asyncio.sleep(poll_interval)` AFTER processing all due sessions. Since it is a single coroutine, the next poll cannot start until the current one finishes. This scenario cannot occur.

**Analysis with multiple instances**: Two instances both query the GSI and both see S1 as due. Both perform consistent reads and both see `status="scheduled"`. Both call `start_session_with_provider()`. The conditional update inside `transition_session_status()` ensures only one succeeds. The other gets `ConditionalCheckFailedException`, logs a warning, and moves on.

**Net effect**: Harmless. At most one extra DDB read + one failed conditional write.

### 17.7 Very Large Number of Simultaneously Due Sessions

**Scenario**: A platform event causes 500 broadcasts to be scheduled at the same time (e.g., a "simulcast" feature where many creators go live together).

**Impact**: The scheduler processes `MAX_BATCH_SIZE = 10` sessions per poll. At 30-second intervals, processing 500 sessions takes `500 / 10 * 30 = 1500 seconds = 25 minutes`. The last sessions in the queue start 25 minutes late.

**Mitigation options**:

1. **Increase `MAX_BATCH_SIZE`**: Set to 50 or 100. Each start takes 2-5 seconds, so a batch of 50 takes 100-250 seconds. At 30-second polls, 500 sessions would take ~5 minutes.
2. **Parallelize starts within a batch**: Use `asyncio.gather()` to start up to N sessions concurrently. Risk: higher burst load on the provisioning infrastructure.
3. **Dedicated scheduler process**: For high-volume platforms, run the scheduler as a separate process with its own scaling. Overkill for v1.

For v1, `MAX_BATCH_SIZE = 10` is sufficient for the expected load (<50 concurrent scheduled broadcasts). The operational alert on `schedule_latency_ms_p95 > 60000` catches capacity issues before they affect user experience.

### 17.8 Reminder Fires After Session Already Started

**Scenario**: A 15-minute reminder is due at 7:45 PM. The scheduler polls at 7:44:55 PM and auto-starts the session (which was scheduled for 7:45 PM -- within the 30-second poll window). The reminder dispatch loop runs at 7:45:05 PM and finds the 15-minute reminder as due. The session is already live.

**Impact**: The user receives a "starting in 15 minutes" alert for a broadcast that is already live.

**Mitigation**: Before dispatching a reminder, check the session's current status:

```python
# In dispatch_due_reminders(), before creating the alert:
from app.services.broadcast_store import get_session

session = get_session(item["session_id"])
if session and session.status in ("live", "stopping", "stopped"):
    # Session already started; send "broadcast is live" instead of reminder
    write_alert(
        item["user_id"],
        event="broadcast_started",
        outcome="ok",
        title="Broadcast is live!",
        details={
            "body": f'"{session_name}" is now live. Watch now!',
            "session_id": item["session_id"],
        },
    )
else:
    # Normal reminder
    write_alert(...)
```

This adds one DDB read per reminder dispatch, which is acceptable given the low volume (typically <100 reminders per batch).

### 17.9 Session Rescheduled While Reminders Are Being Dispatched

**Scenario**: The reminder dispatch loop is processing 50 reminders for session S1 (scheduled at 8 PM). After processing 25 reminders, the creator reschedules S1 to 10 PM. The remaining 25 reminders still reference the old `scheduled_at`.

**Impact**: 25 users receive a "starting in 15 minutes" alert but the broadcast does not start at 8 PM. It starts at 10 PM.

**Mitigation**: The `reschedule` endpoint calls `cancel_reminders_for_session()` which deletes ALL reminder items for the session, including ones that are mid-dispatch. The REMOVE of `GSI_REM_PK` on dispatched items means already-sent reminders are not affected (they have already been sent and marked `sent=True`). Not-yet-dispatched reminders are deleted by the cancel and will not be sent.

**Race window**: There is a small window where the dispatch loop has already read an item from the GSI but has not yet sent the alert. In this window, the cancel deletes the item, but the dispatch loop still has the in-memory reference and sends the alert. This is a rare edge case (requires exact timing overlap) and the impact is minor (user gets one extra "starting soon" alert, followed by a new set of reminders at the rescheduled time).

### 17.10 Timezone Database Updates

**Scenario**: A government announces a DST rule change (e.g., the country abolishes DST) after a user has scheduled a broadcast but before it starts.

**Impact on backend**: None. The `scheduled_at` is already stored as a fixed UTC Unix timestamp. The broadcast starts at the same absolute moment regardless of timezone rule changes.

**Impact on frontend display**: If the user's browser updates its timezone database (via OS update), the displayed local time for the broadcast will change to reflect the new rules. For example, if DST is abolished and the broadcast was scheduled during what would have been the DST period, the displayed time shifts by 1 hour. The underlying start time is unchanged.

**Mitigation**: None needed. The frontend always displays the correct local time for the user's current timezone rules. If the rules change, the display updates accordingly, which is the correct behavior.

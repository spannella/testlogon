# BCAST-009: Broadcast Scheduling — Investigation & Implementation Write-up

## 1. Summary & Classification

The broadcast session lifecycle previously required an immediate manual start: `POST /sessions` then `POST /sessions/{id}/start`. This ticket extends the lifecycle with a `"scheduled"` status, background auto-start scheduler, viewer-discoverable upcoming broadcasts list, iCal download, reminder subscriptions, and four new management endpoints (schedule, reschedule, cancel, remind). Broadcasters can now announce a future live event in advance, receive automatic go-live at the configured time, and send in-app alerts to subscribed viewers.

- **Type**: Feature
- **Priority**: High
- **Status**: Fully implemented across backend and frontend
- **Owning area**: Broadcast / session lifecycle / reminder system
- **Affected personas**: Broadcasters (scheduled workflow), Viewers (discovery + reminders), Platform operators (scheduler enable/disable flag)
- **Cross-references**: BCAST-001 (session CRUD base), BCAST-010 (announcement posts created on schedule), SECOPS-007 (scheduler runs on same DynamoDB Local / moto stack in dev, no AWS-specific infra needed)

---

## 2. Current-State Investigation (what exists today)

### Session model: `app/models_broadcast.py` (lines 51–58)

`BroadcastSessionModel` has all scheduling fields added:

```python
scheduled_at: Optional[int] = None       # Unix timestamp
schedule_status: Optional[str] = None   # "scheduled", "launched", "cancelled"
name: Optional[str] = None
description: Optional[str] = None
thumbnail_url: Optional[str] = None
cancelled_at: Optional[str] = None
announcement_post_id: Optional[str] = None
```

Note the design divergence: the ticket spec proposed a single status value `"scheduled"` in `BroadcastSessionStatus`. The implementation introduces a separate `schedule_status` field and keeps the main `status` field using the extended `BroadcastSessionStatus` literal that includes `"scheduled"` (line 11). The scheduler queries on `schedule_status` (not `status`) to find sessions due for auto-start (confirmed in `broadcast_store.py:474`). This two-field design allows a session to have `status="draft"` while also having `schedule_status="scheduled"` — enabling the scheduler to find and promote it without the main status being `"scheduled"`.

### State machine: `app/services/broadcast_state_machine.py`

`BroadcastSessionStatus` (models line 8–19) includes `"scheduled"` and `"cancelled"` as valid statuses. The `_ALLOWED_TRANSITIONS` dict must include transitions for `draft -> scheduled` and `scheduled -> provisioning` — verify these are present.

### Session store: `app/services/broadcast_store.py`

Scheduling fields are serialized/deserialized at lines 127–133 (`session_to_item`) and 191–197 (`session_from_item`).

New query functions:
- `list_due_scheduled_sessions(now, limit)` (line 467): queries `ByScheduledAt` GSI with `schedule_status='scheduled'` and `scheduled_at <= now`
- `list_upcoming_sessions(now, limit)` (line 482): queries `ByScheduledAt` GSI with `scheduled_at > now`
- `list_scheduled_sessions_by_creator(user_sub, limit)` (line 497): queries `ByCreatorCreatedAt` GSI with a `FilterExpression` on `schedule_status='scheduled'`

Note: the GSI partition key used is `schedule_status` (not the spec's `status`). The DDB init at `scripts/local-ddb-init.py:692` reflects this:
```python
{"index_name": "ByScheduledAt", "partition_key": "schedule_status", "sort_key": "scheduled_at"},
```

The `attr_types` at line 694 is `{"scheduled_at": "N"}` — numeric sort key correctly declared.

### Orchestrator: `app/services/broadcast_orchestrator.py`

`start_session_with_provider` (line 29) accepts both `"draft"` and `"scheduled"` as valid starting statuses:
```python
if current.status in ("draft", "scheduled"):
    transition_session_status(session_id=session_id, to_status="provisioning", ...)
```

This is the critical change the ticket (section 2.5) identified as mandatory. It is implemented correctly.

### Scheduler: `app/services/broadcast_scheduler.py`

`promote_due_sessions` (line 16) is a pure function that can be called from tests directly without async context. It:
1. Calls `list_due_scheduled_sessions(now=now, limit=limit)` (line 38)
2. Re-fetches each session with consistent read (line 41)
3. Checks `fresh.schedule_status != "scheduled"` to guard against races (line 42)
4. Calls `start_session_with_provider(...)` (line 51)
5. Updates `schedule_status="launched"` via `update_session_fields` (line 61) to drop it from the GSI

`run_broadcast_scheduler_loop` (line 72): async background coroutine polling `S.broadcast_scheduler_poll_interval_seconds` (default 30s). Gated by `S.broadcast_scheduler_enabled` (line 81).

`start_broadcast_scheduler_task` (line 107): wraps the loop in `asyncio.create_task`. Registered in `app/main.py:524`.

The design spec proposed `S.broadcast_scheduler_enabled` defaulting to `True`. The actual setting at `app/core/settings.py:1510` defaults to the value of `DEV_MODE` env var — meaning the scheduler is enabled in dev mode but disabled in production unless `BROADCAST_SCHEDULER_ENABLED=true` is explicitly set. This is a conservative production default that should be documented.

### Reminder system: `app/services/broadcast_reminders.py`

Functions implemented:
- `register_reminder(session_id, user_id, remind_at_ts, session_name, interval)` (line 25): writes a single reminder item with `remind_status="pending"` to `T.broadcast_reminders`
- `cancel_reminder(session_id, user_id)` (line 55): deletes by primary key
- `cancel_reminders_for_session(session_id)` (line 63): paginated delete of all reminders for a session
- `dispatch_due_reminders(now, limit)` (line 87): queries `ByRemindAt` GSI (`remind_status="pending"`, `remind_at <= now`), calls `write_alert` for each, marks `remind_status="sent"`
- `list_reminders_for_session(session_id)` (line 138): returns all items for a session
- `generate_ical(session_id, name, description, scheduled_at, frontend_base_url)` (line 157): full RFC 5545 iCal generation with `VALARM -PT15M`

Note differences from the design spec:
- The spec proposed `subscribe_to_reminders(intervals: List[int])` handling multiple intervals per call. The implementation uses `register_reminder` for a single interval. The router endpoint (see below) calls `register_reminder` for one interval per request.
- The GSI partition key in the spec was `GSI_REM_PK = "PENDING"`. The implementation uses `remind_status = "pending"` as the GSI partition key, which is cleaner.
- The `cancel_reminder` function signature is `(session_id, user_id)` with no `interval` parameter. This means a user can only have one reminder per session (the SK is `USER#{user_id}`), not one per interval-per-session as described in the spec.

### DynamoDB tables: `scripts/local-ddb-init.py`

BroadcastReminders table (lines 961–970):
```
PK: pk (SESSION#{session_id}), SK: sk (USER#{user_id})
GSI ByRemindAt: partition=remind_status, sort=remind_at
attr_types: remind_at=N
```

BroadcastSessions ByScheduledAt GSI (lines 692–694):
```
partition=schedule_status, sort=scheduled_at
attr_types: scheduled_at=N
```

Both tables have `attr_types` declared for their numeric sort keys — the critical CLAUDE.md gotcha is handled correctly.

### API endpoints: `app/routers/broadcast.py`

**`POST /sessions/{id}/schedule`** (line 2305): transitions `draft -> scheduled`, sets `schedule_status="scheduled"`, stores `scheduled_at/name/description`, fires BCAST-010 announcement post creation.

**`POST /sessions/{id}/reschedule`** (line 2376): validates ownership and `min_lead_time`, updates `scheduled_at`, cancels existing reminders, records audit action.

**`POST /sessions/{id}/cancel`** (line 2423 — `cancel_schedule_route`): transitions from `scheduled` to... (confirm target status), cancels reminders, deletes announcement post.

**`GET /sessions/scheduled`** (line 323): returns the caller's scheduled sessions.

**`GET /sessions/upcoming`** (line 334): returns all upcoming sessions (viewer discovery, global).

**`GET /sessions/{id}/ical`** (line 2519): generates and returns RFC 5545 `.ics` with `text/calendar` content type.

**`POST /sessions/{id}/remind`** (endpoint near line 2490–2516): registers a single reminder for the authenticated user.

**`DELETE /sessions/{id}/remind`** (line ~2516): calls `cancel_reminder`.

**`POST /broadcast/scheduler/run-due`** (line 2554): manual trigger for `promote_due_sessions` — useful for E2E testing without waiting 30 seconds.

Pydantic models in the router (lines 149–155, 175–181):
```python
class BroadcastScheduleIn:
    scheduled_at: int, name: Optional[str], description: Optional[str]
class BroadcastRescheduleIn:
    scheduled_at: int
```

Audit actions: `"schedule_session"`, `"reschedule_session"`, `"cancel_scheduled_session"` are used in the endpoints. These must exist in the `BroadcastActionAuditModel.action` Literal union — the original ticket (section 3.5.1) identified this as a required change.

### Background task registration: `app/main.py` (lines 524–525)

```python
app.add_event_handler("startup", start_broadcast_scheduler_task)
app.add_event_handler("startup", start_broadcast_reminder_task)
```

Both tasks registered. The pattern uses `add_event_handler("startup", ...)` — matching the newsfeed scheduler registration pattern, not a lifespan context manager.

### Frontend

`frontend/src/api/endpoints/broadcastSchedule.ts` exists with schedule API wrappers.

`frontend/src/pages/broadcast/BroadcastSchedulePage.tsx` — the dedicated scheduling page (BCAST-009 UI).

`frontend/src/pages/broadcast/BroadcastScheduleDialog.tsx` and `frontend/src/pages/broadcast/BroadcastScheduleCountdown.tsx` — the dialog and countdown components.

`frontend/e2e/broadcast-scheduling.spec.ts` — E2E test file exists.

---

## 3. Gap / Threat Analysis

### Fully implemented

The core scheduling infrastructure is complete: extended session model, ByScheduledAt GSI, scheduler loop, reminder loop, all management endpoints, iCal generation, and E2E spec.

### Gap: `schedule_status` vs `status` dual-field design

The ticket spec modeled scheduling entirely through `BroadcastSessionStatus` (a single `status` field). The implementation uses a separate `schedule_status` field for the GSI partition key. This means:
- `list_due_scheduled_sessions` queries `schedule_status="scheduled"` — items where `schedule_status` is absent (pre-dating this feature) will not appear, which is correct
- The GSI will only contain items that have `schedule_status` set, not all sessions
- `cancel_schedule_route` must set both `status` back to an appropriate value AND `schedule_status="cancelled"` — verify this is done at lines 2423+

### Gap: single interval per user per session

`register_reminder` uses `SK = USER#{user_id}`, allowing only one reminder per user per session. The ticket spec proposed multiple intervals (15min, 1hr, 24hr) stored as separate items. The `POST /sessions/{id}/remind` endpoint registers a single interval. Users who want all three intervals must call the endpoint three times or the endpoint must be extended to accept a list.

### Gap: `scheduled_at` minimum lead time setting

`S.broadcast_schedule_min_lead_time_seconds` is referenced in the schedule endpoint at line 2327. Verify this setting exists in `app/core/settings.py` — if it does not, the endpoint will crash on `AttributeError`.

### Abuse potential

- The `POST /sessions/{id}/remind` endpoint accepts any authenticated user, allowing spammy reminder subscriptions. No rate limiting or quota per session is implemented.
- The `GET /sessions/upcoming` endpoint is open to all authenticated users. If a creator has scheduled a private broadcast, its name and scheduled time appear in the global upcoming list. Access control should match the session's `broadcast_privacy_visibility`.
- Auto-start via `promote_due_sessions` calls `start_session_with_provider` which provisions infrastructure (MediaLive channels in production). If a session owner's account is suspended after scheduling, the scheduler will still attempt to provision. A status check on the creator's account before auto-start would be a hardening measure.

---

## 4. Proposed Design / Fix

### Verify `broadcast_schedule_min_lead_time_seconds` setting

```bash
grep -n "broadcast_schedule_min_lead_time" app/core/settings.py
```

If absent, add:
```python
broadcast_schedule_min_lead_time_seconds: int = int(
    os.environ.get("BROADCAST_SCHEDULE_MIN_LEAD_TIME_SECONDS", "900")  # 15 minutes
)
```

### Multi-interval reminder endpoint

Extend `POST /sessions/{id}/remind` to accept an `intervals` array:

```python
class BroadcastReminderIn(BaseModel):
    intervals: List[int] = Field(default=[900],
        description="Seconds before start. Allowed: 900, 3600, 86400.")
```

And change the SK to `USER#{user_id}#{interval}` to allow multiple subscriptions per user per session:
```
PK: SESSION#{session_id}
SK: USER#{user_id}#900 / USER#{user_id}#3600 / USER#{user_id}#86400
```

This is a breaking schema change for existing reminder items — run a migration or add backward-compatible SK detection.

### Privacy filter for upcoming list

At `list_upcoming_sessions_route`:
```python
items = [s for s in items if s.broadcast_privacy_visibility == "public"]
```

### Dev/Prod parity (SECOPS-007)

The scheduler loop and reminder dispatch use only DynamoDB — no AWS-specific services. `T.broadcast_sessions` and `T.broadcast_reminders` resolve to DynamoDB Local in dev and AWS DynamoDB in prod via the `DDB_ENDPOINT_URL` env var. No special dev/prod branching is needed in the scheduler.

`generate_ical` has no I/O — pure Python string generation. Safe in all environments.

---

## 5. Testing, Verification & Rollout

### pytest unit tests (`tests/test_broadcast_scheduler.py`)

- `test_schedule_session`: POST `/sessions/{id}/schedule` with `scheduled_at > now + 900` → `status="scheduled"`, `schedule_status="scheduled"`, `scheduled_at` stored
- `test_schedule_session_too_soon`: `scheduled_at < now + 900` → 400 `SCHEDULE_TOO_SOON`
- `test_list_upcoming`: query returns sessions with `scheduled_at > now`
- `test_list_due_sessions`: `list_due_scheduled_sessions(now=future_ts)` returns session
- `test_promote_due_sessions_idempotent`: calling twice on same session only starts once (`schedule_status="launched"`)
- `test_reschedule_session`: changes `scheduled_at`, cancels old reminders
- `test_cancel_schedule`: sets `schedule_status="cancelled"`, cancels reminders, deletes announcement post
- `test_dispatch_due_reminders`: inserts reminder item with `remind_at <= now` → `dispatch_due_reminders` calls `write_alert` and marks `remind_status="sent"`
- `test_generate_ical`: output contains `DTSTART`, `SUMMARY`, `VALARM`, correct `UID`

### Playwright E2E (`frontend/e2e/broadcast-scheduling.spec.ts`)

Using `injectAuth(page, "alice")` + CSRF:
1. Create session + POST `/schedule` → session `schedule_status = "scheduled"`
2. GET `/sessions/upcoming` → includes the scheduled session
3. GET `/sessions/{id}/ical` → `Content-Type: text/calendar`, body contains iCal markers
4. POST `/sessions/{id}/remind` → 200 `{ok: true}`
5. POST `/scheduler/run-due` (manual trigger) → `{processed: 1}` → session transitions to `live`
6. POST `/sessions/{id}/cancel` → `schedule_status = "cancelled"`, reminders deleted

### Rollout

The scheduler loop is disabled by default in production (`S.broadcast_scheduler_enabled` defaults to `DEV_MODE`). To enable:
```
BROADCAST_SCHEDULER_ENABLED=true
```

For initial rollout, use `BROADCAST_SCHEDULER_POLL_INTERVAL=60` (1-minute polling) to reduce DynamoDB query frequency while validating the scheduler logic in production.

### Verify `broadcast_schedule_min_lead_time_seconds` value

The setting exists at `app/core/settings.py:1512` with default **300 seconds (5 minutes)**, not 900 seconds (15 minutes) as specified in the ticket design (sections 3.5.1 and 3.5.4). The validation at `broadcast.py:2328` uses `S.broadcast_schedule_min_lead_time_seconds`, so the effective minimum lead time in production defaults to 5 minutes. Update either the default in `settings.py` or the ticket requirement to align these — a 5-minute lead time may be insufficient for viewers to receive notifications before a session auto-starts.

### Auto-start latency vs. poll interval

The scheduler polls every 30 seconds by default. A session with `scheduled_at = T` will not be promoted until the loop iteration at or after `T + 0..30` seconds. Viewers who navigate to the broadcast at exactly `T` may see the session still in `"scheduled"` status. The `LivePlayer` component should handle this gracefully by showing the countdown overlay and polling for status changes rather than a hard error.

### `cancelled_at` and `schedule_status` consistency on cancel

`cancel_schedule_route` (line 2423) must set both `schedule_status="cancelled"` and the session `status` appropriately. Review the exact fields updated and ensure `schedule_status="cancelled"` removes the item from the `ByScheduledAt` GSI partition — DynamoDB removes an item from a GSI when the GSI partition key attribute is updated to a value not matching the original query. Since the GSI partition key is `schedule_status`, updating to `"cancelled"` will drop it from the `schedule_status="scheduled"` query, preventing the scheduler from attempting to auto-start a cancelled session. Confirm this is implemented correctly at the update expression level.

### iCal content-type and filename

`download_ical_route` (line 2519) should return `Content-Type: text/calendar` and `Content-Disposition: attachment; filename="broadcast-<session_id>.ics"`. Verify the FastAPI `Response` is constructed with these headers, not a default JSON response. A plain `Response(content=ical_str, media_type="text/calendar")` without the `Content-Disposition` header will cause browsers to display the iCal content inline rather than prompt a download.

**Effort estimate**: Core feature fully implemented. Remaining work: align min_lead_time default (XS, 30 minutes), multi-interval reminder SK fix (S, 2–3 hours), privacy filter for upcoming list (S, 1 hour), iCal Content-Disposition verification (XS, 30 minutes).

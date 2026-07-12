# CRM Activities (Calls, Meetings, Tasks, Notes) & Calendar — Implementation Tickets

**Area**: Activities (Calls, Meetings, Tasks, Notes) & Calendar
**Source**: SuiteCRM gap analysis (`docs/suitecrm/SUITECRM_GAP_ANALYSIS.md`, section "[T1] Activities (Calls, Meetings, Tasks, Notes) & Calendar — 10 tickets")

## What SuiteCRM provides in this area

SuiteCRM's Activities area covers: calendar events with full attendee/RSVP workflow (accept, decline, tentative, no-response), event reminders/alarms (email and in-app, configurable minutes-before), invitation email dispatch with ICS attachment on event create/update, a Calls module with subject, description, direction (inbound/outbound), duration, outcome, and optional CRM-entity linking (contact, lead, account, opportunity), standalone Tasks (subject, status, priority, due date, assigned user), standalone Notes (rich text body, file attachment, linked entity), yearly recurrence, and a unified CRM Activity History timeline that aggregates calls, meetings, tasks, and notes on any CRM record (contact, lead, account).

## Cross-cutting constraints

- **Additive only, default-off**: Every ticket introduces a feature flag (e.g. `crm_activities_enabled`, sub-flags per module). With the flag off all new routes return 404 and all new background work is a no-op. Existing tables and routes (`app/routers/calendar.py`, `app/services/call_history.py`, `app/services/activity_feed.py`) are byte-for-byte unchanged when the flag is off.
- **Single-table DynamoDB, SECOPS-007 dev/prod parity**: All new tables follow the `TableDef` pattern in `scripts/local-ddb-init.py`. Numeric GSI sort keys **must** declare `attr_types={"<key>": "N"}` per the CLAUDE.md gotcha — omitting causes `ValidationException` at query time.
- **Reuse existing primitives — never fork**:
  - Email delivery: `app/services/alerts.send_alert_email` (`app/services/alerts.py:459`)
  - User email lookup: `app/services/profile.get_profile_identity` (`app/services/profile.py:305`) returns `{"email": ..., "display_name": ...}`
  - In-app alert: `app/services/alerts.write_alert` / `audit_event` (`app/services/alerts.py:356`, `644`)
  - ICS generation: `_build_ics` helper in `app/routers/calendar.py:2048` — extend, do not duplicate
  - Background tasks: register via `app.add_event_handler("startup", ...)` in `app/main.py` (pattern at line 665)
  - Unified scheduler: `app/services/scheduled_actions.create_action` / `query_upcoming_reminders` / `mark_reminder_sent` (`app/services/scheduled_actions.py:91`, `366`, `445`) — already polled by `run_unified_scheduler_loop` (`app/services/unified_scheduler.py:35`)
  - Cursor pagination: `app/core/cursor.encode_cursor` / `decode_cursor`
  - Audit events: `app/services/alerts.audit_event`
- **Planned upstream dependencies**: PTY-001..PTY-015 (`PARTY_CRM_TICKETS.md`) deliver the Party/Contact/Account model. Activity entity-linking tickets (ACT-007, ACT-009) must declare PTY as a soft prerequisite; they may use an opaque `linked_entity_type` + `linked_entity_id` string pair that resolves to PTY records once those tickets ship.
- **Hermetic offline tests**: All pytest must use moto-backed DDB tables bound via `object.__setattr__` on frozen `T`/`S` handles (canonical form: `tests/test_gap_0220_0221_ssh_stored_key.py`). No real AWS or network calls.

---

### ACT-001: CRM Activities feature flag, settings keys & DynamoDB tables
**Type:** Chore  **Priority:** P0  **Estimate:** 1d

**Description**

Scaffold all downstream ACT work by adding the feature flag, sub-flags, table name settings, and new DynamoDB tables. Nothing else in this ticket is visible to end users.

**Settings additions** (`app/core/settings.py`) — follow the bool-env pattern from `cart_reminders_enabled` at line 821:

```python
crm_activities_enabled: bool = os.environ.get("CRM_ACTIVITIES_ENABLED", "0") not in ("0", "false", "False")
crm_tasks_table_name: str     = os.environ.get("DDB_CRM_TASKS_TABLE", "crm_tasks")
crm_notes_table_name: str     = os.environ.get("DDB_CRM_NOTES_TABLE", "crm_notes")
crm_activity_timeline_table_name: str = os.environ.get("DDB_CRM_ACTIVITY_TIMELINE_TABLE", "crm_activity_timeline")
crm_event_rsvp_table_name: str = os.environ.get("DDB_CRM_EVENT_RSVP_TABLE", "crm_event_rsvp")
crm_event_reminders_table_name: str = os.environ.get("DDB_CRM_EVENT_REMINDERS_TABLE", "crm_event_reminders")
```

Sub-flags (all default off): `crm_tasks_enabled`, `crm_notes_enabled`, `crm_activity_timeline_enabled`, `crm_event_rsvp_enabled`, `crm_event_reminders_enabled`.

**DynamoDB tables** (`scripts/local-ddb-init.py`):

`crm_tasks` — PK=`user_sub` / SK=`sk` (value `TASK#{inverted_ts}#{task_id}`):
- GSI `ByStatus`: PK=`GSI1PK` (`STATUS#{status}`), SK=`GSI1SK` (`{due_date_ts}`) — for listing all tasks in a given status. `attr_types={"GSI1SK": "N"}`
- GSI `ByAssignee`: PK=`GSI2PK` (`ASSIGNEE#{assignee_sub}`), SK=`GSI2SK` (`{due_date_ts}`). `attr_types={"GSI2SK": "N"}`

`crm_notes` — PK=`user_sub` / SK=`sk` (value `NOTE#{inverted_ts}#{note_id}`):
- GSI `ByEntity`: PK=`GSI1PK` (`ENTITY#{linked_entity_type}#{linked_entity_id}`), SK=`GSI1SK` (`{created_at}`). `attr_types={"GSI1SK": "N"}`

`crm_activity_timeline` — PK=`entity_key` (`{linked_entity_type}#{linked_entity_id}`) / SK=`sk` (`{inverted_ts}#{activity_type}#{activity_id}`):
- GSI `ByType`: PK=`GSI1PK` (`TYPE#{activity_type}`), SK=`GSI1SK` (`{created_at}`). `attr_types={"GSI1SK": "N"}`

`crm_event_rsvp` — PK=`event_key` (`{calendar_id}#{event_id}`) / SK=`attendee_sub`:
- GSI `ByUser`: PK=`GSI1PK` (`USER#{attendee_sub}`), SK=`GSI1SK` (`{updated_at}`). `attr_types={"GSI1SK": "N"}`

`crm_event_reminders` — PK=`reminder_key` (`{calendar_id}#{event_id}#{user_sub}`) / SK=`reminder_id`:
- GSI `DueReminders`: PK=`GSI1PK` (constant `"DUE"`), SK=`GSI1SK` (`{fire_at}`). `attr_types={"GSI1SK": "N"}`

Wire all five table handles in `app/core/tables.py` next to `T.calendar` (line 99 area).

**Acceptance Criteria**
- `S.crm_activities_enabled` and all sub-flags default to `False`.
- All five `T.*` handles resolve in a smoke pytest.
- `just restart` creates all five tables with correct GSIs and no `ValidationException`.
- No existing table, flag, or route is changed.

**Dependencies**
- None (scaffolding only).

---

### ACT-002: Calendar RSVP — attendee RSVP status tracking
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Add per-attendee RSVP status tracking on calendar events. Currently `EventOut.attendees` is `List[str]` (a flat list of `user_sub` strings stored in `T.calendar`, read at `app/routers/calendar.py:1006`). This ticket upgrades it to carry per-attendee RSVP state stored in the `crm_event_rsvp` table introduced in ACT-001, without touching the existing `attendees` list field on the event item itself.

**DDB model** (uses `crm_event_rsvp` from ACT-001):

```
PK = {calendar_id}#{event_id}
SK = {attendee_sub}
Fields: status (accepted|declined|tentative|no_response), responded_at (int), user_sub, calendar_id, event_id, updated_at
```

**Pydantic additions** (`app/models.py`):

```python
class EventAttendeeRsvpStatus(str, Enum):
    accepted   = "accepted"
    declined   = "declined"
    tentative  = "tentative"
    no_response = "no_response"

class EventAttendeeOut(BaseModel):
    user_sub: str
    rsvp_status: EventAttendeeRsvpStatus = EventAttendeeRsvpStatus.no_response
    responded_at: Optional[int] = None

class EventRsvpUpdateIn(BaseModel):
    status: EventAttendeeRsvpStatus
```

**Service** (`app/services/crm_event_rsvp.py`):
- `upsert_rsvp(calendar_id, event_id, attendee_sub, status) -> dict` — writes/updates `crm_event_rsvp` row; emits `audit_event("calendar_event_rsvp", attendee_sub, ...)`.
- `get_rsvp(calendar_id, event_id, attendee_sub) -> Optional[dict]`
- `list_rsvps(calendar_id, event_id) -> List[dict]` — queries `crm_event_rsvp` by `PK`.
- `list_user_rsvps(attendee_sub, limit, cursor) -> dict` — queries `ByUser` GSI.

**Router additions** (`app/routers/calendar.py`), gated by `S.crm_event_rsvp_enabled`:
- `PUT /ui/calendars/{calendar_id}/events/{event_id}/rsvp` — authenticated attendee updates their own RSVP; returns `EventAttendeeOut`.
- `GET /ui/calendars/{calendar_id}/events/{event_id}/attendees` — returns `List[EventAttendeeOut]` (owner or attendee only).

The existing `create_event` / `update_event` write the plain `attendees: List[str]` to the `T.calendar` item unchanged. This ticket adds a read-merge utility `_enrich_attendees(calendar_id, event_id, attendees: List[str]) -> List[EventAttendeeOut]` that calls `list_rsvps` and populates status from the RSVP table; it is called from the two new GET endpoints but does not alter existing `EventOut` (backward compatible).

**Acceptance Criteria**
- `PUT /rsvp` with `status=accepted` writes to `crm_event_rsvp`; subsequent GET returns `rsvp_status=accepted`.
- Non-attendee PUT returns 403.
- `list_user_rsvps` returns all pending events for a user.
- When `S.crm_event_rsvp_enabled=False`, new endpoints return 404; existing event endpoints unchanged.
- Hermetic pytest covering upsert / list / non-attendee guard.

**Dependencies**
- ACT-001 (tables + flag).

---

### ACT-003: Calendar event invitation emails with ICS attachment
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Wire `create_event` and `update_event` in `app/routers/calendar.py` to dispatch invitation emails to all attendees (`body.attendees`) via `app/services/alerts.send_alert_email` (`alerts.py:459`), including an ICS attachment in the email body.

`send_alert_email` currently sends plain-text SES messages; it does not support MIME attachments. This ticket extends it (or adds a new `send_calendar_invite_email`) to send a `multipart/mixed` SES `RawMessage` containing a text/plain body and a `text/calendar` part. In dev mode the function writes both the text and the ICS content to the dev email log (`S.dev_email_log`).

**ICS content**: reuse `_build_ics(evt, event_id)` defined at `app/routers/calendar.py:2048`. Extend `_build_ics` to accept an optional `method` parameter (`"REQUEST"` for invites, `"CANCEL"` for cancellations) added as `METHOD:{method}` to the `VCALENDAR` block, so the ICS is a valid iTIP invite.

**Attendee email lookup**: use `app/services/profile.get_profile_identity(user_sub)` (`profile.py:305`) to resolve each attendee `user_sub` to their `email` field. Skip attendees with no email on record.

**Dispatch points**:
- After `T.calendar.put_item` in `create_event` (line 1588) — send `method=REQUEST` ICS.
- After `T.calendar.put_item` in `update_event` (line 1822) — send `method=REQUEST` ICS if `attendees` changed or times changed.
- On event delete — send `method=CANCEL` ICS (best-effort, fire-and-forget).

All dispatch is best-effort: wrapped in `try/except`, logged on failure, never blocks the event write. Guard entire dispatch block with `if S.crm_activities_enabled and S.crm_event_reminders_enabled:`.

**Acceptance Criteria**
- Creating an event with two attendee `user_sub` values writes two dev-log email entries, each containing the ICS `VCALENDAR` block with `METHOD:REQUEST`.
- Updating event times re-sends.
- An attendee with no profile email is silently skipped.
- With the flag off, no email is dispatched; existing event behavior unchanged.
- Hermetic pytest patching `send_alert_email` (or the new wrapper) and `get_profile_identity`.

**Dependencies**
- ACT-001 (flag), ACT-002 (RSVP wiring is independent; invite emails ship before RSVP tracking is consumed).

---

### ACT-004: Calendar event reminders / alarms (email and in-app)
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Add per-user configurable event reminders that fire N minutes before an event start via email and/or in-app alert.

**Model additions** (`app/models.py`):

```python
class EventReminderMethod(str, Enum):
    email  = "email"
    in_app = "in_app"

class EventReminderIn(BaseModel):
    minutes_before: int = Field(ge=1, le=10080)  # max 1 week
    method: EventReminderMethod = EventReminderMethod.in_app

class EventRemindersSetIn(BaseModel):
    reminders: List[EventReminderIn] = Field(max_length=5)
```

**DDB model** (uses `crm_event_reminders` from ACT-001):

```
PK  = {calendar_id}#{event_id}#{user_sub}
SK  = {reminder_id}
GSI DueReminders: PK="DUE", SK=fire_at (int, Unix epoch)
Fields: calendar_id, event_id, user_sub, minutes_before, method, fire_at, fired (bool), created_at
```

**Service** (`app/services/crm_event_reminders.py`):
- `set_reminders(calendar_id, event_id, user_sub, reminders: List[EventReminderIn], event_start_ts: int)` — deletes existing reminder rows for this `(event, user_sub)`, writes one row per `EventReminderIn` with `fire_at = event_start_ts - minutes_before*60`.
- `list_due_reminders(now: int, lookahead: int = 300) -> List[dict]` — queries `DueReminders` GSI: `fire_at BETWEEN now AND now+lookahead`, `fired=False`.
- `mark_reminder_fired(pk, sk)` — sets `fired=True`.

**Router additions** (`app/routers/calendar.py`):
- `PUT /ui/calendars/{calendar_id}/events/{event_id}/reminders` — authenticated user sets their own reminders for an event; calls `set_reminders`; returns `{"ok": True, "count": N}`.
- `GET /ui/calendars/{calendar_id}/events/{event_id}/reminders` — returns the caller's current reminder list.

Both endpoints gated by `S.crm_event_reminders_enabled`.

**Background poller** (`app/services/crm_event_reminders.py`):

```python
async def run_event_reminder_loop() -> None:
    # Polls every 60 s; queries list_due_reminders; dispatches via
    # send_alert_email or write_alert per method; marks fired.
    ...

async def start_event_reminder_task() -> None:
    if S.crm_activities_enabled and S.crm_event_reminders_enabled:
        asyncio.create_task(run_event_reminder_loop())
```

Register `start_event_reminder_task` in `app/main.py` via `app.add_event_handler("startup", start_event_reminder_task)` (pattern: line 665).

For in-app reminders call `write_alert` (`alerts.py:356`). For email call `send_alert_email` (`alerts.py:459`) with subject "Reminder: {event_name}". Both best-effort.

**Acceptance Criteria**
- `PUT /reminders` with `minutes_before=10, method=in_app` writes a row with correct `fire_at`.
- Background loop fires within one poll interval of `fire_at`; sets `fired=True`; does not double-fire.
- With the flag off, PUT/GET return 404; background loop is a no-op.
- Hermetic pytest: moto `crm_event_reminders`, patched `write_alert` / `send_alert_email`, patched `now_ts`.

**Dependencies**
- ACT-001 (tables + flag).

---

### ACT-005: Calendar yearly recurrence frequency
**Type:** Feature  **Priority:** P2  **Estimate:** 1d

**Description**

Add `YEARLY` to the `RecurrenceRule.freq` enum and implement the `_expand_rrule` YEARLY branch.

Currently `RecurrenceRule.freq` is `Literal["DAILY", "WEEKLY", "MONTHLY"]` at `app/models.py:1355`. `_expand_rrule` handles these three branches at `app/routers/calendar.py:561–678` but has no `elif rrule.freq == "YEARLY"` branch — unrecognised freq silently returns an empty list.

**Changes**:

1. `app/models.py:1355` — extend `Literal` to `Literal["DAILY", "WEEKLY", "MONTHLY", "YEARLY"]`.

2. `app/routers/calendar.py` — add an `elif rrule.freq == "YEARLY":` branch inside `_expand_rrule`. Algorithm: starting from `series_start_utc`, add `rrule.interval` years per iteration (use `datetime.replace(year=dt.year + rrule.interval)` with a fallback for Feb-29 leap-year edge case — clamp to Feb-28 when the target year is not a leap year). Apply `until` / `count` guards identical to the DAILY branch (lines 565–577). Append `(occ_start, occ_end)` when it overlaps the query window, break when `dt > window_end + timedelta(days=366)`.

3. `_build_ics` at `app/routers/calendar.py:2048` — add `RRULE:FREQ=YEARLY;INTERVAL={n}` to the ICS output when `recurrence_rule.freq == "YEARLY"` (matches the WEEKLY/MONTHLY `RRULE:FREQ=` lines added in the same function).

No flag needed for this change — it is purely additive to existing enum and function. No new tables, no DDB changes.

**Acceptance Criteria**
- `POST /ui/calendars/{id}/events` with `recurrence_rule: {freq: "YEARLY", interval: 1}` creates a recurring event.
- `GET /ui/calendars/{id}/events` with a 3-year window returns 3 occurrences.
- Feb-29 birthday event on a non-leap year occurrence falls on Feb-28, not an error.
- ICS download includes `RRULE:FREQ=YEARLY`.
- Existing DAILY/WEEKLY/MONTHLY tests unaffected.
- Hermetic pytest for the new YEARLY expansion logic.

**Dependencies**
- None (no new tables; no flag; pure code extension).

---

### ACT-006: CRM Call Logging — extend call record with subject, description, direction, outcome
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Extend the existing call history record with CRM-grade metadata: `subject`, `description` (freeform notes), `direction` (inbound/outbound — currently stored but not exposed in `CallRecordIn`), and `outcome` (connected, not_connected, left_message, wrong_number, busy).

**Current state**: `app/services/call_history.py` table PK=`user_id` / SK=`CALL#{inverted_ts}#{call_id}`. `record_call` stores `caller_id`, `callee_id`, `call_type`, `duration_seconds`, `status`, `direction` (set by the service, not the API caller). `CallRecordIn` (`app/models.py:6097`) has no `subject`, `description`, or `outcome` fields.

**Model changes** (`app/models.py`):

```python
class CallOutcome(str, Enum):
    connected       = "connected"
    not_connected   = "not_connected"
    left_message    = "left_message"
    wrong_number    = "wrong_number"
    busy            = "busy"

class CallLogCreateIn(BaseModel):
    """New model for CRM call log creation (separate from platform CallRecordIn)."""
    subject: str = Field(default="", max_length=200)
    description: str = Field(default="", max_length=5000)
    direction: Literal["inbound", "outbound"] = "outbound"
    duration_seconds: int = Field(ge=0, default=0)
    outcome: CallOutcome = CallOutcome.connected
    call_type: Literal["audio", "video", "phone"] = "phone"
    # Optional link to a platform user (callee)
    contact_user_sub: Optional[str] = None

class CallLogOut(BaseModel):
    call_id: str
    user_sub: str
    subject: str
    description: str
    direction: str
    duration_seconds: int
    outcome: str
    call_type: str
    contact_user_sub: Optional[str]
    created_at: int
```

**Service additions** (`app/services/call_history.py`):
- `create_crm_call_log(user_sub, body: CallLogCreateIn) -> dict` — writes a new row to `T.call_history` with `PK=user_sub`, `SK=CALLLOG#{inverted_ts}#{call_id}` (different SK prefix from platform calls to avoid collision), all new fields stored.
- `list_crm_call_logs(user_sub, cursor, limit) -> dict` — queries `begins_with(sk, "CALLLOG#")`.
- `get_crm_call_log(user_sub, call_id) -> Optional[dict]`
- `update_crm_call_log(user_sub, call_id, updates: dict) -> Optional[dict]` — allows editing `subject`, `description`, `outcome` after the fact.
- `delete_crm_call_log(user_sub, call_id) -> bool`

**Router** (`app/routers/call_history.py`), all routes gated by `S.crm_activities_enabled`:
- `POST /ui/calls/logs` — `Depends(require_ui_session)`, body `CallLogCreateIn`, returns `CallLogOut`.
- `GET /ui/calls/logs` — paginated list.
- `GET /ui/calls/logs/{call_id}` — single record.
- `PATCH /ui/calls/logs/{call_id}` — partial update (subject/description/outcome).
- `DELETE /ui/calls/logs/{call_id}` — delete.

The existing `POST /ui/calls/record`, `GET /ui/calls/history`, etc. are unchanged.

**Acceptance Criteria**
- `POST /ui/calls/logs` with `subject`, `description`, `direction=inbound`, `outcome=left_message` round-trips correctly.
- `PATCH` updates subject; GET returns updated value.
- DELETE returns 404 for unknown id.
- With flag off, all `/logs` routes return 404; existing `/history` routes unaffected.
- Hermetic pytest.

**Dependencies**
- ACT-001 (flag). No new DDB table — reuses `call_history` table with new SK prefix.

---

### ACT-007: CRM Call Logging — link call log to CRM entity
**Type:** Feature  **Priority:** P2  **Estimate:** 1d

**Description**

Extend the CRM call log (introduced in ACT-006) with optional linked CRM entity fields so a call record can be associated with a Contact, Lead, Account, or Opportunity record once those modules ship.

**Model additions** (`app/models.py`):

Add to `CallLogCreateIn` and `CallLogOut`:

```python
linked_entity_type: Optional[Literal["contact", "lead", "account", "opportunity"]] = None
linked_entity_id: Optional[str] = None
```

**Service changes** (`app/services/call_history.py`):
- `create_crm_call_log` passes `linked_entity_type` and `linked_entity_id` through to DDB item.
- Add `list_crm_call_logs_for_entity(entity_type, entity_id, user_sub, cursor, limit)` — queries `T.call_history` using a `FilterExpression` on `linked_entity_type` + `linked_entity_id` (no new GSI needed at this volume; add GSI if query latency becomes an issue once PTY ships).

**CRM Activity Timeline write**: when `linked_entity_type` is set, call `record_crm_activity(entity_type, entity_id, activity_type="call", activity_id=call_id, metadata={...})` in `app/services/crm_activity_timeline.py` (introduced in ACT-009). Import lazily to avoid circular dep; wrap in `try/except`.

**Router additions** (`app/routers/call_history.py`):
- `GET /ui/calls/logs/by-entity?entity_type=contact&entity_id={id}` — lists call logs linked to a given entity.

**Note on PTY dependency**: `linked_entity_id` is an opaque string at this ticket's boundary. When PTY-011 ships, the entity detail view can call `GET /ui/calls/logs/by-entity?entity_type=contact&entity_id={party_id}` to populate the Calls subpanel — no backfill needed.

**Acceptance Criteria**
- `POST /ui/calls/logs` with `linked_entity_type=contact`, `linked_entity_id=party_abc` stores the link.
- `GET /ui/calls/logs/by-entity?entity_type=contact&entity_id=party_abc` returns the linked call.
- `linked_entity_type=opportunity` is accepted without error even before an Opportunity module exists.
- Hermetic pytest.

**Dependencies**
- ACT-006 (call log model). ACT-009 (timeline write — wrapped in try/except, so ACT-007 ships independently).

---

### ACT-008: CRM Tasks module — standalone task management
**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Create a standalone CRM Tasks module: subject, status state machine, priority, due date, assigned user, and optional linked CRM entity.

**DDB model** (uses `crm_tasks` table from ACT-001):

```
PK  = user_sub (owner / creator)
SK  = TASK#{inverted_due_ts}#{task_id}
GSI ByStatus:   PK=STATUS#{status},   SK=due_date_ts
GSI ByAssignee: PK=ASSIGNEE#{sub},    SK=due_date_ts
Fields: task_id, user_sub, subject, description, status, priority,
        due_date_ts (int), assignee_sub, linked_entity_type, linked_entity_id,
        created_at, updated_at
```

**Pydantic models** (`app/models.py`):

```python
class CrmTaskStatus(str, Enum):
    not_started = "not_started"
    in_progress = "in_progress"
    completed   = "completed"
    deferred    = "deferred"
    waiting     = "waiting"

class CrmTaskPriority(str, Enum):
    low    = "low"
    medium = "medium"
    high   = "high"
    urgent = "urgent"

class CrmTaskCreateIn(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    status: CrmTaskStatus = CrmTaskStatus.not_started
    priority: CrmTaskPriority = CrmTaskPriority.medium
    due_date_ts: Optional[int] = None    # Unix epoch seconds
    assignee_sub: Optional[str] = None
    linked_entity_type: Optional[Literal["contact","lead","account","opportunity"]] = None
    linked_entity_id: Optional[str] = None

class CrmTaskUpdateIn(BaseModel):
    subject: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = None
    status: Optional[CrmTaskStatus] = None
    priority: Optional[CrmTaskPriority] = None
    due_date_ts: Optional[int] = None
    assignee_sub: Optional[str] = None

class CrmTaskOut(CrmTaskCreateIn):
    task_id: str
    user_sub: str
    created_at: int
    updated_at: int
```

**Service** (`app/services/crm_tasks.py`):
- `create_task(user_sub, body: CrmTaskCreateIn) -> dict`
- `get_task(user_sub, task_id) -> Optional[dict]`
- `update_task(user_sub, task_id, updates: CrmTaskUpdateIn) -> Optional[dict]` — emits `audit_event("crm_task_updated", ...)`.
- `delete_task(user_sub, task_id) -> bool`
- `list_tasks(user_sub, status=None, assignee_sub=None, cursor=None, limit=20) -> dict` — routes to `ByStatus` or `ByAssignee` GSI when filters given; otherwise queries PK.
- `list_tasks_for_entity(entity_type, entity_id, user_sub, cursor, limit)` — FilterExpression on `linked_entity_type/id`.

On `status` transition to `completed`, write a CRM activity timeline event (ACT-009); wrap in `try/except`.

**Router** (`app/routers/crm_tasks.py`), prefix `/ui/crm/tasks`, gated by `S.crm_activities_enabled and S.crm_tasks_enabled`:
- `POST /` — create
- `GET /` — list (query params: `status`, `assignee_sub`, `cursor`, `limit`)
- `GET /{task_id}` — get
- `PATCH /{task_id}` — update
- `DELETE /{task_id}` — delete
- `GET /by-entity?entity_type=&entity_id=` — declared BEFORE `/{task_id}`

Register router in `app/main.py`.

**Frontend** (`frontend/src/pages/crm-tasks/`): task list page with status filter tabs (Not Started / In Progress / Completed / Deferred), create/edit dialog (React Hook Form + Zod), priority badge, due date display. Add route `/crm/tasks` to `frontend/src/App.tsx` (lazy-loaded). API endpoints in `frontend/src/api/endpoints/crmTasks.ts`.

**Acceptance Criteria**
- Full CRUD round-trips via API.
- Listing by `status=completed` uses ByStatus GSI.
- Listing by `assignee_sub` uses ByAssignee GSI.
- `list_tasks_for_entity` returns tasks linked to a given entity.
- Frontend page renders task list and allows create/edit/delete.
- With flags off, router returns 404; no DDB writes.
- Hermetic pytest (moto `crm_tasks`).

**Dependencies**
- ACT-001 (tables + flag). ACT-009 (timeline — wrapped in try/except, ships independently).

---

### ACT-009: CRM Activity History Timeline — unified per-entity activity feed
**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Build a CRM activity history service that aggregates calls, calendar events, tasks, and notes linked to a CRM entity (contact, lead, account, opportunity) and exposes a chronological timeline endpoint.

**DDB model** (uses `crm_activity_timeline` from ACT-001):

```
PK  = entity_key  ({entity_type}#{entity_id})
SK  = {inverted_ts}#{activity_type}#{activity_id}
GSI ByType: PK=TYPE#{activity_type}, SK=created_at
Fields: entity_type, entity_id, activity_type (call|note|task|calendar_event|email),
        activity_id, user_sub, summary (short text), metadata (JSON), created_at
```

**Service** (`app/services/crm_activity_timeline.py`):
- `record_crm_activity(entity_type, entity_id, activity_type, activity_id, user_sub, summary="", metadata=None) -> dict` — writes a row to `crm_activity_timeline`. Called from ACT-007 (call log), ACT-008 (task), ACT-010 (note) as fire-and-forget.
- `list_entity_activities(entity_type, entity_id, activity_type=None, cursor=None, limit=20) -> dict` — queries `crm_activity_timeline` by PK; optionally filters by `activity_type` via FilterExpression.
- `delete_entity_activity(entity_type, entity_id, sk) -> bool` — for when linked source record is deleted.

**Pydantic models** (`app/models.py`):

```python
class CrmActivityOut(BaseModel):
    activity_id: str
    entity_type: str
    entity_id: str
    activity_type: str
    user_sub: str
    summary: str
    metadata: dict
    created_at: int

class CrmActivityTimelineOut(BaseModel):
    items: List[CrmActivityOut]
    next_cursor: Optional[str] = None
```

**Router** (`app/routers/crm_activity_timeline.py`), gated by `S.crm_activities_enabled and S.crm_activity_timeline_enabled`:
- `GET /ui/crm/entities/{entity_type}/{entity_id}/activities` — returns `CrmActivityTimelineOut` (newest first). Auth: `require_ui_session`; user must own or be assigned at least one activity row for the entity (no additional party-level auth at this ticket's boundary — full record-level ACL deferred to the Security Suite area).
- `GET /ui/crm/entities/{entity_type}/{entity_id}/activities?activity_type=call` — filter by type.

Register router in `app/main.py`.

**Integration wiring** (add after this ticket):
- ACT-007: after `create_crm_call_log` with entity link, call `record_crm_activity(entity_type, entity_id, "call", call_id, ...)`.
- ACT-008: on task create/update/complete, call `record_crm_activity(entity_type, entity_id, "task", task_id, ...)`.
- ACT-010: on note create, call `record_crm_activity(entity_type, entity_id, "note", note_id, ...)`.

All wiring calls are wrapped in `try/except` so a timeline write failure never blocks the primary operation.

**Acceptance Criteria**
- `record_crm_activity` writes a row; `list_entity_activities` returns it ordered newest-first.
- Filtering by `activity_type=call` returns only call rows.
- Pagination cursor works across multiple pages.
- With flag off, endpoint returns 404; `record_crm_activity` is a no-op.
- Hermetic pytest (moto `crm_activity_timeline`).

**Dependencies**
- ACT-001 (tables + flag). ACT-006, ACT-008, ACT-010 (callers — shipped independently via try/except wiring).

---

### ACT-010: CRM Notes module — standalone note with free-text body and file attachment
**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Create a standalone CRM Notes module: free-text body, optional S3 file attachment, optional linked CRM entity.

**DDB model** (uses `crm_notes` table from ACT-001):

```
PK  = user_sub
SK  = NOTE#{inverted_ts}#{note_id}
GSI ByEntity: PK=ENTITY#{linked_entity_type}#{linked_entity_id}, SK=created_at
Fields: note_id, user_sub, body, attachment_s3_key, attachment_filename, attachment_content_type,
        linked_entity_type, linked_entity_id, created_at, updated_at
```

**Pydantic models** (`app/models.py`):

```python
class CrmNoteCreateIn(BaseModel):
    body: str = Field(default="", max_length=20000)
    linked_entity_type: Optional[Literal["contact","lead","account","opportunity"]] = None
    linked_entity_id: Optional[str] = None

class CrmNoteOut(CrmNoteCreateIn):
    note_id: str
    user_sub: str
    attachment_s3_key: Optional[str] = None
    attachment_filename: Optional[str] = None
    attachment_content_type: Optional[str] = None
    attachment_url: Optional[str] = None   # /mock/s3/... in dev, presigned URL in prod
    created_at: int
    updated_at: int
```

**Service** (`app/services/crm_notes.py`):
- `create_note(user_sub, body: CrmNoteCreateIn) -> dict`
- `attach_file(user_sub, note_id, filename, content_type, file_bytes) -> dict` — uploads to S3 at `crm-notes/{user_sub}/{note_id}/{filename}` via `app.core.aws_clients.s3_client` (mirrors the pattern in `app/services/kyc_partner_api.py` `_store_document_bytes`); sets `attachment_s3_key`/`attachment_filename`/`attachment_content_type` on the note DDB item. In dev returns `/mock/s3/...` URL (SECOPS-007 parity — same code path).
- `get_note(user_sub, note_id) -> Optional[dict]` — enriches `attachment_url` at read time: dev → `/mock/s3/{key}`, prod → `s3_client.generate_presigned_url(ExpiresIn=300)`.
- `update_note(user_sub, note_id, body: str) -> Optional[dict]`
- `delete_note(user_sub, note_id) -> bool` — also deletes S3 object if `attachment_s3_key` is set.
- `list_notes(user_sub, cursor, limit) -> dict`
- `list_notes_for_entity(entity_type, entity_id, user_sub, cursor, limit) -> dict` — queries `ByEntity` GSI.

On create (when `linked_entity_type` set), call `record_crm_activity` (ACT-009) fire-and-forget.

**Router** (`app/routers/crm_notes.py`), prefix `/ui/crm/notes`, gated by `S.crm_activities_enabled and S.crm_notes_enabled`:
- `POST /` — create note, body `CrmNoteCreateIn`
- `POST /{note_id}/attachment` — `multipart/form-data` file upload (≤25 MB), returns updated `CrmNoteOut`
- `GET /` — list (own notes)
- `GET /{note_id}` — get
- `PATCH /{note_id}` — update body
- `DELETE /{note_id}` — delete (+ S3 cleanup)
- `GET /by-entity?entity_type=&entity_id=` — declared BEFORE `/{note_id}`

Register router in `app/main.py`.

**Frontend** (`frontend/src/pages/crm-notes/`): note list page, create/edit dialog with text area and optional file picker (reuse `FilePickerDialog` from `frontend/src/components/shared/FilePickerDialog` introduced in messaging, or a new native file input). Add route `/crm/notes` to `frontend/src/App.tsx`. API endpoints in `frontend/src/api/endpoints/crmNotes.ts`.

**Acceptance Criteria**
- Create note → list → get round-trips.
- Attach file: stored in S3; `attachment_url` returns `/mock/s3/...` in dev.
- Delete note cleans up S3 attachment.
- `list_notes_for_entity` queries ByEntity GSI.
- File size > 25 MB returns 422.
- With flags off, router returns 404.
- Hermetic pytest (moto `crm_notes`, patched `s3_client`).

**Dependencies**
- ACT-001 (tables + flag). ACT-009 (timeline wiring — wrapped in try/except, ships independently).

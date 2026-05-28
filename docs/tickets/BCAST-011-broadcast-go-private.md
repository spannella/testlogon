# BCAST-011: Broadcast "Go Private" (1-on-1 Paid Call)

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-27  
**Priority**: High  
**Estimated effort**: 7-9 days  
**Depends on**: BCAST-005 (Live Chat), CALL-001 through CALL-010 (WebRTC Call Infrastructure)

---

## 1. Overview & Motivation

### The Gap

During a live broadcast, there is no mechanism for a viewer to escalate from the public broadcast into a private 1-on-1 video call with the creator. The platform has two mature but completely isolated systems: the broadcast infrastructure (`app/routers/broadcast.py`, `app/services/broadcast_store.py`) for one-to-many live streaming, and the messenger call infrastructure (CALL-001 through CALL-010) for private 1-on-1 WebRTC calls. These systems share no state, no UI handoff, and no billing linkage. A viewer who wants a private session with a broadcaster must leave the broadcast entirely, navigate to messages, and initiate a separate call -- losing the broadcast context and requiring the creator to manually manage the transition.

The broadcast session state machine (`app/services/broadcast_state_machine.py`) has no concept of a "private" or "paused" state. The valid statuses are: `draft`, `provisioning`, `ready`, `live`, `stopping`, `stopped`, `error`. There is no way to temporarily suspend a live broadcast without fully stopping it, and no mechanism to resume after a private interaction.

The messenger call billing (CALL-011 pay-per-minute) exists as a timer-based billing system, but it is scoped to messenger calls. It has no awareness of broadcast context, no concept of a "minimum rate" set by a creator, and no linkage back to a broadcast session for resumption.

### Why This Is Needed

1. **Premium monetization**: Private sessions are the highest-value interaction a creator can offer. Platforms with private call features report 5-10x higher per-minute revenue compared to broadcast tips or chat tips.

2. **Seamless user experience**: Viewers should be able to request a private session without leaving the broadcast context. The creator should see the request inline and accept/decline without interrupting their flow.

3. **Broadcast continuity**: When a creator goes private, remaining viewers should not be abruptly disconnected. The broadcast should transition gracefully -- either pausing with a holding screen, ending cleanly, or continuing with alternate content.

4. **Creator control**: Creators must set their own minimum per-minute rate, choose how the broadcast behaves during a private session, and have full control over accepting or declining requests.

### Architecture After This Change

```
┌────────────────────────────────────────────────────────────────────────┐
│  Viewer Broadcast Player                                                │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Video Player                                                     │  │
│  │                                                                  │  │
│  │  [Go Private] button visible to viewer                           │  │
│  │                                                                  │  │
│  │  ┌───────────────────────────────────────────────────────┐       │  │
│  │  │ GoPrivateDialog                                       │       │  │
│  │  │                                                       │       │  │
│  │  │  Creator's rate: $5.00/min                            │       │  │
│  │  │  Your offer:     [$  5 .00] /min                      │       │  │
│  │  │  Max duration:   [60] minutes                         │       │  │
│  │  │  Estimated cost: $300.00                              │       │  │
│  │  │                                                       │       │  │
│  │  │  Payment method: [Visa ****4242 ▼]                    │       │  │
│  │  │                                                       │       │  │
│  │  │  [Cancel]  [Send Request]                             │       │  │
│  │  └───────────────────────────────────────────────────────┘       │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘

                 │ POST /broadcast/sessions/{id}/private-request
                 │ { rate_per_minute_cents: 500, payment_method_id: "pm_..." }
                 ▼

┌────────────────────────────────────────────────────────────────────────┐
│  Backend                                                                │
│                                                                         │
│  ┌───── BroadcastSessions table ─────┐  ┌── BroadcastPrivateSessions ──┐│
│  │ PK: session_id                    │  │ PK: BCAST#{session_id}       ││
│  │ status: "live" → "private"        │  │ SK: PRIVATE#{private_id}     ││
│  │ private_session_id: "priv_abc"    │  │ viewer_id: "viewer_sub"      ││
│  │ private_behavior: "pause"         │  │ rate_per_minute_cents: 500   ││
│  └───────────────────────────────────┘  │ status: "requested"          ││
│                                         │ started_at: null             ││
│  SSE fan-out to remaining viewers:      │ ended_at: null               ││
│  "private:broadcast_paused"             │ total_billed_cents: 0        ││
│                                         └──────────────────────────────┘│
│  WebRTC call session created:                                           │
│  Reuses CALL-001..CALL-010 infrastructure                               │
└────────────────────────────────────────────────────────────────────────┘

                 │ SSE event: "private:accepted"
                 ▼

┌────────────────────────────────────────────────────────────────────────┐
│  Creator Dashboard (private session)                                    │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Private Call with viewer_display_name                            │  │
│  │ ┌────────┐  ┌────────┐                                          │  │
│  │ │ Local  │  │ Remote │   Rate: $5.00/min                        │  │
│  │ │ Video  │  │ Video  │   Duration: 04:32                        │  │
│  │ │        │  │        │   Billed: $22.67                          │  │
│  │ └────────┘  └────────┘                                          │  │
│  │                                                                  │  │
│  │  [End Private Session]                                           │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Paused Broadcast (behind the private session):                         │
│  │ "You are in a private session. Your broadcast is paused."           │
│  │ [Resume Broadcast]  (disabled until private session ends)           │
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│  Waiting Viewers                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ┌────────────────────────────────────────────────────────────┐   │  │
│  │ │               Creator is in a private session              │   │  │
│  │ │                     Please wait...                         │   │  │
│  │ │                                                            │   │  │
│  │ │              Chat remains active below                     │   │  │
│  │ └────────────────────────────────────────────────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### Private Request Flow — Sequence Diagram

```
Viewer                  Backend                       Creator (SSE)       Other Viewers (SSE)
  │                       │                               │                     │
  │ POST private-request  │                               │                     │
  │ {rate: 500, pm: ".."}│                               │                     │
  │──────────────────────>│                               │                     │
  │                       │ Validate:                     │                     │
  │                       │ - session live                │                     │
  │                       │ - rate >= min_rate            │                     │
  │                       │ - viewer has valid PM         │                     │
  │                       │ - no pending request          │                     │
  │                       │                               │                     │
  │                       │ DDB: create PRIVATE# item    │                     │
  │                       │ status = "requested"          │                     │
  │                       │                               │                     │
  │                       │───── SSE: private:request ───>│                     │
  │   201 {request_id}    │                               │                     │
  │<──────────────────────│                               │                     │
  │                       │                               │                     │
  │                       │   POST .../accept             │                     │
  │                       │   {behavior: "pause"}         │                     │
  │                       │<──────────────────────────────│                     │
  │                       │                               │                     │
  │                       │ DDB: update PRIVATE# →        │                     │
  │                       │   status = "accepted"         │                     │
  │                       │ DDB: update session →         │                     │
  │                       │   status = "private"          │                     │
  │                       │   private_behavior = "pause"  │                     │
  │                       │                               │                     │
  │                       │── SSE: private:accepted ─────>│                     │
  │                       │── SSE: private:accepted ──────────────────────────>│
  │                       │                               │   (shows holding    │
  │                       │                               │    screen)          │
  │                       │                               │                     │
  │                       │ Create WebRTC call session    │                     │
  │                       │ (reuse CALL-001 infra)        │                     │
  │                       │                               │                     │
  │                       │ Start billing timer            │                     │
  │                       │                               │                     │
  │  ─ ─ ─ WebRTC call in progress ─ ─ ─ ─ ─ ─ ─ ─ ─ >│                     │
  │                       │                               │                     │
  │  POST .../end         │                               │                     │
  │──────────────────────>│                               │                     │
  │                       │ DDB: update PRIVATE# →        │                     │
  │                       │   status = "ended"            │                     │
  │                       │   total_billed_cents          │                     │
  │                       │                               │                     │
  │                       │ Write billing ledger entries  │                     │
  │                       │   DEBIT: viewer               │                     │
  │                       │   CREDIT: creator             │                     │
  │                       │                               │                     │
  │                       │── SSE: private:ended ────────>│                     │
  │                       │                               │                     │
  │                       │   POST .../resume             │                     │
  │                       │<──────────────────────────────│                     │
  │                       │                               │                     │
  │                       │ DDB: update session →         │                     │
  │                       │   status = "live"             │                     │
  │                       │                               │                     │
  │                       │── SSE: private:broadcast_resumed ────────────────>│
  │                       │                               │   (hides holding    │
  │                       │                               │    screen)          │
```

---

## 2. Current State Analysis

### 2.1 Broadcast Session State Machine (`app/services/broadcast_state_machine.py`)

The current valid transitions are:

```
draft → provisioning → ready → live → stopping → stopped
                                 │                   ▲
                                 └──── error ────────┘
```

There is no `private` state. The `validate_transition()` function checks against a hardcoded map of `{from_status: [allowed_to_statuses]}`. Adding a `private` state requires extending this map with:
- `live` -> `private` (going private from a live broadcast)
- `private` -> `live` (resuming broadcast after private session)
- `private` -> `stopping` (stopping broadcast while in private, if creator decides not to resume)

### 2.2 Broadcast Store (`app/services/broadcast_store.py`)

`BroadcastSessionModel` (from `app/models_broadcast.py`) contains: `id`, `profile_id`, `status`, `ingest_url`, `stream_key_ref`, `stream_key_last_rotated_at`, `stream_key_rotation_interval_seconds`, `started_at`, `stopped_at`, `created_by`, `created_at`, `updated_at`. No fields for private session tracking. The `get_session()` function (line 136) fetches by `session_id` PK and returns the model.

### 2.3 Broadcast SSE Infrastructure (`app/services/broadcast_sse.py`)

In-memory pub/sub with `asyncio.Queue` instances (50 lines). `broadcast_sse_publish(session_id, event)` fans out to all subscribers. Dead queues (full, maxsize=100) are discarded. Already used for `chat:message`, `chat:delete`, `chat:mute`, `viewer_count`, `shelf:add`, `shelf:remove`, `shelf:price_update`, `purchase:completed`. New `private:*` event types will use this same infrastructure.

### 2.4 WebRTC Call Infrastructure (CALL-001 through CALL-010)

The messenger call system provides:
- **Signaling**: `app/routers/calls.py` with `POST /messaging/calls/initiate`, `/answer`, `/ice-candidate`, `/hangup`
- **Call records**: Stored in the `MessageCallSessions` DDB table with `PK=call_id` (no sort key), status states: `invited`, `accepted`, `connected`, `ended`, `missed`, `declined`, `busy`, `failed`, `canceled`
- **Recording**: CALL-009/CALL-010 for optional call recording via MediaRecorder API
- **Media**: getUserMedia, RTCPeerConnection, STUN/TURN configuration

The private session will create a call record in the `MessageCallSessions` table. Note that `CallSessionRecord` does not currently have a `broadcast_session_id` field — this field needs to be added to `CallSessionRecord` in `app/services/messaging_call_sessions.py` and to `_item_from_record()`/`_record_from_item()` to link the call back to the broadcast session.

### 2.5 Billing Ledger (`app/services/tip_ledger.py`)

The `write_tip_ledger()` function writes paired debit/credit entries to `T.billing`. The private session billing will follow the same pattern but with `content_type="private_call"` and per-minute rate tracking. The `TipLedgerEntry` class currently only accepts `content_type` values of `"message"`, `"post"`, or `"comment"`. A new billing function specific to private sessions is needed (or extend `TipLedgerEntry` to accept `"private_call"`).

### 2.6 Viewer Count Tracking (`app/services/broadcast_viewers.py`)

`register_viewer()`, `touch_viewer()`, `unregister_viewer()`, `get_viewer_count()` manage viewer presence via DDB with TTL-based expiry (60s). The viewer who goes private should remain "registered" as a viewer (they are still watching the creator, just privately). Viewer count semantics during a private session: the private viewer is one of the viewers, but the broadcast itself is paused. The viewer count SSE event continues to fire for the remaining viewers.

### 2.7 Broadcast Router Structure (`app/routers/broadcast.py`)

The router is currently 1279 lines (after LCOM-001 through LCOM-004 additions):
- Lines 1-61: Imports and router declaration
- Lines 62-163: Pydantic models for profiles, sessions, audit, playback
- Lines 164-568: Core endpoints (CRUD, start/stop, playback, audit, viewers, health, SSE)
- Lines 570-772: Recording endpoints (BCAST-006, BCAST-008)
- Lines 774-1034: Chat endpoints (BCAST-005)
- Lines 1036-1279: Product shelf and pricing endpoints (LCOM-001, LCOM-004)

Private session endpoints will be inserted after the recording section and before chat, around line 773 -- maintaining the logical ordering of broadcast lifecycle features.

### 2.8 Payment Method Validation Pattern

From `app/routers/messaging.py` (locked message unlock flow) and `app/routers/newsfeed.py` (post unlock), the PM validation pattern is:

```python
pm_item = T.billing.get_item(
    Key={"pk": f"USER#{user_id}", "sk": f"PM#{payment_method_id}"}
).get("Item")
if not pm_item:
    raise HTTPException(status_code=400, detail="Payment method not found")
```

The private session request endpoint will use this same pattern to validate the viewer's payment method before creating the request.

---

## 3. Technical Design

### 3.1 Extended Broadcast Session State Machine

Add the `private` state with these transitions:

```
Existing transitions (unchanged):
  draft → provisioning → ready → live → stopping → stopped
                                  │                    ▲
                                  └──── error ─────────┘

New transitions (BCAST-011):
  live → private       (creator accepts a private request)
  private → live       (creator resumes broadcast after private ends)
  private → stopping   (creator stops broadcast entirely during/after private)
```

**File**: `app/services/broadcast_state_machine.py`

Add `"private"` to the valid statuses set and extend the transition map:

```python
# Existing map entry:
"live": ["stopping", "error"],

# Updated:
"live": ["stopping", "error", "private"],

# New entries:
"private": ["live", "stopping"],
```

### 3.2 DynamoDB Model — BroadcastPrivateSession

**Note**: The existing `BroadcastSessions` table has only `session_id` as its partition key and **no sort key**, so it cannot support composite `pk`/`sk` access patterns. Private session items require a new `BroadcastPrivateSessions` table with `pk` (S) as partition key and `sk` (S) as sort key, added to `scripts/local-ddb-init.py`.

New items stored in the new `BroadcastPrivateSessions` table:

| Attribute | Type | Notes |
|-----------|------|-------|
| `pk` | S | `BCAST#{session_id}` (partition key) |
| `sk` | S | `PRIVATE#{private_session_id}` (sort key) |
| `private_session_id` | S | `priv_` + uuid4().hex |
| `session_id` | S | Parent broadcast session ID |
| `viewer_id` | S | Viewer's user_sub |
| `viewer_display_name` | S | Display name at request time |
| `rate_per_minute_cents` | N | Agreed per-minute rate |
| `status` | S | `requested`, `accepted`, `active`, `ended`, `declined`, `cancelled`, `expired` |
| `behavior` | S | `pause`, `end`, `continue` (set on accept) |
| `payment_method_id` | S | Viewer's PM for billing |
| `call_id` | S | Linked WebRTC call ID (set on accept) |
| `max_duration_minutes` | N | Maximum session length (default 60) |
| `requested_at` | N | Unix timestamp |
| `accepted_at` | N | Unix timestamp (null until accepted) |
| `started_at` | N | Unix timestamp (null until WebRTC connected) |
| `ended_at` | N | Unix timestamp (null until ended) |
| `ended_by` | S | `viewer`, `creator`, `timeout`, `system` |
| `total_billed_cents` | N | Final billed amount (0 until ended) |
| `billing_debit_entry_id` | S | Ledger entry ID for viewer debit |
| `billing_credit_entry_id` | S | Ledger entry ID for creator credit |
| `ttl` | N | DDB TTL — 90 days after creation |

**DDB Access Pattern Diagram**:

```
BroadcastPrivateSessions Table (NEW — pk/sk composite key)
┌─────────────────────────────────────────────────────────────────┐
│ PK (pk): BCAST#{session_id}                                     │
│ SK (sk): PRIVATE#{private_session_id}                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  private_session_id  (S)  "priv_abc123def456"                  │
│  session_id          (S)  "sess_xyz789"                        │
│  viewer_id           (S)  "e2e_alice@test.local"               │
│  rate_per_minute_cents (N) 500                                 │
│  status              (S)  "requested" | "accepted" | "active"  │
│                            | "ended" | "declined" | "cancelled"│
│                            | "expired"                          │
│  behavior            (S)  "pause" | "end" | "continue"        │
│  payment_method_id   (S)  "pm_visa_4242"                      │
│  call_id             (S)  "call_abc123" (null until accepted)  │
│  started_at          (N)  null → unix_ts                       │
│  ended_at            (N)  null → unix_ts                       │
│  total_billed_cents  (N)  0 → final amount                     │
│  ttl                 (N)  created_at + 90 days                 │
│                                                                 │
│  Access Patterns:                                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ 1. Query(BCAST#{session_id}, begins_with("PRIVATE#"))   │   │
│  │    → list all private sessions for a broadcast          │   │
│  │ 2. GetItem(BCAST#{session_id}, PRIVATE#{private_id})    │   │
│  │    → get single private session                          │   │
│  │ 3. Query + FilterExpression(status = "requested")       │   │
│  │    → list pending requests for creator                   │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

A new `BroadcastPrivateSessions` DDB table is needed because the existing `BroadcastSessions` table has only `session_id` as its partition key with **no sort key**, and cannot support the composite `pk`/`sk` access pattern required here. The `BroadcastSessions` table stores session items with `session_id` as the primary key and `pk` as a non-key attribute (set by `session_to_item()` to `SESSION#{session_id}`). The new table must be added to `scripts/local-ddb-init.py` and `T.broadcast_private_sessions` added to `app/core/tables.py`.

### 3.3 Private Session State Machine

```
                  ┌──────────────┐
                  │  requested   │
                  └──────┬───┬──┘
                         │   │
              ┌──────────┘   └──────────┐
              ▼                         ▼
     ┌────────────────┐       ┌──────────────────┐
     │   accepted     │       │   declined       │ (terminal)
     └────────┬───────┘       └──────────────────┘
              │
              ▼
     ┌────────────────┐
     │   active       │ ← WebRTC connected, billing starts
     └────────┬───────┘
              │
              ▼
     ┌────────────────┐
     │   ended        │ (terminal — billing finalized)
     └────────────────┘

  Side transitions from "requested":
    requested → cancelled   (viewer cancels before creator responds)
    requested → expired     (creator doesn't respond within 60s timeout)
```

### 3.4 Broadcast Session Fields Extension

Add fields to the broadcast session record (stored on the `BroadcastSessions` table item):

| Attribute | Type | Notes |
|-----------|------|-------|
| `private_session_id` | S | Currently active private session ID (null when not in private) |
| `private_behavior` | S | `pause`, `end`, `continue` — how broadcast behaves during private |
| `private_min_rate_cents` | N | Creator's minimum per-minute rate (set in broadcast settings) |

These are stored as top-level attributes on the existing session DDB item. Note that `transition_session_status()` in `broadcast_store.py` uses `put_item` (full replace), not `update_item`. Any new fields added to the session must be included in `BroadcastSessionModel`, `session_to_item()`, and `session_from_item()` so they survive the full-replace pattern. The DDB key for session items is `{"session_id": session_id}` (not `{"pk": ..., "sk": ...}` — the `pk` field is a non-key attribute).

### 3.5 API Endpoints

#### 3.5.1 Submit Private Request

```
POST /ui/broadcast/sessions/{session_id}/private-request
```

**Auth**: `require_ui_session` — any authenticated viewer.

**Request model**:

```python
class PrivateRequestIn(BaseModel):
    """Request body for a viewer requesting a private session.

    The rate_per_minute_cents must meet or exceed the creator's minimum rate
    (stored as private_min_rate_cents on the session). If the creator has not
    set a minimum rate, the platform default of 100 cents ($1.00/min) applies.
    """
    rate_per_minute_cents: int = Field(..., ge=100, le=10000,
        description="Offered per-minute rate in cents. Must meet creator's minimum.")
    payment_method_id: str = Field(..., min_length=1, max_length=128,
        description="Payment method ID to charge for the session.")
    max_duration_minutes: int = Field(default=60, ge=5, le=120,
        description="Maximum session length in minutes (5-120).")
```

**Response model**:

```python
class PrivateRequestOut(BaseModel):
    request_id: str
    session_id: str
    viewer_id: str
    rate_per_minute_cents: int
    status: str  # "requested"
    max_duration_minutes: int
    requested_at: int
```

**Validation**:

1. Session must exist and be in `live` status.
2. Caller must NOT be the session creator (creators cannot request private sessions with themselves).
3. Rate must meet or exceed `session.private_min_rate_cents` (default 100 if not set).
4. Payment method must exist in `T.billing` under `USER#{viewer_id}`.
5. No existing `requested` or `active` private session for this broadcast (one at a time).

**Error responses**:

| Code | Condition | Error Detail |
|------|-----------|-------------|
| 400 | Rate below creator's minimum | `"Rate must be at least {min_rate} cents per minute."` |
| 400 | Invalid payment method | `"Payment method not found."` |
| 403 | Session not live | `"Private requests are only available during live broadcasts."` |
| 403 | Creator requesting own private | `"Cannot request a private session on your own broadcast."` |
| 409 | Existing pending/active private session | `"A private session is already in progress or pending."` |

#### 3.5.2 List Pending Private Requests

```
GET /ui/broadcast/sessions/{session_id}/private-requests
```

**Auth**: `require_ui_session` — only session creator.

**Response model**:

```python
class PrivateRequestListOut(BaseModel):
    requests: List[PrivateRequestOut] = Field(default_factory=list)
```

**Behavior**: Queries `BCAST#{session_id}` with `begins_with("PRIVATE#")` and filters for `status == "requested"`. Returns requests sorted by `requested_at` ascending (oldest first).

#### 3.5.3 Accept Private Request

```
POST /ui/broadcast/sessions/{session_id}/private-requests/{request_id}/accept
```

**Auth**: `require_ui_session` — only session creator.

**Request model**:

```python
class PrivateRequestAcceptIn(BaseModel):
    """Creator's response when accepting a private request.

    The behavior field determines what happens to the public broadcast:
    - "pause": Show holding screen, broadcast resumes when private ends
    - "end": Stop broadcast entirely, viewers notified
    - "continue": Broadcast continues (e.g., with co-host or recorded content)
    """
    behavior: str = Field(..., pattern="^(pause|end|continue)$",
        description="How the broadcast should behave during the private session.")
```

**Behavior**:

1. Validate the request exists and is in `requested` status.
2. Update private session status to `accepted`.
3. Transition broadcast session status from `live` to `private` (via state machine).
4. Store `private_session_id` and `private_behavior` on the session record.
5. If behavior is `"end"`: trigger stop_session_with_provider to fully stop the broadcast.
6. If behavior is `"pause"`: broadcast SSE publishes `private:broadcast_paused` to remaining viewers.
7. If behavior is `"continue"`: no broadcast state change for viewers (broadcast stays "live" conceptually).
8. Create a WebRTC call record in the `MessageCallSessions` table (via `create_call_session()` from `app/services/messaging_call_sessions.py`), with the new `broadcast_session_id` field linking it to the broadcast session.
9. Publish `private:accepted` SSE event to the requesting viewer (includes call signaling details).

**Response model**:

```python
class PrivateAcceptOut(BaseModel):
    private_session_id: str
    session_id: str
    status: str  # "accepted"
    behavior: str
    call_id: str
    rate_per_minute_cents: int
```

#### 3.5.4 Decline Private Request

```
POST /ui/broadcast/sessions/{session_id}/private-requests/{request_id}/decline
```

**Auth**: `require_ui_session` — only session creator.

**Behavior**:

1. Update private session status to `declined`.
2. Publish `private:declined` SSE event to the requesting viewer.
3. No broadcast state change.

**Response**: `{"ok": true, "request_id": "..."}`

#### 3.5.5 Cancel Private Request (Viewer)

```
POST /ui/broadcast/sessions/{session_id}/private-requests/{request_id}/cancel
```

**Auth**: `require_ui_session` — only the requesting viewer.

**Behavior**: Updates status from `requested` to `cancelled`. Only valid while status is `requested`.

**Response**: `{"ok": true, "request_id": "..."}`

#### 3.5.6 End Private Session

```
POST /ui/broadcast/sessions/{session_id}/private/{private_id}/end
```

**Auth**: `require_ui_session` — either the viewer or the creator.

**Behavior**:

1. Validate private session exists and is in `active` status.
2. Calculate `total_billed_cents` from elapsed time and `rate_per_minute_cents` (rounded up to nearest minute).
3. Update private session status to `ended` with `ended_at`, `ended_by`, `total_billed_cents`.
4. Write billing ledger entries (debit viewer, credit creator) using the pattern from `app/services/tip_ledger.py`.
5. Terminate the WebRTC call (hangup signal).
6. Clear `private_session_id` from the broadcast session record.
7. Publish `private:ended` SSE event to both parties.

**Response model**:

```python
class PrivateSessionEndOut(BaseModel):
    private_session_id: str
    session_id: str
    status: str  # "ended"
    duration_seconds: int
    total_billed_cents: int
    ended_by: str
```

#### 3.5.7 Resume Broadcast

```
POST /ui/broadcast/sessions/{session_id}/resume
```

**Auth**: `require_ui_session` — only session creator.

**Behavior**:

1. Validate session is in `private` status and no active private session remains.
2. Transition session status from `private` to `live` (via state machine).
3. Clear `private_behavior` from session record.
4. Publish `private:broadcast_resumed` SSE event to all subscribers.
5. Viewers see the holding screen disappear and broadcast video resume.

**Response**: The updated `BroadcastSessionOut`.

**Error responses**:

| Code | Condition | Error Detail |
|------|-----------|-------------|
| 403 | Caller is not session creator | `"Only the broadcaster can resume the broadcast."` |
| 409 | Session not in private status | `"Broadcast is not in private mode."` |
| 409 | Active private session still in progress | `"Private session is still active. End it first."` |

### 3.6 Service Layer — `app/services/broadcast_private.py`

New service file (~250 lines) for private session business logic.

```python
"""Broadcast private session service — manages 1-on-1 paid call sessions during broadcasts."""

from __future__ import annotations

import logging
import math
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger("broadcast.private")

DEFAULT_MIN_RATE_CENTS = 100  # $1.00/min platform default
REQUEST_EXPIRY_SECONDS = 60  # Requests expire if creator doesn't respond in 60s


def create_private_request(
    session_id: str,
    viewer_id: str,
    viewer_display_name: str,
    rate_per_minute_cents: int,
    payment_method_id: str,
    max_duration_minutes: int = 60,
    *,
    min_rate_cents: int = DEFAULT_MIN_RATE_CENTS,
) -> Dict[str, Any]:
    """Create a private session request from a viewer.

    Args:
        session_id: The broadcast session ID.
        viewer_id: The viewer's user_sub.
        viewer_display_name: Viewer's display name.
        rate_per_minute_cents: Offered per-minute rate.
        payment_method_id: Viewer's payment method ID.
        max_duration_minutes: Maximum session length.
        min_rate_cents: Creator's minimum rate (from session settings).

    Returns:
        Dict with request details suitable for API response.

    Raises:
        HTTPException(400) if rate is below minimum.
        HTTPException(409) if a private session is already pending or active.
    """
    if rate_per_minute_cents < min_rate_cents:
        raise HTTPException(
            status_code=400,
            detail=f"Rate must be at least {min_rate_cents} cents per minute.",
        )

    # Check for existing pending/active private sessions
    existing = _get_active_or_pending(session_id)
    if existing:
        raise HTTPException(
            status_code=409,
            detail="A private session is already in progress or pending.",
        )

    ts = now_ts()
    private_id = f"priv_{uuid.uuid4().hex}"

    item = {
        "pk": f"BCAST#{session_id}",
        "sk": f"PRIVATE#{private_id}",
        "private_session_id": private_id,
        "session_id": session_id,
        "viewer_id": viewer_id,
        "viewer_display_name": viewer_display_name,
        "rate_per_minute_cents": rate_per_minute_cents,
        "payment_method_id": payment_method_id,
        "max_duration_minutes": max_duration_minutes,
        "status": "requested",
        "requested_at": ts,
        "accepted_at": None,
        "started_at": None,
        "ended_at": None,
        "ended_by": None,
        "total_billed_cents": 0,
        "call_id": None,
        "behavior": None,
        "ttl": ts + 90 * 24 * 3600,
    }
    # Remove None values (DDB cannot store None for non-map attributes)
    item = {k: v for k, v in item.items() if v is not None}
    T.broadcast_private_sessions.put_item(Item=item)

    logger.info(
        "broadcast.private.requested session_id=%s viewer=%s rate=%d",
        session_id, viewer_id, rate_per_minute_cents,
    )

    return _private_session_out(item)


def list_pending_requests(session_id: str) -> List[Dict[str, Any]]:
    """List pending private requests for a broadcast session."""
    resp = T.broadcast_private_sessions.query(
        KeyConditionExpression=(
            Key("pk").eq(f"BCAST#{session_id}")
            & Key("sk").begins_with("PRIVATE#")
        ),
        FilterExpression=Attr("status").eq("requested"),
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: int(x.get("requested_at", 0)))
    return [_private_session_out(i) for i in items]


def accept_private_request(
    session_id: str,
    private_session_id: str,
    behavior: str,
    call_id: str,
) -> Dict[str, Any]:
    """Accept a private session request.

    Args:
        session_id: The broadcast session ID.
        private_session_id: The private session request ID.
        behavior: "pause", "end", or "continue".
        call_id: The newly created WebRTC call ID.

    Returns:
        Dict with accepted session details.

    Raises:
        HTTPException(404) if request not found.
        HTTPException(409) if request is not in "requested" status.
    """
    item = _get_private_session(session_id, private_session_id)
    if not item:
        raise HTTPException(status_code=404, detail="Private request not found.")
    if item.get("status") != "requested":
        raise HTTPException(status_code=409, detail="Request is no longer pending.")

    ts = now_ts()
    T.broadcast_private_sessions.update_item(
        Key={"pk": f"BCAST#{session_id}", "sk": f"PRIVATE#{private_session_id}"},
        UpdateExpression=(
            "SET #st = :status, accepted_at = :at, behavior = :beh, call_id = :cid"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":status": "accepted",
            ":at": ts,
            ":beh": behavior,
            ":cid": call_id,
        },
    )

    logger.info(
        "broadcast.private.accepted session_id=%s private_id=%s behavior=%s",
        session_id, private_session_id, behavior,
    )

    item.update({"status": "accepted", "accepted_at": ts, "behavior": behavior, "call_id": call_id})
    return _private_session_out(item)


def activate_private_session(session_id: str, private_session_id: str) -> Dict[str, Any]:
    """Mark a private session as active (WebRTC connected, billing starts).

    Called when the WebRTC call reaches "connected" state.
    """
    ts = now_ts()
    T.broadcast_private_sessions.update_item(
        Key={"pk": f"BCAST#{session_id}", "sk": f"PRIVATE#{private_session_id}"},
        UpdateExpression="SET #st = :status, started_at = :sa",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":status": "active", ":sa": ts},
    )
    item = _get_private_session(session_id, private_session_id)
    return _private_session_out(item) if item else {}


def end_private_session(
    session_id: str,
    private_session_id: str,
    ended_by: str,
) -> Dict[str, Any]:
    """End an active private session. Calculate and write billing.

    Args:
        session_id: The broadcast session ID.
        private_session_id: The private session ID.
        ended_by: Who ended it ("viewer", "creator", "timeout", "system").

    Returns:
        Dict with final session details including billing.

    Raises:
        HTTPException(404) if session not found.
        HTTPException(409) if session is not in "active" status.
    """
    item = _get_private_session(session_id, private_session_id)
    if not item:
        raise HTTPException(status_code=404, detail="Private session not found.")
    if item.get("status") != "active":
        raise HTTPException(status_code=409, detail="Private session is not active.")

    ts = now_ts()
    started_at = int(item.get("started_at", ts))
    duration_seconds = max(0, ts - started_at)
    rate = int(item.get("rate_per_minute_cents", 0))

    # Bill rounded up to nearest minute (minimum 1 minute)
    billed_minutes = max(1, math.ceil(duration_seconds / 60))
    total_billed_cents = billed_minutes * rate

    # Cap at max duration billing
    max_mins = int(item.get("max_duration_minutes", 60))
    total_billed_cents = min(total_billed_cents, max_mins * rate)

    # Write billing ledger entries
    debit_id, credit_id = _write_private_billing(
        viewer_id=item["viewer_id"],
        creator_id=_get_session_creator(session_id),
        amount_cents=total_billed_cents,
        private_session_id=private_session_id,
        session_id=session_id,
        payment_method_id=item.get("payment_method_id", ""),
    )

    T.broadcast_private_sessions.update_item(
        Key={"pk": f"BCAST#{session_id}", "sk": f"PRIVATE#{private_session_id}"},
        UpdateExpression=(
            "SET #st = :status, ended_at = :ea, ended_by = :eb, "
            "total_billed_cents = :tbc, billing_debit_entry_id = :did, "
            "billing_credit_entry_id = :cid"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":status": "ended",
            ":ea": ts,
            ":eb": ended_by,
            ":tbc": total_billed_cents,
            ":did": debit_id,
            ":cid": credit_id,
        },
    )

    logger.info(
        "broadcast.private.ended session_id=%s private_id=%s duration=%ds billed=%d",
        session_id, private_session_id, duration_seconds, total_billed_cents,
    )

    return {
        "private_session_id": private_session_id,
        "session_id": session_id,
        "status": "ended",
        "duration_seconds": duration_seconds,
        "total_billed_cents": total_billed_cents,
        "ended_by": ended_by,
    }


def decline_private_request(session_id: str, private_session_id: str) -> bool:
    """Decline a pending private request. Returns True if found and declined."""
    item = _get_private_session(session_id, private_session_id)
    if not item or item.get("status") != "requested":
        return False

    T.broadcast_private_sessions.update_item(
        Key={"pk": f"BCAST#{session_id}", "sk": f"PRIVATE#{private_session_id}"},
        UpdateExpression="SET #st = :status",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":status": "declined"},
    )
    return True


def cancel_private_request(session_id: str, private_session_id: str, viewer_id: str) -> bool:
    """Cancel a pending private request (viewer-initiated). Returns True if successful."""
    item = _get_private_session(session_id, private_session_id)
    if not item or item.get("status") != "requested":
        return False
    if item.get("viewer_id") != viewer_id:
        return False

    T.broadcast_private_sessions.update_item(
        Key={"pk": f"BCAST#{session_id}", "sk": f"PRIVATE#{private_session_id}"},
        UpdateExpression="SET #st = :status",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":status": "cancelled"},
    )
    return True


# ─── Internal Helpers ────────────────────────────────────────────

def _get_private_session(session_id: str, private_session_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single private session item from DDB."""
    return T.broadcast_private_sessions.get_item(
        Key={"pk": f"BCAST#{session_id}", "sk": f"PRIVATE#{private_session_id}"}
    ).get("Item")


def _get_active_or_pending(session_id: str) -> Optional[Dict[str, Any]]:
    """Check if there is an active or pending private session for this broadcast."""
    resp = T.broadcast_private_sessions.query(
        KeyConditionExpression=(
            Key("pk").eq(f"BCAST#{session_id}")
            & Key("sk").begins_with("PRIVATE#")
        ),
        FilterExpression=Attr("status").is_in(["requested", "accepted", "active"]),
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def _get_session_creator(session_id: str) -> str:
    """Get the creator user_sub for a broadcast session."""
    from app.services.broadcast_store import get_session
    session = get_session(session_id)
    return session.created_by


def _write_private_billing(
    viewer_id: str,
    creator_id: str,
    amount_cents: int,
    private_session_id: str,
    session_id: str,
    payment_method_id: str,
) -> tuple[str, str]:
    """Write paired debit/credit billing ledger entries for a private session.

    Returns (debit_entry_id, credit_entry_id).
    """
    import uuid as _uuid

    ts = now_ts()
    debit_id = _uuid.uuid4().hex
    credit_id = _uuid.uuid4().hex
    reason = "Private session"
    meta = {
        "content_type": "private_call",
        "private_session_id": private_session_id,
        "session_id": session_id,
        "viewer_id": viewer_id,
        "creator_id": creator_id,
        "payment_method_id": payment_method_id,
    }

    try:
        T.billing.put_item(Item={
            "pk": f"USER#{viewer_id}",
            "sk": f"LEDGER#{ts}#{debit_id}",
            "entry_id": debit_id,
            "ts": ts,
            "type": "debit",
            "amount_cents": amount_cents,
            "currency": "USD",
            "state": "settled",
            "reason": reason,
            "meta": meta,
        })
    except Exception:
        logger.warning("private_billing_debit_failed viewer=%s amount=%d", viewer_id, amount_cents)

    try:
        T.billing.put_item(Item={
            "pk": f"USER#{creator_id}",
            "sk": f"LEDGER#{ts}#{credit_id}",
            "entry_id": credit_id,
            "ts": ts,
            "type": "credit",
            "amount_cents": amount_cents,
            "currency": "USD",
            "state": "settled",
            "reason": reason,
            "meta": meta,
        })
    except Exception:
        logger.warning("private_billing_credit_failed creator=%s amount=%d", creator_id, amount_cents)

    return debit_id, credit_id


def _private_session_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert DDB item to output dict with Decimal-to-int coercion."""
    return {
        "request_id": item.get("private_session_id", ""),
        "private_session_id": item.get("private_session_id", ""),
        "session_id": item.get("session_id", ""),
        "viewer_id": item.get("viewer_id", ""),
        "viewer_display_name": item.get("viewer_display_name", ""),
        "rate_per_minute_cents": int(item.get("rate_per_minute_cents", 0)),
        "status": item.get("status", ""),
        "behavior": item.get("behavior"),
        "call_id": item.get("call_id"),
        "max_duration_minutes": int(item.get("max_duration_minutes", 60)),
        "requested_at": int(item.get("requested_at", 0)),
        "accepted_at": int(item["accepted_at"]) if item.get("accepted_at") else None,
        "started_at": int(item["started_at"]) if item.get("started_at") else None,
        "ended_at": int(item["ended_at"]) if item.get("ended_at") else None,
        "ended_by": item.get("ended_by"),
        "total_billed_cents": int(item.get("total_billed_cents", 0)),
    }
```

### 3.7 SSE Events

| Event Type | Payload | Trigger | Recipients |
|------------|---------|---------|------------|
| `private:request` | `{viewer_id, viewer_display_name, rate_per_minute_cents, request_id}` | Viewer sends private request | Creator only (via targeted SSE or filtered client-side) |
| `private:accepted` | `{private_session_id, behavior, call_id, viewer_id}` | Creator accepts request | Requesting viewer + all viewers (for holding screen) |
| `private:declined` | `{request_id}` | Creator declines request | Requesting viewer |
| `private:cancelled` | `{request_id}` | Viewer cancels request | Creator |
| `private:broadcast_paused` | `{session_id, message: "Creator is in a private session"}` | Behavior is "pause" and creator accepts | All remaining viewers |
| `private:ended` | `{private_session_id, duration_seconds, total_billed_cents}` | Private session ends | Both parties |
| `private:broadcast_resumed` | `{session_id}` | Creator resumes after private | All viewers |

SSE delivery uses the existing `broadcast_sse_publish(session_id, event)` infrastructure. All events are published to the same session-scoped channel. Client-side filtering determines who sees what (e.g., the requesting viewer checks `event.viewer_id === myUserId` before showing acceptance UI).

### 3.8 Max Duration Auto-Timeout

A background asyncio task monitors active private sessions. When `started_at + max_duration_minutes * 60 < now_ts()`, the session is automatically ended with `ended_by="timeout"`. This uses the same background loop pattern as scheduled message delivery in `app/routers/messaging.py`.

```python
async def _private_session_timeout_loop():
    """Background task that checks for expired private sessions every 30 seconds."""
    while True:
        await asyncio.sleep(30)
        try:
            # Scan for active private sessions past their max duration
            # In production, this would use a GSI. For dev, scan is acceptable.
            _check_and_timeout_expired_sessions()
        except Exception:
            logger.exception("private_session_timeout_loop_error")
```

### 3.9 Frontend — Go Private Button and Dialog

```typescript
// frontend/src/pages/broadcast/GoPrivateButton.tsx

/**
 * GoPrivateButton — viewer-facing button to request a private session.
 *
 * Displayed in the broadcast player controls when the session is live.
 * Opens a dialog where the viewer enters their offered rate, selects
 * a payment method, and sends the request.
 *
 * Hidden when:
 * - Viewer is the broadcaster (cannot request private on own stream)
 * - Session is not live
 * - A private session is already pending or active
 *
 * React Query integration:
 * - requestMutation calls POST /broadcast/sessions/{id}/private-request
 * - On success: shows "Request sent" toast, disables button
 * - On SSE private:accepted: navigates to private call view
 * - On SSE private:declined: shows "Request declined" toast, re-enables button
 */
```

### 3.10 Frontend — Private Session View

```typescript
// frontend/src/pages/broadcast/PrivateSessionView.tsx

/**
 * PrivateSessionView — full-screen video call interface for the private session.
 *
 * Reuses the WebRTC media components from the messenger call system:
 * - LocalVideoPreview (local camera feed)
 * - RemoteVideoPlayer (remote peer feed)
 * - CallControls (mute, camera toggle, end call)
 *
 * Additional UI elements:
 * - Billing timer showing elapsed time, per-minute rate, running total
 * - "End Session" button (prominent, red)
 * - Warning at 5 minutes remaining (if max duration set)
 *
 * Billing display updates every second via local timer (not SSE).
 */
```

### 3.11 Frontend — Holding Screen

```typescript
// frontend/src/pages/broadcast/PrivateHoldingScreen.tsx

/**
 * PrivateHoldingScreen — displayed to remaining viewers when broadcast is paused.
 *
 * Shows:
 * - "Creator is in a private session" message
 * - "Please wait..." subtitle
 * - Optional: chat panel remains active below
 * - Animated waiting indicator
 *
 * Listens for SSE private:broadcast_resumed event to auto-dismiss.
 */
```

### 3.12 Frontend Component Hierarchy

```
LivePlayer (viewer)
├── MediaPlayer (video)
│   └── PrivateHoldingScreen (overlay, shown when session.status === "private")
├── BroadcastControls
│   └── GoPrivateButton                    ← NEW (BCAST-011)
│       └── GoPrivateDialog                ← NEW
│           ├── RateInput
│           ├── PaymentMethodSelector
│           ├── DurationSelector
│           └── RequestButton
├── ProductShelfPanel
├── BroadcastChat
└── ChatOverlay

BroadcasterDashboard
├── SessionControls
│   └── PrivateRequestNotification         ← NEW (BCAST-011)
│       ├── ViewerInfo (name, rate offered)
│       ├── BehaviorSelect (pause/end/continue)
│       ├── AcceptButton
│       └── DeclineButton
├── PrivateSessionView                     ← NEW (replaces main view during private)
│   ├── LocalVideoPreview
│   ├── RemoteVideoPlayer
│   ├── BillingTimer
│   ├── CallControls
│   └── EndSessionButton
├── ProductShelfManager
└── ChatModeration
```

---

## 4. Implementation Plan

### Phase 1: Backend — State Machine Extension + DDB Model (1 day)

| File | Change | Lines Changed |
|------|--------|---------------|
| `app/services/broadcast_state_machine.py` | Add `private` to valid statuses. Add `live → private`, `private → live`, `private → stopping` transitions. | +5 |
| `app/services/broadcast_store.py` | Add `private_session_id`, `private_behavior`, `private_min_rate_cents` to `BroadcastSessionModel`, `session_to_item()`, and `session_from_item()` (required because `transition_session_status()` uses `put_item` full replace). | +20 |
| `scripts/local-ddb-init.py` | Add `BroadcastPrivateSessions` table with `pk` (S) partition key and `sk` (S) sort key. | +8 |
| `app/core/tables.py` | Add `broadcast_private_sessions` table handle. | +2 |
| `app/services/messaging_call_sessions.py` | Add `broadcast_session_id` field to `CallSessionRecord`, `_item_from_record()`, `_record_from_item()`. | +6 |

### Phase 2: Backend — Private Session Service (2 days)

| File | Change | Lines Changed |
|------|--------|---------------|
| `app/services/broadcast_private.py` | New service file. `create_private_request()` (~50 lines), `list_pending_requests()` (~15 lines), `accept_private_request()` (~40 lines), `activate_private_session()` (~15 lines), `end_private_session()` (~60 lines), `decline_private_request()` (~15 lines), `cancel_private_request()` (~15 lines), `_write_private_billing()` (~40 lines), helpers (~30 lines). | ~280 |

### Phase 3: Backend — Router Endpoints (1.5 days)

| File | Change | Lines Changed |
|------|--------|---------------|
| `app/routers/broadcast.py` | Add Pydantic models (~60 lines): `PrivateRequestIn`, `PrivateRequestOut`, `PrivateRequestAcceptIn`, `PrivateAcceptOut`, `PrivateSessionEndOut`, `PrivateRequestListOut`. Add 7 endpoint functions (~180 lines): submit, list, accept, decline, cancel, end, resume. Insert before chat section. Register background timeout task in startup. | +240 |
| `app/main.py` | Register background timeout task for private session expiry. | +5 |

### Phase 4: Frontend — Go Private Dialog + Request Flow (1.5 days)

| File | Type | Lines |
|------|------|-------|
| `frontend/src/pages/broadcast/GoPrivateButton.tsx` | Create — button + dialog with rate input, PM selector, duration dropdown, request mutation | ~180 |
| `frontend/src/pages/broadcast/PrivateHoldingScreen.tsx` | Create — overlay for waiting viewers with animated indicator | ~60 |
| `frontend/src/api/endpoints/broadcast-private.ts` | Create — API endpoint wrappers for all 7 private session endpoints | ~80 |

### Phase 5: Frontend — Private Session View + Billing Timer (1.5 days)

| File | Type | Lines |
|------|------|-------|
| `frontend/src/pages/broadcast/PrivateSessionView.tsx` | Create — video call UI with billing timer, reuses call components | ~200 |
| `frontend/src/pages/broadcast/PrivateRequestNotification.tsx` | Create — creator-side notification for incoming private requests | ~120 |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Modify — handle `private:*` SSE events, show holding screen, transition to private view | +40 |

### Summary of All Files

| File | Type | Estimated Lines |
|------|------|-----------------|
| `app/services/broadcast_state_machine.py` | Modify | +5 |
| `app/services/broadcast_store.py` | Modify | +20 |
| `app/services/messaging_call_sessions.py` | Modify | +6 |
| `scripts/local-ddb-init.py` | Modify | +8 |
| `app/core/tables.py` | Modify | +2 |
| `app/services/broadcast_private.py` | Create | ~280 |
| `app/routers/broadcast.py` | Modify | +240 |
| `app/main.py` | Modify | +5 |
| `frontend/src/api/endpoints/broadcast-private.ts` | Create | ~80 |
| `frontend/src/pages/broadcast/GoPrivateButton.tsx` | Create | ~180 |
| `frontend/src/pages/broadcast/PrivateHoldingScreen.tsx` | Create | ~60 |
| `frontend/src/pages/broadcast/PrivateSessionView.tsx` | Create | ~200 |
| `frontend/src/pages/broadcast/PrivateRequestNotification.tsx` | Create | ~120 |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Modify | +40 |
| **Total** | | **~1230** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_broadcast_private.py`)

New file, ~350 lines, using `moto` for DynamoDB mocking.

```python
import pytest
from moto import mock_dynamodb
from app.services.broadcast_private import (
    create_private_request,
    list_pending_requests,
    accept_private_request,
    end_private_session,
    decline_private_request,
    cancel_private_request,
    activate_private_session,
)


def test_create_request_stores_item_with_requested_status(broadcast_table):
    """Creating a private request stores a DDB item with status='requested'."""
    result = create_private_request(
        session_id="sess_1", viewer_id="alice", viewer_display_name="Alice",
        rate_per_minute_cents=500, payment_method_id="pm_123",
    )
    assert result["status"] == "requested"
    assert result["rate_per_minute_cents"] == 500
    assert result["viewer_id"] == "alice"


def test_create_request_rejects_rate_below_minimum(broadcast_table):
    """Request with rate below creator's minimum is rejected with 400."""
    with pytest.raises(Exception) as exc_info:
        create_private_request(
            session_id="sess_1", viewer_id="alice", viewer_display_name="Alice",
            rate_per_minute_cents=50, payment_method_id="pm_123",
            min_rate_cents=100,
        )
    assert "400" in str(exc_info.value.status_code)


def test_create_request_rejects_duplicate_pending(broadcast_table):
    """Second request while one is pending returns 409."""
    create_private_request(
        session_id="sess_1", viewer_id="alice", viewer_display_name="Alice",
        rate_per_minute_cents=500, payment_method_id="pm_123",
    )
    with pytest.raises(Exception) as exc_info:
        create_private_request(
            session_id="sess_1", viewer_id="bob", viewer_display_name="Bob",
            rate_per_minute_cents=600, payment_method_id="pm_456",
        )
    assert "409" in str(exc_info.value.status_code)


def test_list_pending_returns_only_requested(broadcast_table):
    """list_pending_requests returns only items with status='requested'."""
    create_private_request(
        session_id="sess_1", viewer_id="alice", viewer_display_name="Alice",
        rate_per_minute_cents=500, payment_method_id="pm_123",
    )
    requests = list_pending_requests("sess_1")
    assert len(requests) == 1
    assert requests[0]["status"] == "requested"


def test_accept_transitions_to_accepted(broadcast_table):
    """Accepting a request transitions status to 'accepted'."""
    req = create_private_request(
        session_id="sess_1", viewer_id="alice", viewer_display_name="Alice",
        rate_per_minute_cents=500, payment_method_id="pm_123",
    )
    result = accept_private_request("sess_1", req["private_session_id"], "pause", "call_1")
    assert result["status"] == "accepted"
    assert result["behavior"] == "pause"
    assert result["call_id"] == "call_1"


def test_decline_transitions_to_declined(broadcast_table):
    """Declining a request transitions status to 'declined'."""
    req = create_private_request(
        session_id="sess_1", viewer_id="alice", viewer_display_name="Alice",
        rate_per_minute_cents=500, payment_method_id="pm_123",
    )
    assert decline_private_request("sess_1", req["private_session_id"]) is True
    # Verify no longer pending
    assert len(list_pending_requests("sess_1")) == 0


def test_cancel_only_allowed_by_requester(broadcast_table):
    """Cancel fails if caller is not the original requester."""
    req = create_private_request(
        session_id="sess_1", viewer_id="alice", viewer_display_name="Alice",
        rate_per_minute_cents=500, payment_method_id="pm_123",
    )
    assert cancel_private_request("sess_1", req["private_session_id"], "bob") is False
    assert cancel_private_request("sess_1", req["private_session_id"], "alice") is True


def test_end_session_calculates_billing(broadcast_table, billing_table):
    """Ending a session calculates total_billed_cents from duration and rate."""
    req = create_private_request(
        session_id="sess_1", viewer_id="alice", viewer_display_name="Alice",
        rate_per_minute_cents=500, payment_method_id="pm_123",
    )
    accept_private_request("sess_1", req["private_session_id"], "pause", "call_1")
    activate_private_session("sess_1", req["private_session_id"])
    # Simulate time passing -- in real test, mock now_ts
    result = end_private_session("sess_1", req["private_session_id"], "viewer")
    assert result["status"] == "ended"
    assert result["total_billed_cents"] >= 500  # At least 1 minute billed


def test_end_session_writes_billing_ledger(broadcast_table, billing_table):
    """Ending a private session writes debit and credit ledger entries."""
    req = create_private_request(
        session_id="sess_1", viewer_id="alice", viewer_display_name="Alice",
        rate_per_minute_cents=500, payment_method_id="pm_123",
    )
    accept_private_request("sess_1", req["private_session_id"], "pause", "call_1")
    activate_private_session("sess_1", req["private_session_id"])
    end_private_session("sess_1", req["private_session_id"], "creator")
    # Verify ledger entries exist for alice (debit) and creator (credit)
    # Query T.billing for USER#alice LEDGER# entries
```

### 5.2 E2E Tests (`frontend/e2e/broadcast-private.spec.ts`)

New file, ~400 lines.

**Section 123: Private Request Flow (5 tests)**:

1. `Viewer submits private request with valid rate and PM`
   - Create broadcast session, set to live
   - Viewer sends POST private-request with rate=500
   - Assert 201 response with status="requested"

2. `Request rejected when rate is below creator minimum`
   - Set session private_min_rate_cents=1000
   - Viewer requests with rate=500
   - Assert 400 response

3. `Creator sees pending request and accepts with "pause" behavior`
   - Submit request, creator lists pending requests
   - Creator accepts with behavior="pause"
   - Assert private session status="accepted"
   - Assert broadcast session status transitions to "private"

4. `Creator declines private request`
   - Submit request, creator declines
   - Assert private session status="declined"
   - Assert broadcast session remains "live"

5. `Viewer cancels pending request`
   - Submit request, viewer cancels before creator responds
   - Assert private session status="cancelled"

**Section 124: Private Session Billing (4 tests)**:

1. `Active private session ends with correct billing calculation`
   - Accept and activate a private session at $5.00/min
   - End after simulated duration
   - Assert total_billed_cents = ceil(duration/60) * 500

2. `Billing ledger debit written for viewer`
   - End a private session
   - Query billing table for viewer
   - Assert LEDGER entry with type="debit", reason="Private session"

3. `Billing ledger credit written for creator`
   - End a private session
   - Query billing table for creator
   - Assert LEDGER entry with type="credit", meta.content_type="private_call"

4. `Creator resumes broadcast after private session ends`
   - End private session, creator calls POST .../resume
   - Assert broadcast session status transitions back to "live"

---

## 6. Security Considerations

### 6.1 Authentication & Authorization

- All private session endpoints require `require_ui_session` (cookie auth with CSRF, or Bearer token).
- **Request endpoint**: Any authenticated viewer except the session creator.
- **Accept/Decline/List endpoints**: Only the session creator.
- **Cancel endpoint**: Only the original requesting viewer.
- **End endpoint**: Either the viewer or the creator (both parties can end).
- **Resume endpoint**: Only the session creator.

### 6.2 Payment Validation

- The viewer's `payment_method_id` is validated against `T.billing` at request time.
- If the PM is deleted between request and session end, billing writes will still succeed (they debit the user, not charge the PM directly -- the PM reference is metadata only in the current ledger pattern).

### 6.3 Rate Abuse Prevention

- Only one pending or active private session per broadcast at a time (enforced by `_get_active_or_pending` check).
- Requests have a 60-second expiry timeout. Unclaimed requests are automatically marked `expired`.
- Maximum session duration is capped at 120 minutes (`max_duration_minutes` field, validated `le=120`).
- Minimum rate is 100 cents ($1.00/min) platform-wide, creator can set higher.

### 6.4 Data Privacy

- Private session records include viewer_id and creator_id. These are user identifiers, not PII.
- No video/audio content is stored by the private session system. Call recording (CALL-009) is a separate opt-in feature.
- Private session metadata (rate, duration, billing) is accessible only to the two parties involved.

---

## 7. Migration & Rollback Plan

### 7.1 Schema Changes

- **State machine**: Add `private` to allowed statuses. This is backward-compatible -- existing sessions in non-private states are unaffected.
- **DDB**: A new `BroadcastPrivateSessions` table is required (with `pk`/`sk` composite key), added to `scripts/local-ddb-init.py` and `app/core/tables.py`. The existing `BroadcastSessions` table has only `session_id` as PK (no SK) and cannot support the composite key pattern.
- **Session fields**: New optional fields (`private_session_id`, `private_behavior`, `private_min_rate_cents`) on session items. These must be added to `BroadcastSessionModel`, `session_to_item()`, and `session_from_item()` because `transition_session_status()` uses `put_item` (full replace). Existing sessions without these fields continue to work -- they default to `None`/`0`.

### 7.2 Rollback Steps

1. Revert code changes (restore original state machine transitions, remove private endpoints).
2. Delete `app/services/broadcast_private.py`.
3. Sessions in `private` status would need manual intervention -- update them to `live` or `stopped` via DDB console.
4. Private session DDB items in the `BroadcastPrivateSessions` table can be left in place (TTL will expire them in 90 days) or batch-deleted.

### 7.3 Feature Flag

Optional: `BROADCAST_PRIVATE_ENABLED` environment variable (default `true`). When `false`, the `GoPrivateButton` is hidden and the request endpoint returns 503.

---

## 8. Acceptance Criteria

1. A viewer can submit a private session request during a live broadcast.
2. The request includes a per-minute rate that meets the creator's minimum.
3. The creator sees pending requests and can accept or decline.
4. On accept with "pause" behavior, remaining viewers see a holding screen.
5. A WebRTC video call is established between the viewer and creator.
6. Billing accrues per-minute, rounded up to the nearest minute.
7. Either party can end the private session.
8. On end, paired debit/credit billing ledger entries are written.
9. After the private session ends, the creator can resume the broadcast.
10. Resumed broadcast publishes SSE event and viewers see the stream again.
11. Requests expire after 60 seconds without response.
12. Only one private session (pending or active) is allowed per broadcast at a time.
13. All 5 Section 123 E2E tests pass.
14. All 4 Section 124 E2E tests pass.

---

## 9. Viewer Queue System

### 9.1 Problem Statement

When multiple viewers request private sessions during a popular broadcast, only one can be active at a time (enforced by `_get_active_or_pending`). The current design rejects subsequent requests with a 409. This creates a poor experience -- viewers who are ready to pay cannot even queue up. A queue system allows multiple viewers to line up and be served in order.

### 9.2 Queue Data Model

Queue entries are stored in the new `BroadcastPrivateSessions` table (which has `pk`/`sk` composite keys) with a new sort key prefix:

| Attribute | Type | Notes |
|-----------|------|-------|
| `pk` | S | `BCAST#{session_id}` |
| `sk` | S | `QUEUE#{position:04d}#{viewer_id}` |
| `viewer_id` | S | Queued viewer's user_sub |
| `viewer_display_name` | S | Display name |
| `rate_per_minute_cents` | N | Offered rate |
| `payment_method_id` | S | Pre-validated PM |
| `max_duration_minutes` | N | Requested max duration |
| `position` | N | 1-based queue position |
| `status` | S | `queued`, `offered`, `expired`, `left` |
| `queued_at` | N | Unix timestamp |
| `offered_at` | N | When the viewer was offered the private session (null until offered) |
| `offer_expires_at` | N | Offer expiry (offered_at + 60s) |
| `ttl` | N | 90 days |

### 9.3 Queue Behavior

**Enqueue**: When a private session is already pending or active, the viewer is added to the queue instead of receiving a 409:

```python
def enqueue_private_request(
    session_id: str,
    viewer_id: str,
    viewer_display_name: str,
    rate_per_minute_cents: int,
    payment_method_id: str,
    max_duration_minutes: int,
    min_rate_cents: int,
) -> Dict[str, Any]:
    if rate_per_minute_cents < min_rate_cents:
        raise HTTPException(400, f"Rate must be at least {min_rate_cents} cents per minute.")

    # Get current queue length
    queue = _get_queue(session_id)
    if len(queue) >= MAX_QUEUE_SIZE:
        raise HTTPException(409, "Queue is full. Please try again later.")

    position = len(queue) + 1
    ts = now_ts()

    item = {
        "pk": f"BCAST#{session_id}",
        "sk": f"QUEUE#{position:04d}#{viewer_id}",
        "viewer_id": viewer_id,
        "viewer_display_name": viewer_display_name,
        "rate_per_minute_cents": rate_per_minute_cents,
        "payment_method_id": payment_method_id,
        "max_duration_minutes": max_duration_minutes,
        "position": position,
        "status": "queued",
        "queued_at": ts,
        "ttl": ts + 90 * 24 * 3600,
    }
    T.broadcast_private_sessions.put_item(Item=item)

    # Notify creator
    broadcast_sse_publish(session_id, {
        "_type": "private:queue_joined",
        "viewer_id": viewer_id,
        "viewer_display_name": viewer_display_name,
        "position": position,
        "rate_per_minute_cents": rate_per_minute_cents,
    })

    return {"position": position, "queue_size": position, "status": "queued"}
```

**Queue position display**: Each queued viewer receives their position via the enqueue response and SSE updates:

```
┌─────────────────────────────────────────┐
│  Private Session Queue                   │
│                                          │
│  Your position: #2 of 4                  │
│  Estimated wait: ~15 minutes             │
│                                          │
│  [Leave Queue]                           │
└─────────────────────────────────────────┘
```

**FIFO with creator reorder**: The queue is FIFO by default. The creator can reorder or skip viewers:

```python
@router.post("/{session_id}/private-queue/reorder")
def reorder_queue(
    session_id: str,
    body: QueueReorderIn,  # { viewer_id: str, new_position: int }
    ctx=Depends(require_ui_session),
):
    """Creator reorders a viewer in the queue."""
    # Validate creator owns session
    # Update position field and re-number remaining entries
```

**Queue timeout**: Each queued request expires after 5 minutes if the viewer does not reach the front of the queue. When a viewer's request expires, they are removed from the queue and remaining viewers are promoted:

```python
QUEUE_TIMEOUT_SECONDS = 300  # 5 minutes

def _check_queue_expirations(session_id: str) -> None:
    queue = _get_queue(session_id)
    ts = now_ts()
    for entry in queue:
        if entry["status"] == "queued" and ts - int(entry["queued_at"]) > QUEUE_TIMEOUT_SECONDS:
            _expire_queue_entry(session_id, entry)
            broadcast_sse_publish(session_id, {
                "_type": "private:queue_expired",
                "viewer_id": entry["viewer_id"],
            })
```

**Offer to next in queue**: When a private session ends, the system automatically offers the session to the next viewer in the queue:

```python
def _offer_to_next_in_queue(session_id: str) -> Optional[Dict]:
    queue = _get_queue(session_id)
    for entry in queue:
        if entry["status"] == "queued":
            # Offer the session to this viewer
            ts = now_ts()
            T.broadcast_private_sessions.update_item(
                Key={"pk": entry["pk"], "sk": entry["sk"]},
                UpdateExpression="SET #st = :offered, offered_at = :oa, offer_expires_at = :oe",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={
                    ":offered": "offered",
                    ":oa": ts,
                    ":oe": ts + 60,  # 60 seconds to accept
                },
            )
            broadcast_sse_publish(session_id, {
                "_type": "private:queue_offer",
                "viewer_id": entry["viewer_id"],
                "expires_in_seconds": 60,
            })
            return entry
    return None
```

### 9.4 Queue Position SSE Notifications

When a viewer's queue position changes (due to someone ahead leaving or a reorder), they receive an SSE update:

```
SSE event: private:queue_position_update
{ viewer_id: "bob", new_position: 1, queue_size: 3 }
```

### 9.5 Queue Limits and Configuration

```python
# app/core/settings.py
broadcast_private_queue_max_size: int = int(os.environ.get("BROADCAST_PRIVATE_QUEUE_MAX_SIZE", "10"))
broadcast_private_queue_timeout_seconds: int = int(os.environ.get("BROADCAST_PRIVATE_QUEUE_TIMEOUT_SECONDS", "300"))
broadcast_private_queue_offer_seconds: int = int(os.environ.get("BROADCAST_PRIVATE_QUEUE_OFFER_SECONDS", "60"))
```

---

## 10. Billing Dispute Handling

### 10.1 Network Disconnection During Private Call

Private calls can drop due to network issues on either side. Without handling, the viewer continues to be billed while unable to use the service.

**Grace period**: When a WebRTC connection drops (detected via ICE connection state change to `"disconnected"` or `"failed"`), a 60-second reconnection window starts. During this window:

1. Billing continues (to prevent abuse by intentionally disconnecting).
2. Both parties see a "Reconnecting..." overlay with a 60-second countdown.
3. If the connection is re-established within 60 seconds, the session continues normally.
4. If not re-established within 60 seconds, the session ends with `ended_by: "system_disconnect"`.

```python
def handle_private_call_disconnect(
    session_id: str,
    private_session_id: str,
    disconnected_party: str,  # "viewer" or "creator"
) -> Dict[str, Any]:
    """Handle WebRTC disconnection during a private call.

    Starts a 60-second grace period. If not reconnected, ends the session
    and calculates partial billing.
    """
    ts = now_ts()
    T.broadcast_private_sessions.update_item(
        Key={"pk": f"BCAST#{session_id}", "sk": f"PRIVATE#{private_session_id}"},
        UpdateExpression=(
            "SET disconnect_detected_at = :dda, "
            "disconnect_party = :dp, "
            "reconnect_deadline = :rd"
        ),
        ExpressionAttributeValues={
            ":dda": ts,
            ":dp": disconnected_party,
            ":rd": ts + 60,
        },
    )

    broadcast_sse_publish(session_id, {
        "_type": "private:disconnected",
        "private_session_id": private_session_id,
        "disconnected_party": disconnected_party,
        "reconnect_deadline": ts + 60,
    })

    return {"reconnect_deadline": ts + 60}
```

### 10.2 Automatic Partial Refund for System Errors

If the session ends due to a system error (server crash, infrastructure failure, `ended_by: "system"` or `"system_disconnect"`), the viewer receives an automatic partial refund for the unused portion of their billed time:

```python
def _calculate_system_error_refund(
    total_billed_cents: int,
    duration_seconds: int,
    max_duration_minutes: int,
) -> int:
    """Calculate refund for system-terminated private sessions.

    Refunds the unused portion of the minimum billing (1 minute) or the
    remaining purchased time if the viewer had committed to max_duration.
    """
    # Minimum: refund 50% of the last billed minute
    billed_minutes = max(1, math.ceil(duration_seconds / 60))
    last_minute_seconds = duration_seconds % 60
    if last_minute_seconds < 30:
        # Less than half the last minute was used; refund 1 minute
        rate = total_billed_cents // billed_minutes
        return rate
    return 0
```

### 10.3 Dispute Flow via MOD-003 Appeals System

If a viewer disputes a private session charge (e.g., claims the creator disconnected intentionally), the dispute follows the MOD-003 appeals workflow:

1. Viewer files a dispute via `POST /ui/appeals` with `appeal_type: "billing_dispute"` and `context: { private_session_id, session_id }`.
2. The appeals queue routes the dispute to a moderator.
3. The moderator reviews the private session record (duration, ended_by, disconnect events) and the billing ledger entries.
4. Resolution options:
   - **Full refund**: Moderator issues a full refund (credit viewer, debit creator).
   - **Partial refund**: Moderator issues prorated refund.
   - **No refund**: Dispute denied (e.g., viewer initiated the disconnect).
5. Both parties are notified of the resolution via the notification system.

---

## 11. Recording Consent

### 11.1 Two-Party Consent Notice

When a private call begins, both parties see a consent notice:

```
┌────────────────────────────────────────────┐
│  Private Session Notice                     │
│                                             │
│  This private session may be recorded if    │
│  both parties consent.                      │
│                                             │
│  Recording is currently: [OFF]              │
│                                             │
│  By continuing, you agree to the platform's │
│  Terms of Service for private sessions.     │
│                                             │
│  [Decline & Leave]   [Accept & Continue]    │
└────────────────────────────────────────────┘
```

### 11.2 Recording During Private Calls

CALL-009/CALL-010 recording infrastructure can be used during private calls. However, privacy-sensitive private calls require explicit mutual consent:

**Creator enables recording**: The creator can toggle recording during the private session. When the creator enables recording:

1. A `private:recording_requested` SSE event is sent to the viewer.
2. The viewer sees a consent dialog: "The creator wants to record this session. Do you consent?"
3. If the viewer consents (`POST /{session_id}/private/{private_id}/consent-recording`), recording starts.
4. If the viewer declines, recording is not enabled. The creator is notified.

```python
@router.post("/{session_id}/private/{private_id}/request-recording")
def request_private_recording(
    session_id: str,
    private_id: str,
    ctx=Depends(require_ui_session),
):
    """Creator requests recording consent from the viewer."""
    session = _get_and_validate_session(session_id)
    if session.created_by != ctx["user_sub"]:
        raise HTTPException(403, "Only the broadcaster can request recording.")

    private_session = _get_private_session(session_id, private_id)
    if not private_session or private_session.get("status") != "active":
        raise HTTPException(409, "Private session is not active.")

    broadcast_sse_publish(session_id, {
        "_type": "private:recording_requested",
        "private_session_id": private_id,
        "requested_by": ctx["user_sub"],
    })

    return {"ok": True, "status": "consent_pending"}


@router.post("/{session_id}/private/{private_id}/consent-recording")
def consent_private_recording(
    session_id: str,
    private_id: str,
    body: RecordingConsentIn,  # { consent: bool }
    ctx=Depends(require_ui_session),
):
    """Viewer grants or denies recording consent."""
    private_session = _get_private_session(session_id, private_id)
    if not private_session or private_session.get("viewer_id") != ctx["user_sub"]:
        raise HTTPException(403, "Only the private session viewer can consent.")

    if body.consent:
        T.broadcast_private_sessions.update_item(
            Key={"pk": f"BCAST#{session_id}", "sk": f"PRIVATE#{private_id}"},
            UpdateExpression="SET recording_consented = :rc, recording_consented_at = :rca",
            ExpressionAttributeValues={":rc": True, ":rca": now_ts()},
        )
        broadcast_sse_publish(session_id, {
            "_type": "private:recording_consented",
            "private_session_id": private_id,
        })
    else:
        broadcast_sse_publish(session_id, {
            "_type": "private:recording_denied",
            "private_session_id": private_id,
        })

    return {"ok": True, "consent": body.consent}
```

### 11.3 Recording Indicator

When recording is active during a private call, both parties see a persistent recording indicator:

```typescript
// In PrivateSessionView.tsx
{isRecording && (
  <div className="absolute top-4 left-4 flex items-center gap-2 bg-red-600/90 text-white px-3 py-1 rounded-full text-sm">
    <div className="w-2 h-2 bg-white rounded-full animate-pulse" />
    Recording
  </div>
)}
```

### 11.4 Recording Cannot Be Enabled Without Consent

The recording toggle in the creator's UI is disabled until the viewer has consented:

```typescript
<Button
  variant={isRecording ? "destructive" : "outline"}
  disabled={!viewerConsentGranted}
  onClick={() => {
    if (!viewerConsentGranted) {
      requestRecordingConsent.mutate();
    } else {
      toggleRecording.mutate();
    }
  }}
>
  {!viewerConsentGranted ? (
    <Tooltip content="Viewer consent required">
      <VideoOff className="h-4 w-4" />
    </Tooltip>
  ) : isRecording ? (
    <><Square className="h-4 w-4" /> Stop Recording</>
  ) : (
    <><Circle className="h-4 w-4" /> Start Recording</>
  )}
</Button>
```

---

## 12. Acceptance Criteria (Extended)

| # | Criterion | Pass Condition |
|---|-----------|----------------|
| AC-1 | Viewer submits private request during live broadcast | POST `/private-request` returns 201 with `status: "requested"` |
| AC-2 | Request rejected when rate below creator minimum | POST with rate < `private_min_rate_cents` returns 400 |
| AC-3 | Creator sees pending requests | GET `/private-requests` returns list sorted by `requested_at` ascending |
| AC-4 | Creator accepts with "pause" behavior | POST `/accept` transitions private session to "accepted" and broadcast to "private" |
| AC-5 | Remaining viewers see holding screen | SSE `private:broadcast_paused` event received by all non-private viewers |
| AC-6 | WebRTC call established on accept | Response includes `call_id`; call record created in `MessageCallSessions` table |
| AC-7 | Billing accrues per-minute, rounded up | `total_billed_cents = ceil(duration_seconds / 60) * rate_per_minute_cents` |
| AC-8 | Either party can end session | POST `/end` succeeds for both viewer and creator; `ended_by` records who ended it |
| AC-9 | Billing ledger entries written on end | `T.billing` contains DEBIT for viewer and CREDIT for creator with matching amounts |
| AC-10 | Creator resumes broadcast after private session | POST `/resume` transitions broadcast from "private" to "live"; viewers see stream again |
| AC-11 | Requests expire after 60 seconds | Unclaimed requests auto-transition to "expired" status |
| AC-12 | Only one active private session per broadcast | Second request while one is active/pending returns 409 (or queues if queue enabled) |
| AC-13 | Creator cannot request private on own broadcast | POST from broadcaster returns 403 |
| AC-14 | Invalid payment method rejected | POST with non-existent PM returns 400 |
| AC-15 | Creator declines request | POST `/decline` transitions request to "declined"; viewer receives SSE notification |
| AC-16 | Viewer cancels pending request | POST `/cancel` transitions request to "cancelled" (only while status is "requested") |
| AC-17 | Max duration auto-timeout | Session at `max_duration_minutes` auto-ends with `ended_by: "timeout"` |
| AC-18 | Grace period on disconnect | 60-second reconnection window before session auto-ends |
| AC-19 | Recording requires viewer consent | Recording toggle disabled until viewer consents; consent stored in DDB |
| AC-20 | Recording indicator visible to both parties | Both viewer and creator see red recording indicator when recording is active |
| AC-21 | Queue system (if enabled) accepts multiple requests | Viewers beyond the first receive a queue position instead of 409 |
| AC-22 | All Section 123 E2E tests pass | 5 tests covering request/accept/decline/cancel flow |
| AC-23 | All Section 124 E2E tests pass | 4 tests covering billing, ledger, and resume flow |

---

## 13. Related Tickets

| Ticket | Relationship |
|--------|-------------|
| BCAST-005 | Chat continues during private (chat infra reused) |
| BCAST-012 | Private chat tiers (complementary feature, text-based private) |
| CALL-001 through CALL-010 | WebRTC call infrastructure reused for private video |
| MON-002 | Billing ledger pattern reused for private session billing |
| MON-003 | Creator earnings dashboard will aggregate private session credits |

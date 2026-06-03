# MSG-009: Find-a-DateTime Message

**Ticket**: MSG-009
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

MSG-009 adds a group availability finder to the messaging system. Unlike meeting polls (which present a fixed set of time slot options for voting), Find-a-DateTime lets participants mark their available time ranges on a continuous grid, then automatically computes the best overlapping windows. This is the messaging equivalent of tools like When2meet or Doodle's "Find a Time" — embedded directly in a conversation as a new message kind.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a conversation participant, I want to create a "Find a DateTime" request specifying a date range and daily time window. | POST creates `find_datetime` message; grid shows date range x time slots. |
| Creator | As the creator, I want to set a deadline after which availability submission closes. | `deadline_hours` field (default 48h); auto-closes after expiry. |
| Participant | As a participant, I want to mark which time slots I'm available on the grid. | Submit availability as a list of `{date, start_time, end_time}` ranges. |
| Participant | As a participant, I want to update my availability before the deadline. | PUT replaces previous availability; grid updates. |
| All | As any participant, I want to see the overlap heat map showing when most people are free. | Grid cells colored by count of available participants. |
| Creator | As the creator, I want to close the poll early and see the best overlapping times. | POST close; response includes ranked "best windows" with participant counts. |
| All | As a participant, I want to see the final result as a summary in the conversation. | Result message shows top 3 best windows with participant names. |

### 1.3 How It Differs from Meeting Polls

| Feature | Meeting Poll (existing) | Find-a-DateTime (this ticket) |
|---------|------------------------|-------------------------------|
| Input | Creator defines specific time slots | Creator defines a date range + daily window |
| Participant action | Vote yes/no/maybe on each slot | Mark available ranges on continuous grid |
| Output | Most-voted slot wins | Algorithm finds best overlapping windows |
| Granularity | Per-slot (arbitrary times) | Configurable: 15/30/60 minute slots |
| Visualization | Simple vote counts | Heat map grid |

### 1.4 Why This Is Needed Now

Meeting polls work well when the organizer already has candidate times in mind. But for open-ended scheduling ("when can everyone meet this week?"), a free-form availability grid is far more effective. This is the #1 requested scheduling feature in user feedback, and the calendar + meeting poll infrastructure (already built) provides the storage and SSE patterns needed.

---

## 2. Current State Analysis

### 2.1 Meeting Poll Infrastructure

Meeting polls are stored in the `calendar` DDB table (see `scripts/local-ddb-init.py:63`, `app/core/settings.py:417`) with `calendar_id = MPOLL#{poll_id}` (PK pattern, see `app/routers/messaging.py:9287`). The same table and pattern will be used for Find-a-DateTime with `calendar_id = FADT#{poll_id}`. Key service functions:

- `app/routers/messaging.py:9259`: `create_meeting_poll_message()` — creates poll + message
<!-- NOTE: There is no separate `app/services/messaging.py`. All messaging logic lives in the monolith router `app/routers/messaging.py` (13,287 lines). -->
- SSE events: `poll:vote`, `poll:confirmed` — real-time updates via `useMessagingStream.ts` (see `frontend/src/hooks/useMessagingStream.ts:62,162-163`)
- Frontend: `MeetingPollComposer.tsx` — composer UI in ComposeBar (see `frontend/src/pages/messages/MeetingPollComposer.tsx`, integrated at `ComposeBar.tsx:18,160,1777`)

### 2.2 Calendar Table

The `calendar` DDB table (see `scripts/local-ddb-init.py:63`, PK=`calendar_id`, SK=`sk`) uses a single-table design:
- PK: `calendar_id` (e.g., `MPOLL#abc123`)
- SK: `meta` for metadata (see `messaging.py:9383`), `vote#{user_sub}` for votes (see `:9391`), `SLOT#{slot_id}` for time slots
<!-- NOTE: The existing meeting poll code uses lowercase SK values: "meta" (not "META") and "vote#" (not "VOTE#"). See `messaging.py:9383` for `"sk": "meta"` and `:9391` for `begins_with("vote#")`. The FADT design should be consistent — either adopt the lowercase convention of existing polls or document the intentional difference. -->

Find-a-DateTime will use:
- PK: `FADT#{poll_id}`
- SK: `META` for metadata, `AVAIL#{user_sub}` for user availability, `RESULT` for computed result

### 2.3 Messaging Integration

New message kinds are added by:
1. Defining the message kind string in the backend
2. Adding a send endpoint
3. Storing kind-specific fields on the message item
4. Adding rendering in `MessageBubble.tsx`

### 2.4 Gaps

1. **No find-a-datetime message kind** — backend and frontend don't support it. (VERIFIED: `kind` Literal at `messaging.py:2330` does not include `find_datetime`.)
2. **No availability grid storage** — no DDB schema for user availability ranges. (VERIFIED: no `FADT#` prefix used anywhere in the codebase.)
3. **No overlap computation** — no algorithm to find best overlapping windows.
4. **No availability grid UI** — no interactive time grid component. (VERIFIED: no `AvailabilityGrid` or `FindDateTime` components exist in `frontend/src/`.)
5. **No auto-close mechanism** — meeting polls don't have deadline-based auto-close.

---

## 3. Architecture Diagram

```
┌───────────────────────────────────────────────────────────────────────┐
│                        FRONTEND (React)                               │
│                                                                       │
│  ┌──────────────────┐                                                 │
│  │   ComposeBar      │                                                │
│  │  ┌──────────────┐ │                                                │
│  │  │ Calendar btn  │─┼─────┐                                         │
│  │  │ "Find a Time" │ │     │                                         │
│  │  └──────────────┘ │     │                                         │
│  └──────────────────┘     │                                         │
│                            ▼                                         │
│  ┌────────────────────────────────────────────┐                      │
│  │       FindDateTimeComposer (modal)          │                      │
│  │  ┌──────────┐ ┌──────────┐ ┌────────────┐  │                      │
│  │  │ Title    │ │ Date     │ │ Time Window│  │                      │
│  │  │  input   │ │ Range    │ │ start/end  │  │                      │
│  │  └──────────┘ └──────────┘ └────────────┘  │                      │
│  │  ┌──────────────┐ ┌──────────────────┐     │                      │
│  │  │ Slot Duration │ │ Deadline Selector│     │                      │
│  │  │ 15/30/60 min  │ │ 12h-7d dropdown  │     │                      │
│  │  └──────────────┘ └──────────────────┘     │                      │
│  │  [Create]  [Cancel]                         │                      │
│  └───────────────────┬────────────────────────┘                      │
│                       │ POST                                          │
│  ┌────────────────────▼──────────────────────────┐                   │
│  │          FindDateTimeCard (in MessageBubble)   │                   │
│  │  ┌──────────────────────────────────────────┐  │                   │
│  │  │ Title: "Team standup this week"          │  │                   │
│  │  │ Date range: Jun 1 - Jun 7               │  │                   │
│  │  │ Status: OPEN / CLOSED                    │  │                   │
│  │  └──────────────────────────────────────────┘  │                   │
│  │  [Submit Availability] → AvailabilityGrid      │                   │
│  │  [Close & Compute] (creator only)              │                   │
│  │                                                 │                   │
│  │  ┌──────────────────────────────────────────┐  │                   │
│  │  │ AvailabilityGrid (modal)                 │  │                   │
│  │  │                                          │  │                   │
│  │  │    Mon  Tue  Wed  Thu  Fri               │  │                   │
│  │  │ 9  [x] [ ] [x] [x] [ ]                  │  │                   │
│  │  │ 10 [x] [x] [x] [x] [ ]                  │  │                   │
│  │  │ 11 [x] [x] [x] [ ] [x]                  │  │                   │
│  │  │ 12 [ ] [x] [x] [x] [x]                  │  │                   │
│  │  │ ...                                      │  │                   │
│  │  │ Click/drag to toggle slots               │  │                   │
│  │  │ [Submit]  [Cancel]                       │  │                   │
│  │  └──────────────────────────────────────────┘  │                   │
│  │                                                 │                   │
│  │  ┌──────────────────────────────────────────┐  │                   │
│  │  │ FindDateTimeResult (after close)         │  │                   │
│  │  │ Best windows:                            │  │                   │
│  │  │  1. Wed 10:00-11:30 (3/3 participants)   │  │                   │
│  │  │  2. Thu 09:00-10:00 (2/3 participants)   │  │                   │
│  │  │  3. Mon 09:00-11:00 (2/3 participants)   │  │                   │
│  │  │ + Heat map grid (green gradient)         │  │                   │
│  │  └──────────────────────────────────────────┘  │                   │
│  └─────────────────────────────────────────────────┘                  │
└──────────────────────────────┬────────────────────────────────────────┘
                               │ HTTP / SSE
┌──────────────────────────────▼────────────────────────────────────────┐
│                        BACKEND (FastAPI)                               │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  messaging router (app/routers/messaging.py)                     │ │
│  │                                                                  │ │
│  │  POST /conversations/{id}/messages/find-datetime                 │ │
│  │       → create_find_datetime() + create message (kind=find_dt)   │ │
│  │  POST /messages/find-datetime/{poll_id}/availability             │ │
│  │       → submit_availability() + SSE: fadt:availability           │ │
│  │  POST /messages/find-datetime/{poll_id}/close                    │ │
│  │       → close_and_compute() + SSE: fadt:result                   │ │
│  │  GET  /messages/find-datetime/{poll_id}                          │ │
│  │       → get_find_datetime() (meta + availabilities + result)     │ │
│  └───────────────────────────┬──────────────────────────────────────┘ │
│                               │                                       │
│  ┌───────────────────────────▼──────────────────────────────────────┐ │
│  │  messaging_find_datetime.py (service)                            │ │
│  │                                                                  │ │
│  │  create_find_datetime()    → T.calendar PutItem FADT#{id}/META   │ │
│  │  submit_availability()     → T.calendar PutItem FADT#{id}/AVAIL# │ │
│  │  close_and_compute()       → _compute_best_windows()             │ │
│  │                            → T.calendar PutItem FADT#{id}/RESULT │ │
│  │  get_find_datetime()       → T.calendar Query PK=FADT#{id}      │ │
│  └───────────────────────────┬──────────────────────────────────────┘ │
│                               │                                       │
│  ┌───────────────────────────▼──────────────────────────────────────┐ │
│  │  calendar DDB Table (single-table design)                        │ │
│  │                                                                  │ │
│  │  PK: FADT#{poll_id}  │  SK: META                                │ │
│  │                       │     → title, from_date, to_date,         │ │
│  │                       │        start_hour, end_hour, status,     │ │
│  │                       │        deadline_at, participant_count    │ │
│  │                       │  SK: AVAIL#{user_sub}                    │ │
│  │                       │     → slots[], submitted_at, user_name   │ │
│  │                       │  SK: RESULT                              │ │
│  │                       │     → best_windows[], computed_at        │ │
│  │                                                                  │ │
│  │  PK: MPOLL#{poll_id}  (existing meeting polls — same table)     │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  SSE (Server-Sent Events)                                        │ │
│  │  fadt:availability  → { poll_id, user_sub, participant_count }   │ │
│  │  fadt:result        → { poll_id, best_windows[] }                │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

**Data Flow — Creating a Find-a-DateTime**:
1. Creator opens FindDateTimeComposer from ComposeBar
2. Fills in title, date range, time window, slot duration, deadline
3. POST `/conversations/{id}/messages/find-datetime`
4. Backend: creates FADT record in calendar table + message item with `kind=find_datetime`
5. SSE broadcasts new message to participants
6. MessageBubble renders FindDateTimeCard with title, date range, "Submit Availability" button

**Data Flow — Submitting Availability**:
1. Participant clicks "Submit Availability" on FindDateTimeCard
2. AvailabilityGrid modal opens with the date/time configuration
3. Participant clicks/drags to select available slots
4. POST `/messages/find-datetime/{poll_id}/availability` with slot list
5. Backend stores AVAIL#{user_sub} item, increments participant_count
6. SSE `fadt:availability` event invalidates React Query cache
7. Other participants see updated participant count

**Data Flow — Closing and Computing Results**:
1. Creator clicks "Close & Compute" button
2. POST `/messages/find-datetime/{poll_id}/close`
3. Backend: queries all AVAIL# items, runs `_compute_best_windows()`, stores RESULT item
4. SSE `fadt:result` event invalidates React Query cache
5. FindDateTimeCard re-renders with FindDateTimeResult showing top windows + heat map

---

## 4. Technical Design

### 4.1 Data Model

#### 4.1.1 Find-a-DateTime Record (Calendar Table)

**PK**: `FADT#{poll_id}`, **SK**: `META`

| Field | Type | Description |
|-------|------|-------------|
| `poll_id` | String | `fadt_<uuid4_hex>` |
| `conversation_id` | String | Conversation this belongs to |
| `message_id` | String | Message that created this |
| `creator_sub` | String | User who created it |
| `title` | String | e.g., "Team standup this week" |
| `from_date` | String | Start date (ISO: `2026-06-01`) |
| `to_date` | String | End date (ISO: `2026-06-07`) |
| `start_hour` | Number | Daily window start (0-23, e.g., 9) |
| `end_hour` | Number | Daily window end (1-24, e.g., 17) |
| `slot_duration_minutes` | Number | 15, 30, or 60 |
| `deadline_at` | Number | Unix timestamp when submissions close |
| `status` | String | `open`, `closed` |
| `created_at` | Number | Unix timestamp |
| `participant_count` | Number | Number of users who submitted availability |

#### 4.1.2 Availability Submission

**PK**: `FADT#{poll_id}`, **SK**: `AVAIL#{user_sub}`

| Field | Type | Description |
|-------|------|-------------|
| `user_sub` | String | Participant user sub |
| `user_name` | String | Display name (denormalized for result display) |
| `slots` | List | List of available slot keys: `["2026-06-01T09:00", "2026-06-01T09:30", ...]` |
| `submitted_at` | Number | Unix timestamp |

Slots are encoded as ISO datetime strings at the grid granularity. A user marks individual grid cells, and the full set is stored as a list.

#### 4.1.3 Result Record

**PK**: `FADT#{poll_id}`, **SK**: `RESULT`

| Field | Type | Description |
|-------|------|-------------|
| `computed_at` | Number | Unix timestamp |
| `best_windows` | List | Ranked list of `{start: str, end: str, count: int, participants: [str]}` |

### 4.2 DynamoDB Access Patterns

| # | Access Pattern | Table/Index | PK | SK | Operation | Notes |
|---|---------------|-------------|----|----|-----------|-------|
| 1 | Create FADT poll | `calendar` | `FADT#{poll_id}` | `META` | `PutItem` | Initial metadata with status=open |
| 2 | Get FADT metadata | `calendar` | `FADT#{poll_id}` | `META` | `GetItem` | Single 1 RCU read |
| 3 | Submit availability | `calendar` | `FADT#{poll_id}` | `AVAIL#{user_sub}` | `PutItem` | Overwrites previous submission |
| 4 | Get single user availability | `calendar` | `FADT#{poll_id}` | `AVAIL#{user_sub}` | `GetItem` | For pre-filling grid on re-open |
| 5 | List all availabilities | `calendar` | `FADT#{poll_id}` | `BEGINS_WITH "AVAIL#"` | `Query` | Used during close to compute overlap |
| 6 | Get all FADT data | `calendar` | `FADT#{poll_id}` | — (all SKs) | `Query` | Returns META + all AVAIL# + RESULT |
| 7 | Store result | `calendar` | `FADT#{poll_id}` | `RESULT` | `PutItem` | best_windows list |
| 8 | Update status to closed | `calendar` | `FADT#{poll_id}` | `META` | `UpdateItem` | `SET status = "closed"` |
| 9 | Increment participant_count | `calendar` | `FADT#{poll_id}` | `META` | `UpdateItem` | `ADD participant_count 1` (conditional: new submission) |

**Example DynamoDB Items**:

```json
// FADT META item
{
  "calendar_id": {"S": "FADT#fadt_abc123def456"},
  "sk": {"S": "META"},
  "poll_id": {"S": "fadt_abc123def456"},
  "conversation_id": {"S": "conv_xyz789"},
  "message_id": {"S": "m_msg111222"},
  "creator_sub": {"S": "alice-sub-001"},
  "title": {"S": "Team standup this week"},
  "from_date": {"S": "2026-06-01"},
  "to_date": {"S": "2026-06-07"},
  "start_hour": {"N": "9"},
  "end_hour": {"N": "17"},
  "slot_duration_minutes": {"N": "30"},
  "deadline_at": {"N": "1748672400"},
  "status": {"S": "open"},
  "created_at": {"N": "1748499600"},
  "participant_count": {"N": "2"}
}

// Availability submission
{
  "calendar_id": {"S": "FADT#fadt_abc123def456"},
  "sk": {"S": "AVAIL#alice-sub-001"},
  "user_sub": {"S": "alice-sub-001"},
  "user_name": {"S": "Alice"},
  "slots": {"L": [
    {"S": "2026-06-01T09:00"},
    {"S": "2026-06-01T09:30"},
    {"S": "2026-06-01T10:00"},
    {"S": "2026-06-02T09:00"},
    {"S": "2026-06-02T09:30"},
    {"S": "2026-06-03T14:00"},
    {"S": "2026-06-03T14:30"},
    {"S": "2026-06-03T15:00"}
  ]},
  "submitted_at": {"N": "1748500200"}
}

// Result item (after close)
{
  "calendar_id": {"S": "FADT#fadt_abc123def456"},
  "sk": {"S": "RESULT"},
  "computed_at": {"N": "1748503800"},
  "best_windows": {"L": [
    {"M": {
      "start": {"S": "2026-06-01T09:00"},
      "end": {"S": "2026-06-01T10:30"},
      "count": {"N": "3"},
      "participants": {"L": [
        {"S": "Alice"},
        {"S": "Bob"},
        {"S": "Charlie"}
      ]}
    }},
    {"M": {
      "start": {"S": "2026-06-03T14:00"},
      "end": {"S": "2026-06-03T15:30"},
      "count": {"N": "2"},
      "participants": {"L": [
        {"S": "Alice"},
        {"S": "Bob"}
      ]}
    }}
  ]}
}
```

### 4.3 Backend Service

**File**: `app/services/messaging_find_datetime.py`

```python
def create_find_datetime(
    *,
    conversation_id: str,
    creator_sub: str,
    title: str,
    from_date: str,    # ISO date
    to_date: str,      # ISO date
    start_hour: int,   # 0-23
    end_hour: int,     # 1-24
    slot_duration_minutes: int,  # 15, 30, or 60
    deadline_hours: int = 48,
) -> dict:
    """Create a Find-a-DateTime poll and return metadata."""
    poll_id = f"fadt_{uuid4().hex}"
    ts = now_ts()
    deadline_at = ts + (deadline_hours * 3600)

    # Validate: from_date < to_date, start_hour < end_hour
    # Validate: date range <= 14 days
    # Validate: slot_duration_minutes in (15, 30, 60)

    item = {
        "calendar_id": f"FADT#{poll_id}",
        "sk": "META",
        "poll_id": poll_id,
        "conversation_id": conversation_id,
        "creator_sub": creator_sub,
        "title": title,
        "from_date": from_date,
        "to_date": to_date,
        "start_hour": start_hour,
        "end_hour": end_hour,
        "slot_duration_minutes": slot_duration_minutes,
        "deadline_at": deadline_at,
        "status": "open",
        "created_at": ts,
        "participant_count": 0,
    }
    T.calendar.put_item(Item=item)
    return item

def submit_availability(
    *,
    poll_id: str,
    user_sub: str,
    user_name: str,
    slots: list[str],
) -> dict:
    """Submit or update a user's available slots."""
    # 1. Check poll exists and status == "open"
    # 2. Check deadline not passed
    # 3. Validate all slots are within the date range and time window
    # 4. Put AVAIL#{user_sub} item
    # 5. Increment participant_count (if new submission)
    # 6. Emit SSE event: fadt:availability
    # 7. Return availability record

def close_and_compute(poll_id: str, user_sub: str) -> dict:
    """Close the poll and compute best overlapping windows."""
    # 1. Verify caller is creator
    # 2. Set status = "closed"
    # 3. Query all AVAIL# items
    # 4. Compute overlap: for each slot, count how many participants are available
    # 5. Find contiguous windows with highest participant count
    # 6. Rank by count (desc), then by earliest start
    # 7. Store RESULT item with top 10 windows
    # 8. Emit SSE event: fadt:result
    # 9. Return result

def get_find_datetime(poll_id: str) -> dict:
    """Get poll metadata + all availabilities + result (if closed)."""
    # Query PK=FADT#{poll_id}, all SK items
    # Assemble response with meta, availabilities[], result (if exists)

def _compute_best_windows(
    availabilities: list[dict],
    slot_duration_minutes: int,
) -> list[dict]:
    """Compute ranked overlapping windows from availability data."""
    # 1. Build a counter: slot_key → set of participant user_subs
    # 2. For each slot, record count
    # 3. Find contiguous runs of slots where count >= 2
    # 4. For each run, calculate the minimum count across slots
    # 5. Rank by (min_count desc, run_length desc, start_time asc)
    # 6. Return top 10 windows
```

### 4.4 Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Optional

# ---------- Request Models ----------

class CreateFindDateTimeIn(BaseModel):
    """Request body for creating a Find-a-DateTime poll."""
    title: str = Field(..., min_length=1, max_length=200,
        description="Poll title (e.g., 'Team standup this week')")
    from_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$",
        description="Start date (ISO format: YYYY-MM-DD)")
    to_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$",
        description="End date (ISO format: YYYY-MM-DD)")
    start_hour: int = Field(..., ge=0, le=23,
        description="Daily time window start hour (0-23)")
    end_hour: int = Field(..., ge=1, le=24,
        description="Daily time window end hour (1-24)")
    slot_duration_minutes: int = Field(default=30,
        description="Slot granularity: 15, 30, or 60 minutes")
    deadline_hours: int = Field(default=48, ge=1, le=336,
        description="Hours until submissions close (max 14 days)")

    model_config = {"json_schema_extra": {"examples": [
        {"title": "Team standup this week", "from_date": "2026-06-01",
         "to_date": "2026-06-07", "start_hour": 9, "end_hour": 17,
         "slot_duration_minutes": 30, "deadline_hours": 48}
    ]}}

class SubmitAvailabilityIn(BaseModel):
    """Request body for submitting availability."""
    slots: list[str] = Field(..., max_length=500,
        description="List of available slot keys (ISO datetime at grid granularity)")

    model_config = {"json_schema_extra": {"examples": [
        {"slots": ["2026-06-01T09:00", "2026-06-01T09:30", "2026-06-01T10:00"]}
    ]}}

# ---------- Response Models ----------

class BestWindowOut(BaseModel):
    """A computed best overlapping window."""
    start: str = Field(..., description="Window start ISO datetime")
    end: str = Field(..., description="Window end ISO datetime")
    count: int = Field(..., ge=0, description="Number of available participants")
    participants: list[str] = Field(default_factory=list,
        description="Display names of available participants")

class FindDateTimeResultOut(BaseModel):
    """Computed result after closing a poll."""
    computed_at: int
    best_windows: list[BestWindowOut]

class AvailabilityOut(BaseModel):
    """A single participant's availability submission."""
    user_sub: str
    user_name: str
    slots: list[str]
    submitted_at: int

class FindDateTimeMetaOut(BaseModel):
    """Full Find-a-DateTime poll response."""
    poll_id: str
    conversation_id: str
    message_id: str
    creator_sub: str
    title: str
    from_date: str
    to_date: str
    start_hour: int
    end_hour: int
    slot_duration_minutes: int
    deadline_at: int
    status: str  # "open" | "closed"
    created_at: int
    participant_count: int

class FindDateTimeFullOut(BaseModel):
    """Complete FADT response with metadata, availabilities, and result."""
    meta: FindDateTimeMetaOut
    availabilities: list[AvailabilityOut] = Field(default_factory=list)
    result: Optional[FindDateTimeResultOut] = None

class FindDateTimeMessageOut(BaseModel):
    """Response from creating a FADT message."""
    message_id: str
    conversation_id: str
    kind: str = "find_datetime"
    find_datetime_id: str
    find_datetime_title: str
    find_datetime_status: str
    created_at: int
```

### 4.5 API Request/Response Examples

#### 4.5.1 Create Find-a-DateTime Poll

```bash
curl -s -X POST \
  "http://localhost:8000/ui/messaging/conversations/conv_xyz789/messages/find-datetime" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Team standup this week",
    "from_date": "2026-06-01",
    "to_date": "2026-06-07",
    "start_hour": 9,
    "end_hour": 17,
    "slot_duration_minutes": 30,
    "deadline_hours": 48
  }' | jq .
```

**Response** (201):
```json
{
  "message_id": "m_msg111222",
  "conversation_id": "conv_xyz789",
  "kind": "find_datetime",
  "find_datetime_id": "fadt_abc123def456",
  "find_datetime_title": "Team standup this week",
  "find_datetime_status": "open",
  "created_at": 1748499600,
  "sender_id": "alice-sub-001",
  "text": null,
  "reactions": {}
}
```

#### 4.5.2 Submit Availability

```bash
curl -s -X POST \
  "http://localhost:8000/ui/messaging/messages/find-datetime/fadt_abc123def456/availability" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{
    "slots": [
      "2026-06-01T09:00", "2026-06-01T09:30", "2026-06-01T10:00",
      "2026-06-02T09:00", "2026-06-02T09:30",
      "2026-06-03T14:00", "2026-06-03T14:30", "2026-06-03T15:00"
    ]
  }' | jq .
```

**Response** (200):
```json
{
  "ok": true,
  "poll_id": "fadt_abc123def456",
  "user_sub": "alice-sub-001",
  "slots_count": 8,
  "participant_count": 1,
  "submitted_at": 1748500200
}
```

#### 4.5.3 Get Find-a-DateTime Poll (Open)

```bash
curl -s -X GET \
  "http://localhost:8000/ui/messaging/messages/find-datetime/fadt_abc123def456" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  | jq .
```

**Response** (200):
```json
{
  "meta": {
    "poll_id": "fadt_abc123def456",
    "conversation_id": "conv_xyz789",
    "message_id": "m_msg111222",
    "creator_sub": "alice-sub-001",
    "title": "Team standup this week",
    "from_date": "2026-06-01",
    "to_date": "2026-06-07",
    "start_hour": 9,
    "end_hour": 17,
    "slot_duration_minutes": 30,
    "deadline_at": 1748672400,
    "status": "open",
    "created_at": 1748499600,
    "participant_count": 2
  },
  "availabilities": [
    {
      "user_sub": "alice-sub-001",
      "user_name": "Alice",
      "slots": [
        "2026-06-01T09:00", "2026-06-01T09:30", "2026-06-01T10:00",
        "2026-06-02T09:00", "2026-06-02T09:30",
        "2026-06-03T14:00", "2026-06-03T14:30", "2026-06-03T15:00"
      ],
      "submitted_at": 1748500200
    },
    {
      "user_sub": "bob-sub-002",
      "user_name": "Bob",
      "slots": [
        "2026-06-01T09:00", "2026-06-01T09:30",
        "2026-06-02T10:00", "2026-06-02T10:30",
        "2026-06-03T14:00", "2026-06-03T14:30"
      ],
      "submitted_at": 1748500800
    }
  ],
  "result": null
}
```

#### 4.5.4 Close and Compute Results

```bash
curl -s -X POST \
  "http://localhost:8000/ui/messaging/messages/find-datetime/fadt_abc123def456/close" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  | jq .
```

**Response** (200):
```json
{
  "ok": true,
  "poll_id": "fadt_abc123def456",
  "status": "closed",
  "result": {
    "computed_at": 1748503800,
    "best_windows": [
      {
        "start": "2026-06-01T09:00",
        "end": "2026-06-01T10:00",
        "count": 2,
        "participants": ["Alice", "Bob"]
      },
      {
        "start": "2026-06-03T14:00",
        "end": "2026-06-03T15:00",
        "count": 2,
        "participants": ["Alice", "Bob"]
      }
    ]
  }
}
```

#### 4.5.5 Non-Creator Close Attempt

```bash
curl -s -X POST \
  "http://localhost:8000/ui/messaging/messages/find-datetime/fadt_abc123def456/close" \
  -H "Cookie: ui_session=sess_bob; ui_csrf=csrf_bob; ui_access_token=jwt_bob" \
  -H "x-csrf-token: csrf_bob" \
  | jq .
```

**Response** (403):
```json
{
  "detail": "Only the creator can close this poll"
}
```

### 4.6 Backend Router

Add endpoints to `app/routers/messaging.py`:

```python
@router.post("/conversations/{conv_id}/messages/find-datetime", status_code=201)
def create_find_datetime_message(conv_id: str, body: CreateFindDateTimeIn, ctx=Depends(require_ui_session)):
    """Create a Find-a-DateTime message in a conversation."""

@router.post("/messages/find-datetime/{poll_id}/availability")
def submit_availability(poll_id: str, body: SubmitAvailabilityIn, ctx=Depends(require_ui_session)):
    """Submit availability for a Find-a-DateTime poll."""

@router.post("/messages/find-datetime/{poll_id}/close")
def close_find_datetime(poll_id: str, ctx=Depends(require_ui_session)):
    """Close a Find-a-DateTime poll and compute results (creator only)."""

@router.get("/messages/find-datetime/{poll_id}")
def get_find_datetime(poll_id: str, ctx=Depends(require_ui_session)):
    """Get Find-a-DateTime poll details, availabilities, and results."""
```

### 4.7 Message Fields

Add to message item when kind = `find_datetime`:

| Field | Type | Description |
|-------|------|-------------|
| `find_datetime_id` | String | `fadt_<uuid4_hex>` |
| `find_datetime_title` | String | Poll title |
| `find_datetime_status` | String | `open` or `closed` |

### 4.8 Frontend Components

**FindDateTimeComposer** (`frontend/src/pages/messages/FindDateTimeComposer.tsx`):

```typescript
interface FindDateTimeComposerProps {
  onSubmit: (data: CreateFindDateTimeIn) => void;
  onCancel: () => void;
}
```

- Title input
- Date range picker (from_date, to_date)
- Time window selector (start_hour, end_hour dropdowns)
- Slot duration radio (15 / 30 / 60 min)
- Deadline selector (hours dropdown: 12h, 24h, 48h, 72h, 7d)
- "Create" and "Cancel" buttons

**AvailabilityGrid** (`frontend/src/components/shared/AvailabilityGrid.tsx`):

```typescript
interface AvailabilityGridProps {
  fromDate: string;
  toDate: string;
  startHour: number;
  endHour: number;
  slotDurationMinutes: number;
  selectedSlots: string[];
  onSlotsChange: (slots: string[]) => void;
  readOnly?: boolean;
  heatMap?: Record<string, number>;  // slot → participant count (for results view)
  maxParticipants?: number;
}
```

- Columns: one per day in the date range
- Rows: time slots from start_hour to end_hour at slot_duration intervals
- Click/drag to toggle slot selection
- Heat map mode: cells colored by availability count (green gradient)
- Responsive: horizontal scroll on mobile for many days

**FindDateTimeResult** (`frontend/src/pages/messages/FindDateTimeResult.tsx`):

- Displays top 3 best windows with participant count and names
- Heat map grid showing all availability data
- "Closed" badge on message

**FindDateTimeCard** (`frontend/src/pages/messages/FindDateTimeCard.tsx`):

- Wrapper rendered in MessageBubble for `kind=find_datetime`
- Shows title, date range, status
- "Submit Availability" button opens AvailabilityGrid modal
- Creator sees "Close & Compute" button
- After close: shows FindDateTimeResult inline

### 4.9 Frontend Component Tree

```
ComposeBar
├── ToolbarRow
│   ├── ... (existing buttons)
│   └── FindDateTimeButton (new — calendar icon with clock overlay)
│       └── FindDateTimeComposer (modal/dialog)
│           ├── TitleInput (text, max 200 chars)
│           ├── DateRangePicker
│           │   ├── FromDateInput (date picker)
│           │   └── ToDateInput (date picker)
│           ├── TimeWindowSelector
│           │   ├── StartHourDropdown (0-23)
│           │   └── EndHourDropdown (1-24)
│           ├── SlotDurationRadioGroup
│           │   ├── Radio "15 min"
│           │   ├── Radio "30 min" (default)
│           │   └── Radio "60 min"
│           ├── DeadlineSelector (dropdown: 12h, 24h, 48h, 72h, 7d)
│           └── ActionButtons
│               ├── Button "Create" (primary)
│               └── Button "Cancel" (ghost)

MessageBubble (kind=find_datetime)
└── FindDateTimeCard
    ├── CardHeader
    │   ├── ClockIcon
    │   ├── Title ("Team standup this week")
    │   ├── DateRange ("Jun 1 - Jun 7")
    │   └── StatusBadge ("Open" | "Closed")
    ├── CardBody
    │   ├── ParticipantCount ("2 participants responded")
    │   ├── DeadlineCountdown ("Closes in 23h 45m")
    │   └── SubmitAvailabilityButton
    │       └── Dialog (AvailabilityGrid)
    │           ├── AvailabilityGrid
    │           │   ├── DayColumnHeaders (Mon, Tue, ...)
    │           │   ├── TimeRowLabels (9:00, 9:30, ...)
    │           │   └── SlotCells[][] (click/drag to toggle)
    │           ├── SelectedCount ("8 slots selected")
    │           └── ActionButtons
    │               ├── Button "Submit" (primary)
    │               └── Button "Cancel" (ghost)
    ├── CreatorActions (only for creator)
    │   └── Button "Close & Compute" (destructive)
    └── FindDateTimeResult (only when status=closed)
        ├── BestWindowsList
        │   └── WindowCard[] (ranked)
        │       ├── Rank ("#1")
        │       ├── TimeRange ("Wed 10:00-11:30")
        │       ├── ParticipantCount ("3/3")
        │       └── ParticipantNames ("Alice, Bob, Charlie")
        └── HeatMapGrid (read-only AvailabilityGrid with gradient coloring)
```

**State Management**:
```typescript
// FindDateTimeCard
const { data: fadtData } = useQuery({
  queryKey: ["find-datetime", pollId, conversationId],
  queryFn: () => getFindDateTime(pollId),
  refetchInterval: fadtData?.meta.status === "open" ? 30000 : false,
});

// AvailabilityGrid modal
const [selectedSlots, setSelectedSlots] = useState<string[]>([]);
const [isDragging, setIsDragging] = useState(false);
const [dragMode, setDragMode] = useState<"select" | "deselect">("select");

// Submit mutation
const submitMut = useMutation({
  mutationFn: (slots: string[]) => submitAvailability(pollId, { slots }),
  onSuccess: () => {
    queryClient.invalidateQueries(["find-datetime", pollId]);
    setGridOpen(false);
  },
});
```

### 4.10 SSE Events

| Event | Payload | Trigger |
|-------|---------|---------|
| `fadt:availability` | `{ poll_id, user_sub, participant_count }` | User submits/updates availability |
| `fadt:result` | `{ poll_id, best_windows }` | Creator closes poll |

Handled in `useMessagingStream.ts`:
```typescript
case "fadt:availability":
case "fadt:result":
  queryClient.invalidateQueries(["find-datetime", data.poll_id]);
  break;
```

### 4.11 Settings

```python
# Find-a-DateTime (MSG-009)
find_datetime_max_date_range_days: int = int(os.environ.get("FIND_DATETIME_MAX_DATE_RANGE", "14"))
find_datetime_max_slots_per_user: int = int(os.environ.get("FIND_DATETIME_MAX_SLOTS", "500"))
```

---

## 5. Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|----------|-------------|------------|---------------------|-----------------|
| 1 | Date range exceeds 14 days | 400 | `date_range_too_long` | "Date range cannot exceed 14 days" | Reduce the date range |
| 2 | start_hour >= end_hour | 400 | `invalid_time_window` | "start_hour must be less than end_hour" | Fix time window values |
| 3 | from_date >= to_date | 400 | `invalid_date_range` | "from_date must be before to_date" | Swap dates or select correct range |
| 4 | from_date in the past | 400 | `date_in_past` | "from_date must be today or later" | Select a future date |
| 5 | slot_duration_minutes not in {15, 30, 60} | 422 | `validation_error` | "slot_duration_minutes must be 15, 30, or 60" | Select a valid slot duration |
| 6 | Availability submission to closed poll | 400 | `poll_closed` | "Poll is closed" | Poll has already been finalized |
| 7 | Availability submission past deadline | 400 | `deadline_passed` | "Submission deadline has passed" | No recovery; deadline was server-side |
| 8 | Non-creator attempts to close | 403 | `forbidden` | "Only the creator can close this poll" | Ask the creator to close it |
| 9 | Slot outside date/time range | 400 | `slot_out_of_range` | "Slot is outside the allowed range" | Select slots within the configured range |
| 10 | Too many slots (>500) | 422 | `validation_error` | "Maximum 500 slots per submission" | Reduce the number of selected slots |
| 11 | Poll not found | 404 | `not_found` | "Find-a-DateTime poll not found" | Check poll ID; poll may have been deleted |
| 12 | User not conversation participant | 403 | `not_participant` | "You are not a participant in this conversation" | Join the conversation first |
| 13 | Close already-closed poll | 400 | `already_closed` | "Poll is already closed" | View the existing results |
| 14 | Empty slots list | 422 | `validation_error` | "At least one slot must be selected" | Select at least one available time |
| 15 | Duplicate slot keys in submission | 200 | — | (Deduplicated server-side, no error) | No action needed |

---

## 6. Implementation Plan

### 6.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/messaging_find_datetime.py` | Find-a-DateTime business logic |
| `frontend/src/pages/messages/FindDateTimeComposer.tsx` | Composer for creating FADT polls |
| `frontend/src/components/shared/AvailabilityGrid.tsx` | Interactive time grid component |
| `frontend/src/pages/messages/FindDateTimeCard.tsx` | Message bubble card for FADT |
| `frontend/src/pages/messages/FindDateTimeResult.tsx` | Results display component |

### 6.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/messaging.py` | Add FADT endpoints |
| `app/models.py` | Add FADT request/response models |
| `frontend/src/api/types.ts` | Add FADT TypeScript types |
| `frontend/src/api/endpoints/messaging.ts` | Add FADT API functions |
| `frontend/src/pages/messages/ComposeBar.tsx` | Add FADT button + composer trigger |
| `frontend/src/pages/messages/MessageBubble.tsx` | Render FindDateTimeCard for `kind=find_datetime` |
| `frontend/src/hooks/useMessagingStream.ts` | Handle `fadt:` SSE events |

### 6.3 Step-by-Step Order

1. Implement `messaging_find_datetime.py` service (create, submit, close, compute)
2. Add router endpoints to `messaging.py`
3. Add Pydantic models
4. Build AvailabilityGrid component (shared, reusable for FEED-003)
5. Build FindDateTimeComposer
6. Build FindDateTimeCard + FindDateTimeResult
7. Integrate into ComposeBar and MessageBubble
8. Add SSE event handling
9. Write E2E tests

---

## 7. Observability & Monitoring

### 7.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `msg009_fadt_created_total` | Counter | — | FADT polls created |
| `msg009_availability_submitted_total` | Counter | `is_update` | Availability submissions (new vs update) |
| `msg009_fadt_closed_total` | Counter | — | FADT polls closed by creator |
| `msg009_fadt_auto_closed_total` | Counter | — | FADT polls auto-closed by deadline |
| `msg009_best_window_count` | Histogram | — | Number of best windows per computed result |
| `msg009_participant_count` | Histogram | — | Number of participants at close time |
| `msg009_slots_per_submission` | Histogram | — | Number of slots per availability submission |
| `msg009_compute_latency_ms` | Histogram | — | Time to compute best windows |

### 7.2 Log Events

| Event | Level | Fields | Description |
|-------|-------|--------|-------------|
| `fadt.created` | INFO | `creator_sub`, `poll_id`, `conversation_id`, `from_date`, `to_date`, `slot_duration_minutes` | FADT poll created |
| `fadt.availability.submitted` | INFO | `user_sub`, `poll_id`, `slots_count`, `is_update` | Availability submitted |
| `fadt.closed` | INFO | `creator_sub`, `poll_id`, `participant_count`, `best_window_count` | Poll closed and results computed |
| `fadt.deadline.passed` | INFO | `poll_id`, `participant_count` | Poll deadline reached (auto-close candidate) |
| `fadt.compute.slow` | WARN | `poll_id`, `participant_count`, `slots_total`, `latency_ms` | Computation took >500ms |
| `fadt.availability.rejected` | WARN | `user_sub`, `poll_id`, `reason` | Availability submission rejected |

### 7.3 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| FADT compute latency p95 > 2s | `histogram_quantile(0.95, msg009_compute_latency_ms) > 2000` | Warning | Check participant count; optimize algorithm |
| FADT creation error rate > 5% | Error rate on POST endpoint > 5% | Warning | Check validation logic; review error logs |
| Orphaned open polls > 100 | Count of FADT polls with status=open and deadline_at < now - 24h | Info | Run cleanup job to auto-close stale polls |

### 7.4 Dashboard Queries

```promql
# FADT polls created per day
sum(increase(msg009_fadt_created_total[24h]))

# Average participants per poll
histogram_quantile(0.5, msg009_participant_count)

# Compute latency distribution
histogram_quantile(0.5, msg009_compute_latency_ms)
histogram_quantile(0.95, msg009_compute_latency_ms)
histogram_quantile(0.99, msg009_compute_latency_ms)
```

---

## 8. Rollout Plan

### 8.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `MSG009_FIND_DATETIME_ENABLED` | `false` | Enable Find-a-DateTime message kind |
| `MSG009_AUTO_CLOSE_ENABLED` | `false` | Enable deadline-based auto-close background task |

### 8.2 Rollout Phases

| Phase | Duration | Actions |
|-------|----------|---------|
| 1. Backend deploy | Day 1 | Deploy backend with endpoints + service. Feature flag OFF. Calendar table already exists (shared with meeting polls). |
| 2. Internal testing | Day 2-3 | Enable `MSG009_FIND_DATETIME_ENABLED` for internal users. Create test FADT polls in dev conversations. Verify availability grid, overlap computation, SSE events. |
| 3. Auto-close testing | Day 4-5 | Enable `MSG009_AUTO_CLOSE_ENABLED`. Create polls with short deadlines (1h). Verify auto-close + result computation. |
| 4. Gradual rollout | Day 6-10 | Ramp from 10% to 100%. Monitor compute latency, participant engagement, grid interaction UX. |
| 5. GA | Day 11 | Remove feature flags. Document in user guide. |

### 8.3 Rollback Procedure

1. Set `MSG009_FIND_DATETIME_ENABLED` to `false`. Frontend hides "Find a Time" button in ComposeBar.
2. Existing FADT messages remain in conversations but FindDateTimeCard falls back to a static "Find-a-DateTime poll" text.
3. Open polls can still be viewed via direct API call but no new submissions accepted.
4. FADT data in calendar table is preserved (no data loss).
5. If auto-close has issues: set `MSG009_AUTO_CLOSE_ENABLED` to `false` independently.

---

## 9. Performance Considerations

| # | Concern | Impact | Mitigation |
|---|---------|--------|------------|
| 1 | Overlap computation with many participants | O(P * S) where P=participants, S=slots per participant | For 14-day range with 30-min slots and 50 participants: 14 * 16 * 50 = 11,200 slot checks — trivial. Cap at 500 slots/user, 200 participants. |
| 2 | Large slot lists in DDB item | 500 string slots ~10KB per AVAIL item | Well within DDB 400KB item limit. Use `StringSet` instead of `List` if deduplication needed (saves 10-20%). |
| 3 | Query all availabilities on close | Single partition query (PK=FADT#{id}) returns META + all AVAIL + RESULT | Efficient single-partition query. With 200 participants, ~200 items, ~2MB total — within DDB 1MB query page limit if each AVAIL is <5KB. Use pagination for safety. |
| 4 | Real-time grid updates | SSE event per availability submission | Only invalidates React Query cache — no grid re-render unless component is mounted. Grid re-render is O(days * slots_per_day) DOM elements — max 14 * 32 = 448 cells. |
| 5 | AvailabilityGrid drag interaction | Many rapid state updates during drag | Use `requestAnimationFrame` for drag tracking. Batch slot toggles with `useRef` and flush on `mouseup`. |
| 6 | Heat map color computation | Counting participants per slot for coloring | Pre-compute in `useMemo` when availabilities data changes. O(total_slots) — negligible. |
| 7 | Deadline polling | Checking if deadline has passed | Client-side countdown timer. No polling needed — compare `deadline_at` with `Date.now()`. Server validates on submission. |
| 8 | Multiple concurrent submissions | Race condition on participant_count | Use DDB `ADD participant_count 1` with `ConditionExpression: attribute_not_exists(sk)` for first submission. If condition fails (update), skip increment. |

---

## 10. E2E Test Plan

### 10.1 Test File

`frontend/e2e/find-a-datetime.spec.ts` — 26 tests across 5 sections.

### 10.2 Test Setup

```typescript
const TS = Date.now();
let alicePage: Page;
let bobPage: Page;
let groupConvoId: string;
let fadtPollId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice, Bob sessions
  // Create a group conversation with Alice + Bob
  // Compute date strings for from_date (tomorrow) and to_date (3 days from now)
});
```

### 10.3 Section 296: Find-a-DateTime Creation API (6 tests)

| # | Test | Assertion |
|---|------|-----------|
| 296.1 | Create FADT poll with valid parameters | POST; 201; response has `find_datetime_id`, `kind=find_datetime` |
| 296.2 | FADT poll metadata stored correctly | GET `/messages/find-datetime/{id}`; `title`, `from_date`, `to_date`, `start_hour`, `end_hour`, `slot_duration_minutes` match input |
| 296.3 | Reject FADT with from_date > to_date | POST with reversed dates; 400 |
| 296.4 | Reject FADT with start_hour >= end_hour | POST with `start_hour=17, end_hour=9`; 400 |
| 296.5 | Reject FADT with invalid slot_duration | POST with `slot_duration_minutes=45`; 422 |
| 296.6 | Reject FADT with date range > 14 days | POST with 15-day range; 400; "Date range cannot exceed 14 days" |

### 10.4 Section 297: Availability Submission API (6 tests)

| # | Test | Assertion |
|---|------|-----------|
| 297.1 | Alice submits availability | POST `/messages/find-datetime/{id}/availability`; 200; slots stored |
| 297.2 | Bob submits availability | POST; 200; `participant_count` incremented to 2 |
| 297.3 | Alice updates availability | POST again with different slots; 200; old slots replaced |
| 297.4 | Reject availability for non-existent poll | POST to random poll_id; 404 |
| 297.5 | Reject availability with slot outside date range | POST with slot date outside `from_date..to_date`; 400 |
| 297.6 | Reject availability with empty slots list | POST with `slots: []`; 422 |

### 10.5 Section 298: Close & Compute API (6 tests)

| # | Test | Assertion |
|---|------|-----------|
| 298.1 | Creator closes FADT poll | POST `/messages/find-datetime/{id}/close`; 200; `status=closed` |
| 298.2 | Result includes best overlapping windows | Response has `best_windows` array; each entry has `start`, `end`, `count`, `participants` |
| 298.3 | Best windows ranked by participant count descending | `best_windows[0].count >= best_windows[1].count` |
| 298.4 | Non-creator cannot close poll | Bob POST close; 403 |
| 298.5 | Closed poll rejects new availability submissions | POST availability to closed poll; 400; "poll is closed" |
| 298.6 | Close already-closed poll returns error | POST close again; 400; "already closed" |

### 10.6 Section 299: Find-a-DateTime Message Rendering (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 299.1 | FADT message appears in conversation | GET messages; find message with `kind=find_datetime`; has `find_datetime_title` |
| 299.2 | Open FADT shows title and date range | Message card displays title and date range text |
| 299.3 | After availability submission, participant count updates | GET poll; `participant_count` matches expected |
| 299.4 | Closed FADT shows result summary | GET poll after close; `best_windows` populated |
| 299.5 | FADT poll data retrievable by any participant | Bob GET `/messages/find-datetime/{id}`; 200; sees all availabilities |

### 10.7 Section 300: Edge Cases & Concurrent Access (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 300.1 | Concurrent availability submissions don't lose data | Alice and Bob submit simultaneously; both stored; participant_count = 2 |
| 300.2 | 15-minute slot duration generates correct grid | Create FADT with `slot_duration_minutes=15`; submit slots; verify slot keys are at 15-min intervals |
| 300.3 | Maximum slots (500) accepted | Submit 500 slots; 200; all stored |

---

## 11. Security Considerations

- Only conversation participants can create FADT polls or submit availability
- Only the creator can close the poll
- Availability data is visible to all conversation participants (transparent scheduling)
- Deadline enforcement prevents late submissions (server-side timestamp check)
- Maximum 500 slots per submission prevents abuse
- Date range capped at 14 days to limit grid size and computation cost
- Slot keys are validated against the poll's date/time configuration (no arbitrary strings)
- Poll IDs are UUID-based — not guessable

---

## 12. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| Calendar DDB table | Existing | Available |
| Meeting poll SSE patterns | Existing | Available |
| AvailabilityGrid component | New (this ticket) | Shared with FEED-003 |

---

## Codebase References

| File | Line(s) | What was verified |
|------|---------|-------------------|
| `scripts/local-ddb-init.py` | 63 | Calendar table exists — `TableDef("calendar", "calendar_id", "sk")` — will be reused for `FADT#` prefix items |
| `app/core/settings.py` | 417 | `calendar_table_name` setting exists — no new DDB table needed (single-table design) |
| `app/routers/messaging.py` | 9259-9355 | `create_meeting_poll_message()` — reference implementation for creating a new message kind with calendar table items |
| `app/routers/messaging.py` | 9287 | `"calendar_id": f"MPOLL#{poll_id}"` — PK pattern to follow with `FADT#` prefix |
| `app/routers/messaging.py` | 9383 | `"sk": "meta"` — existing polls use **lowercase** SK values, not `META` as proposed in this spec |
| `app/routers/messaging.py` | 9391 | `begins_with("vote#")` — existing polls use **lowercase** SK prefix, not `VOTE#` |
| `app/routers/messaging.py` | 9371-9465 | `get_meeting_poll()` and `vote_meeting_poll()` — patterns for FADT get/submit endpoints |
| `app/routers/messaging.py` | 2330 | Message `kind` Literal — no `find_datetime` kind exists yet — **needs addition** |
| `frontend/src/hooks/useMessagingStream.ts` | 62, 162-163 | SSE handling for `poll:vote`, `poll:confirmed` — pattern for `fadt:availability`, `fadt:result` events; no `fadt:` events handled yet |
| `frontend/src/pages/messages/MeetingPollComposer.tsx` | — | EXISTS — ComposeBar integration pattern for FindDateTimeComposer to follow |
| `frontend/src/pages/messages/ComposeBar.tsx` | 18, 160, 1777 | MeetingPollComposer import and integration — pattern for FindDateTimeComposer button |
| `app/core/settings.py` | — | No `find_datetime_max_date_range_days` or similar settings — **new settings required** |
| `app/services/messaging_find_datetime.py` | — | **Does not exist** — new service required |
| `frontend/src/pages/messages/FindDateTimeComposer.tsx` | — | **Does not exist** — new component required |
| `frontend/src/components/shared/AvailabilityGrid.tsx` | — | **Does not exist** — new shared component required |
| `frontend/src/pages/messages/FindDateTimeCard.tsx` | — | **Does not exist** — new component required |
| `frontend/src/pages/messages/FindDateTimeResult.tsx` | — | **Does not exist** — new component required |

---

## Testing Strategy

### Unit Tests (`tests/test_find_datetime.py`)
**Framework**: pytest + moto (DynamoDB/S3 mock)

| # | Test Function | What It Verifies |
|---|--------------|-----------------|
| 1 | `test_create_find_datetime_request` | Create find datetime request |
| 2 | `test_submit_availability_ranges` | Submit availability ranges |
| 3 | `test_update_availability_replaces` | Update availability replaces |
| 4 | `test_compute_overlap_heat_map` | Compute overlap heat map |
| 5 | `test_close_poll_returns_best_windows` | Close poll returns best windows |
| 6 | `test_deadline_auto_closes` | Deadline auto closes |
| 7 | `test_result_message_top3_windows` | Result message top3 windows |
| 8 | `test_participant_count_in_overlap` | Participant count in overlap |

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/find-datetime.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~14 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

**Negative/Edge Tests**: 401 without auth, 403 for wrong role, 404 for missing resources, 409 for conflicts, 422 for validation errors.

### Test Data Requirements
- Test users: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- Session seeding: `python3 e2e_admin_session_setup.py` before test run

### CI/Pipeline
- Feature flags: `FIND_DATETIME_ENABLED=true`
- Tests run serially (single Playwright worker, `workers: 1`)
- Retry safety: 1 retry configured; tests use unique timestamps (`Date.now()`) for isolation
- Run: `cd frontend && npx playwright test e2e/<spec-file>`

---

## Dependencies & Merge Safety

### Depends On

No dependencies -- this ticket can be implemented independently.

### Depended On By

No downstream dependents identified.

### Merge Strategy
**Independent -- new message kind=find_datetime. DDB storage uses existing calendar table pattern. No modification to existing message kinds.**

### Merge Checklist
- [ ] Feature flags configured in `.env.local`: FIND_DATETIME_ENABLED=true
- [ ] Service file created/modified: `app/services/find_datetime.py`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/find-datetime.spec.ts`
- [ ] Unit tests pass: `.venv/bin/pytest tests/test_find_datetime.py`

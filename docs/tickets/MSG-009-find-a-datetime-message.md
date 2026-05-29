# MSG-009: Find-a-DateTime Message

**Ticket**: MSG-009
**Author**: Engineering
**Status**: Design
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
| Creator | As a conversation participant, I want to create a "Find a DateTime" request specifying a date range and daily time window. | POST creates `find_datetime` message; grid shows date range × time slots. |
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

Meeting polls are stored in the `calendar` DDB table with `calendar_id = MPOLL#{poll_id}` (PK pattern). The same table and pattern will be used for Find-a-DateTime with `calendar_id = FADT#{poll_id}`. Key service functions:

- `app/services/messaging.py`: `create_meeting_poll_message()` — creates poll + message
- SSE events: `poll:vote`, `poll:confirmed` — real-time updates via `useMessagingStream.ts`
- Frontend: `MeetingPollComposer.tsx` — composer UI in ComposeBar

### 2.2 Calendar Table

The `calendar` DDB table uses a single-table design:
- PK: `calendar_id` (e.g., `MPOLL#abc123`)
- SK: `META` for metadata, `VOTE#{user_sub}` for votes, `SLOT#{slot_id}` for time slots

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

1. **No find-a-datetime message kind** — backend and frontend don't support it.
2. **No availability grid storage** — no DDB schema for user availability ranges.
3. **No overlap computation** — no algorithm to find best overlapping windows.
4. **No availability grid UI** — no interactive time grid component.
5. **No auto-close mechanism** — meeting polls don't have deadline-based auto-close.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 Find-a-DateTime Record (Calendar Table)

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

#### 3.1.2 Availability Submission

**PK**: `FADT#{poll_id}`, **SK**: `AVAIL#{user_sub}`

| Field | Type | Description |
|-------|------|-------------|
| `user_sub` | String | Participant user sub |
| `user_name` | String | Display name (denormalized for result display) |
| `slots` | List | List of available slot keys: `["2026-06-01T09:00", "2026-06-01T09:30", ...]` |
| `submitted_at` | Number | Unix timestamp |

Slots are encoded as ISO datetime strings at the grid granularity. A user marks individual grid cells, and the full set is stored as a list.

#### 3.1.3 Result Record

**PK**: `FADT#{poll_id}`, **SK**: `RESULT`

| Field | Type | Description |
|-------|------|-------------|
| `computed_at` | Number | Unix timestamp |
| `best_windows` | List | Ranked list of `{start: str, end: str, count: int, participants: [str]}` |

### 3.2 Backend Service

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

### 3.3 Backend Router

Add endpoints to `app/routers/messaging.py`:

```python
class CreateFindDateTimeIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    from_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    to_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    start_hour: int = Field(..., ge=0, le=23)
    end_hour: int = Field(..., ge=1, le=24)
    slot_duration_minutes: int = Field(default=30)
    deadline_hours: int = Field(default=48, ge=1, le=336)  # max 14 days

class SubmitAvailabilityIn(BaseModel):
    slots: list[str] = Field(..., max_length=500)  # max 500 slots

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

### 3.4 Message Fields

Add to message item when kind = `find_datetime`:

| Field | Type | Description |
|-------|------|-------------|
| `find_datetime_id` | String | `fadt_<uuid4_hex>` |
| `find_datetime_title` | String | Poll title |
| `find_datetime_status` | String | `open` or `closed` |

### 3.5 Frontend Components

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
- "Submit Availability" button → opens AvailabilityGrid modal
- Creator sees "Close & Compute" button
- After close: shows FindDateTimeResult inline

### 3.6 SSE Events

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

### 3.7 Settings

```python
# Find-a-DateTime (MSG-009)
find_datetime_max_date_range_days: int = int(os.environ.get("FIND_DATETIME_MAX_DATE_RANGE", "14"))
find_datetime_max_slots_per_user: int = int(os.environ.get("FIND_DATETIME_MAX_SLOTS", "500"))
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/messaging_find_datetime.py` | Find-a-DateTime business logic |
| `frontend/src/pages/messages/FindDateTimeComposer.tsx` | Composer for creating FADT polls |
| `frontend/src/components/shared/AvailabilityGrid.tsx` | Interactive time grid component |
| `frontend/src/pages/messages/FindDateTimeCard.tsx` | Message bubble card for FADT |
| `frontend/src/pages/messages/FindDateTimeResult.tsx` | Results display component |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/messaging.py` | Add FADT endpoints |
| `app/models.py` | Add FADT request/response models |
| `frontend/src/api/types.ts` | Add FADT TypeScript types |
| `frontend/src/api/endpoints/messaging.ts` | Add FADT API functions |
| `frontend/src/pages/messages/ComposeBar.tsx` | Add FADT button + composer trigger |
| `frontend/src/pages/messages/MessageBubble.tsx` | Render FindDateTimeCard for `kind=find_datetime` |
| `frontend/src/hooks/useMessagingStream.ts` | Handle `fadt:` SSE events |

### 4.3 Step-by-Step Order

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

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/find-a-datetime.spec.ts` — 20 tests across 4 sections.

### 5.2 Test Setup

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

### 5.3 Section 296: Find-a-DateTime Creation API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 296.1 | Create FADT poll with valid parameters | POST; 201; response has `find_datetime_id`, `kind=find_datetime` |
| 296.2 | FADT poll metadata stored correctly | GET `/messages/find-datetime/{id}`; `title`, `from_date`, `to_date`, `start_hour`, `end_hour`, `slot_duration_minutes` match input |
| 296.3 | Reject FADT with from_date > to_date | POST with reversed dates; 400 |
| 296.4 | Reject FADT with start_hour >= end_hour | POST with `start_hour=17, end_hour=9`; 400 |
| 296.5 | Reject FADT with invalid slot_duration | POST with `slot_duration_minutes=45`; 422 |

### 5.4 Section 297: Availability Submission API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 297.1 | Alice submits availability | POST `/messages/find-datetime/{id}/availability`; 200; slots stored |
| 297.2 | Bob submits availability | POST; 200; `participant_count` incremented to 2 |
| 297.3 | Alice updates availability | POST again with different slots; 200; old slots replaced |
| 297.4 | Reject availability for non-existent poll | POST to random poll_id; 404 |
| 297.5 | Reject availability with slot outside date range | POST with slot date outside `from_date..to_date`; 400 |

### 5.5 Section 298: Close & Compute API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 298.1 | Creator closes FADT poll | POST `/messages/find-datetime/{id}/close`; 200; `status=closed` |
| 298.2 | Result includes best overlapping windows | Response has `best_windows` array; each entry has `start`, `end`, `count`, `participants` |
| 298.3 | Best windows ranked by participant count descending | `best_windows[0].count >= best_windows[1].count` |
| 298.4 | Non-creator cannot close poll | Bob POST close; 403 |
| 298.5 | Closed poll rejects new availability submissions | POST availability to closed poll; 400; "poll is closed" |

### 5.6 Section 299: Find-a-DateTime Message Rendering (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 299.1 | FADT message appears in conversation | GET messages; find message with `kind=find_datetime`; has `find_datetime_title` |
| 299.2 | Open FADT shows title and date range | Message card displays title and date range text |
| 299.3 | After availability submission, participant count updates | GET poll; `participant_count` matches expected |
| 299.4 | Closed FADT shows result summary | GET poll after close; `best_windows` populated |
| 299.5 | FADT poll data retrievable by any participant | Bob GET `/messages/find-datetime/{id}`; 200; sees all availabilities |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Date range exceeds 14 days | 400 | "Date range cannot exceed 14 days" |
| start_hour >= end_hour | 400 | "start_hour must be less than end_hour" |
| from_date >= to_date | 400 | "from_date must be before to_date" |
| slot_duration_minutes not in {15, 30, 60} | 422 | Pydantic validation |
| Availability submission to closed poll | 400 | "Poll is closed" |
| Availability submission past deadline | 400 | "Submission deadline has passed" |
| Non-creator attempts to close | 403 | "Only the creator can close this poll" |
| Slot outside date/time range | 400 | "Slot is outside the allowed range" |

---

## 7. Security Considerations

- Only conversation participants can create FADT polls or submit availability
- Only the creator can close the poll
- Availability data is visible to all conversation participants (transparent scheduling)
- Deadline enforcement prevents late submissions (server-side timestamp check)
- Maximum 500 slots per submission prevents abuse

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| Calendar DDB table | Existing | Available |
| Meeting poll SSE patterns | Existing | Available |
| AvailabilityGrid component | New (this ticket) | Shared with FEED-003 |

# FEED-003: Find-a-DateTime Newsfeed Post

**Ticket**: FEED-003
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 4-5 days
**Depends on**: MSG-009 (Find-a-DateTime Message — backend logic, AvailabilityGrid component)

---

## 1. Overview & Motivation

### 1.1 Purpose

FEED-003 extends the Find-a-DateTime concept (MSG-009) from private conversations to the public newsfeed. Creators can publish a Find-a-DateTime post that lets their followers submit availability on a time grid. This is useful for scheduling community events, meetups, livestreams, or Q&A sessions based on audience availability.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to publish a "Find a Time" post so my followers can submit their availability for a community event. | Post appears in feed with title, date range, and "Submit Availability" button. |
| Creator | As the creator, I want to close the poll and see when most followers are free. | Close action computes overlap; result displayed on post. |
| Follower | As a follower, I want to mark my available times on the grid. | Click "Submit Availability"; grid opens; submit; confirmation shown. |
| Follower | As a follower, I want to see the results after the creator closes the poll. | Post shows top best windows with participant counts. |
| Follower | As a follower, I want to update my availability before the deadline. | Re-open grid; update slots; save. |

### 1.3 Why This Is Needed Now

With MSG-009 providing the core Find-a-DateTime logic and the shared `AvailabilityGrid` component, extending to newsfeed posts is a low-effort, high-value addition. Creators frequently want to poll their audience for event timing — this feature eliminates the need for external scheduling tools.

---

## 2. Current State Analysis

### 2.1 Newsfeed Post Infrastructure

Posts are stored in `app_single_table` DynamoDB with PK `POST#{post_id}`, SK `META`. The `CreatePostRequest` model (see `app/routers/newsfeed.py:1276`) accepts various content types including polls (existing `app/services/newsfeed_polls.py`). Adding `kind="find_datetime"` follows the same extension pattern.
<!-- VERIFIED: app/services/newsfeed_polls.py exists; app/routers/newsfeed.py:3205 — newsfeed_polls_enabled check -->
<!-- VERIFIED: scripts/local-ddb-init.py:222 — app_single_table -->

### 2.2 Find-a-DateTime Backend (MSG-009)

<!-- NOTE: app/services/messaging_find_datetime.py does NOT exist yet — MSG-009 has not been implemented. This is a blocking dependency. New implementation required. -->
`app/services/messaging_find_datetime.py` provides:
- `create_find_datetime()` — creates poll in calendar table
- `submit_availability()` — stores user's available slots
- `close_and_compute()` — computes best overlapping windows
- `get_find_datetime()` — retrieves poll + availabilities + result

These functions are conversation-agnostic (they only reference `conversation_id` for linking). For newsfeed posts, we'll add a `post_id` linkage instead.

### 2.3 AvailabilityGrid Component (MSG-009)

<!-- NOTE: frontend/src/components/shared/AvailabilityGrid.tsx does NOT exist yet — MSG-009 has not been implemented. This is a blocking dependency. New implementation required. -->
The shared `AvailabilityGrid` component in `frontend/src/components/shared/AvailabilityGrid.tsx` handles the interactive time grid UI. It accepts `fromDate`, `toDate`, `startHour`, `endHour`, `slotDurationMinutes`, and callbacks for slot selection. This component is fully reusable for the newsfeed context.

### 2.4 Gaps

1. **No `find_datetime` post kind** — newsfeed doesn't support this content type.
2. **No post-linked FADT storage** — MSG-009 links polls to conversations, not posts.
3. **No FADT in CreatePost composer** — no UI for creating FADT posts.
4. **No FADT rendering in PostCard** — no card component for FADT posts in feed.
5. **No post-level FADT endpoints** — need `/posts/find-datetime/*` routes.

---

## 3. Technical Design

### 3.1 Architecture & Data Flow

```
                    Find-a-DateTime Post Creation Flow
  ┌──────────────┐     ┌────────────────────┐     ┌──────────────┐
  │  CreatePost   │────>│ POST /posts/       │────>│  DynamoDB     │
  │  (frontend)   │     │  find-datetime     │     │               │
  │               │     │  (newsfeed.py)      │     │  app_single   │
  │  title +      │     │                    │     │  _table       │
  │  from_date +  │     │  1. create post    │     │  PK=POST#id   │
  │  to_date +    │     │  2. create FADT    │     │  SK=META       │
  │  hours +      │     │     poll in cal    │     │               │
  │  body         │     │     table          │     │  calendar     │
  └──────────────┘     └────────────────────┘     │  PK=FADT#pid  │
                                                   └──────────────┘

                    Availability Submission Flow
  ┌──────────────┐     ┌────────────────────┐     ┌──────────────┐
  │ Availability  │────>│ POST /posts/find-  │────>│  calendar     │
  │ Grid (shared) │     │  datetime/{id}/    │     │  table        │
  │               │     │  availability      │     │               │
  │  selected     │     │                    │     │  PK=FADT#pid  │
  │  time slots   │     │  submit_avail()    │     │  SK=AVAIL#usr │
  └──────────────┘     └────────────────────┘     └──────────────┘

                    Close & Compute Flow
  ┌──────────────┐     ┌────────────────────┐     ┌──────────────┐
  │  Creator      │────>│ POST /posts/find-  │────>│  calendar     │
  │  clicks Close │     │  datetime/{id}/    │     │  table        │
  │               │     │  close             │     │               │
  │               │     │                    │     │  PK=FADT#pid  │
  │               │     │  close_and_compute │     │  status=closed│
  │               │     │  → best_windows    │     │  best_windows │
  └──────────────┘     └────────────────────┘     └──────────────┘
```

### 3.2 Data Model Extension

The Find-a-DateTime poll record (stored in `calendar` table with PK `FADT#{poll_id}`) will be extended with an optional `post_id` field:

| Field | Type | Description |
|-------|------|-------------|
| `post_id` | String (optional) | Post this poll belongs to (null for conversation-linked) |

The post item in `app_single_table` stores:

| Field | Type | Description |
|-------|------|-------------|
| `find_datetime_id` | String | `fadt_<uuid4_hex>` |
| `post_kind` | String | `"find_datetime"` |

### 3.3 Detailed DynamoDB Access Patterns

| Access Pattern | Table | Key Condition | Filter | Use Case |
|---------------|-------|---------------|--------|----------|
| Create FADT post | `app_single_table` | PK=`POST#{post_id}`, SK=`META` | -- | Write new post with `post_kind=find_datetime`, `find_datetime_id` |
| Create FADT poll | `calendar` | PK=`FADT#{poll_id}`, SK=`META` | -- | Write poll record with `post_id`, dates, hours, deadline |
| Submit availability | `calendar` | PK=`FADT#{poll_id}`, SK=`AVAIL#{user_sub}` | -- | Write user's selected time slots |
| Update availability | `calendar` | PK=`FADT#{poll_id}`, SK=`AVAIL#{user_sub}` | -- | Overwrite previous slot selection |
| List all availabilities | `calendar` | PK=`FADT#{poll_id}`, SK `begins_with("AVAIL#")` | -- | Fetch all submissions for overlap computation |
| Close poll + compute | `calendar` | PK=`FADT#{poll_id}`, SK=`META` | -- | Update status=closed, write best_windows |
| Get FADT poll details | `calendar` | PK=`FADT#{poll_id}`, SK=`META` | -- | Read poll metadata + results for rendering |
| List FADT posts in feed | `app_single_table` GSI1 | GSI1PK=`FEED#{user_id}` | `post_kind=find_datetime` | Filter feed for FADT posts only (optional) |

### 3.4 Backend Service Extension

**File**: `app/services/messaging_find_datetime.py`

Add `post_id` parameter to `create_find_datetime()`:

```python
def create_find_datetime(
    *,
    conversation_id: str = None,  # For MSG-009
    post_id: str = None,          # For FEED-003
    creator_sub: str,
    title: str,
    from_date: str,
    to_date: str,
    start_hour: int,
    end_hour: int,
    slot_duration_minutes: int,
    deadline_hours: int = 48,
) -> dict:
    # Exactly one of conversation_id or post_id must be set
    ...
```

The `submit_availability()` and `close_and_compute()` functions remain unchanged — they operate on `poll_id` regardless of context.

Access control for post-linked polls:
- Anyone can submit availability (the post is public/follower-visible)
- Only the post creator can close the poll

### 3.5 Backend Router

**File**: `app/routers/newsfeed.py`

```python
class CreateFindDateTimePostIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    from_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    to_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    start_hour: int = Field(..., ge=0, le=23)
    end_hour: int = Field(..., ge=1, le=24)
    slot_duration_minutes: int = Field(default=30)
    deadline_hours: int = Field(default=48, ge=1, le=336)
    body: str = Field(default="", max_length=5000)  # Optional description text

@router.post("/posts/find-datetime", status_code=201)
def create_find_datetime_post(body: CreateFindDateTimePostIn, ctx=Depends(require_ui_session)):
    """Create a Find-a-DateTime newsfeed post."""
    user_sub = ctx["user_sub"]
    post_id = f"p_{uuid4().hex}"

    # Create the post item
    # Create the FADT poll linked to post_id
    # Return post + poll data

@router.post("/posts/find-datetime/{poll_id}/availability")
def submit_post_availability(poll_id: str, body: SubmitAvailabilityIn, ctx=Depends(require_ui_session)):
    """Submit availability for a post-linked Find-a-DateTime poll."""
    # Delegates to messaging_find_datetime.submit_availability()

@router.post("/posts/find-datetime/{poll_id}/close")
def close_post_find_datetime(poll_id: str, ctx=Depends(require_ui_session)):
    """Close a post-linked Find-a-DateTime poll (creator only)."""
    # Delegates to messaging_find_datetime.close_and_compute()

@router.get("/posts/find-datetime/{poll_id}")
def get_post_find_datetime(poll_id: str, ctx=Depends(require_ui_session)):
    """Get Find-a-DateTime poll details for a post."""
    # Delegates to messaging_find_datetime.get_find_datetime()
```

### 3.6 API Request/Response Examples

**Create FADT post**:

```
POST /ui/posts/find-datetime
Content-Type: application/json
x-csrf-token: <csrf>

{
  "title": "Community Meetup - When are you free?",
  "from_date": "2026-06-05",
  "to_date": "2026-06-07",
  "start_hour": 9,
  "end_hour": 21,
  "slot_duration_minutes": 60,
  "deadline_hours": 72,
  "body": "Let's find the best time for our monthly community meetup! Mark your availability below."
}
```

**Response (201)**:
```json
{
  "post_id": "p_a1b2c3d4e5f6",
  "user_id": "alice@test.local",
  "user_name": "Alice Creator",
  "post_kind": "find_datetime",
  "find_datetime_id": "fadt_7a8b9c0d1e2f",
  "body": "Let's find the best time for our monthly community meetup!",
  "created_at": 1748520100,
  "like_count": 0,
  "comment_count": 0
}
```

**Submit availability**:

```
POST /ui/posts/find-datetime/fadt_7a8b9c0d1e2f/availability
Content-Type: application/json
x-csrf-token: <csrf>

{
  "slots": [
    "2026-06-05T09:00",
    "2026-06-05T10:00",
    "2026-06-05T14:00",
    "2026-06-06T09:00",
    "2026-06-06T10:00"
  ]
}
```

**Response (200)**:
```json
{
  "ok": true,
  "participant_count": 5,
  "your_slot_count": 5
}
```

**Close poll and compute results**:

```
POST /ui/posts/find-datetime/fadt_7a8b9c0d1e2f/close
x-csrf-token: <csrf>
```

**Response (200)**:
```json
{
  "status": "closed",
  "participant_count": 8,
  "best_windows": [
    {
      "start": "2026-06-05T10:00",
      "end": "2026-06-05T11:00",
      "count": 7,
      "participants": ["alice@test.local", "bob@test.local", "charlie@test.local", "dave@test.local", "eve@test.local", "frank@test.local", "grace@test.local"]
    },
    {
      "start": "2026-06-06T09:00",
      "end": "2026-06-06T10:00",
      "count": 6,
      "participants": ["alice@test.local", "bob@test.local", "charlie@test.local", "dave@test.local", "eve@test.local", "frank@test.local"]
    },
    {
      "start": "2026-06-05T14:00",
      "end": "2026-06-05T15:00",
      "count": 5,
      "participants": ["alice@test.local", "bob@test.local", "charlie@test.local", "dave@test.local", "eve@test.local"]
    }
  ]
}
```

**Get FADT poll details**:

```
GET /ui/posts/find-datetime/fadt_7a8b9c0d1e2f
```

**Response (200)**:
```json
{
  "poll_id": "fadt_7a8b9c0d1e2f",
  "title": "Community Meetup - When are you free?",
  "from_date": "2026-06-05",
  "to_date": "2026-06-07",
  "start_hour": 9,
  "end_hour": 21,
  "slot_duration_minutes": 60,
  "deadline_at": 1748779300,
  "status": "open",
  "participant_count": 5,
  "availabilities": [
    {
      "user_sub": "bob@test.local",
      "user_name": "Bob",
      "slots": ["2026-06-05T09:00", "2026-06-05T10:00"]
    }
  ],
  "best_windows": null
}
```

### 3.7 Pydantic Model Definitions

```python
# In app/models.py

class CreateFindDateTimePostIn(BaseModel):
    """Request model for creating a Find-a-DateTime newsfeed post."""
    title: str = Field(..., min_length=1, max_length=200)
    from_date: str = Field(
        ...,
        pattern=r"^\d{4}-\d{2}-\d{2}$",
        description="Start date in YYYY-MM-DD format",
    )
    to_date: str = Field(
        ...,
        pattern=r"^\d{4}-\d{2}-\d{2}$",
        description="End date in YYYY-MM-DD format",
    )
    start_hour: int = Field(..., ge=0, le=23, description="Earliest hour of day (0-23)")
    end_hour: int = Field(..., ge=1, le=24, description="Latest hour of day (1-24)")
    slot_duration_minutes: int = Field(
        default=30,
        ge=15,
        le=120,
        description="Duration of each time slot in minutes",
    )
    deadline_hours: int = Field(
        default=48,
        ge=1,
        le=336,
        description="Hours from creation until submission deadline",
    )
    body: str = Field(
        default="",
        max_length=5000,
        description="Optional description text for the post",
    )

    @model_validator(mode="after")
    def validate_date_range(self):
        from datetime import datetime
        try:
            fd = datetime.strptime(self.from_date, "%Y-%m-%d")
            td = datetime.strptime(self.to_date, "%Y-%m-%d")
        except ValueError:
            raise ValueError("Invalid date format")
        if fd >= td:
            raise ValueError("from_date must be before to_date")
        if (td - fd).days > 14:
            raise ValueError("Date range cannot exceed 14 days")
        if self.start_hour >= self.end_hour:
            raise ValueError("start_hour must be less than end_hour")
        return self


class SubmitAvailabilityIn(BaseModel):
    """Request model for submitting availability on a FADT poll."""
    slots: List[str] = Field(
        ...,
        min_length=1,
        max_length=200,
        description="List of time slot strings in YYYY-MM-DDTHH:MM format",
    )


class FindDateTimePollOut(BaseModel):
    """Response model for FADT poll data."""
    poll_id: str
    title: str
    from_date: str
    to_date: str
    start_hour: int
    end_hour: int
    slot_duration_minutes: int
    deadline_at: int
    status: str  # "open" or "closed"
    participant_count: int = 0
    availabilities: List[Dict[str, Any]] = Field(default_factory=list)
    best_windows: Optional[List[Dict[str, Any]]] = None


class FindDateTimePostOut(BaseModel):
    """Response model for a FADT post (includes post + poll metadata)."""
    post_id: str
    user_id: str
    user_name: Optional[str] = None
    post_kind: Literal["find_datetime"] = "find_datetime"
    find_datetime_id: str
    body: str = ""
    created_at: int = 0
    like_count: int = 0
    comment_count: int = 0
```

### 3.8 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface FindDateTimePost extends FeedPost {
  find_datetime_id: string;
}

export interface FindDateTimePollData {
  poll_id: string;
  title: string;
  from_date: string;
  to_date: string;
  start_hour: number;
  end_hour: number;
  slot_duration_minutes: number;
  deadline_at: number;
  status: "open" | "closed";
  participant_count: number;
  availabilities: Array<{
    user_sub: string;
    user_name: string;
    slots: string[];
  }>;
  best_windows?: Array<{
    start: string;
    end: string;
    count: number;
    participants: string[];
  }>;
}
```

### 3.9 Frontend API

**File**: `frontend/src/api/endpoints/newsfeed.ts`

```typescript
export const createFindDateTimePost = (data: CreateFindDateTimePostIn) =>
  api.post<FindDateTimePost>("/ui/posts/find-datetime", data);

export const submitPostAvailability = (pollId: string, slots: string[]) =>
  api.post(`/ui/posts/find-datetime/${pollId}/availability`, { slots });

export const closePostFindDateTime = (pollId: string) =>
  api.post(`/ui/posts/find-datetime/${pollId}/close`);

export const getPostFindDateTime = (pollId: string) =>
  api.get<FindDateTimePollData>(`/ui/posts/find-datetime/${pollId}`);
```

### 3.10 Frontend Component Tree

```
PostCard (modified)
├── PostHeader (author, timestamp, overflow menu)
├── PostBody (text content, images)
├── FindDateTimeSection (new, conditional on post_kind=find_datetime)
│   ├── FindDateTimePostCard (new component)
│   │   ├── TitleDisplay (poll title, date range summary)
│   │   ├── ParticipantCount badge
│   │   ├── StatusBadge ("Open" / "Closed")
│   │   ├── DeadlineDisplay (countdown to deadline if open)
│   │   ├── SubmitButton → opens AvailabilityGridDialog
│   │   │   └── Dialog
│   │   │       ├── AvailabilityGrid (shared from MSG-009)
│   │   │       │   ├── DateHeaders (columns)
│   │   │       │   ├── TimeLabels (rows)
│   │   │       │   └── SlotCells (clickable grid cells)
│   │   │       ├── SelectedCount display
│   │   │       └── Submit / Cancel buttons
│   │   ├── CloseButton (creator only, when status=open)
│   │   └── ResultsPanel (when status=closed)
│   │       ├── BestWindowCard (top 3 windows)
│   │       │   ├── TimeRange display
│   │       │   ├── ParticipantCount
│   │       │   └── ParticipantAvatars (truncated list)
│   │       └── HeatMapGrid (visual overlay showing density)
├── PostActions (like, comment, tip, react)
└── CommentsThread (if expanded)

CreatePost (modified)
├── TextArea (body input)
├── ContentTypeToolbar
│   ├── ...existing buttons
│   └── FindTimeButton (new) ← opens FindDateTimeComposer
├── FindDateTimeComposer (conditional, reused from MSG-009)
│   ├── Input: title
│   ├── DateRangePicker: from_date / to_date
│   ├── HourSelectors: start_hour / end_hour
│   ├── SlotDurationSelect: 15 / 30 / 60 / 120 min
│   └── DeadlineHoursInput
└── PublishButton
```

### 3.11 Frontend Components

**FindDateTimePostCard** (`frontend/src/pages/feed/FindDateTimePostCard.tsx`):

- Renders as a card within PostCard when `post.post_kind === "find_datetime"`
- Shows title, date range, time window, participant count
- "Submit Availability" button opens AvailabilityGrid dialog
- Creator sees "Close Poll" button
- After close: shows top 3 best windows with participant names
- Heat map visualization of all availability data

**CreatePost Integration**:

Add "Find a Time" button to the content type selector in `CreatePost.tsx`:
```tsx
<Button variant="ghost" size="sm" onClick={() => setShowFindDateTime(true)}>
  <CalendarSearch className="h-4 w-4 mr-1" /> Find a Time
</Button>
```

Opens `FindDateTimeComposer` (from MSG-009, reused) in a dialog.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/pages/feed/FindDateTimePostCard.tsx` | Post card for FADT posts |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/services/messaging_find_datetime.py` | Add `post_id` parameter to `create_find_datetime()` |
| `app/routers/newsfeed.py` | Add FADT post endpoints |
| `app/models.py` | Add `CreateFindDateTimePostIn`, `FindDateTimePollOut`, `FindDateTimePostOut` models |
| `frontend/src/api/types.ts` | Add FADT post types |
| `frontend/src/api/endpoints/newsfeed.ts` | Add FADT API functions |
| `frontend/src/pages/feed/CreatePost.tsx` | Add "Find a Time" button + composer integration |
| `frontend/src/pages/feed/PostCard.tsx` | Render FindDateTimePostCard for FADT posts |

### 4.3 Step-by-Step Order

1. Extend `create_find_datetime()` with `post_id` parameter
2. Add newsfeed router endpoints
3. Add Pydantic models
4. Add frontend types and API client
5. Build FindDateTimePostCard
6. Integrate into CreatePost and PostCard
7. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/feed-find-datetime.spec.ts` — 24 tests across 6 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
const TOMORROW = new Date(Date.now() + 86400000).toISOString().split("T")[0];
const NEXT_WEEK = new Date(Date.now() + 7 * 86400000).toISOString().split("T")[0];
let fadtPollId: string;
let fadtPostId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice (creator) and Bob (follower) sessions
});
```

### 5.3 Section 300: FADT Post Creation API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 300.1 | Create FADT post with valid parameters | POST `/posts/find-datetime`; 201; response has `find_datetime_id`, `post_id` |
| 300.2 | FADT post appears in creator's feed | GET `/feed`; find post with `find_datetime_id` set |
| 300.3 | FADT poll data retrievable via poll endpoint | GET `/posts/find-datetime/{poll_id}`; `title`, `from_date`, `to_date` match |
| 300.4 | Reject FADT post with invalid date range | POST with `from_date > to_date`; 400 |

### 5.4 Section 301: FADT Post Availability & Results API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 301.1 | Bob submits availability on FADT post | POST `/posts/find-datetime/{id}/availability`; 200 |
| 301.2 | Alice submits availability on own FADT post | POST; 200; `participant_count` = 2 |
| 301.3 | Alice closes FADT poll | POST `/posts/find-datetime/{id}/close`; 200; `status=closed`, `best_windows` present |
| 301.4 | Best windows contain overlapping slots | `best_windows[0].count >= 2`; `best_windows[0].participants` includes both users |
| 301.5 | Bob cannot close Alice's FADT poll | Bob POST close; 403 |

### 5.5 Section 302: FADT Post Rendering (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 302.1 | FADT post shows title and date range | GET post; response has `find_datetime_id`, title matches |
| 302.2 | Closed FADT post includes best_windows in poll data | GET poll after close; `best_windows` array length > 0 |
| 302.3 | Participant count reflects submissions | GET poll; `participant_count` matches actual submissions |

### 5.6 Section 303: FADT Post Validation Edge Cases (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 303.1 | Reject date range exceeding 14 days | POST with 15-day range; 400; "Date range cannot exceed 14 days" |
| 303.2 | Reject start_hour >= end_hour | POST with `start_hour=18, end_hour=9`; 400/422 |
| 303.3 | Reject empty title | POST with `title=""`; 422; min_length validation |
| 303.4 | Reject deadline_hours > 336 (14 days) | POST with `deadline_hours=500`; 422; le validation |
| 303.5 | Accept slot_duration_minutes 15, 30, 60, 120 | POST with `slot_duration_minutes=60`; 201 |

### 5.7 Section 304: Availability Update & Deadline (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 304.1 | Update availability overwrites previous | Bob submits 3 slots; Bob resubmits with 5 slots; GET poll; Bob's slots count = 5 |
| 304.2 | Availability rejected on closed poll | Close poll; Bob submits; 400; "Poll is closed" |
| 304.3 | Empty slots array rejected | POST availability with `slots=[]`; 422 |
| 304.4 | Slots outside date range rejected | POST availability with slot outside from_date/to_date; 400 |

### 5.8 Section 305: FADT Post Interactions (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 305.1 | Like FADT post | POST `/posts/{id}/like`; 200; `like_count` incremented |
| 305.2 | Comment on FADT post | POST `/posts/{id}/comments`; 201; comment_count incremented |
| 305.3 | React to FADT post | POST `/posts/{id}/reactions` with emoji; 200; reactions_counts updated |

---

## 6. Error Handling

### 6.1 Error Matrix

| Scenario | HTTP Status | Error Code | Error Message | Recovery Action |
|----------|-------------|------------|---------------|-----------------|
| Invalid date range (from >= to) | 400 | `invalid_date_range` | "from_date must be before to_date" | Show form validation error on date pickers |
| Date range > 14 days | 400 | `date_range_exceeded` | "Date range cannot exceed 14 days" | Constrain date pickers to 14-day max |
| Non-creator closes poll | 403 | `forbidden` | "Only the creator can close this poll" | Hide Close button for non-creators |
| Availability after deadline | 400 | `deadline_passed` | "Submission deadline has passed" | Disable Submit Availability button; show deadline |
| Availability on closed poll | 400 | `poll_closed` | "Poll is closed" | Show "closed" badge; disable grid |
| Empty title | 422 | `validation_error` | Pydantic min_length validation | Show inline form error |
| start_hour >= end_hour | 400 | `invalid_hours` | "start_hour must be less than end_hour" | Show form validation error |
| Unauthenticated | 401 | `unauthorized` | "Authentication required" | Redirect to login |
| Poll not found | 404 | `not_found` | "Poll not found" | Show error message; return to feed |

---

## 7. Security Considerations

- Post-linked polls allow any authenticated user to submit availability (the post is visible in feed)
- Creator-only close enforcement via `creator_sub` check
- Slot validation prevents submission of slots outside the defined date/time range
- Deadline enforcement is server-side (not trusting client clocks)
- Availabilities are visible to all participants after close (by design for community scheduling)
- Rate limiting on availability submission: 10 per user per poll per hour

---

## 8. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Poll data fetch latency | < 200ms p95 | Single DDB query on FADT#{poll_id}; no joins |
| Availability grid render | < 100ms for 14-day grid | AvailabilityGrid uses virtualization for large grids; memoized cell components |
| Close & compute latency | < 500ms for 100 participants | Overlap computation is O(slots * participants); pre-sorted slot arrays |
| Heat map rendering | 60fps scroll | Canvas-based heat map for large grids; rasterized at render time |
| Feed query with FADT posts | < 200ms p95 | FADT posts are regular post items; no additional query needed |
| Many concurrent submissions | Consistent writes | DDB put_item is idempotent per user per poll; no race conditions |

---

## 9. Observability

### 9.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `fadt_post_created_total` | Counter | -- | Number of FADT posts created |
| `fadt_availability_submitted_total` | Counter | -- | Number of availability submissions |
| `fadt_poll_closed_total` | Counter | -- | Number of polls closed |
| `fadt_best_window_participants_avg` | Gauge | -- | Average participant count in best windows |

### 9.2 Logging

| Event | Level | Fields |
|-------|-------|--------|
| FADT post created | INFO | `post_id`, `poll_id`, `user_id`, `from_date`, `to_date` |
| Availability submitted | INFO | `poll_id`, `user_id`, `slot_count` |
| Poll closed | INFO | `poll_id`, `user_id`, `participant_count`, `best_window_count` |
| Availability rejected (deadline) | WARN | `poll_id`, `user_id`, `deadline_at` |
| Non-creator close attempt | WARN | `poll_id`, `user_id`, `creator_sub` |

### 9.3 Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| FADT poll close failures | > 10 errors/hour in close_and_compute | Medium |
| Availability submission rate | > 500 submissions/hour (DDB throttle risk) | Low |

---

## 10. Rollout Plan

### 10.1 Feature Flag

```python
# app/core/settings.py
find_datetime_posts_enabled: bool = os.environ.get("FIND_DATETIME_POSTS_ENABLED", "true").lower() == "true"
```

When disabled, the backend rejects `POST /posts/find-datetime` with 400 "Find-a-DateTime posts are not enabled". The frontend hides the "Find a Time" button in CreatePost.

### 10.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Backend only | Deploy backend endpoints; feature flag ON in dev only | 1 day | All unit tests pass |
| Phase 2: Internal testing | Enable for test accounts; test full flow with AvailabilityGrid | 2 days | E2E tests pass; manual QA with 5+ participants |
| Phase 3: GA | Enable for all users; monitor poll creation and submission rates | Permanent | No errors in Phase 2; submission latency < 200ms p95 |

---

## 11. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| Find-a-DateTime backend logic | MSG-009 | Required — **NOT YET IMPLEMENTED** (`app/services/messaging_find_datetime.py` does not exist) |
| AvailabilityGrid component | MSG-009 | Required — **NOT YET IMPLEMENTED** (`frontend/src/components/shared/AvailabilityGrid.tsx` does not exist) |
| FindDateTimeComposer | MSG-009 | Required (reused) — **NOT YET IMPLEMENTED** |

---

## Codebase References

### Existing Files (verified)
| File | Key References | Lines |
|------|---------------|-------|
| `app/routers/newsfeed.py` | `CreatePostRequest`, `_post_to_dict`, `create_post` | 1276, 1900, 3013 |
| `app/services/newsfeed_polls.py` | Existing poll system (pattern to follow) | - |
| `app/routers/newsfeed.py` | Poll creation in `create_post` | 3205-3209 |
| `scripts/local-ddb-init.py` | `app_single_table` definition | 222 |
| `app/services/social.py` | `get_following` (for follower audience) | 167 |

### Files That Do NOT Exist Yet (blocking dependencies from MSG-009)
| File | Purpose | Status |
|------|---------|--------|
| `app/services/messaging_find_datetime.py` | Find-a-DateTime backend logic | Not implemented |
| `frontend/src/components/shared/AvailabilityGrid.tsx` | Interactive time grid UI | Not implemented |
| `frontend/src/components/shared/FindDateTimeComposer.tsx` | FADT creation form | Not implemented |

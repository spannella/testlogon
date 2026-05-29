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

Posts are stored in `app_single_table` DynamoDB with PK `POST#{post_id}`, SK `META`. The `CreatePostRequest` model accepts various content types including polls (existing `newsfeed_polls.py`). Adding `kind="find_datetime"` follows the same extension pattern.

### 2.2 Find-a-DateTime Backend (MSG-009)

`app/services/messaging_find_datetime.py` provides:
- `create_find_datetime()` — creates poll in calendar table
- `submit_availability()` — stores user's available slots
- `close_and_compute()` — computes best overlapping windows
- `get_find_datetime()` — retrieves poll + availabilities + result

These functions are conversation-agnostic (they only reference `conversation_id` for linking). For newsfeed posts, we'll add a `post_id` linkage instead.

### 2.3 AvailabilityGrid Component (MSG-009)

The shared `AvailabilityGrid` component in `frontend/src/components/shared/AvailabilityGrid.tsx` handles the interactive time grid UI. It accepts `fromDate`, `toDate`, `startHour`, `endHour`, `slotDurationMinutes`, and callbacks for slot selection. This component is fully reusable for the newsfeed context.

### 2.4 Gaps

1. **No `find_datetime` post kind** — newsfeed doesn't support this content type.
2. **No post-linked FADT storage** — MSG-009 links polls to conversations, not posts.
3. **No FADT in CreatePost composer** — no UI for creating FADT posts.
4. **No FADT rendering in PostCard** — no card component for FADT posts in feed.
5. **No post-level FADT endpoints** — need `/posts/find-datetime/*` routes.

---

## 3. Technical Design

### 3.1 Data Model Extension

The Find-a-DateTime poll record (stored in `calendar` table with PK `FADT#{poll_id}`) will be extended with an optional `post_id` field:

| Field | Type | Description |
|-------|------|-------------|
| `post_id` | String (optional) | Post this poll belongs to (null for conversation-linked) |

The post item in `app_single_table` stores:

| Field | Type | Description |
|-------|------|-------------|
| `find_datetime_id` | String | `fadt_<uuid4_hex>` |
| `post_kind` | String | `"find_datetime"` |

### 3.2 Backend Service Extension

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

### 3.3 Backend Router

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

### 3.4 Frontend Types

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

### 3.5 Frontend API

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

### 3.6 Frontend Components

**FindDateTimePostCard** (`frontend/src/pages/feed/FindDateTimePostCard.tsx`):

- Renders as a card within PostCard when `post.post_kind === "find_datetime"`
- Shows title, date range, time window, participant count
- "Submit Availability" button → opens AvailabilityGrid dialog
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
| `app/models.py` | Add `CreateFindDateTimePostIn` model |
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

`frontend/e2e/feed-find-datetime.spec.ts` — 12 tests across 3 sections.

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

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Invalid date range | 400 | "from_date must be before to_date" |
| Date range > 14 days | 400 | "Date range cannot exceed 14 days" |
| Non-creator closes poll | 403 | "Only the creator can close this poll" |
| Availability after deadline | 400 | "Submission deadline has passed" |
| Availability on closed poll | 400 | "Poll is closed" |

---

## 7. Security Considerations

- Post-linked polls allow any authenticated user to submit availability (the post is visible in feed)
- Creator-only close enforcement via `creator_sub` check
- Slot validation prevents submission of slots outside the defined date/time range
- Deadline enforcement is server-side (not trusting client clocks)

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| Find-a-DateTime backend logic | MSG-009 | Required |
| AvailabilityGrid component | MSG-009 | Required |
| FindDateTimeComposer | MSG-009 | Required (reused) |

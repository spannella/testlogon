# FEED-005: Countdown Newsfeed Posts

**Ticket**: FEED-005
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-29
**Priority**: Low
**Estimated effort**: 3-4 days
**Depends on**: MSG-010 (Countdown Messages — CountdownCard component)

---

## 1. Overview & Motivation

### 1.1 Purpose

FEED-005 adds countdown timer posts to the newsfeed. Creators can publish a post with a live countdown to a target datetime, optionally linked to a scheduled broadcast, call, or calendar event. When the countdown reaches zero, a contextual action button ("Watch Live", "Join Call") appears. This builds anticipation for upcoming events and drives engagement in the feed.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to publish a countdown post for an upcoming livestream. | Post appears in feed with title + live ticking timer; "Watch Live" button at zero. |
| Creator | As a creator, I want to add description text alongside a countdown. | Both countdown and text body displayed on the post. |
| Creator | As a creator, I want to schedule a countdown post to publish at a specific time. | Use existing `publish_at` field; post appears in feed at scheduled time with countdown already running. |
| Viewer | As a viewer, I want to see the countdown ticking in real time in my feed. | Timer updates every second without page refresh. |
| Viewer | As a viewer, I want to react to, comment on, and tip countdown posts like any other post. | All standard post interactions work. |

### 1.3 Why This Is Needed Now

With the CountdownCard component from MSG-010 already built, extending it to newsfeed posts is a small incremental effort. Countdown posts are a proven engagement driver — they create urgency and anticipation that increases viewers at event start time.

---

## 2. Current State Analysis

### 2.1 Post Creation

Posts are created via `create_post()` (line 3013) in `app/routers/newsfeed.py`. The `CreatePostRequest` model (line 1276) accepts various fields including `image_urls`, `video_id` (FEED-001), scheduling fields, and lock fields. Adding countdown fields follows the same extension pattern.
<!-- VERIFIED: app/routers/newsfeed.py:1276 — CreatePostRequest; :3013 — create_post -->

### 2.2 CountdownCard Component (MSG-010)

<!-- NOTE: frontend/src/pages/messages/CountdownCard.tsx does NOT exist yet — MSG-010 has not been implemented. -->
<!-- NOTE: frontend/src/components/shared/CountdownCard.tsx also does NOT exist. -->
<!-- This is a blocking dependency. New implementation required. -->
`frontend/src/pages/messages/CountdownCard.tsx` renders a live countdown timer with:
- Title display
- Days/hours/minutes/seconds countdown
- "Time's up!" / "Event started!" state at zero
- Optional "Watch Live" / "Join Call" buttons for linked events
- `data-testid="countdown-card"` for E2E targeting

This component is reusable as-is in the newsfeed PostCard.

### 2.3 Scheduled Posts

The existing `publish_at` field on posts allows scheduling. A countdown post with `publish_at` set will appear in the feed at the scheduled time with the countdown already running (the target datetime is independent of publish time).

### 2.4 Gaps

1. **No countdown fields on posts** — no `countdown_title`, `target_datetime` on post model.
2. **No countdown rendering in PostCard** — PostCard doesn't render CountdownCard.
3. **No countdown option in CreatePost** — composer has no countdown creation UI.
4. **No validation for countdown posts** — `target_datetime` must be future, event linking validated.

---

## 3. Technical Design

### 3.1 Architecture & Data Flow

```
                        Countdown Post Creation Flow
  ┌──────────────┐     ┌────────────────┐     ┌──────────────┐
  │   CreatePost  │────>│  POST /posts   │────>│  DynamoDB     │
  │   (frontend)  │     │  (newsfeed.py) │     │  app_single   │
  │               │     │                │     │  _table       │
  │  countdown    │     │  validate      │     │               │
  │  title +      │     │  target_dt >   │     │  PK=POST#id   │
  │  target_dt +  │     │  now_ts()      │     │  SK=META       │
  │  event_type   │     │                │     │               │
  └──────────────┘     └────────────────┘     └──────────────┘
                                                      │
                                                      v
  ┌──────────────┐     ┌────────────────┐     ┌──────────────┐
  │   PostCard    │<────│  GET /feed     │<────│  GSI1PK=      │
  │  (frontend)   │     │  (newsfeed.py) │     │  FEED#user    │
  │               │     │                │     │               │
  │  CountdownCard│     │  _post_to_dict │     │  countdown_   │
  │  renders live │     │  includes      │     │  title,       │
  │  timer + CTA  │     │  countdown     │     │  target_dt    │
  │  button       │     │  fields        │     │               │
  └──────────────┘     └────────────────┘     └──────────────┘
```

### 3.2 Post Model Extension

Add to `CreatePostRequest` in `app/routers/newsfeed.py`:

```python
class CreatePostRequest(ContentFieldsMixin):
    # ... existing fields ...
    # Countdown fields (FEED-005)
    post_kind: Optional[str] = Field(
        default=None,
        pattern=r"^(text|countdown|find_datetime)$",
        description="Post content kind. Default is text."
    )
    countdown_title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    target_datetime: Optional[int] = Field(default=None, description="UTC Unix timestamp for countdown target")
    associated_event_type: Optional[str] = Field(
        default=None,
        pattern=r"^(broadcast|call|calendar|custom)$",
    )
    associated_event_id: Optional[str] = Field(default=None, max_length=128)
```

### 3.3 Detailed DynamoDB Access Patterns

| Access Pattern | Table | Key Condition | Filter | Use Case |
|---------------|-------|---------------|--------|----------|
| Create countdown post | `app_single_table` | PK=`POST#{post_id}`, SK=`META` | — | Write new post with countdown fields |
| List feed with countdowns | `app_single_table` GSI1 | GSI1PK=`FEED#{user_id}`, GSI1SK desc | — | Feed query returns countdown posts alongside normal posts |
| Get single post | `app_single_table` | PK=`POST#{post_id}`, SK=`META` | — | Get post detail with countdown fields |
| List scheduled countdowns | `app_single_table` GSI1 | GSI1PK=`FEED#{user_id}` | `post_kind=countdown AND status=scheduled` | Creator views upcoming countdown posts |
| Query by event link | `app_single_table` GSI2 | GSI2PK=`EVT#{event_type}#{event_id}` | — | Find countdown posts linked to a specific broadcast/call/calendar event |
| Delete expired countdown | `app_single_table` | PK=`POST#{post_id}`, SK=`META` | — | Soft-delete countdown post where target_datetime < now - retention_window |

**Example DynamoDB Item** (countdown post with broadcast link):

```json
{
  "pk": {"S": "POST#p_7a8b9c0d1e2f"},
  "sk": {"S": "META"},
  "GSI1PK": {"S": "FEED#alice@test.local"},
  "GSI1SK": {"N": "1748520100"},
  "GSI2PK": {"S": "EVT#broadcast#bcast_abc123"},
  "GSI2SK": {"N": "1748520100"},
  "post_id": {"S": "p_7a8b9c0d1e2f"},
  "user_id": {"S": "alice@test.local"},
  "post_kind": {"S": "countdown"},
  "countdown_title": {"S": "Season 2 Premiere Livestream"},
  "target_datetime": {"N": "1748700000"},
  "associated_event_type": {"S": "broadcast"},
  "associated_event_id": {"S": "bcast_abc123"},
  "body": {"S": "Get ready for the Season 2 premiere! Set your alarms!"},
  "created_at": {"N": "1748520100"},
  "like_count": {"N": "0"},
  "comment_count": {"N": "0"},
  "status": {"S": "active"},
  "reactions": {"M": {}}
}
```

**Example DynamoDB Item** (custom countdown, no event link):

```json
{
  "pk": {"S": "POST#p_zz990011aabb"},
  "sk": {"S": "META"},
  "GSI1PK": {"S": "FEED#alice@test.local"},
  "GSI1SK": {"N": "1748521000"},
  "post_id": {"S": "p_zz990011aabb"},
  "user_id": {"S": "alice@test.local"},
  "post_kind": {"S": "countdown"},
  "countdown_title": {"S": "New Year 2027 Countdown"},
  "target_datetime": {"N": "1798761600"},
  "associated_event_type": {"S": "custom"},
  "body": {"S": "Happy New Year everyone!"},
  "created_at": {"N": "1748521000"},
  "like_count": {"N": "0"},
  "comment_count": {"N": "0"},
  "status": {"S": "active"}
}
```

### 3.4 Post Creation Validation

In `create_post()`:

```python
if req.post_kind == "countdown":
    if not req.countdown_title:
        raise HTTPException(status_code=400, detail="countdown_title required for countdown posts")
    if not req.target_datetime or req.target_datetime <= now_ts():
        raise HTTPException(status_code=400, detail="target_datetime must be in the future")
    if req.associated_event_type and req.associated_event_type != "custom" and not req.associated_event_id:
        raise HTTPException(status_code=400, detail="associated_event_id required for non-custom events")
```

Store countdown fields in post item:

```python
post_item = {
    # ... existing fields ...
    "post_kind": req.post_kind or "text",
    "countdown_title": req.countdown_title,
    "target_datetime": req.target_datetime,
    "associated_event_type": req.associated_event_type,
    "associated_event_id": req.associated_event_id,
}
```

### 3.5 Post Response Extension

In `_post_to_dict()`:

```python
return {
    # ... existing fields ...
    "post_kind": post.get("post_kind", "text"),
    "countdown_title": post.get("countdown_title"),
    "target_datetime": post.get("target_datetime"),
    "associated_event_type": post.get("associated_event_type"),
    "associated_event_id": post.get("associated_event_id"),
}
```

### 3.6 API Request/Response Examples

**Create countdown post** (curl):

```bash
curl -X POST http://localhost:8000/ui/posts \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_1" \
  -d '{
    "post_kind": "countdown",
    "countdown_title": "Season 2 Premiere Livestream",
    "target_datetime": 1748700000,
    "associated_event_type": "broadcast",
    "associated_event_id": "bcast_abc123",
    "body": "Get ready for the Season 2 premiere! Set your alarms!"
  }'
```

**Response (201)**:
```json
{
  "post_id": "p_7a8b9c0d1e2f",
  "user_id": "alice@test.local",
  "post_kind": "countdown",
  "countdown_title": "Season 2 Premiere Livestream",
  "target_datetime": 1748700000,
  "associated_event_type": "broadcast",
  "associated_event_id": "bcast_abc123",
  "body": "Get ready for the Season 2 premiere! Set your alarms!",
  "created_at": 1748520100,
  "like_count": 0,
  "comment_count": 0
}
```

**Create custom countdown post** (curl — no event link):

```bash
curl -X POST http://localhost:8000/ui/posts \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_1" \
  -d '{
    "post_kind": "countdown",
    "countdown_title": "New Year 2027",
    "target_datetime": 1798761600,
    "associated_event_type": "custom",
    "body": "Counting down to midnight!"
  }'
```

**Response (201)**:
```json
{
  "post_id": "p_zz990011aabb",
  "user_id": "alice@test.local",
  "post_kind": "countdown",
  "countdown_title": "New Year 2027",
  "target_datetime": 1798761600,
  "associated_event_type": "custom",
  "body": "Counting down to midnight!",
  "created_at": 1748521000,
  "like_count": 0,
  "comment_count": 0
}
```

**Get feed with countdown posts** (curl):

```bash
curl -X GET "http://localhost:8000/ui/feed?limit=20" \
  -H "Cookie: ui_session=sess_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..."
```

**Response (200)**:
```json
{
  "posts": [
    {
      "post_id": "p_7a8b9c0d1e2f",
      "user_id": "alice@test.local",
      "user_name": "Alice Creator",
      "post_kind": "countdown",
      "countdown_title": "Season 2 Premiere Livestream",
      "target_datetime": 1748700000,
      "associated_event_type": "broadcast",
      "associated_event_id": "bcast_abc123",
      "body": "Get ready for the Season 2 premiere!",
      "created_at": 1748520100,
      "like_count": 12,
      "comment_count": 3,
      "reactions_counts": {"fire": 5, "heart": 2}
    }
  ]
}
```

**Get single countdown post** (curl):

```bash
curl -X GET http://localhost:8000/ui/posts/p_7a8b9c0d1e2f \
  -H "Cookie: ui_session=sess_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..."
```

**Response (200)**:
```json
{
  "post_id": "p_7a8b9c0d1e2f",
  "user_id": "alice@test.local",
  "post_kind": "countdown",
  "countdown_title": "Season 2 Premiere Livestream",
  "target_datetime": 1748700000,
  "associated_event_type": "broadcast",
  "associated_event_id": "bcast_abc123",
  "body": "Get ready for the Season 2 premiere!",
  "created_at": 1748520100,
  "like_count": 12,
  "comment_count": 3,
  "reactions_counts": {"fire": 5, "heart": 2},
  "unlocked": true
}
```

**Error: past target_datetime** (curl):

```bash
curl -X POST http://localhost:8000/ui/posts \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_1" \
  -d '{
    "post_kind": "countdown",
    "countdown_title": "Already past",
    "target_datetime": 1600000000
  }'
```

**Response (400)**:
```json
{
  "detail": "target_datetime must be in the future"
}
```

### 3.7 Pydantic Model Definitions

```python
# In app/models.py

class CreateCountdownPostIn(BaseModel):
    """Request model for creating a countdown post."""
    post_kind: Literal["countdown"] = "countdown"
    countdown_title: str = Field(..., min_length=1, max_length=200)
    target_datetime: int = Field(..., gt=0, description="UTC Unix timestamp")
    associated_event_type: Optional[Literal["broadcast", "call", "calendar", "custom"]] = None
    associated_event_id: Optional[str] = Field(default=None, max_length=128)
    body: Optional[str] = Field(default=None, max_length=5000)
    image_urls: Optional[List[str]] = None
    lock_price_cents: Optional[int] = Field(default=None, ge=0)
    publish_at: Optional[int] = None

    @model_validator(mode="after")
    def validate_event_link(self):
        if self.associated_event_type and self.associated_event_type != "custom":
            if not self.associated_event_id:
                raise ValueError("associated_event_id required for non-custom events")
        return self

class CountdownPostOut(BaseModel):
    """Response model for countdown post data."""
    post_id: str
    user_id: str
    user_name: Optional[str] = None
    post_kind: Literal["countdown"] = "countdown"
    countdown_title: str
    target_datetime: int
    associated_event_type: Optional[str] = None
    associated_event_id: Optional[str] = None
    body: Optional[str] = None
    created_at: int = 0
    like_count: int = 0
    comment_count: int = 0
    reactions_counts: Optional[Dict[str, int]] = None
```

### 3.8 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface FeedPost {
  // ... existing fields ...
  post_kind?: "text" | "countdown" | "find_datetime" | null;
  countdown_title?: string | null;
  target_datetime?: number | null;
  associated_event_type?: "broadcast" | "call" | "calendar" | "custom" | null;
  associated_event_id?: string | null;
}
```

### 3.9 Frontend Component Tree

```
PostCard (modified)
├── PostHeader (author, timestamp, overflow menu)
├── PostBody (text content, images)
├── CountdownSection (new, conditional)
│   └── CountdownCard (from shared components)
│       ├── countdown_title display
│       ├── TimerDisplay
│       │   ├── DaysUnit
│       │   ├── HoursUnit
│       │   ├── MinutesUnit
│       │   └── SecondsUnit
│       ├── EventLinkButton (conditional on event_type)
│       │   ├── "Watch Live" (broadcast)
│       │   ├── "Join Call" (call)
│       │   ├── "View Event" (calendar)
│       │   └── (none for custom)
│       └── "Time's up!" state (when target_datetime <= now)
├── PostActions (like, comment, tip, react)
└── CommentsThread (if expanded)

CreatePost (modified)
├── TextArea (body input)
├── ContentTypeToolbar
│   ├── ImageButton
│   ├── PollButton
│   ├── CountdownButton (new) ← opens CountdownComposer
│   └── ...other buttons
├── CountdownComposer (conditional, new)
│   ├── Input: countdown_title
│   ├── DateTimePicker: target_datetime
│   ├── Select: associated_event_type
│   └── Input: associated_event_id (if event_type !== "custom")
├── SchedulePanel (existing)
└── PublishButton
```

### 3.10 PostCard Integration

**File**: `frontend/src/pages/feed/PostCard.tsx`

```tsx
{post.post_kind === "countdown" && post.countdown_title && post.target_datetime && (
  <div className="mt-3">
    <CountdownCard
      title={post.countdown_title}
      targetDatetime={post.target_datetime}
      associatedEventType={post.associated_event_type || "custom"}
      associatedEventId={post.associated_event_id}
    />
  </div>
)}
```

Import `CountdownCard` from the messages page (or move to `components/shared/`):

```typescript
import { CountdownCard } from "@/components/shared/CountdownCard";
```

### 3.11 CreatePost Integration

Add countdown creation to `CreatePost.tsx`:

```tsx
<Button variant="ghost" size="sm" onClick={() => setCountdownMode(true)}>
  <Timer className="h-4 w-4 mr-1" /> Countdown
</Button>

{countdownMode && (
  <div className="border rounded-md p-3 space-y-2">
    <Input placeholder="Countdown title" value={countdownTitle} onChange={...} />
    <DateTimePicker value={targetDatetime} onChange={...} />
    <Select value={eventType} onValueChange={...}>
      <SelectItem value="custom">Custom</SelectItem>
      <SelectItem value="broadcast">Broadcast</SelectItem>
      <SelectItem value="call">Call</SelectItem>
      <SelectItem value="calendar">Calendar Event</SelectItem>
    </Select>
    {eventType !== "custom" && (
      <Input placeholder="Event ID" value={eventId} onChange={...} />
    )}
  </div>
)}
```

Submit adds countdown fields to the create post payload:

```typescript
const payload = {
  ...buildContentPayload(body, editorMode, richDoc),
  post_kind: countdownMode ? "countdown" : undefined,
  countdown_title: countdownMode ? countdownTitle : undefined,
  target_datetime: countdownMode ? Math.floor(targetDatetime.getTime() / 1000) : undefined,
  associated_event_type: countdownMode ? eventType : undefined,
  associated_event_id: countdownMode && eventType !== "custom" ? eventId : undefined,
};
```

---

## 4. Implementation Plan

### 4.1 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/newsfeed.py` | Extend `CreatePostRequest` with countdown fields; add validation in `create_post`; extend `_post_to_dict` |
| `app/models.py` | Add `CreateCountdownPostIn`, `CountdownPostOut` models |
| `frontend/src/api/types.ts` | Add countdown fields to `FeedPost` |
| `frontend/src/pages/feed/PostCard.tsx` | Render CountdownCard for countdown posts |
| `frontend/src/pages/feed/CreatePost.tsx` | Add countdown creation UI |

### 4.2 Files to Move/Share

| From | To | Reason |
|------|----|--------|
| `frontend/src/pages/messages/CountdownCard.tsx` | `frontend/src/components/shared/CountdownCard.tsx` | Shared between messaging and newsfeed |

### 4.3 Step-by-Step Order

1. Move CountdownCard to shared components
2. Extend CreatePostRequest with countdown fields
3. Add validation in create_post
4. Extend _post_to_dict with countdown fields
5. Add frontend types
6. Integrate CountdownCard into PostCard
7. Add countdown creation UI to CreatePost
8. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/feed-countdown-posts.spec.ts` — 20 tests across 5 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
const FUTURE_TS = Math.floor(Date.now() / 1000) + 7200; // 2 hours from now
let countdownPostId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice and Bob sessions
});
```

### 5.3 Section 309: Countdown Post Creation API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 309.1 | Create countdown post with valid parameters | POST `/posts` with `post_kind=countdown`, `countdown_title`, `target_datetime`; 200/201; response has all countdown fields |
| 309.2 | Countdown post with body text | POST with `body` and countdown fields; response has both `body` and `countdown_title` |
| 309.3 | Reject countdown post with past target_datetime | POST with `target_datetime` in past; 400 |
| 309.4 | Reject broadcast countdown without event ID | POST `associated_event_type=broadcast` without `associated_event_id`; 400 |

### 5.4 Section 310: Countdown Post in Feed (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 310.1 | Countdown post appears in creator's feed | GET `/feed`; find post with `post_kind=countdown` |
| 310.2 | Countdown post has all countdown fields in response | `countdown_title`, `target_datetime`, `associated_event_type` present |
| 310.3 | Standard interactions work on countdown posts | POST comment + reaction on countdown post; both succeed |

### 5.5 Section 311: Countdown Post Rendering (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 311.1 | Countdown post renders timer card in feed | Navigate to feed; `[data-testid="countdown-card"]` visible on countdown post |
| 311.2 | Countdown card shows correct title | Card contains countdown_title text |
| 311.3 | Custom countdown shows no event link button | Card with `associated_event_type=custom` has no "Watch Live" or "Join" button |

### 5.6 Section 312: Countdown Post Edge Cases (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 312.1 | Countdown post with image | POST with `image_urls` + countdown fields; 201; both image and countdown rendered |
| 312.2 | Locked countdown post requires unlock | POST with `lock_price_cents=500` + countdown; viewer cannot see countdown_title until unlock |
| 312.3 | Custom event type has no associated_event_id | POST `associated_event_type=custom` without `associated_event_id`; 201 (custom does not require event ID) |
| 312.4 | Countdown post with very far future target | POST with `target_datetime` 365 days away; 201; countdown shows days count |
| 312.5 | Reject countdown without title | POST `post_kind=countdown` without `countdown_title`; 400 |

### 5.7 Section 313: Countdown Post Interactions (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 313.1 | Like countdown post | POST `/posts/{id}/like`; 200; `like_count` incremented |
| 313.2 | React to countdown post | POST `/posts/{id}/reactions` with emoji; 200; reactions_counts updated |
| 313.3 | Comment on countdown post | POST `/posts/{id}/comments` with text; 201; comment_count incremented |
| 313.4 | Tip countdown post | POST `/posts/{id}/tip` with amount; 200; tip_total_cents updated |
| 313.5 | Get individual countdown post | GET `/posts/{id}`; 200; all countdown fields present in response |

### 5.8 Section 314: Countdown Post Concurrent Access & Negative Tests (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 314.1 | Two users create countdown posts to same broadcast simultaneously | Both POST requests succeed with distinct `post_id` values; both reference same `associated_event_id` |
| 314.2 | Delete a countdown post | DELETE `/posts/{id}`; 200; subsequent GET returns 404 or `status=deleted` |
| 314.3 | Update countdown post body after creation | PATCH `/posts/{id}` with new `body` text; 200; countdown fields remain unchanged |
| 314.4 | Countdown post with empty body (title only) | POST with `countdown_title` + `target_datetime`, no `body`; 201; `body` is null in response |
| 314.5 | Countdown post with max-length title (200 chars) | POST with 200-char `countdown_title`; 201; title stored and returned in full |

### 5.9 Section 315: Countdown Post UI Composer Tests (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 315.1 | Countdown button toggles composer panel | Click Countdown toolbar button; countdown form fields appear; click again to dismiss |
| 315.2 | Submit disabled until required fields filled | With countdown mode on but no title, submit button disabled; fill title + datetime, button becomes enabled |
| 315.3 | Event type selector shows/hides event ID field | Select "Broadcast" → event ID input appears; select "Custom" → event ID input hidden |

---

## 6. Error Handling

### 6.1 Error Matrix

| Scenario | HTTP Status | Error Code | Error Message | Recovery Action |
|----------|-------------|------------|---------------|-----------------|
| target_datetime in past | 400 | `target_in_past` | "target_datetime must be in the future" | Client should validate before submit |
| Missing countdown_title | 400 | `missing_title` | "countdown_title required for countdown posts" | Show inline form error |
| Non-custom event without ID | 400 | `missing_event_id` | "associated_event_id required for non-custom events" | Show inline form error |
| Invalid post_kind | 422 | `validation_error` | Pydantic pattern validation | Show generic validation error |
| target_datetime too far (>2yr) | 400 | `target_too_far` | "target_datetime cannot be more than 2 years in the future" | Show date picker constraint |
| Invalid associated_event_id ref | 404 | `event_not_found` | "Associated event not found" | Show event picker error |
| Post not found | 404 | `not_found` | "Post not found" | Redirect to feed |
| Unauthenticated | 401 | `unauthorized` | "Authentication required" | Redirect to login |

---

## 7. Security Considerations

- target_datetime validated server-side (client cannot bypass future check)
- associated_event_id is a reference only — event's own ACL controls access
- Timer is client-side cosmetic display; no server resources consumed for ticking
- Countdown posts follow the same visibility rules as all posts (locked, deleted, etc.)
- No countdown-specific SSRF risk since event IDs are validated against known tables

---

## 8. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Countdown tick CPU on client | < 1% CPU per visible countdown | `requestAnimationFrame` with 1s throttle; only tick visible cards |
| Multiple countdowns in feed | Support 10+ visible countdowns | Shared single `setInterval(1000)` drives all countdown instances |
| Feed query latency | < 200ms p95 | No additional DDB query; countdown fields are on the same post item |
| CountdownCard bundle size | < 5KB gzipped | Shared component already loaded for messaging; no extra import cost |
| Event link resolution | Lazy load on CTA click | CTA button navigates to event page; no prefetch at render time |

---

## 9. Observability

### 9.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `countdown_post_created_total` | Counter | `event_type` | Number of countdown posts created |
| `countdown_post_viewed_total` | Counter | `state` (active/expired) | Number of countdown posts viewed |
| `countdown_cta_clicked_total` | Counter | `event_type` | CTA button clicks when countdown reaches zero |
| `countdown_post_expired_total` | Counter | `event_type` | Countdown posts where `target_datetime` has passed |
| `countdown_validation_failed_total` | Counter | `reason` (past_target, missing_title, missing_event_id) | Validation failures on countdown creation |
| `countdown_post_locked_total` | Counter | — | Countdown posts created with `lock_price_cents > 0` |
| `countdown_post_scheduled_total` | Counter | — | Countdown posts created with `publish_at` (scheduled) |

### 9.2 Logging

| Event | Level | Fields |
|-------|-------|--------|
| Countdown post created | INFO | `post_id`, `user_id`, `target_datetime`, `event_type`, `has_body`, `is_locked` |
| Invalid countdown target rejected | WARN | `user_id`, `target_datetime`, `reason` |
| Countdown CTA clicked | INFO | `post_id`, `user_id`, `event_type`, `event_id` |
| Countdown post expired (target_datetime passed) | DEBUG | `post_id`, `target_datetime`, `seconds_past` |
| Countdown post deleted | INFO | `post_id`, `user_id` |

### 9.3 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Countdown creation spike | > 100 countdown posts/hour for single user | Low | Review for spam/abuse |
| Countdown validation error rate | > 20% of countdown create requests fail validation | Medium | Check client-side validation logic |
| Countdown CTA dead links | > 5% of CTA clicks resolve to 404 event | High | Check event cleanup / referential integrity |

### 9.4 Dashboard Queries

**Countdown posts created per day** (Prometheus):
```promql
sum(increase(countdown_post_created_total[1d])) by (event_type)
```

**Active vs expired countdowns in feed views**:
```promql
sum(rate(countdown_post_viewed_total[5m])) by (state)
```

**CTA click-through rate** (percent of views that result in CTA click):
```promql
sum(rate(countdown_cta_clicked_total[1h])) / sum(rate(countdown_post_viewed_total{state="expired"}[1h])) * 100
```

---

## 10. Rollout Plan

### 10.1 Feature Flag

```python
# app/core/settings.py
countdown_posts_enabled: bool = os.environ.get("COUNTDOWN_POSTS_ENABLED", "true").lower() == "true"
```

### 10.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Backend only | Deploy backend with countdown fields; feature flag ON in dev only | 1 day | All unit tests pass |
| Phase 2: Internal testing | Enable for internal test accounts | 2 days | E2E tests pass; manual QA sign-off |
| Phase 3: Canary (5%) | Enable for 5% of creators via tenant flag | 2 days | Error rate < 0.1%; no UI regressions |
| Phase 4: GA | Enable for all users; remove feature flag guard | Permanent | No errors in Phase 3; positive engagement signal |

### 10.3 Migration Steps

1. Deploy backend changes with `COUNTDOWN_POSTS_ENABLED=false` (no new DB tables needed; countdown fields stored on existing post items)
2. Run `scripts/local-ddb-init.py` to add GSI2 for event-link lookups if not already present
3. Deploy frontend bundle with CountdownCard integration (hidden behind feature flag in CreatePost)
4. Flip `COUNTDOWN_POSTS_ENABLED=true` per rollout phase

### 10.4 Rollback Procedure

1. Set `COUNTDOWN_POSTS_ENABLED=false` — disables countdown creation in `create_post()`
2. Existing countdown posts continue to render (frontend CountdownCard is always included; only creation is gated)
3. If frontend regression: revert to previous frontend bundle; countdown posts degrade to showing raw `countdown_title` text without timer
4. No DynamoDB migration needed for rollback — countdown fields are optional attributes on post items

---

## 11. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| CountdownCard component | MSG-010 | Required — **NOT YET IMPLEMENTED** (neither `frontend/src/pages/messages/CountdownCard.tsx` nor `frontend/src/components/shared/CountdownCard.tsx` exist) |
| CreatePostRequest extension | Existing | Available (see `app/routers/newsfeed.py:1276`) |
| PostCard rendering | Existing | Available (see `frontend/src/pages/feed/PostCard.tsx`) |

---

## Codebase References

### Existing Files (verified)
| File | Key References | Lines |
|------|---------------|-------|
| `app/routers/newsfeed.py` | `CreatePostRequest` | 1276 |
| `app/routers/newsfeed.py` | `create_post` | 3013 |
| `app/routers/newsfeed.py` | `_post_to_dict` | 1900 |
| `frontend/src/pages/feed/PostCard.tsx` | Post card rendering | - |
| `frontend/src/pages/feed/CreatePost.tsx` | Post composer | - |
| `scripts/local-ddb-init.py` | `app_single_table` | 222 |

### Files That Do NOT Exist Yet (blocking dependency)
| File | Purpose | Status |
|------|---------|--------|
| `frontend/src/pages/messages/CountdownCard.tsx` | Countdown timer card (MSG-010) | Not implemented |
| `frontend/src/components/shared/CountdownCard.tsx` | Shared countdown card | Not implemented |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_countdown_posts.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_feed_005_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_feed_005_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_feed_005_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_feed_005_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_feed_005_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_feed_005_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_feed_005_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_feed_005_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/countdown-posts.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 10

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `COUNTDOWN_POSTS_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `COUNTDOWN_POSTS_ENABLED` must be enabled for tests to run
- Serial execution: run with `--workers 1` to avoid shared state conflicts
- Retry safety: tests use unique timestamps/UUIDs per run; safe to retry on failure

---

## Dependencies & Merge Safety

### Depends On

| Ticket | Status | What It Provides |
|--------|--------|-----------------|
| (none) | -- | This ticket has no upstream ticket dependencies |

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| FEED-008 | Enhanced post composer includes countdown option |

### Merge Strategy

**Independent** -- Changes are additive (new service files, new router, new frontend pages). Shared infrastructure files (`main.py`, `settings.py`, `tables.py`, `local-ddb-init.py`) receive only additive modifications.

### Merge Checklist

- [ ] All new DDB tables/GSIs added to `scripts/local-ddb-init.py`
- [ ] Settings added to `app/core/settings.py`
- [ ] Table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Frontend routes added to `App.tsx`
- [ ] Feature flag `COUNTDOWN_POSTS_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite

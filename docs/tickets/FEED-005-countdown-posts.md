# FEED-005: Countdown Newsfeed Posts

**Ticket**: FEED-005
**Author**: Engineering
**Status**: Design
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

Posts are created via `create_post()` in `app/routers/newsfeed.py`. The `CreatePostRequest` model accepts various fields including `image_urls`, `video_id` (FEED-001), scheduling fields (`publish_at`, `schedule_timezone`), and lock fields. Adding countdown fields follows the same extension pattern.

### 2.2 CountdownCard Component (MSG-010)

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

### 3.1 Post Model Extension

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

### 3.2 Post Creation Validation

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

### 3.3 Post Response Extension

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

### 3.4 Frontend Types

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

### 3.5 PostCard Integration

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

### 3.6 CreatePost Integration

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

`frontend/e2e/feed-countdown-posts.spec.ts` — 10 tests across 3 sections.

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

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| target_datetime in past | 400 | "target_datetime must be in the future" |
| Missing countdown_title | 400 | "countdown_title required for countdown posts" |
| Non-custom event without ID | 400 | "associated_event_id required for non-custom events" |
| Invalid post_kind | 422 | Pydantic pattern validation |

---

## 7. Security Considerations

- target_datetime validated server-side
- associated_event_id is a reference only — event's own ACL controls access
- Timer is client-side cosmetic display; no server resources consumed for ticking

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| CountdownCard component | MSG-010 | Required |

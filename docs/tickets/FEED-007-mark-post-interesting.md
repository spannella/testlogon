# FEED-007: Mark Post Interesting / Not Interesting

**Ticket**: FEED-007
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Low
**Estimated effort**: 3-4 days
**Depends on**: FEED-006 (Hide Post — hide behavior for "not interesting" signal)

---

## 1. Overview & Motivation

### 1.1 Purpose

FEED-007 adds signal-based feed ranking inputs by letting users mark posts as "interesting" or "not interesting." These signals serve two purposes: (1) immediate UX feedback — "not interesting" hides the post from the user's feed (reusing FEED-006 hide logic), and (2) aggregate ranking data — per-post counters (`interesting_count`, `not_interesting_count`) that can power future recommendation and ranking algorithms.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Viewer | As a viewer, I want to mark a post as "interesting" to signal I'd like more content like this. | Click "Interesting" in overflow menu; post marked; counter incremented. |
| Viewer | As a viewer, I want to mark a post as "not interesting" to hide it and signal I'd like less content like this. | Click "Not for me" in overflow menu; post hidden from feed; counter incremented. |
| Viewer | As a viewer, I want to undo my signal. | Delete signal via API; counter decremented; if was "not interesting", post reappears in feed. |
| Creator | As a creator, I want to see aggregate signal counts on my posts. | Post response includes `interesting_count` and `not_interesting_count`. |
| Platform | As the platform, I want to collect signal data for future feed ranking improvements. | Signals stored per user per post; aggregates maintained on post records. |

### 1.3 Why This Is Needed Now

Feed relevance is critical for user retention. Without explicit signals, the platform has no data to train ranking models. Collecting "interesting" / "not interesting" signals is the first step toward personalized feed ranking. The signals also provide immediate value by hiding unwanted content (via FEED-006 integration).

---

## 2. Current State Analysis

### 2.1 Existing Signals

Posts already have:
- **Likes**: `POST /posts/{id}/like` — simple like/unlike toggle
- **Reactions**: `POST /posts/{id}/reactions` — emoji reactions with counts
- **Comments**: Engagement signal from comment count
- **Tips**: Monetary engagement signal

These are all positive signals. There is no negative signal mechanism.

### 2.2 Hide Post (FEED-006)

FEED-006 provides `hide_post(user_sub, post_id)` and `unhide_post(user_sub, post_id)` functions. "Not interesting" will call `hide_post` in addition to storing the signal.

### 2.3 Post Storage

Posts in `app_single_table` have various counter fields (`like_count`, `comment_count`, `tip_total_cents`). Adding `interesting_count` and `not_interesting_count` follows the same atomic counter pattern.

### 2.4 Gaps

1. **No signal storage** — no per-user signal records.
2. **No aggregate counters** — no `interesting_count` / `not_interesting_count` on posts.
3. **No signal endpoints** — no API to submit or remove signals.
4. **No "Interesting" / "Not for me" UI** — no options in PostCard overflow menu.
5. **No integration with hide** — "not interesting" doesn't trigger hide.

---

## 3. Technical Design

### 3.1 Data Model

**Per-user signal** (billing table pattern):

| PK | SK | Fields |
|----|----|--------|
| `USER#{user_sub}` | `POST_SIGNAL#{post_id}` | `signal: String ("interesting" \| "not_interesting")`, `created_at: Number`, `post_id: String` |

**Post aggregate counters** (on post item in `app_single_table`):

| Field | Type | Description |
|-------|------|-------------|
| `interesting_count` | Number | Count of "interesting" signals |
| `not_interesting_count` | Number | Count of "not interesting" signals |

### 3.2 Backend Service

**File**: `app/services/feed_preferences.py` (extend from FEED-006)

```python
def signal_post(user_sub: str, post_id: str, signal: str) -> None:
    """Mark a post as interesting or not interesting."""
    # 1. Check for existing signal
    existing = _get_signal(user_sub, post_id)

    # 2. If same signal exists, no-op
    if existing and existing.get("signal") == signal:
        return

    # 3. If different signal exists, remove old signal's counter
    if existing:
        old_signal = existing["signal"]
        _decrement_signal_counter(post_id, old_signal)
        if old_signal == "not_interesting":
            unhide_post(user_sub, post_id)

    # 4. Store new signal
    T.billing.put_item(Item={
        "pk": f"USER#{user_sub}",
        "sk": f"POST_SIGNAL#{post_id}",
        "signal": signal,
        "created_at": now_ts(),
        "post_id": post_id,
    })

    # 5. Increment new signal's counter
    _increment_signal_counter(post_id, signal)

    # 6. If "not_interesting", also hide the post
    if signal == "not_interesting":
        hide_post(user_sub, post_id)

def remove_signal(user_sub: str, post_id: str) -> None:
    """Remove a signal from a post."""
    existing = _get_signal(user_sub, post_id)
    if not existing:
        return

    signal = existing["signal"]

    # Delete signal record
    T.billing.delete_item(Key={
        "pk": f"USER#{user_sub}",
        "sk": f"POST_SIGNAL#{post_id}",
    })

    # Decrement counter
    _decrement_signal_counter(post_id, signal)

    # If was "not_interesting", unhide
    if signal == "not_interesting":
        unhide_post(user_sub, post_id)

def _get_signal(user_sub: str, post_id: str) -> dict | None:
    resp = T.billing.get_item(Key={
        "pk": f"USER#{user_sub}",
        "sk": f"POST_SIGNAL#{post_id}",
    })
    return resp.get("Item")

def _increment_signal_counter(post_id: str, signal: str) -> None:
    field = f"{signal}_count"
    T.app_single_table.update_item(
        Key={"pk": f"POST#{post_id}", "sk": "META"},
        UpdateExpression=f"ADD {field} :one",
        ExpressionAttributeValues={":one": 1},
    )

def _decrement_signal_counter(post_id: str, signal: str) -> None:
    field = f"{signal}_count"
    T.app_single_table.update_item(
        Key={"pk": f"POST#{post_id}", "sk": "META"},
        UpdateExpression=f"ADD {field} :neg_one",
        ExpressionAttributeValues={":neg_one": -1},
    )
```

### 3.3 Backend Router

**File**: `app/routers/newsfeed.py`

```python
class PostSignalIn(BaseModel):
    signal: str = Field(..., pattern=r"^(interesting|not_interesting)$")

@router.post("/posts/{post_id}/signal", status_code=200)
def signal_post_endpoint(post_id: str, body: PostSignalIn, ctx=Depends(require_ui_session)):
    """Mark a post as interesting or not interesting."""
    user_sub = ctx["user_sub"]
    post = _get_post(post_id)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") == user_sub:
        raise HTTPException(status_code=400, detail="Cannot signal your own post")
    signal_post(user_sub, post_id, body.signal)
    return {"ok": True}

@router.delete("/posts/{post_id}/signal", status_code=200)
def remove_signal_endpoint(post_id: str, ctx=Depends(require_ui_session)):
    """Remove a signal from a post."""
    remove_signal(ctx["user_sub"], post_id)
    return {"ok": True}
```

### 3.4 Post Response Extension

In `_post_to_dict()`:

```python
return {
    # ... existing fields ...
    "interesting_count": int(post.get("interesting_count", 0)),
    "not_interesting_count": int(post.get("not_interesting_count", 0)),
}
```

### 3.5 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface FeedPost {
  // ... existing fields ...
  interesting_count?: number;
  not_interesting_count?: number;
}
```

### 3.6 Frontend API

**File**: `frontend/src/api/endpoints/newsfeed.ts`

```typescript
export const signalPost = (postId: string, signal: "interesting" | "not_interesting") =>
  api.post(`/ui/posts/${postId}/signal`, { signal });

export const removeSignal = (postId: string) =>
  api.delete(`/ui/posts/${postId}/signal`);
```

### 3.7 PostCard Enhancement

Add to the overflow menu in PostCard:

```tsx
{post.user_id !== currentUser.sub && (
  <>
    <DropdownMenuItem onClick={() => handleSignal(post.post_id, "interesting")}>
      <ThumbsUp className="h-4 w-4 mr-2" /> Interesting
    </DropdownMenuItem>
    <DropdownMenuItem onClick={() => handleSignal(post.post_id, "not_interesting")}>
      <ThumbsDown className="h-4 w-4 mr-2" /> Not for me
    </DropdownMenuItem>
  </>
)}
```

"Not for me" triggers hide + signal, with undo toast (same pattern as FEED-006):

```tsx
const handleSignal = async (postId: string, signal: string) => {
  await signalPostMutation.mutateAsync({ postId, signal });

  if (signal === "not_interesting") {
    toast({
      title: "Post hidden",
      description: "Thanks for the feedback. You'll see less content like this.",
      action: (
        <Button variant="outline" size="sm" onClick={() => handleRemoveSignal(postId)}>
          Undo
        </Button>
      ),
      duration: 10000,
    });
  } else {
    toast({ title: "Thanks for the feedback!", duration: 3000 });
  }
};
```

---

## 4. Implementation Plan

### 4.1 Files to Modify

| File | Changes |
|------|---------|
| `app/services/feed_preferences.py` | Add `signal_post`, `remove_signal` functions |
| `app/routers/newsfeed.py` | Add signal endpoints; include signal counts in `_post_to_dict` |
| `app/models.py` | Add `PostSignalIn` model |
| `frontend/src/api/types.ts` | Add signal counts to `FeedPost` |
| `frontend/src/api/endpoints/newsfeed.ts` | Add signal API functions |
| `frontend/src/pages/feed/PostCard.tsx` | Add "Interesting" and "Not for me" to overflow menu |

### 4.2 Step-by-Step Order

1. Add signal storage functions to `feed_preferences.py`
2. Add counter increment/decrement logic
3. Integrate with `hide_post` for "not_interesting"
4. Add router endpoints
5. Include counters in `_post_to_dict`
6. Add frontend types and API
7. Add menu options and toast to PostCard
8. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/feed-post-signals.spec.ts` — 10 tests across 3 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let alicePostId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice and Bob sessions
  // Alice creates a post
});
```

### 5.3 Section 320: Signal Post API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 320.1 | Mark post as "interesting" | POST `/posts/{id}/signal` with `signal=interesting`; 200 |
| 320.2 | Interesting count incremented | GET post; `interesting_count` = 1 |
| 320.3 | Mark post as "not_interesting" | POST with `signal=not_interesting`; 200 |
| 320.4 | "Not interesting" also hides post from feed | GET `/feed`; post not in results |

### 5.4 Section 321: Signal Remove & Toggle API (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 321.1 | Remove signal | DELETE `/posts/{id}/signal`; 200 |
| 321.2 | Counter decremented after remove | GET post; signal count back to 0 |
| 321.3 | Cannot signal own post | POST `/posts/{own_id}/signal`; 400; "Cannot signal your own post" |

### 5.5 Section 322: Signal UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 322.1 | "Interesting" option in overflow menu | Navigate to feed; open overflow; "Interesting" visible |
| 322.2 | "Not for me" option in overflow menu | "Not for me" visible in overflow menu |
| 322.3 | "Not for me" hides post and shows undo toast | Click "Not for me"; post hidden; toast with "Undo" visible |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Post not found | 404 | "Post not found" |
| Signal own post | 400 | "Cannot signal your own post" |
| Invalid signal value | 422 | Pydantic pattern validation |
| Remove non-existent signal | 200 | No-op (idempotent) |
| Duplicate signal | 200 | No-op (same signal already set) |

---

## 7. Security Considerations

- Users can only submit signals for their own accounts
- Signal data is private (users cannot see who signaled their posts)
- Aggregate counts are public (visible on post response)
- Counter manipulation prevented by server-side deduplication (one signal per user per post)

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Atomic counter updates | DynamoDB `ADD` operation is atomic; no race conditions |
| Signal change (interesting → not_interesting) | Two counter updates in sequence; eventual consistency is acceptable |
| Counter accuracy | Counters may drift by 1 in rare race conditions; periodic reconciliation job (future) |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| Hide Post functionality | FEED-006 | Required (hide_post/unhide_post functions) |

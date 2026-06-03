# FEED-007: Mark Post Interesting / Not Interesting

**Ticket**: FEED-007
**Author**: Engineering
**Status**: Implemented
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

FEED-006 provides `hide_post` at `app/routers/newsfeed.py:4051` (using `pk_hide` at line 820). "Not interesting" will call `hide_post` in addition to storing the signal.
<!-- VERIFIED: app/routers/newsfeed.py:4051 — hide_post; :820 — pk_hide -->
<!-- NOTE: unhide_post does not exist yet — FEED-006 unhide endpoint still needed -->

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

### 3.0 Architecture Diagram

```
                   Signal Post Flow (Interesting / Not Interesting)
  ┌──────────────┐     ┌──────────────────┐     ┌──────────────────┐
  │  PostCard     │────>│ POST /posts/     │────>│  DynamoDB          │
  │  (frontend)   │     │  {id}/signal     │     │  billing table     │
  │               │     │  newsfeed.py     │     │                    │
  │  Overflow:    │     │                  │     │  PK=USER#sub       │
  │  "Interesting"│     │  1. Check exist  │     │  SK=POST_SIGNAL#   │
  │  "Not for me" │     │     signal       │     │    {post_id}       │
  │               │     │  2. Swap counter │     │  signal=interesting │
  └──────┬───────┘     │  3. Put signal   │     │  /not_interesting   │
         │              │  4. Hide if neg  │     └──────────────────┘
         │              └──────────────────┘              │
         v                       │                        v
  ┌──────────────┐              │              ┌──────────────────┐
  │  Undo Toast   │              │              │  DynamoDB          │
  │  (10s for     │              │              │  app_single_table  │
  │  "not for me")│              └─────────────>│                    │
  │               │                             │  PK=POST#{post_id} │
  └──────────────┘                             │  SK=META            │
                                               │  interesting_count  │
  ┌──────────────┐     ┌──────────────────┐    │  not_interesting_   │
  │  Feed Query   │<────│ GET /feed        │    │  count              │
  │  (filtered)   │     │  newsfeed.py     │    │  (ADD :1 / ADD :-1) │
  │               │     │                  │    └──────────────────┘
  │  hidden_ids   │     │  hidden_ids      │
  │  excludes     │     │  includes posts  │
  │  "not for me" │     │  marked "not     │
  │  posts        │     │  interesting"    │
  └──────────────┘     └──────────────────┘
```

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

### 3.1b Detailed DynamoDB Access Patterns

| Access Pattern | Table | Key Condition | Filter | Use Case |
|---------------|-------|---------------|--------|----------|
| Store signal | `billing` | PK=`USER#{sub}`, SK=`POST_SIGNAL#{post_id}` | — | PutItem; write signal record |
| Get user signal for post | `billing` | PK=`USER#{sub}`, SK=`POST_SIGNAL#{post_id}` | — | GetItem; check for existing signal before toggle |
| Remove signal | `billing` | PK=`USER#{sub}`, SK=`POST_SIGNAL#{post_id}` | — | DeleteItem |
| List all signals by user | `billing` | PK=`USER#{sub}`, SK begins_with `POST_SIGNAL#` | — | Query; for analytics or export |
| Increment signal counter | `app_single_table` | PK=`POST#{post_id}`, SK=`META` | — | UpdateItem ADD `interesting_count :1` |
| Decrement signal counter | `app_single_table` | PK=`POST#{post_id}`, SK=`META` | — | UpdateItem ADD `interesting_count :-1` |

**Example DynamoDB Item** (signal record — interesting):

```json
{
  "pk": {"S": "USER#bob@test.local"},
  "sk": {"S": "POST_SIGNAL#p_7a8b9c0d1e2f"},
  "signal": {"S": "interesting"},
  "created_at": {"N": "1748520500"},
  "post_id": {"S": "p_7a8b9c0d1e2f"}
}
```

**Example DynamoDB Item** (signal record — not interesting):

```json
{
  "pk": {"S": "USER#charlie@test.local"},
  "sk": {"S": "POST_SIGNAL#p_7a8b9c0d1e2f"},
  "signal": {"S": "not_interesting"},
  "created_at": {"N": "1748521200"},
  "post_id": {"S": "p_7a8b9c0d1e2f"}
}
```

**Example post item with signal counters** (app_single_table):

```json
{
  "pk": {"S": "POST#p_7a8b9c0d1e2f"},
  "sk": {"S": "META"},
  "post_id": {"S": "p_7a8b9c0d1e2f"},
  "user_id": {"S": "alice@test.local"},
  "body": {"S": "Check out my new video!"},
  "like_count": {"N": "5"},
  "comment_count": {"N": "2"},
  "interesting_count": {"N": "12"},
  "not_interesting_count": {"N": "3"}
}
```

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

### 3.4b API Request/Response Examples

**Mark post as interesting** (curl):

```bash
curl -X POST http://localhost:8000/ui/posts/p_7a8b9c0d1e2f/signal \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_bob123; ui_csrf=csrf_tok_b; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_b" \
  -d '{"signal": "interesting"}'
```

**Response (200)**:
```json
{"ok": true}
```

**Mark post as not interesting** (curl):

```bash
curl -X POST http://localhost:8000/ui/posts/p_7a8b9c0d1e2f/signal \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_bob123; ui_csrf=csrf_tok_b; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_b" \
  -d '{"signal": "not_interesting"}'
```

**Response (200)**:
```json
{"ok": true}
```

**Remove signal** (curl):

```bash
curl -X DELETE http://localhost:8000/ui/posts/p_7a8b9c0d1e2f/signal \
  -H "Cookie: ui_session=sess_bob123; ui_csrf=csrf_tok_b; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_b"
```

**Response (200)**:
```json
{"ok": true}
```

**Error: signal own post** (curl):

```bash
curl -X POST http://localhost:8000/ui/posts/p_alice_own_post/signal \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice123; ui_csrf=csrf_tok_a; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_a" \
  -d '{"signal": "interesting"}'
```

**Response (400)**:
```json
{"detail": "Cannot signal your own post"}
```

**Post response with signal counts** (curl):

```bash
curl -X GET http://localhost:8000/ui/posts/p_7a8b9c0d1e2f \
  -H "Cookie: ui_session=sess_alice123; ui_csrf=csrf_tok_a; ui_access_token=eyJ..."
```

**Response (200)**:
```json
{
  "post_id": "p_7a8b9c0d1e2f",
  "user_id": "alice@test.local",
  "body": "Check out my new video!",
  "interesting_count": 12,
  "not_interesting_count": 3,
  "like_count": 5,
  "comment_count": 2
}
```

### 3.4c Pydantic Models

```python
# In app/models.py

class PostSignalIn(BaseModel):
    """Request model for submitting a post signal."""
    signal: str = Field(
        ...,
        pattern=r"^(interesting|not_interesting)$",
        description="Signal type: 'interesting' or 'not_interesting'"
    )

    class Config:
        json_schema_extra = {
            "example": {"signal": "interesting"}
        }

class PostSignalOut(BaseModel):
    """Response for signal operations."""
    ok: bool = True

class PostWithSignalCounts(BaseModel):
    """Post response that includes aggregate signal counts."""
    post_id: str
    user_id: str
    body: Optional[str] = None
    interesting_count: int = 0
    not_interesting_count: int = 0
    like_count: int = 0
    comment_count: int = 0
    # Plus all other standard post fields...
```

### 3.4d Frontend Component Tree

```
PostCard (modified)
├── PostHeader
│   └── OverflowMenu (DropdownMenu)
│       ├── "Interesting" (new) → signalPost(id, "interesting")
│       │   └── ThumbsUp icon + "Interesting" text
│       ├── "Not for me" (new) → signalPost(id, "not_interesting") + hide
│       │   └── ThumbsDown icon + "Not for me" text
│       ├── "Hide" (from FEED-006)
│       ├── "Report"
│       └── ...
├── PostBody
├── SignalIndicator (optional, creator-only, shows counts)
│   ├── InterestingBadge (count + ThumbsUp icon)
│   └── NotInterestingBadge (count + ThumbsDown icon)
├── PostActions (like, comment, tip, react)
└── CommentsThread

UndoToast (reused from FEED-006)
├── "Post hidden" title (for "not for me")
├── "Thanks for the feedback" description
└── Undo Button → removeSignal(id) + unhide
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

### 5.5 Section 322: Signal UI (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 322.1 | "Interesting" option in overflow menu | Navigate to feed; open overflow; "Interesting" visible |
| 322.2 | "Not for me" option in overflow menu | "Not for me" visible in overflow menu |
| 322.3 | "Not for me" hides post and shows undo toast | Click "Not for me"; post hidden; toast with "Undo" visible |
| 322.4 | Clicking undo restores post after "not for me" | Click "Undo" on toast; post reappears in feed; signal removed |
| 322.5 | Signal options not shown on own post | Open overflow on own post; neither "Interesting" nor "Not for me" present |

### 5.6 Section 323: Signal Toggle & Edge Cases (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 323.1 | Toggle from "interesting" to "not_interesting" | Signal "interesting" then "not_interesting"; interesting_count decremented, not_interesting incremented, post hidden |
| 323.2 | Toggle from "not_interesting" to "interesting" | Signal "not_interesting" then "interesting"; counters swap; post unhidden and reappears in feed |
| 323.3 | Same signal twice is idempotent | Signal "interesting" twice; counter stays at 1 |
| 323.4 | Two users signal same post independently | Bob signals "interesting", Charlie signals "not_interesting"; interesting_count=1, not_interesting_count=1 |
| 323.5 | Remove signal on deleted post | Creator deletes post; remove signal returns 200 (idempotent); no crash |

---

## 6. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Post not found | 404 | `not_found` | "Post not found" | Redirect to feed |
| Signal own post | 400 | `cannot_signal_own` | "Cannot signal your own post" | Don't show signal options for own posts |
| Invalid signal value | 422 | `validation_error` | Pydantic pattern validation error | Show inline error |
| Remove non-existent signal | 200 | — | No-op (idempotent) | No action needed |
| Duplicate signal (same type) | 200 | — | No-op (already set) | No action needed |
| Unauthenticated | 401 | `unauthorized` | "Authentication required" | Redirect to login |
| CSRF token mismatch | 403 | `csrf_invalid` | "Invalid CSRF token" | Refresh page |
| Rate limited | 429 | `rate_limited` | "Too many requests" | Retry after backoff |
| DDB counter update failed | 500 | `internal_error` | "Something went wrong" | Retry; counter reconciliation job will fix drift |
| Post deleted while signaling | 404 | `not_found` | "Post not found" | Remove from cache; show toast |

---

## 7. Security Considerations

- Users can only submit signals for their own accounts
- Signal data is private (users cannot see who signaled their posts)
- Aggregate counts are public (visible on post response)
- Counter manipulation prevented by server-side deduplication (one signal per user per post)
- Rate limiting prevents bulk signal abuse (50 signals per minute per user)
- No PII in signal records (only user_sub + post_id + signal type)

---

## 8. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Atomic counter updates | < 10ms | DynamoDB `ADD` operation is atomic; no race conditions |
| Signal change (interesting → not_interesting) | < 25ms | Two counter updates in sequence; eventual consistency is acceptable |
| Counter accuracy | Drift < 1 per 10K signals | Counters may drift by 1 in rare race conditions; periodic reconciliation job (future) |
| Signal check on feed render | No per-post check | Signals are not displayed to non-creators in feed; no extra read needed |
| Creator signal count display | < 5ms extra per post | Counts stored on post item; no join needed |
| Optimistic UI | Instant | Remove post from feed cache on "not for me" before API response |

### 8.1 Rate Limiting

- Signal creation: 50 operations per minute per user
- Signal removal: 50 operations per minute per user
- Rate limit keyed on user_sub (not IP) to prevent abuse from authenticated users

### 8.2 Counter Reconciliation

Future improvement: a scheduled job that recounts signals from the billing table and updates post counters. This corrects any drift from failed partial operations (e.g., signal stored but counter update timed out).

```python
# Future: app/services/signal_reconciliation.py
def reconcile_signal_counts(post_id: str) -> None:
    """Recount signals from source-of-truth (billing table) and update post counters."""
    interesting = 0
    not_interesting = 0
    # Scan all POST_SIGNAL# records referencing this post
    # (requires GSI or scan — design deferred to implementation)
    T.app_single_table.update_item(
        Key={"pk": f"POST#{post_id}", "sk": "META"},
        UpdateExpression="SET interesting_count = :ic, not_interesting_count = :nic",
        ExpressionAttributeValues={":ic": interesting, ":nic": not_interesting},
    )
```

---

## 9. Observability

### 9.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `post_signal_submitted_total` | Counter | `signal_type` (interesting/not_interesting) | Total signals submitted |
| `post_signal_removed_total` | Counter | `signal_type` | Total signals removed |
| `post_signal_toggled_total` | Counter | `from`, `to` | Signal changed from one type to another |
| `post_signal_latency_ms` | Histogram | `operation` (submit/remove) | Latency of signal operations |
| `post_signal_counter_drift` | Gauge | — | Detected drift between counted signals and stored counter (from reconciliation) |

### 9.2 Logging

| Event | Level | Fields |
|-------|-------|--------|
| Signal submitted | INFO | `user_sub`, `post_id`, `signal`, `previous_signal` |
| Signal removed | INFO | `user_sub`, `post_id`, `previous_signal` |
| Signal own post rejected | WARN | `user_sub`, `post_id` |
| Counter update failed | ERROR | `post_id`, `signal`, `error` |
| Signal change (toggle) | INFO | `user_sub`, `post_id`, `from_signal`, `to_signal` |

### 9.3 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High not_interesting rate | > 30% of signals for single creator's posts are "not_interesting" | Medium | Review content quality |
| Signal counter drift detected | Reconciliation finds drift > 5 | Low | Auto-corrects; log for investigation |
| Signal error rate | > 5% of signal operations fail | High | Check DDB throughput |
| Bulk signal abuse | Single user submits > 200 signals/hour | High | Rate limit and review |

### 9.4 Dashboard Queries

**Signal distribution per day**:
```promql
sum(increase(post_signal_submitted_total[1d])) by (signal_type)
```

**Interesting-to-not-interesting ratio**:
```promql
sum(rate(post_signal_submitted_total{signal_type="interesting"}[1h]))
  /
sum(rate(post_signal_submitted_total{signal_type="not_interesting"}[1h]))
```

---

## 10. Rollout Plan

### 10.1 Feature Flag

```python
# app/core/settings.py
post_signals_enabled: bool = os.environ.get("POST_SIGNALS_ENABLED", "true").lower() == "true"
```

### 10.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Backend | Deploy signal endpoints; flag OFF | 1 day | Unit tests pass |
| Phase 2: Internal | Enable for internal accounts; collect data | 3 days | E2E pass; no DDB errors |
| Phase 3: Canary 10% | Enable for 10% of users | 3 days | Signal volume healthy; no counter drift |
| Phase 4: GA | Enable for all users | Permanent | Positive signal data quality |

### 10.3 Migration

No DDB migration needed. New SK prefix `POST_SIGNAL#` in billing table. New fields `interesting_count` / `not_interesting_count` on post items are added on first signal (DDB ADD creates attribute if missing with initial value).

### 10.4 Rollback

1. Set `POST_SIGNALS_ENABLED=false` — disables signal endpoints
2. Existing signal records remain in billing table (dormant)
3. Signal counters remain on post items but are not displayed when flag is off
4. "Not interesting" hide records persist (managed by FEED-006 independently)
5. Re-enabling restores all accumulated signal data

---

## 11. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| Hide Post functionality | FEED-006 | Required — `hide_post` exists (line 4051), `unhide_post` NOT YET IMPLEMENTED |

---

## Codebase References

### Existing Files (verified)
| File | Key References | Lines |
|------|---------------|-------|
| `app/routers/newsfeed.py` | `hide_post` (FEED-006 dependency) | 4051 |
| `app/routers/newsfeed.py` | `pk_hide` helper | 820 |
| `app/routers/newsfeed.py` | `_post_to_dict` (will add signal counts) | 1900 |
| `app/routers/newsfeed.py` | `CreatePostRequest` | 1276 |
| `scripts/local-ddb-init.py` | `app_single_table` definition | 222 |
| `frontend/src/pages/feed/PostCard.tsx` | Post card (needs "Interesting" / "Not for me" menu) | - |

### Not Yet Implemented
| Feature | Notes |
|---------|-------|
| Signal storage (`POST_SIGNAL#` prefix) | New implementation required |
| Signal endpoints (`POST /posts/{id}/signal`, `DELETE /posts/{id}/signal`) | New implementation required |
| `interesting_count` / `not_interesting_count` on posts | New fields on post items |
| `app/services/feed_preferences.py` | Does not exist — new implementation required |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_post_signals.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_feed_007_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_feed_007_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_feed_007_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_feed_007_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_feed_007_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_feed_007_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_feed_007_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_feed_007_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/post-signals.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 10

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `POST_SIGNALS_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `POST_SIGNALS_ENABLED` must be enabled for tests to run
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
| (none currently) | -- |

### Merge Strategy

**Independent** -- Changes are additive (new service files, new router, new frontend pages). Shared infrastructure files (`main.py`, `settings.py`, `tables.py`, `local-ddb-init.py`) receive only additive modifications.

### Merge Checklist

- [ ] All new DDB tables/GSIs added to `scripts/local-ddb-init.py`
- [ ] Settings added to `app/core/settings.py`
- [ ] Table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Frontend routes added to `App.tsx`
- [ ] Feature flag `POST_SIGNALS_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite

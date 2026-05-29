# FEED-006: Hide Post

**Ticket**: FEED-006
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 3-4 days

---

## 1. Overview & Motivation

### 1.1 Purpose

FEED-006 adds the ability for users to hide individual posts from their feed without unfollowing the poster. Hidden posts are soft-hidden — they still exist and are visible to the poster and other users, but the hiding user no longer sees them in their feed. An undo toast allows reversal within 10 seconds, and a dedicated hidden posts page lets users review and unhide posts later.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Viewer | As a viewer, I want to hide a post I don't want to see anymore. | Click "Hide" in post overflow menu; post disappears from feed. |
| Viewer | As a viewer, I want to undo a hide within 10 seconds. | Toast notification with "Undo" button; clicking restores post to feed. |
| Viewer | As a viewer, I want to see all posts I've hidden. | `/hidden-posts` page shows list of hidden posts. |
| Viewer | As a viewer, I want to unhide a previously hidden post. | Click "Unhide" on hidden posts page; post reappears in feed. |
| Poster | As the post creator, I want my post to remain visible to everyone except the user who hid it. | Other users' feeds still show the post. |

### 1.3 Why This Is Needed Now

Feed curation is a basic social platform feature. Without hide functionality, users who see unwanted content can only unfollow the poster (losing all their content) or ignore it. Hide gives fine-grained control without affecting the follow relationship, improving user satisfaction and feed quality.

---

## 2. Current State Analysis

### 2.1 Feed Query

`GET /feed` in `app/routers/newsfeed.py` queries the `GSI1PK = FEED#{viewer_user_id}` index to fetch posts. The response iterates through DDB items and calls `_post_to_dict()` (line 1900) for each. There is a `pk_hide` helper (line 820) and a `hide_post` endpoint (line 4051) that writes hide records. Feed filtering checks hidden status at line 2257.
<!-- VERIFIED: app/routers/newsfeed.py:820 — pk_hide; :4051 — hide_post; :2257 — hidden post check -->

### 2.2 Post Storage

Posts are stored in `app_single_table` with PK `POST#{post_id}`, SK `META`. There is no per-user hide state on the post record.

### 2.3 User Preference Storage Pattern

The platform uses the `billing` table for per-user key-value data with the pattern `pk=USER#{user_sub}`, `sk=<TYPE>#{<id>}`. This pattern is used for payment methods, billing records, and other user-scoped data. Hidden post IDs will follow the same pattern.

### 2.4 Gaps

<!-- NOTE: Gap 1 is partially closed — hide_post endpoint exists (line 4051) with pk_hide helper (line 820) and feed filtering (line 2257). However, unhide and list-hidden endpoints are still needed. -->
1. ~~**No hide endpoint**~~ — PARTIALLY DONE: `POST /feed/hide` exists at `app/routers/newsfeed.py:4051`; unhide/DELETE not yet implemented.
2. ~~**No hidden post storage**~~ — DONE: Uses `pk_hide(user_id)` pattern (line 820), stored in `app_single_table`.
3. ~~**No feed filtering**~~ — DONE: Feed filtering checks hidden status at line 2257.
4. **No "Hide" UI** — no option in PostCard overflow menu.
5. **No hidden posts page** — no management page for reviewing hidden posts.
6. **No undo mechanism** — no toast with undo capability.

---

## 3. Technical Design

### 3.1 Architecture & Data Flow

```
                    Hide Post Flow
  ┌───────────────┐     ┌────────────────────┐     ┌──────────────┐
  │  PostCard      │────>│ POST /posts/{id}/  │────>│  DynamoDB     │
  │  overflow menu │     │   hide             │     │  billing      │
  │                │     │  (newsfeed.py)      │     │  table        │
  │  "Hide" click  │     │                    │     │               │
  │  → mutation    │     │  1. verify post    │     │  PK=USER#sub  │
  │  → optimistic  │     │  2. verify !own    │     │  SK=HIDDEN_   │
  │    remove      │     │  3. put_item       │     │    POST#pid   │
  └───────────────┘     └────────────────────┘     └──────────────┘
        │
        v
  ┌───────────────┐
  │  Toast with    │
  │  "Undo" button │
  │  (10s timeout) │
  │                │
  │  Undo click → │
  │  DELETE /posts │
  │  /{id}/hide    │
  └───────────────┘

                    Feed Query with Hidden Post Filtering
  ┌───────────────┐     ┌────────────────────┐     ┌──────────────┐
  │  FeedPage      │<────│ GET /feed          │<────│  Two DDB      │
  │  (frontend)    │     │ (newsfeed.py)       │     │  queries:     │
  │                │     │                    │     │               │
  │  posts[]       │     │ 1. fetch posts     │     │ 1. GSI1 feed  │
  │  (hidden ones  │     │ 2. fetch hidden_ids│     │ 2. billing    │
  │   excluded)    │     │ 3. filter posts    │     │    begins_with│
  │                │     │                    │     │    HIDDEN_POST│
  └───────────────┘     └────────────────────┘     └──────────────┘
```

### 3.2 Data Model

Hidden posts are stored in the `billing` table (user preference pattern):

| PK | SK | Fields |
|----|----|--------|
| `USER#{user_sub}` | `HIDDEN_POST#{post_id}` | `hidden_at: Number`, `post_id: String` |

This leverages the existing `billing` table without creating a new table. The query pattern (list all hidden posts for a user) uses the PK with a begins_with filter on SK.

### 3.3 Detailed DynamoDB Access Patterns

| Access Pattern | Table | Key Condition | Filter | Use Case |
|---------------|-------|---------------|--------|----------|
| Hide a post | `billing` | PK=`USER#{user_sub}`, SK=`HIDDEN_POST#{post_id}` | -- | put_item to create hidden post record |
| Unhide a post | `billing` | PK=`USER#{user_sub}`, SK=`HIDDEN_POST#{post_id}` | -- | delete_item to remove hidden post record |
| List hidden post IDs | `billing` | PK=`USER#{user_sub}`, SK `begins_with("HIDDEN_POST#")` | -- | Fetch all hidden post IDs for feed filtering |
| List hidden posts with details | `billing` + `app_single_table` | Step 1: billing query; Step 2: batch_get on app_single_table | -- | Fetch hidden post metadata for management page |
| Check if specific post is hidden | `billing` | PK=`USER#{user_sub}`, SK=`HIDDEN_POST#{post_id}` | -- | get_item for single post check |
| Feed query with hidden filtering | `app_single_table` GSI1 + `billing` | Step 1: GSI1 feed query; Step 2: billing hidden IDs query | In-memory: exclude hidden IDs from feed results | Feed response excludes hidden posts |

### 3.4 Backend Service

**File**: `app/services/feed_preferences.py`

```python
def hide_post(user_sub: str, post_id: str) -> None:
    """Hide a post from the user's feed."""
    T.billing.put_item(Item={
        "pk": f"USER#{user_sub}",
        "sk": f"HIDDEN_POST#{post_id}",
        "hidden_at": now_ts(),
        "post_id": post_id,
    })

def unhide_post(user_sub: str, post_id: str) -> None:
    """Unhide a post (remove hide record)."""
    T.billing.delete_item(Key={
        "pk": f"USER#{user_sub}",
        "sk": f"HIDDEN_POST#{post_id}",
    })

def list_hidden_post_ids(user_sub: str) -> set[str]:
    """Get all hidden post IDs for a user."""
    resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq(f"USER#{user_sub}") & Key("sk").begins_with("HIDDEN_POST#"),
    )
    return {item["post_id"] for item in resp.get("Items", [])}

def list_hidden_posts(user_sub: str) -> list[dict]:
    """Get all hidden posts with metadata for the management page."""
    hidden_items = T.billing.query(
        KeyConditionExpression=Key("pk").eq(f"USER#{user_sub}") & Key("sk").begins_with("HIDDEN_POST#"),
    ).get("Items", [])

    posts = []
    for item in hidden_items:
        post = _get_post(item["post_id"])
        if post:
            posts.append({
                **_post_to_dict(post),
                "hidden_at": item["hidden_at"],
            })
    return sorted(posts, key=lambda p: p["hidden_at"], reverse=True)
```

### 3.5 Feed Query Modification

In `GET /feed` endpoint, after fetching posts:

```python
# Fetch hidden post IDs for the viewer
hidden_ids = list_hidden_post_ids(user_sub)

# Filter out hidden posts
posts = [p for p in posts if p.get("post_id") not in hidden_ids]
```

This adds one additional DDB query per feed request. For most users with few hidden posts, this is negligible. For users with thousands of hidden posts, consider caching the set in-memory (e.g., per-request cache).

### 3.6 API Request/Response Examples

**Hide a post**:

```
POST /ui/posts/p_abc123/hide
x-csrf-token: <csrf>
```

**Response (200)**:
```json
{
  "ok": true
}
```

**Unhide a post**:

```
DELETE /ui/posts/p_abc123/hide
x-csrf-token: <csrf>
```

**Response (200)**:
```json
{
  "ok": true
}
```

**Cannot hide own post**:

```
POST /ui/posts/p_own_post/hide
x-csrf-token: <csrf>
```

**Response (400)**:
```json
{
  "detail": "Cannot hide your own post"
}
```

**List hidden posts**:

```
GET /ui/posts/hidden
```

**Response (200)**:
```json
[
  {
    "post_id": "p_abc123",
    "user_id": "bob@test.local",
    "user_name": "Bob Creator",
    "body": "Check out my latest creation...",
    "image_urls": ["https://..."],
    "created_at": 1748520100,
    "like_count": 42,
    "comment_count": 7,
    "hidden_at": 1748600000
  },
  {
    "post_id": "p_def456",
    "user_id": "charlie@test.local",
    "user_name": "Charlie",
    "body": "Another post...",
    "created_at": 1748500000,
    "like_count": 5,
    "comment_count": 1,
    "hidden_at": 1748590000
  }
]
```

**Feed response with hidden posts filtered out**:

```
GET /ui/feed
```

**Response (200)** — posts with IDs matching hidden set are excluded:
```json
{
  "posts": [
    {
      "post_id": "p_xyz789",
      "user_id": "bob@test.local",
      "body": "This post is NOT hidden and appears in feed",
      "created_at": 1748610000
    }
  ]
}
```

### 3.7 Pydantic Model Definitions

```python
# In app/models.py

class HidePostOut(BaseModel):
    """Response for hide/unhide post actions."""
    ok: bool = True


class HiddenPostOut(BaseModel):
    """Response model for a hidden post in the management list."""
    post_id: str
    user_id: str
    user_name: Optional[str] = None
    body: Optional[str] = None
    body_plain: Optional[str] = None
    image_urls: Optional[List[str]] = None
    created_at: int = 0
    like_count: int = 0
    comment_count: int = 0
    hidden_at: int = 0
```

### 3.8 Backend Router

**File**: `app/routers/newsfeed.py`

```python
@router.post("/posts/{post_id}/hide", status_code=200)
def hide_post_endpoint(post_id: str, ctx=Depends(require_ui_session)):
    """Hide a post from the user's feed."""
    user_sub = ctx["user_sub"]
    # Verify post exists
    post = _get_post(post_id)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    # Can't hide own posts
    if post.get("user_id") == user_sub:
        raise HTTPException(status_code=400, detail="Cannot hide your own post")
    hide_post(user_sub, post_id)
    return {"ok": True}

@router.delete("/posts/{post_id}/hide", status_code=200)
def unhide_post_endpoint(post_id: str, ctx=Depends(require_ui_session)):
    """Unhide a previously hidden post."""
    unhide_post(ctx["user_sub"], post_id)
    return {"ok": True}

@router.get("/posts/hidden", status_code=200)
def list_hidden_posts_endpoint(ctx=Depends(require_ui_session)):
    """List all posts hidden by the current user."""
    return list_hidden_posts(ctx["user_sub"])
```

### 3.9 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface HiddenPost extends FeedPost {
  hidden_at: number;
}
```

### 3.10 Frontend API

**File**: `frontend/src/api/endpoints/newsfeed.ts`

```typescript
export const hidePost = (postId: string) =>
  api.post(`/ui/posts/${postId}/hide`);

export const unhidePost = (postId: string) =>
  api.delete(`/ui/posts/${postId}/hide`);

export const listHiddenPosts = () =>
  api.get<HiddenPost[]>("/ui/posts/hidden");
```

### 3.11 Frontend Component Tree

```
PostCard (modified)
├── PostHeader
│   ├── AuthorInfo (avatar, name, timestamp)
│   └── OverflowMenu (DropdownMenu)
│       ├── ...existing items (Report, etc.)
│       └── HideMenuItem (new, only for non-own posts)
│           ├── <EyeOff> icon + "Hide" label
│           └── onClick → hidePostMutation → optimistic remove → undo toast
├── PostBody
├── PostActions
└── CommentsThread

HiddenPostsPage (new page)
├── PageHeader ("Hidden Posts" + back link)
├── HiddenPostsList
│   └── HiddenPostCard (for each hidden post)
│       ├── PostPreview
│       │   ├── AuthorInfo (avatar, name)
│       │   ├── TextSnippet (first 200 chars of body)
│       │   └── ImageThumbnail (if image_urls present)
│       ├── HiddenTimestamp ("Hidden on May 29, 2026")
│       └── UnhideButton
│           └── onClick → unhidePostMutation → remove from list → success toast
└── EmptyState ("No hidden posts" if list empty)

UndoToast (transient, 10s)
├── Title: "Post hidden"
├── Description: "You won't see this post in your feed anymore."
└── UndoButton → unhidePost → restore to feed cache → dismiss toast
```

### 3.12 PostCard Enhancement

Add "Hide" option to the overflow menu (three-dot button) on PostCard:

```tsx
// In PostCard.tsx overflow menu (DropdownMenu)
{post.user_id !== currentUser.sub && (
  <DropdownMenuItem onClick={() => handleHidePost(post.post_id)}>
    <EyeOff className="h-4 w-4 mr-2" /> Hide
  </DropdownMenuItem>
)}
```

**Hide handler with undo toast**:

```tsx
const handleHidePost = async (postId: string) => {
  await hidePostMutation.mutateAsync(postId);

  toast({
    title: "Post hidden",
    description: "You won't see this post in your feed anymore.",
    action: (
      <Button variant="outline" size="sm" onClick={() => handleUnhide(postId)}>
        Undo
      </Button>
    ),
    duration: 10000, // 10 seconds
  });
};
```

**Optimistic update**: Remove the post from the feed query cache immediately, restore on undo.

### 3.13 HiddenPostsPage

**File**: `frontend/src/pages/feed/HiddenPostsPage.tsx`

- Route: `/hidden-posts`
- Lists all hidden posts with "Unhide" button on each
- Shows post preview (author, text snippet, image thumbnail)
- "Hidden on {date}" timestamp
- Empty state: "No hidden posts"
- `data-testid="hidden-posts-page"`

### 3.14 Route & Navigation

Add route to `frontend/src/App.tsx`:
```tsx
<Route path="/hidden-posts" element={<HiddenPostsPage />} />
```

Add "Hidden Posts" link to feed page or settings page.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/feed_preferences.py` | Hide/unhide logic + hidden post ID queries |
| `frontend/src/pages/feed/HiddenPostsPage.tsx` | Hidden posts management page |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/newsfeed.py` | Add hide/unhide/list-hidden endpoints; filter hidden posts from feed |
| `app/models.py` | Add `HidePostOut`, `HiddenPostOut` Pydantic models |
| `frontend/src/api/types.ts` | Add `HiddenPost` type |
| `frontend/src/api/endpoints/newsfeed.ts` | Add hide/unhide/listHidden API functions |
| `frontend/src/pages/feed/PostCard.tsx` | Add "Hide" to overflow menu with undo toast |
| `frontend/src/App.tsx` | Add `/hidden-posts` route |

### 4.3 Step-by-Step Order

1. Implement `feed_preferences.py` service
2. Add endpoints to newsfeed router
3. Modify `GET /feed` to filter hidden posts
4. Add Pydantic models
5. Add frontend types and API functions
6. Add "Hide" to PostCard overflow menu with undo toast
7. Build HiddenPostsPage
8. Add route
9. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/feed-hide-posts.spec.ts` — 20 tests across 5 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let alicePostId: string;
let bobPostId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice and Bob sessions
  // Alice creates a post (for Bob to hide)
  // Bob creates a post (for Alice to hide)
});
```

### 5.3 Section 317: Hide/Unhide Post API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 317.1 | Hide a post | POST `/posts/{id}/hide`; 200; `ok=true` |
| 317.2 | Hidden post filtered from feed | GET `/feed`; hidden post not in results |
| 317.3 | Unhide a post | DELETE `/posts/{id}/hide`; 200; post reappears in feed |
| 317.4 | Cannot hide own post | POST `/posts/{own_id}/hide`; 400; "Cannot hide your own post" |

### 5.4 Section 318: Hidden Posts List API (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 318.1 | List hidden posts includes hidden post | GET `/posts/hidden`; 200; array includes hidden post with `hidden_at` |
| 318.2 | List hidden posts empty after unhide | Unhide all; GET; 200; empty array |
| 318.3 | Hidden posts sorted by hidden_at descending | Hide two posts; GET; first item has later `hidden_at` |

### 5.5 Section 319: Hide Post UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 319.1 | "Hide" option appears in post overflow menu | Navigate to feed; open overflow on non-own post; "Hide" visible |
| 319.2 | Hiding post shows undo toast | Click "Hide"; toast with "Post hidden" and "Undo" button visible |
| 319.3 | Hidden posts page shows hidden post | Navigate to `/hidden-posts`; hidden post listed with "Unhide" button |

### 5.6 Section 320: Hide Post Edge Cases (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 320.1 | Hide already-hidden post is idempotent | POST hide twice; 200 both times; list still shows 1 entry |
| 320.2 | Unhide non-hidden post is idempotent | DELETE hide on non-hidden post; 200; no error |
| 320.3 | Post not found returns 404 | POST `/posts/nonexistent/hide`; 404; "Post not found" |
| 320.4 | Hide does not affect other users' feeds | Alice hides Bob's post; Charlie's feed still shows Bob's post |
| 320.5 | Hidden post still accessible via direct GET | Hide post; GET `/posts/{id}`; 200; post data returned (hidden only from feed) |

### 5.7 Section 321: Hide Post Undo Flow (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 321.1 | Undo restores post to feed | Hide post; click Undo; GET feed; post reappears |
| 321.2 | Undo removes post from hidden list | Hide post; click Undo; GET hidden; post not in list |
| 321.3 | Multiple hides maintain correct hidden list | Hide post A and B; list has 2; unhide A; list has 1 (B only) |
| 321.4 | Feed maintains correct count after hide/unhide cycle | Count posts before; hide; count -1; unhide; count restored |
| 321.5 | Hidden post hidden_at timestamp is accurate | Hide post; GET hidden; `hidden_at` is within 5 seconds of current time |

---

## 6. Error Handling

### 6.1 Error Matrix

| Scenario | HTTP Status | Error Code | Error Message | Recovery Action |
|----------|-------------|------------|---------------|-----------------|
| Post not found | 404 | `not_found` | "Post not found" | Show error toast; refresh feed |
| Hide own post | 400 | `cannot_hide_own` | "Cannot hide your own post" | Do not show "Hide" option for own posts |
| Unhide non-hidden post | 200 | -- | No-op (idempotent delete) | No action needed |
| Hide already-hidden post | 200 | -- | Overwrites (idempotent put) | No action needed |
| Unauthenticated | 401 | `unauthorized` | "Authentication required" | Redirect to login |
| Hidden post list fetch fails | 500 | `internal_error` | "Unable to load hidden posts" | Show retry button |

---

## 7. Security Considerations

- Users can only manage their own hide preferences
- Hidden post IDs are private to the hiding user
- Post creators cannot see who hid their posts
- Feed filtering is server-side (hidden posts never sent to client in feed response)
- No information leak: the hidden posts list endpoint only returns posts the user explicitly hid

---

## 8. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Extra DDB query per feed request | < 50ms | Single query with begins_with on SK; fast for typical user (<100 hidden posts) |
| Many hidden posts (>1000) | < 200ms | If >1000 hidden posts, could cache in-memory per request; unlikely in practice |
| Hidden post list N+1 | < 500ms for 50 posts | `list_hidden_posts` fetches each post individually; use batch_get_item for >10 posts |
| Optimistic UI update | Instant feedback | Remove post from React Query cache immediately; restore on undo |
| Undo toast timing | 10 seconds | Toast duration set to 10000ms; undo triggers DELETE + cache restore |
| Feed query total latency | < 250ms p95 | Feed query + hidden ID query run in parallel (asyncio.gather) |

---

## 9. Observability

### 9.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `post_hidden_total` | Counter | -- | Number of posts hidden |
| `post_unhidden_total` | Counter | `source` (undo/management) | Number of posts unhidden, labeled by source |
| `post_hide_undo_rate` | Gauge | -- | Percentage of hides that are undone within 10 seconds |
| `hidden_posts_per_user_avg` | Gauge | -- | Average number of hidden posts per active user |

### 9.2 Logging

| Event | Level | Fields |
|-------|-------|--------|
| Post hidden | INFO | `user_id`, `post_id`, `post_creator_id` |
| Post unhidden (undo) | INFO | `user_id`, `post_id`, `source=undo` |
| Post unhidden (management) | INFO | `user_id`, `post_id`, `source=management` |
| Own post hide attempt blocked | WARN | `user_id`, `post_id` |

### 9.3 Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| Hide rate spike | > 200 hides/hour across platform | Low (may indicate content quality issue) |
| Hidden post list query slow | p95 > 500ms | Medium |

---

## 10. Rollout Plan

### 10.1 Feature Flag

```python
# app/core/settings.py
hide_post_enabled: bool = os.environ.get("HIDE_POST_ENABLED", "true").lower() == "true"
```

When disabled, the backend returns 400 on hide/unhide endpoints. The frontend hides the "Hide" option in the overflow menu. The hidden posts management page shows "This feature is not available."

### 10.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Backend only | Deploy hide/unhide endpoints; feature flag ON in dev | 1 day | Unit tests pass |
| Phase 2: Internal testing | Enable for internal users; test feed filtering + undo flow | 2 days | E2E tests pass; undo works within 10s window |
| Phase 3: GA | Enable for all users; monitor hide rate and undo rate | Permanent | No errors; undo rate > 5% (users are discovering the feature) |

---

## 11. Optimistic Update Implementation Detail

The hide action uses React Query's optimistic update pattern for instant feedback:

```typescript
const hidePostMutation = useMutation({
  mutationFn: (postId: string) => hidePost(postId),
  onMutate: async (postId: string) => {
    // Cancel outgoing feed refetches
    await queryClient.cancelQueries({ queryKey: ["feed"] });

    // Snapshot current feed data
    const previousFeed = queryClient.getQueryData<FeedResponse>(["feed"]);

    // Optimistically remove the post from the feed
    if (previousFeed) {
      queryClient.setQueryData<FeedResponse>(["feed"], {
        ...previousFeed,
        posts: previousFeed.posts.filter((p) => p.post_id !== postId),
      });
    }

    return { previousFeed };
  },
  onError: (_err, _postId, context) => {
    // Restore feed on error
    if (context?.previousFeed) {
      queryClient.setQueryData(["feed"], context.previousFeed);
    }
    toast({ title: "Failed to hide post", variant: "destructive" });
  },
  onSettled: () => {
    queryClient.invalidateQueries({ queryKey: ["feed"] });
    queryClient.invalidateQueries({ queryKey: ["hidden-posts"] });
  },
});
```

The undo handler restores the post by calling `unhidePost` and invalidating both query keys:

```typescript
const handleUnhide = async (postId: string) => {
  await unhidePost(postId);
  queryClient.invalidateQueries({ queryKey: ["feed"] });
  queryClient.invalidateQueries({ queryKey: ["hidden-posts"] });
  toast({ title: "Post restored to your feed" });
};
```

---

## 12. Hidden Posts Page Data Flow

```
HiddenPostsPage mount
  → useQuery(["hidden-posts"], listHiddenPosts)
  → GET /ui/posts/hidden
  → Backend: billing query (PK=USER#sub, SK begins_with HIDDEN_POST#)
  → For each hidden item: get_item on app_single_table (POST#pid, META)
  → Merge hidden_at with post data
  → Sort by hidden_at desc
  → Return array of HiddenPostOut

User clicks "Unhide"
  → unhidePostMutation.mutate(postId)
  → DELETE /ui/posts/{id}/hide
  → Backend: delete_item from billing table
  → onSuccess: invalidate ["hidden-posts"] and ["feed"]
  → Post disappears from list, reappears in feed on next visit
```

---

## 13. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| None | -- | Standalone (uses existing billing table) |

### 13.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| FEED-007 (Mark Post Interesting) | "Not interesting" triggers hide behavior |

---

## Codebase References

### Existing Files (verified)
| File | Key References | Lines |
|------|---------------|-------|
| `app/routers/newsfeed.py` | `pk_hide` helper | 820 |
| `app/routers/newsfeed.py` | `HidePostRequest` model | 1482 |
| `app/routers/newsfeed.py` | `hide_post` endpoint (`POST /feed/hide`) | 4051 |
| `app/routers/newsfeed.py` | Hidden post check in feed | 2257 |
| `app/routers/newsfeed.py` | `_post_to_dict` | 1900 |
| `scripts/local-ddb-init.py` | `app_single_table` definition | 222 |
| `frontend/src/pages/feed/PostCard.tsx` | Post card component (needs "Hide" menu option) | - |

### Not Yet Implemented
| Feature | Notes |
|---------|-------|
| `DELETE /posts/{id}/hide` (unhide endpoint) | Not yet in codebase |
| `GET /ui/posts/hidden` (list hidden posts) | Not yet in codebase |
| Hidden posts management page | No frontend page exists |
| Undo toast mechanism | Not yet implemented |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_hide_post.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_feed_006_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_feed_006_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_feed_006_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_feed_006_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_feed_006_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_feed_006_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_feed_006_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_feed_006_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/hide-post.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 10

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `HIDE_POST_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `HIDE_POST_ENABLED` must be enabled for tests to run
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
- [ ] Feature flag `HIDE_POST_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite

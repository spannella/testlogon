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

`GET /feed` in `app/routers/newsfeed.py` queries the `GSI1PK = FEED#{viewer_user_id}` index to fetch posts. The response iterates through DDB items and calls `_post_to_dict()` for each. Currently there is no filtering of hidden posts.

### 2.2 Post Storage

Posts are stored in `app_single_table` with PK `POST#{post_id}`, SK `META`. There is no per-user hide state on the post record.

### 2.3 User Preference Storage Pattern

The platform uses the `billing` table for per-user key-value data with the pattern `pk=USER#{user_sub}`, `sk=<TYPE>#{<id>}`. This pattern is used for payment methods, billing records, and other user-scoped data. Hidden post IDs will follow the same pattern.

### 2.4 Gaps

1. **No hide endpoint** — no API to hide/unhide posts.
2. **No hidden post storage** — no DDB records for hidden post IDs.
3. **No feed filtering** — `GET /feed` doesn't exclude hidden posts.
4. **No "Hide" UI** — no option in PostCard overflow menu.
5. **No hidden posts page** — no management page for reviewing hidden posts.
6. **No undo mechanism** — no toast with undo capability.

---

## 3. Technical Design

### 3.1 Data Model

Hidden posts are stored in the `billing` table (user preference pattern):

| PK | SK | Fields |
|----|----|--------|
| `USER#{user_sub}` | `HIDDEN_POST#{post_id}` | `hidden_at: Number`, `post_id: String` |

This leverages the existing `billing` table without creating a new table. The query pattern (list all hidden posts for a user) uses the PK with a begins_with filter on SK.

### 3.2 Backend Service

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

### 3.3 Feed Query Modification

In `GET /feed` endpoint, after fetching posts:

```python
# Fetch hidden post IDs for the viewer
hidden_ids = list_hidden_post_ids(user_sub)

# Filter out hidden posts
posts = [p for p in posts if p.get("post_id") not in hidden_ids]
```

This adds one additional DDB query per feed request. For most users with few hidden posts, this is negligible. For users with thousands of hidden posts, consider caching the set in-memory (e.g., per-request cache).

### 3.4 Backend Router

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

### 3.5 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface HiddenPost extends FeedPost {
  hidden_at: number;
}
```

### 3.6 Frontend API

**File**: `frontend/src/api/endpoints/newsfeed.ts`

```typescript
export const hidePost = (postId: string) =>
  api.post(`/ui/posts/${postId}/hide`);

export const unhidePost = (postId: string) =>
  api.delete(`/ui/posts/${postId}/hide`);

export const listHiddenPosts = () =>
  api.get<HiddenPost[]>("/ui/posts/hidden");
```

### 3.7 PostCard Enhancement

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

### 3.8 HiddenPostsPage

**File**: `frontend/src/pages/feed/HiddenPostsPage.tsx`

- Route: `/hidden-posts`
- Lists all hidden posts with "Unhide" button on each
- Shows post preview (author, text snippet, image thumbnail)
- "Hidden on {date}" timestamp
- Empty state: "No hidden posts"
- `data-testid="hidden-posts-page"`

### 3.9 Route & Navigation

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
| `frontend/src/api/types.ts` | Add `HiddenPost` type |
| `frontend/src/api/endpoints/newsfeed.ts` | Add hide/unhide/listHidden API functions |
| `frontend/src/pages/feed/PostCard.tsx` | Add "Hide" to overflow menu with undo toast |
| `frontend/src/App.tsx` | Add `/hidden-posts` route |

### 4.3 Step-by-Step Order

1. Implement `feed_preferences.py` service
2. Add endpoints to newsfeed router
3. Modify `GET /feed` to filter hidden posts
4. Add frontend types and API functions
5. Add "Hide" to PostCard overflow menu with undo toast
6. Build HiddenPostsPage
7. Add route
8. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/feed-hide-posts.spec.ts` — 10 tests across 3 sections.

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

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Post not found | 404 | "Post not found" |
| Hide own post | 400 | "Cannot hide your own post" |
| Unhide non-hidden post | 200 | No-op (idempotent delete) |
| Hide already-hidden post | 200 | Overwrites (idempotent put) |

---

## 7. Security Considerations

- Users can only manage their own hide preferences
- Hidden post IDs are private to the hiding user
- Post creators cannot see who hid their posts
- Feed filtering is server-side (hidden posts never sent to client in feed response)

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Extra DDB query per feed request | Single query with begins_with on SK; fast for typical user (<100 hidden posts) |
| Many hidden posts | If >1000 hidden posts, could cache in-memory per request; unlikely in practice |
| Hidden post list N+1 | `list_hidden_posts` fetches each post individually; batch get for >10 posts |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| None | — | Standalone (uses existing billing table) |

### 9.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| FEED-007 (Mark Post Interesting) | "Not interesting" triggers hide behavior |

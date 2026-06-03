# FEED-009: Post Bookmarks / Save Collections

**Ticket**: FEED-009
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 6-8 days

---

## 1. Overview & Motivation

### 1.1 Purpose

FEED-009 adds a bookmarking system for newsfeed posts. Users can save posts to named collections for later viewing. A default "Saved" collection is auto-created for every user. Users can create additional collections (e.g., "Recipes", "Tutorials", "Inspiration") and organize bookmarks between them. A dedicated Saved Posts page provides collection-based browsing with a sidebar for switching between collections.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Viewer | As a viewer, I want to bookmark a post so I can find it later. | Click bookmark icon on PostCard; post saved to "Saved" collection. |
| Viewer | As a viewer, I want to save a post to a specific collection. | Long-press or dropdown on bookmark; select collection; post saved there. |
| Viewer | As a viewer, I want to create custom collections with descriptive names. | Create collection dialog; name input; collection appears in sidebar. |
| Viewer | As a viewer, I want to browse my saved posts by collection. | Saved Posts page with collection tabs; posts filtered by selected collection. |
| Viewer | As a viewer, I want to remove a bookmark from a post. | Click bookmark icon again; post removed from collection. |
| Viewer | As a viewer, I want to rename or delete a collection. | Edit/delete buttons on collection; posts moved to "Saved" on delete. |
| Viewer | As a viewer, I want to move a bookmark between collections. | "Move to..." option on bookmarked post; select destination collection. |

### 1.3 Why This Is Needed Now

Content bookmarking is a fundamental social platform feature. Users often see posts they want to return to later — recipes to try, tutorials to follow, deals to consider. Without bookmarks, users must scroll through their entire feed or rely on browser bookmarks. Named collections add organization that makes saved content actually useful rather than a dumping ground.

---

## 2. Current State Analysis

### 2.1 Post Interactions

Posts currently support: likes, reactions, comments, tips, unlocking, hiding. There is no bookmark/save mechanism. The PostCard component has an overflow menu (three-dot button) that could host a "Save" option, and there's space for a bookmark icon in the post action bar alongside like and comment buttons.

### 2.2 User Preference Storage

The platform uses the `billing` table for per-user data (PK `USER#{user_sub}`, SK varies). This pattern has been used for payment methods, hidden posts (FEED-006), and post signals (FEED-007). Bookmarks could follow this pattern, but the need for collection grouping and per-collection listing suggests a dedicated table for better query efficiency.

### 2.3 Existing Routes

The route `/saved` is mentioned in CLAUDE.md as potentially already in the sidebar. A dedicated route for the Saved Posts page fits naturally here.

### 2.4 Gaps

<!-- NOTE: Gaps 1-2 are partially closed — basic bookmarks already exist in app/routers/newsfeed.py (lines 5461-5618) using app_single_table with BOOKMARK# prefix. Frontend: frontend/src/api/endpoints/bookmarks.ts and frontend/src/pages/saved/SavedPage.tsx exist. Collections are NOT yet implemented. -->

1. ~~**No `post_bookmarks` DDB table**~~ — PARTIALLY DONE: Bookmarks use `app_single_table` with `pk=BOOKMARK#{user_id}` (line 5461) and `pk=BOOKMARK_LOOKUP#{user_id}` (line 5465). No separate table needed. Collections not yet implemented.
2. ~~**No bookmark endpoints**~~ — DONE: `POST /ui/bookmarks` (line 5483) and `DELETE /ui/bookmarks/{content_type}/{content_id}` (line 5538) exist. `GET /ui/bookmarks` (line 5553) lists bookmarks.
3. **No collection CRUD** — no API to create, rename, or delete collections (new feature needed).
4. **No bookmark icon on PostCard** — needs UI integration.
5. ~~**No Saved Posts page**~~ — DONE: `frontend/src/pages/saved/SavedPage.tsx` exists.
6. **No bookmark state in feed response** — posts don't indicate if they're bookmarked by the viewer.

---

## 3. Technical Design

### 3.1 DynamoDB Table: `post_bookmarks`

| Attribute | Type | Description |
|-----------|------|-------------|
| `user_sub` (PK) | String | User who bookmarked |
| `sk` (SK) | String | Multiple item types (see below) |

**Item types**:

**Collection metadata** (SK = `COLL#{collection_id}`):

| Field | Type | Description |
|-------|------|-------------|
| `collection_id` | String | `coll_<uuid4_hex>` or `default` for the auto-created collection |
| `name` | String | Collection name (e.g., "Saved", "Recipes") |
| `created_at` | Number | Unix timestamp |
| `bookmark_count` | Number | Number of bookmarks in this collection |
| `sort_order` | Number | Display order (0 = first) |

**Bookmark record** (SK = `BM#{post_id}`):

| Field | Type | Description |
|-------|------|-------------|
| `post_id` | String | Bookmarked post ID |
| `collection_id` | String | Which collection this bookmark belongs to |
| `saved_at` | Number | Unix timestamp when bookmarked |
| `post_preview` | Map | Denormalized: `{user_name, text_snippet, image_url}` for fast listing |

**GSIs**:

| GSI | PK | SK | Purpose |
|-----|----|----|---------|
| `GSI1` | `user_sub#collection_id` (composite) | `saved_at` | List bookmarks in a specific collection, sorted by save date |

The composite GSI PK `{user_sub}#COLL#{collection_id}` enables efficient per-collection queries.

**File**: `scripts/local-ddb-init.py`

```python
TableDef(
    name=S.ddb_post_bookmarks_table,
    pk="user_sub",
    sk="sk",
    gsis=[
        GsiDef(name="GSI1", pk="gsi1pk", sk="saved_at"),
    ],
    attr_types={"saved_at": "N", "created_at": "N", "bookmark_count": "N", "sort_order": "N"},
),
```

### 3.2 Settings

**File**: `app/core/settings.py`

```python
# Post bookmarks (FEED-009)
ddb_post_bookmarks_table: str = os.environ.get("DDB_POST_BOOKMARKS_TABLE", "post_bookmarks")
bookmarks_max_collections: int = int(os.environ.get("BOOKMARKS_MAX_COLLECTIONS", "50"))
bookmarks_max_per_collection: int = int(os.environ.get("BOOKMARKS_MAX_PER_COLLECTION", "1000"))
```

### 3.3 Backend Service

**File**: `app/services/post_bookmarks.py`

```python
def ensure_default_collection(user_sub: str) -> dict:
    """Create the default 'Saved' collection if it doesn't exist."""
    key = {"user_sub": user_sub, "sk": "COLL#default"}
    existing = T.post_bookmarks.get_item(Key=key).get("Item")
    if existing:
        return existing
    item = {
        "user_sub": user_sub,
        "sk": "COLL#default",
        "collection_id": "default",
        "name": "Saved",
        "created_at": now_ts(),
        "bookmark_count": 0,
        "sort_order": 0,
    }
    T.post_bookmarks.put_item(Item=item)
    return item

def create_collection(user_sub: str, name: str) -> dict:
    """Create a named bookmark collection."""
    # 1. Check collection count < max
    # 2. Generate collection_id
    # 3. Create COLL# item
    # 4. Return collection dict

def rename_collection(user_sub: str, collection_id: str, name: str) -> dict:
    """Rename a bookmark collection (cannot rename 'default')."""

def delete_collection(user_sub: str, collection_id: str) -> None:
    """Delete a collection and move all its bookmarks to 'default'."""
    # 1. Cannot delete 'default'
    # 2. Query all BM# items with this collection_id
    # 3. Update each to collection_id="default"
    # 4. Delete COLL# item
    # 5. Update default collection bookmark_count

def list_collections(user_sub: str) -> list[dict]:
    """List all bookmark collections for a user."""
    # Query PK=user_sub, SK begins_with "COLL#"
    # Auto-create default if missing

def bookmark_post(user_sub: str, post_id: str, collection_id: str = "default") -> dict:
    """Bookmark a post to a collection."""
    # 1. Validate post exists
    # 2. Check if already bookmarked (get BM#{post_id})
    # 3. If already bookmarked in different collection, update
    # 4. If new bookmark, create BM# item + increment collection count
    # 5. Set GSI1PK for collection query
    # 6. Return bookmark record

def unbookmark_post(user_sub: str, post_id: str) -> None:
    """Remove a bookmark."""
    # 1. Get BM# item to find collection_id
    # 2. Delete BM# item
    # 3. Decrement collection bookmark_count

def move_bookmark(user_sub: str, post_id: str, to_collection_id: str) -> dict:
    """Move a bookmark to a different collection."""
    # 1. Get current BM# item
    # 2. Update collection_id + GSI1PK
    # 3. Decrement old collection count, increment new

def list_bookmarks(user_sub: str, collection_id: str = "default", cursor: str = None) -> dict:
    """List bookmarks in a collection, sorted by saved_at desc."""
    # Query GSI1 PK={user_sub}#COLL#{collection_id}, SK desc
    # Paginate with cursor
    # For each bookmark, fetch current post data

def is_bookmarked(user_sub: str, post_id: str) -> bool:
    """Check if a post is bookmarked."""
    item = T.post_bookmarks.get_item(Key={"user_sub": user_sub, "sk": f"BM#{post_id}"}).get("Item")
    return item is not None

def get_bookmarked_post_ids(user_sub: str) -> set[str]:
    """Get all bookmarked post IDs for a user (for feed annotation)."""
    # Query PK=user_sub, SK begins_with "BM#"
    # Return set of post_ids
```

### 3.4 Backend Router

**File**: `app/routers/post_bookmarks.py`

```python
router = APIRouter(prefix="/ui/posts", tags=["post-bookmarks"])

# Bookmark CRUD
class BookmarkPostIn(BaseModel):
    collection_id: str = Field(default="default", max_length=64)

@router.post("/{post_id}/bookmark", status_code=201)
def bookmark_post_endpoint(post_id: str, body: BookmarkPostIn, ctx=Depends(require_ui_session)):
    """Bookmark a post to a collection."""

@router.delete("/{post_id}/bookmark", status_code=200)
def unbookmark_post_endpoint(post_id: str, ctx=Depends(require_ui_session)):
    """Remove a bookmark from a post."""

@router.get("/bookmarks")
def list_bookmarks_endpoint(
    collection_id: str = Query(default="default"),
    cursor: str = Query(default=None),
    ctx=Depends(require_ui_session),
):
    """List bookmarked posts in a collection."""

# Collection CRUD
class CreateCollectionIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)

class RenameCollectionIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)

@router.post("/bookmark-collections", status_code=201)
def create_collection_endpoint(body: CreateCollectionIn, ctx=Depends(require_ui_session)):
    """Create a bookmark collection."""

@router.get("/bookmark-collections")
def list_collections_endpoint(ctx=Depends(require_ui_session)):
    """List all bookmark collections."""

@router.patch("/bookmark-collections/{collection_id}")
def rename_collection_endpoint(collection_id: str, body: RenameCollectionIn, ctx=Depends(require_ui_session)):
    """Rename a bookmark collection."""

@router.delete("/bookmark-collections/{collection_id}")
def delete_collection_endpoint(collection_id: str, ctx=Depends(require_ui_session)):
    """Delete a collection (moves bookmarks to 'Saved')."""

@router.patch("/{post_id}/bookmark/move")
def move_bookmark_endpoint(post_id: str, body: BookmarkPostIn, ctx=Depends(require_ui_session)):
    """Move a bookmark to a different collection."""
```

### 3.5 Feed Response Annotation

Optionally, `GET /feed` can include a `is_bookmarked` field on each post. This requires fetching the user's bookmarked post IDs and annotating:

```python
# In GET /feed, after fetching posts:
bookmarked_ids = get_bookmarked_post_ids(user_sub)
for post in posts:
    post["is_bookmarked"] = post["post_id"] in bookmarked_ids
```

### 3.6 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface BookmarkCollection {
  collection_id: string;
  name: string;
  created_at: number;
  bookmark_count: number;
  sort_order: number;
}

export interface PostBookmark {
  post_id: string;
  collection_id: string;
  saved_at: number;
  post: FeedPost;  // Full post data
}

export interface FeedPost {
  // ... existing fields ...
  is_bookmarked?: boolean;
}
```

### 3.7 Frontend API

**File**: `frontend/src/api/endpoints/bookmarks.ts`

```typescript
export const bookmarkPost = (postId: string, collectionId?: string) =>
  api.post(`/ui/posts/${postId}/bookmark`, { collection_id: collectionId || "default" });

export const unbookmarkPost = (postId: string) =>
  api.delete(`/ui/posts/${postId}/bookmark`);

export const listBookmarks = (collectionId?: string, cursor?: string) =>
  api.get<{ bookmarks: PostBookmark[]; next_cursor?: string }>("/ui/posts/bookmarks", {
    params: { collection_id: collectionId || "default", cursor },
  });

export const createCollection = (name: string) =>
  api.post<BookmarkCollection>("/ui/posts/bookmark-collections", { name });

export const listCollections = () =>
  api.get<BookmarkCollection[]>("/ui/posts/bookmark-collections");

export const renameCollection = (collectionId: string, name: string) =>
  api.patch(`/ui/posts/bookmark-collections/${collectionId}`, { name });

export const deleteCollection = (collectionId: string) =>
  api.delete(`/ui/posts/bookmark-collections/${collectionId}`);

export const moveBookmark = (postId: string, toCollectionId: string) =>
  api.patch(`/ui/posts/${postId}/bookmark/move`, { collection_id: toCollectionId });
```

### 3.8 Frontend Components

**BookmarkButton** (in PostCard):

```tsx
const isBookmarked = post.is_bookmarked;

<Button
  variant="ghost"
  size="icon"
  onClick={isBookmarked ? handleUnbookmark : handleBookmark}
  data-testid="bookmark-button"
>
  <Bookmark
    className={cn("h-4 w-4", isBookmarked && "fill-current")}
  />
</Button>
```

Long-press or dropdown for collection selection:

```tsx
<DropdownMenu>
  <DropdownMenuTrigger asChild>
    <Button variant="ghost" size="icon" data-testid="bookmark-button">
      <Bookmark className={cn("h-4 w-4", isBookmarked && "fill-current")} />
    </Button>
  </DropdownMenuTrigger>
  <DropdownMenuContent>
    {collections.map(c => (
      <DropdownMenuItem key={c.collection_id} onClick={() => handleBookmarkTo(c.collection_id)}>
        {c.name} ({c.bookmark_count})
      </DropdownMenuItem>
    ))}
    <DropdownMenuSeparator />
    <DropdownMenuItem onClick={() => setCreateCollectionOpen(true)}>
      <Plus className="h-4 w-4 mr-2" /> New Collection
    </DropdownMenuItem>
  </DropdownMenuContent>
</DropdownMenu>
```

**SavedPostsPage** (`frontend/src/pages/feed/SavedPostsPage.tsx`):

Route: `/saved`

Layout:
```
┌─────────────────────────────────────────────┐
│  Saved Posts                                │
├────────┬────────────────────────────────────┤
│        │                                    │
│ Saved  │  [PostCard]                        │
│ (12)   │  [PostCard]                        │
│        │  [PostCard]                        │
│ Recipes│  ...                               │
│ (5)    │                                    │
│        │  [Load More]                       │
│ Inspo  │                                    │
│ (8)    │                                    │
│        │                                    │
│ [+ New]│                                    │
│        │                                    │
└────────┴────────────────────────────────────┘
```

- Left sidebar: collection list with counts
- Active collection highlighted
- Main area: posts in selected collection, rendered as PostCard
- Pagination via cursor-based "Load More" button
- Empty state: "No saved posts in this collection"
- Collection management: rename (edit icon), delete (trash icon, with confirmation)

**CollectionDialog** (`frontend/src/pages/feed/CollectionDialog.tsx`):

- Create or rename collection
- Name input with validation (1-100 chars)
- Confirm/Cancel buttons

### 3.9 Routes & Navigation

**File**: `frontend/src/App.tsx`

```tsx
<Route path="/saved" element={<SavedPostsPage />} />
```

**Sidebar**: Add "Saved" link with `Bookmark` icon.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/post_bookmarks.py` | Bookmark + collection business logic |
| `app/routers/post_bookmarks.py` | REST endpoints |
| `frontend/src/api/endpoints/bookmarks.ts` | API client functions |
| `frontend/src/pages/feed/SavedPostsPage.tsx` | Saved posts page with collection sidebar |
| `frontend/src/pages/feed/CollectionDialog.tsx` | Create/rename collection dialog |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `post_bookmarks` TableDef |
| `app/core/settings.py` | Add bookmark settings |
| `app/core/tables.py` | Add `T.post_bookmarks` |
| `app/main.py` | Register bookmark router |
| `app/routers/newsfeed.py` | Add `is_bookmarked` annotation to feed response |
| `frontend/src/api/types.ts` | Add bookmark types |
| `frontend/src/pages/feed/PostCard.tsx` | Add bookmark button |
| `frontend/src/App.tsx` | Add `/saved` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Saved" nav item |

### 4.3 Step-by-Step Order

1. Add DDB table, settings, table handle
2. Implement `post_bookmarks.py` service (collections + bookmarks)
3. Implement router endpoints
4. Register in main.py
5. Annotate feed response with `is_bookmarked`
6. Add frontend types and API client
7. Add BookmarkButton to PostCard
8. Build SavedPostsPage with collection sidebar
9. Build CollectionDialog
10. Add route and sidebar nav
11. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/post-bookmarks.spec.ts` — 18 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let alicePostId: string;
let bobPostId: string;
let customCollectionId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice and Bob sessions
  // Alice creates a post
  // Bob creates a post
});
```

### 5.3 Section 336: Bookmark CRUD API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 336.1 | Bookmark a post to default collection | POST `/posts/{id}/bookmark`; 201; bookmark created |
| 336.2 | List bookmarks in default collection | GET `/posts/bookmarks`; 200; bookmarked post in results with `saved_at` |
| 336.3 | Unbookmark a post | DELETE `/posts/{id}/bookmark`; 200; re-list; post not in bookmarks |
| 336.4 | Bookmark to specific collection | Create collection; POST bookmark with `collection_id`; 201 |
| 336.5 | Bookmark already-bookmarked post to new collection | POST bookmark again with different collection; updates collection_id |

### 5.4 Section 337: Collection CRUD API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 337.1 | List collections includes auto-created default | GET `/posts/bookmark-collections`; 200; "Saved" collection present |
| 337.2 | Create custom collection | POST `/posts/bookmark-collections` with name; 201; `collection_id` returned |
| 337.3 | Rename collection | PATCH `/posts/bookmark-collections/{id}`; 200; name updated |
| 337.4 | Delete collection moves bookmarks to default | Bookmark to custom; delete custom; bookmark now in "Saved" |
| 337.5 | Cannot delete default collection | DELETE default; 400; "Cannot delete default collection" |

### 5.5 Section 338: Bookmark Management API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 338.1 | Move bookmark between collections | PATCH `/posts/{id}/bookmark/move`; 200; bookmark in new collection |
| 338.2 | Feed response includes is_bookmarked | Bookmark a post; GET `/feed`; post has `is_bookmarked=true` |
| 338.3 | Unbookmarked post has is_bookmarked=false | Unbookmark; GET feed; `is_bookmarked=false` |
| 338.4 | List bookmarks paginates correctly | Bookmark 5 posts; list with limit; verify cursor-based pagination |

### 5.6 Section 339: Bookmark UI (6 tests)

| # | Test | Assertion |
|---|------|-----------|
| 339.1 | Bookmark button visible on PostCard | Navigate to feed; `[data-testid="bookmark-button"]` visible |
| 339.2 | Clicking bookmark saves post | Click bookmark button; icon changes to filled state |
| 339.3 | Clicking filled bookmark unbookmarks post | Click again; icon returns to outline; post removed from saved |
| 339.4 | Saved Posts page shows bookmarked posts | Navigate to `/saved`; bookmarked post visible |
| 339.5 | Collection sidebar shows collections with counts | Collection list visible; "Saved" with correct count |
| 339.6 | Create collection dialog works | Click "+ New"; enter name; confirm; collection appears in sidebar |

### 5.7 Section 340: Bookmark Edge Cases (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 340.1 | Bookmark a locked post | POST bookmark on locked post; 201; post appears in saved list with lock indicator |
| 340.2 | Creator deletes bookmarked post | Alice deletes post; Bob's bookmark list shows it as missing/removed |
| 340.3 | Two users bookmark same post | Alice and Bob both bookmark; each has independent record |
| 340.4 | Rapid bookmark/unbookmark toggle | Toggle 5 times quickly; final state matches last action |

---

## 6. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Post not found | 404 | `not_found` | "Post not found" | Redirect to feed |
| Collection not found | 404 | `collection_not_found` | "Collection not found" | Refresh collections list |
| Delete default collection | 400 | `cannot_delete_default` | "Cannot delete default collection" | Hide delete button for default |
| Rename default collection | 400 | `cannot_rename_default` | "Cannot rename default collection" | Hide rename for default |
| Max collections exceeded (50) | 400 | `max_collections` | "Maximum of 50 collections reached" | Delete unused or upgrade |
| Max bookmarks per collection | 400 | `max_bookmarks` | "Collection is full (1000 max)" | Move bookmarks to other collections |
| Collection name too long | 422 | `validation_error` | "Name must be 100 characters or less" | Show inline error |
| Duplicate collection name | 409 | `duplicate_name` | "Collection name already exists" | Show inline error |
| Bookmark non-existent post | 404 | `not_found` | "Post not found" | Remove stale entry |
| Unauthenticated | 401 | `unauthorized` | "Authentication required" | Redirect to login |
| CSRF mismatch | 403 | `csrf_invalid` | "Invalid CSRF token" | Refresh page |
| Rate limited | 429 | `rate_limited` | "Too many requests" | Retry after backoff |

---

## 7. Security Considerations

- Bookmarks are private to the bookmarking user
- Post creators cannot see who bookmarked their posts
- Collection names are user-scoped (no global namespace)
- Bookmark state (`is_bookmarked`) is only included in the bookmarking user's feed response
- No cross-user access (PK is user_sub; DDB key conditions enforce isolation)
- Rate limiting prevents bulk bookmark abuse (50 operations/min)

---

## 8. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Fetching bookmarked IDs for feed | < 20ms | Single DDB query with begins_with "BM#"; cached per request |
| Many bookmarks (>500) | < 100ms per page | Cursor-based pagination; max 1000 per collection |
| Post data freshness | Eventual (seconds) | Denormalized preview for fast list; full data on detail view |
| Collection count accuracy | Atomic | DynamoDB ADD for counter updates |
| Bookmark toggle perceived latency | Instant | Optimistic UI update in React Query cache |
| Feed annotation overhead | < 10ms | Set lookup O(1) per post |

---

## 9. Observability

### 9.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `bookmark_created_total` | Counter | `collection_type` (default/custom) | Bookmarks created |
| `bookmark_removed_total` | Counter | — | Bookmarks removed |
| `bookmark_moved_total` | Counter | — | Bookmarks moved between collections |
| `collection_created_total` | Counter | — | Collections created |
| `collection_deleted_total` | Counter | — | Collections deleted |
| `bookmark_list_latency_ms` | Histogram | — | Bookmark list query latency |

### 9.2 Logging

| Event | Level | Fields |
|-------|-------|--------|
| Post bookmarked | INFO | `user_sub`, `post_id`, `collection_id` |
| Post unbookmarked | INFO | `user_sub`, `post_id` |
| Collection created | INFO | `user_sub`, `collection_id`, `name` |
| Collection deleted | INFO | `user_sub`, `collection_id`, `bookmarks_moved` |
| Max collections reached | WARN | `user_sub`, `count` |

### 9.3 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Bookmark list slow | p95 > 500ms | Medium | Check DDB throughput |
| High bookmark error rate | > 5% of ops fail | High | Check DDB health |
| Bulk bookmark abuse | > 200 bookmarks/hour from single user | Medium | Review and rate limit |

---

## 10. Rollout Plan

### 10.1 Feature Flag

```python
# app/core/settings.py
post_bookmarks_enabled: bool = os.environ.get("POST_BOOKMARKS_ENABLED", "true").lower() == "true"
```

### 10.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Backend + table | Deploy DDB table + endpoints; flag OFF | 1 day | Unit tests pass |
| Phase 2: Internal | Enable for internal accounts | 3 days | E2E pass; QA sign-off |
| Phase 3: Canary 10% | Enable for 10% of users | 3 days | Error rate < 0.1% |
| Phase 4: GA | Enable for all users | Permanent | Adoption metrics healthy |

### 10.3 Migration

1. Create `post_bookmarks` table via `scripts/local-ddb-init.py`
2. No data migration needed (new empty table)
3. Default collection auto-created on first user access

### 10.4 Rollback

1. Set `POST_BOOKMARKS_ENABLED=false`
2. Bookmark data preserved in DDB (dormant)
3. BookmarkButton hidden; SavedPostsPage shows empty
4. Re-enabling restores all data

---

## 11. API Request/Response Examples

**Bookmark a post** (curl):

```bash
curl -X POST http://localhost:8000/ui/posts/p_abc123/bookmark \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_bob; ui_csrf=csrf_b; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_b" \
  -d '{"collection_id": "default"}'
```

**Response (201)**:
```json
{"post_id": "p_abc123", "collection_id": "default", "saved_at": 1748520500}
```

**Create a collection** (curl):

```bash
curl -X POST http://localhost:8000/ui/posts/bookmark-collections \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_bob; ui_csrf=csrf_b; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_b" \
  -d '{"name": "Recipes"}'
```

**Response (201)**:
```json
{"collection_id": "coll_a1b2c3", "name": "Recipes", "created_at": 1748520600, "bookmark_count": 0, "sort_order": 1}
```

**List bookmarks in collection** (curl):

```bash
curl -X GET "http://localhost:8000/ui/posts/bookmarks?collection_id=default" \
  -H "Cookie: ui_session=sess_bob; ui_csrf=csrf_b; ui_access_token=eyJ..."
```

**Response (200)**:
```json
{
  "bookmarks": [
    {"post_id": "p_abc123", "collection_id": "default", "saved_at": 1748520500, "post": {"post_id": "p_abc123", "body": "Great recipe!", "like_count": 10}}
  ],
  "next_cursor": null
}
```

---

## 12. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| None | — | Uses existing post + bookmark infrastructure |

---

## Codebase References

### Existing Files (verified)
| File | Key References | Lines |
|------|---------------|-------|
| `app/routers/newsfeed.py` | `pk_bookmark` helper | 5461 |
| `app/routers/newsfeed.py` | `pk_bookmark_lookup` helper | 5465 |
| `app/routers/newsfeed.py` | `POST /ui/bookmarks` (`create_bookmark`) | 5483 |
| `app/routers/newsfeed.py` | `DELETE /ui/bookmarks/{content_type}/{content_id}` (`delete_bookmark`) | 5538 |
| `app/routers/newsfeed.py` | `GET /ui/bookmarks` (`list_bookmarks`) | 5553 |
| `frontend/src/api/endpoints/bookmarks.ts` | Bookmark API client | - |
| `frontend/src/pages/saved/SavedPage.tsx` | Saved posts page (exists, may need collection support) | - |
| `scripts/local-ddb-init.py` | `app_single_table` | 222 |

### Not Yet Implemented
| Feature | Notes |
|---------|-------|
| Collection CRUD (create, rename, delete, reorder) | New endpoints and DDB items needed |
| `collection_id` field on bookmark items | Existing bookmarks have no collection concept |
| Collection sidebar in SavedPage | UI enhancement needed |
| Move bookmark between collections | New endpoint needed |
| `is_bookmarked` field in feed post response | Not in `_post_to_dict` yet |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_bookmarks.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_feed_009_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_feed_009_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_feed_009_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_feed_009_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_feed_009_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_feed_009_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_feed_009_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_feed_009_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/bookmarks-collections.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 12

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `BOOKMARKS_COLLECTIONS_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `BOOKMARKS_COLLECTIONS_ENABLED` must be enabled for tests to run
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
- [ ] Feature flag `BOOKMARKS_COLLECTIONS_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite

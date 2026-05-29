# FEED-009: Post Bookmarks / Save Collections

**Ticket**: FEED-009
**Author**: Engineering
**Status**: Design
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

1. **No `post_bookmarks` DDB table** — no storage for bookmarks or collections.
2. **No bookmark endpoints** — no API to save, unsave, or manage bookmarks.
3. **No collection CRUD** — no API to create, rename, or delete collections.
4. **No bookmark icon on PostCard** — no UI affordance for saving.
5. **No Saved Posts page** — no page for browsing saved posts by collection.
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

### 5.6 Section 339: Bookmark UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 339.1 | Bookmark button visible on PostCard | Navigate to feed; `[data-testid="bookmark-button"]` visible |
| 339.2 | Clicking bookmark saves post | Click bookmark button; icon changes to filled state |
| 339.3 | Saved Posts page shows bookmarked posts | Navigate to `/saved`; bookmarked post visible |
| 339.4 | Collection sidebar shows collections with counts | Collection list visible; "Saved" with correct count |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Post not found | 404 | "Post not found" |
| Collection not found | 404 | "Collection not found" |
| Delete default collection | 400 | "Cannot delete default collection" |
| Rename default collection | 400 | "Cannot rename default collection" |
| Max collections exceeded | 400 | "Maximum collection limit reached" |
| Collection name too long | 422 | Pydantic validation |
| Bookmark non-existent post | 404 | "Post not found" |

---

## 7. Security Considerations

- Bookmarks are private to the bookmarking user
- Post creators cannot see who bookmarked their posts
- Collection names are user-scoped (no global namespace)
- Bookmark state (`is_bookmarked`) is only included in the bookmarking user's feed response

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Fetching bookmarked IDs for feed annotation | Single DDB query with begins_with "BM#"; results cached per request |
| Many bookmarks | Cursor-based pagination in list endpoint; max 1000 per collection |
| Post data freshness in bookmark list | Bookmarks store denormalized preview; full post data fetched at list time |
| Collection count accuracy | Atomic counter updates via DynamoDB ADD |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| None | — | Uses existing post infrastructure |

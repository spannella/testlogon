# SOCIAL-001: Post Bookmarks / Save Collections

**Ticket**: SOCIAL-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: P0 — Core User Experience
**Estimated effort**: 10-14 days

---

## 1. Executive Summary

<!-- NOTE: This ticket's "current state" description is OUTDATED. The bookmark system described here has been FULLY IMPLEMENTED:
  - Backend: app/routers/newsfeed.py:5458-5954 — bookmark CRUD + collections + status endpoint
  - Frontend: frontend/src/pages/saved/SavedPage.tsx, frontend/src/api/endpoints/bookmarks.ts
  - PostCard: BookmarkButton integrated at PostCard.tsx:204,232-242
  - Sidebar: "Saved" link at Sidebar.tsx:89
  - Route: /saved at App.tsx:154
  - Types: FeedPost.bookmarked field at types.ts:1969-1970
  - DDB keys: BOOKMARK#{user_id}, BOOKMARK_LOOKUP#{user_id}, BMCOL#{user_id}
  All "Files to Create" listed in section 13 either already exist (SavedPage.tsx, bookmarks.ts) or were implemented inline (BookmarkButton is in PostCard.tsx rather than a separate file; bookmark service is in newsfeed.py rather than bookmarks.py).
-->

The platform currently has no mechanism for users to save content for later viewing. When a user encounters a post or video they want to revisit, their only options are scrolling through their entire feed history, searching by keyword, or sharing the post to a DM conversation with themselves. None of these are satisfactory. Every major social platform (Instagram, Twitter/X, YouTube, TikTok) provides a dedicated bookmark/save feature because it drives repeat engagement: users return to the platform specifically to revisit saved content.

This feature introduces a bookmark system backed by DynamoDB entities in the existing `app_single_table`. Users can bookmark any post or video with a single tap. Bookmarks are organized into collections (folders) that users can create, rename, and delete. A new `/saved` page provides a browsable, filterable view of all saved content. Bookmark icons are added to PostCard and video cards throughout the UI.

The implementation is straightforward: CRUD operations on DynamoDB items with a GSI for user-scoped chronological listing, eight new API endpoints (four for bookmarks, four for collections), one new frontend page, and minor UI additions to existing components. The feature uses the existing `app_single_table` with no new DDB tables or GSIs required.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Bookmark a post (viewer)**
As a feed viewer, I want to bookmark a post so I can easily find it later without scrolling through my entire feed.

*Acceptance criteria:*
- Bookmark icon (outline) visible on every PostCard in the action row.
- Single click toggles bookmark state (outline -> filled).
- Bookmarked posts appear on the `/saved` page.
- Optimistic UI update: icon changes immediately without waiting for API response.
- Success toast: "Saved to bookmarks".

**US-2: Bookmark a video (viewer)**
As a video viewer, I want to bookmark videos from the gallery or video detail page so I can watch them later.

*Acceptance criteria:*
- Bookmark icon visible on video cards in the gallery and video detail page.
- Same toggle behavior as post bookmarks.
- Saved videos appear on `/saved` page alongside saved posts.

**US-3: Organize into collections (power user)**
As a power user, I want to organize my bookmarks into named collections so I can categorize saved content.

*Acceptance criteria:*
- Create collections from the `/saved` page (max 50 per user).
- Assign bookmarks to collections during creation or by moving later.
- Collections have a name (max 100 chars) and item count.
- Delete collection moves its bookmarks to "Uncategorized" (default collection).
- Rename collection updates the display name.

**US-4: Browse saved content (viewer)**
As a user, I want a dedicated page to browse all my saved content, filterable by type and collection.

*Acceptance criteria:*
- `/saved` page accessible from sidebar navigation (Main group).
- Tabs for "All", "Posts", "Videos" content type filtering.
- Collection dropdown/sidebar for filtering by collection.
- Reverse-chronological order (newest saved first).
- Content preview cards with: thumbnail, author name, body snippet, date saved.
- Pagination (load more button or infinite scroll).

**US-5: Remove bookmark (viewer)**
As a user, I want to remove a bookmark I no longer need, either from the PostCard or from the Saved page.

*Acceptance criteria:*
- Clicking filled bookmark icon on PostCard removes the bookmark.
- "Remove" button on bookmark cards in the `/saved` page.
- Optimistic UI: removed immediately from both PostCard and Saved page.
- No confirmation dialog for removal (instant, reversible by re-bookmarking).

**US-6: Bookmark count in navigation (viewer)**
As a user, I want to see how many items I have saved at a glance.

*Acceptance criteria:*
- Badge count on the "Saved" sidebar link showing total bookmark count.
- Collection cards show per-collection item count.

### 2.2 Pain Points

1. **No save-for-later**: Users lose interesting content as they scroll. The feed is chronological and has no "read later" concept. Valuable posts are lost in the stream.
2. **No organized content library**: Power users who curate content (creators saving inspiration, buyers saving product posts) have no tool for this.
3. **Reduced return visits**: Without a reason to come back and revisit content, users consume content once and leave. Bookmarks create a "pull" back to the platform.
4. **No engagement signal for creators**: Bookmarks are a strong signal of high-quality content, but the platform cannot capture this signal today. (Note: bookmarks are private -- not exposed to creators, but can feed recommendation algorithms.)
5. **Friction for saved content retrieval**: The only workaround is DM-to-self (cumbersome) or browser bookmarks (external, not integrated).

### 2.3 Competitive Analysis

| Platform | Feature Name | Collections | Bookmark Count Visible to Others | Creator Sees Count |
|----------|-------------|-------------|----------------------------------|-------------------|
| Instagram | Save | Yes (named collections) | No | No |
| Twitter/X | Bookmarks | No (flat list) | No | No |
| YouTube | Save to playlist | Yes (playlists) | Public playlists visible | Like count shown |
| TikTok | Favorites | Yes (collections) | No | No |
| **This platform** | **None** | **N/A** | **N/A** | **N/A** |

---

## 3. Current State Analysis

### 3.1 Post Data Model

The `FeedPost` TypeScript interface (`frontend/src/api/types.ts:1781-1834`) has no `bookmarked`, `saved`, or `bookmark_count` field. The Python-side post dict returned by `_post_to_dict()` in `app/routers/newsfeed.py` similarly has no bookmark-related fields.

### 3.2 DynamoDB Key Patterns (Newsfeed)

The newsfeed module uses the `app_single_table` (`app/routers/newsfeed.py:54,59`) with key builders at lines 711-793. Existing entity prefixes include:
- `USER#{user_id}` (pk) with sort keys: `META`, `DRAFT#`, `SCHEDULEDPOST#`
- `POST#{post_id}` (pk) with sort key `META`
- `LIKE#{user_id}` (pk) for post likes
- `HIDE#{user_id}` (pk) for hidden posts
- `UNLOCK#{user_id}` (pk) for unlocked posts
- `NOTIF#{user_id}` (pk) for notification references

There is no `BOOKMARK#` or `BMCOL#` prefix anywhere in the codebase (verified: grep returns zero results).

### 3.3 GSI Availability

The `app_single_table` has six GSIs defined (`scripts/local-ddb-init.py:220-226`): GSI1 through GSI5 plus GSI_SCHEDULE_DUE. GSI1 is used for feed fan-out (`GSI1PK=FEED#{user_id}`). The bookmark feature will use the same table with new PK/SK patterns and reuse GSI1 for chronological bookmark listing.

### 3.4 PostCard Action Row

The PostCard action row (`frontend/src/pages/feed/PostCard.tsx:512-560`) currently renders: Heart (like), MessageCircle (comments), DollarSign (Tip), Share2 (share). The bookmark icon will be added after the Share2 button as the final action in the row. The existing `flex items-center gap-4` layout accommodates additional icons.

### 3.5 Sidebar Navigation

The sidebar (`frontend/src/components/layout/Sidebar.tsx:68-137`) has five groups: Main, Commerce, Productivity, Media, Account. The Main group (lines 72-79) currently contains: Dashboard, Messages, Contacts, Helpdesk, Feed, Discover. The "Saved" link will be added after "Discover" (line 78).

### 3.6 Existing Like/Unlike Pattern

The like system provides a reference implementation for bookmark toggle behavior:
- PostCard has a Heart icon that toggles like state
- `liked_by_me: boolean` on the `FeedPost` interface
- Mutation with optimistic update (immediate icon color change)
- DDB entity: `pk=LIKE#{user_id}, sk=POST#{post_id}`

Bookmarks follow the same pattern but with different PK prefix and additional collection support.

### 3.7 Gaps

<!-- NOTE: ALL gaps listed below have been resolved. The bookmark system is fully implemented. -->

1. ~~No bookmark endpoints in any router~~ — **RESOLVED**: Bookmark CRUD at `app/routers/newsfeed.py:5483-5624`, collections at `newsfeed.py:5658-5729`
2. ~~No `BOOKMARK#` or `BMCOL#` key prefix~~ — **RESOLVED**: `pk_bookmark` at `newsfeed.py:5461`, `pk_bookmark_lookup` at `newsfeed.py:5465`, `pk_bmcol` at `newsfeed.py:5654`
3. ~~No `bookmarked` field in `FeedPost` interface~~ — **RESOLVED**: `bookmarked?: boolean` at `types.ts:1969-1970`
4. ~~No bookmark icon in PostCard~~ — **RESOLVED**: `Bookmark`/`BookmarkCheck` icons imported at `PostCard.tsx:4`, mutation at `PostCard.tsx:232-242`
5. ~~No `/saved` route~~ — **RESOLVED**: Route at `App.tsx:154`, lazy-loaded `SavedPage` at `App.tsx:77`
6. ~~No "Saved" link in sidebar~~ — **RESOLVED**: `Sidebar.tsx:89` with `Bookmark` icon
7. ~~No `BookmarkButton` component~~ — **RESOLVED**: Bookmark logic integrated directly into `PostCard.tsx:204-242` (inline, not a separate component)

---

## 4. Technical Architecture

### 4.1 System Diagram

```
PostCard / VideoCard                Backend API                  DynamoDB (app_single_table)
  |                                   |                              |
  |-- POST /ui/bookmarks ------------>|-- put_item ----------------->|  pk=BOOKMARK#{user_id}
  |     { content_type, content_id,   |                              |  sk={content_type}#{content_id}
  |       collection_id? }            |                              |
  |                                   |-- update_item (count) ------>|  pk=BMCOL#{user_id}
  |                                   |                              |  sk=COL#{collection_id}
  |                                   |                              |
  |-- DELETE /ui/bookmarks/{t}/{id} ->|-- delete_item -------------->|  pk=BOOKMARK#{user_id}
  |                                   |                              |  sk={t}#{id}
  |                                   |                              |
  |-- GET /ui/bookmarks ------------->|-- query GSI1 BOOKMARK#{uid}->|  paginated, filtered
  |     ?type=post&collection=X       |   + BatchGetItem for content |
  |                                   |                              |
SavedPage                            |                              |
  |-- GET /ui/bookmark-collections -->|-- query pk=BMCOL#{uid} ---->|  collection list
  |-- POST /ui/bookmark-collections ->|-- put_item ----------------->|  pk=BMCOL#{user_id}
  |                                   |                              |  sk=COL#{collection_id}
  |-- PATCH /{collection_id} -------->|-- update_item -------------->|  rename
  |-- DELETE /{collection_id} ------->|-- delete_item + batch ------>|  move bookmarks to default
```

### 4.2 Data Flow -- Bookmark a Post

1. User clicks bookmark icon on PostCard
2. Frontend optimistically updates: icon filled, count incremented (if shown)
3. Frontend calls `POST /ui/bookmarks` with `{ content_type: "post", content_id: "p_abc", collection_id?: "col_xyz" }`
4. Backend validates: content exists, not already bookmarked, user under quota
5. Backend writes DynamoDB item to `app_single_table`:
   - `pk=BOOKMARK#{user_id}`, `sk=post#{post_id}`
   - `GSI1PK=BOOKMARK#{user_id}`, `GSI1SK={created_at_iso}#{content_type}#{content_id}`
6. Backend increments `item_count` on the collection entity (atomic ADD)
7. Backend returns `{ ok: true, content_type, content_id, created_at }`
8. Frontend invalidates `["bookmarks"]` and `["bookmark-collections"]` query keys

### 4.3 Data Flow -- List Bookmarks on /saved

1. User navigates to `/saved`
2. Frontend calls `GET /ui/bookmarks?limit=24&type=post&collection=all`
3. Backend queries GSI1 with `GSI1PK=BOOKMARK#{user_id}`, ScanIndexForward=False (newest first)
4. Applies FilterExpression for `content_type` if specified
5. For each bookmark item, batch-fetches the actual content metadata (post from `POST#{post_id}/META`, video from video metadata table)
6. Returns enriched bookmark list with content previews
7. Frontend renders grid with collection filter and content type tabs

### 4.4 Data Flow -- Bookmark Status Check

The `/saved` page needs to know which posts in the feed are already bookmarked (to show filled icon). Two approaches:

**Approach A (chosen):** Batch status check endpoint.
- `GET /ui/bookmarks/status?ids=post:p_abc,post:p_def,video:v_ghi`
- Returns `{ statuses: { "post:p_abc": true, "post:p_def": false, "video:v_ghi": true } }`
- Called once per feed page render, batching all visible post IDs

**Approach B (rejected):** Include `bookmarked: boolean` on every post in `_post_to_dict()`.
- Rejected because it adds a DDB `get_item` per post per feed query, which is expensive.

---

## 5. Data Model Deep Dive

### 5.1 Bookmark Entity

Stored in the existing `app_single_table` (no new DynamoDB table required).

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `BOOKMARK#{user_id}` | `"BOOKMARK#alice@test.local"` |
| `sk` | S | `{content_type}#{content_id}` | `"post#p_abc123"` |
| `Entity` | S | `"Bookmark"` | `"Bookmark"` |
| `user_id` | S | Bookmarking user | `"alice@test.local"` |
| `content_type` | S | `"post"` or `"video"` | `"post"` |
| `content_id` | S | ID of the bookmarked content | `"p_abc123"` |
| `collection_id` | S | Collection (default `"default"`) | `"col_xyz"` |
| `created_at` | S | ISO 8601 timestamp | `"2026-05-27T10:00:00Z"` |
| `GSI1PK` | S | `BOOKMARK#{user_id}` | `"BOOKMARK#alice@test.local"` |
| `GSI1SK` | S | `{created_at}#{content_type}#{content_id}` | `"2026-05-27T10:00:00Z#post#p_abc123"` |

**Example DDB item:**
```json
{
  "pk": "BOOKMARK#alice@test.local",
  "sk": "post#p_abc123",
  "Entity": "Bookmark",
  "user_id": "alice@test.local",
  "content_type": "post",
  "content_id": "p_abc123",
  "collection_id": "default",
  "created_at": "2026-05-27T10:00:00Z",
  "GSI1PK": "BOOKMARK#alice@test.local",
  "GSI1SK": "2026-05-27T10:00:00Z#post#p_abc123"
}
```

### 5.2 Collection Entity

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `BMCOL#{user_id}` | `"BMCOL#alice@test.local"` |
| `sk` | S | `COL#{collection_id}` | `"COL#col_xyz"` |
| `Entity` | S | `"BookmarkCollection"` | `"BookmarkCollection"` |
| `user_id` | S | Owner | `"alice@test.local"` |
| `collection_id` | S | UUID | `"col_xyz"` |
| `name` | S | Display name (max 100 chars) | `"Inspiration"` |
| `item_count` | N | Number of bookmarks in collection | `12` |
| `created_at` | S | ISO timestamp | `"2026-05-27T10:00:00Z"` |
| `updated_at` | S | ISO timestamp | `"2026-05-27T11:30:00Z"` |

**Example DDB item:**
```json
{
  "pk": "BMCOL#alice@test.local",
  "sk": "COL#col_xyz",
  "Entity": "BookmarkCollection",
  "user_id": "alice@test.local",
  "collection_id": "col_xyz",
  "name": "Inspiration",
  "item_count": 12,
  "created_at": "2026-05-27T10:00:00Z",
  "updated_at": "2026-05-27T11:30:00Z"
}
```

### 5.3 Access Patterns

| Access Pattern | Key Condition | Index | Filter |
|---------------|---------------|-------|--------|
| Check if user bookmarked a specific item | `pk=BOOKMARK#{uid}, sk={type}#{id}` | Table | None |
| List all bookmarks for user (newest first) | `GSI1PK=BOOKMARK#{uid}`, ScanIndexForward=False | GSI1 | Optional `content_type` via FilterExpression |
| List bookmarks in a collection | `pk=BOOKMARK#{uid}, sk begins_with {type}#` | Table | `collection_id = X` (FilterExpression) |
| Batch check bookmark status | BatchGetItem with keys `[(BOOKMARK#{uid}, post#p1), ...]` | Table | None |
| List all collections for user | `pk=BMCOL#{uid}, sk begins_with COL#` | Table | None |
| Get a single collection | `pk=BMCOL#{uid}, sk=COL#{col_id}` | Table | None |
| Count total bookmarks for user | Query GSI1 with `Select: COUNT` | GSI1 | None |

### 5.4 Settings in `app/core/settings.py`

```python
# Bookmarks (SOCIAL-001)
bookmarks_enabled: bool = os.environ.get("BOOKMARKS_ENABLED", "1") not in ("0", "false", "False")
bookmarks_max_per_user: int = int(os.environ.get("BOOKMARKS_MAX_PER_USER", "5000"))
bookmarks_max_collections: int = int(os.environ.get("BOOKMARKS_MAX_COLLECTIONS", "50"))
bookmarks_collection_name_max_length: int = int(os.environ.get("BOOKMARKS_COLLECTION_NAME_MAX_LENGTH", "100"))
```

No new table handle needed in `app/core/tables.py` since bookmarks use the existing `app_single_table` via direct `ddb.Table()` reference (same pattern as `app/services/social.py:19-20` and `app/routers/newsfeed.py:54,59`).

---

## 6. API Contract Design

### 6.1 Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/bookmarks` | `require_ui_session` | Create a bookmark |
| DELETE | `/ui/bookmarks/{content_type}/{content_id}` | `require_ui_session` | Remove a bookmark |
| GET | `/ui/bookmarks` | `require_ui_session` | List bookmarks (paginated, filterable) |
| GET | `/ui/bookmarks/status` | `require_ui_session` | Check bookmark status for multiple items |
| POST | `/ui/bookmark-collections` | `require_ui_session` | Create a collection |
| PATCH | `/ui/bookmark-collections/{collection_id}` | `require_ui_session` | Rename a collection |
| DELETE | `/ui/bookmark-collections/{collection_id}` | `require_ui_session` | Delete a collection |
| GET | `/ui/bookmark-collections` | `require_ui_session` | List collections |

### 6.2 POST `/ui/bookmarks`

**Request:**
```json
{
  "content_type": "post",
  "content_id": "p_abc123",
  "collection_id": "col_xyz"
}
```
`collection_id` is optional; defaults to `"default"`.

**curl example:**
```bash
curl -X POST http://localhost:8000/ui/bookmarks \
  -H "Cookie: ui_session=...; ui_access_token=...; ui_csrf=..." \
  -H "x-csrf-token: ..." \
  -H "Content-Type: application/json" \
  -d '{"content_type": "post", "content_id": "p_abc123"}'
```

**Response (201):**
```json
{
  "ok": true,
  "content_type": "post",
  "content_id": "p_abc123",
  "collection_id": "default",
  "created_at": "2026-05-27T10:00:00Z"
}
```

**Error Codes:**
| Status | Code | Condition |
|--------|------|-----------|
| 400 | `invalid_content_type` | Must be "post" or "video" |
| 404 | `content_not_found` | Content does not exist |
| 409 | `already_bookmarked` | Duplicate bookmark |
| 429 | `rate_limited` | Rate limit exceeded |
| 400 | `max_bookmarks_reached` | User at 5000 bookmark limit |

### 6.3 DELETE `/ui/bookmarks/{content_type}/{content_id}`

**curl example:**
```bash
curl -X DELETE http://localhost:8000/ui/bookmarks/post/p_abc123 \
  -H "Cookie: ui_session=...; ui_access_token=...; ui_csrf=..." \
  -H "x-csrf-token: ..."
```

**Response (200):**
```json
{
  "ok": true
}
```

**Error Codes:**
| Status | Code | Condition |
|--------|------|-----------|
| 404 | `bookmark_not_found` | User has not bookmarked this content |

### 6.4 GET `/ui/bookmarks`

**Query parameters:**
- `limit` (int, default 24, max 100)
- `cursor` (string, optional)
- `content_type` (string, optional: "post", "video")
- `collection_id` (string, optional: filter to a specific collection)

**curl example:**
```bash
curl "http://localhost:8000/ui/bookmarks?limit=24&content_type=post" \
  -H "Cookie: ui_session=...; ui_access_token=..."
```

**Response (200):**
```json
{
  "bookmarks": [
    {
      "content_type": "post",
      "content_id": "p_abc123",
      "collection_id": "default",
      "created_at": "2026-05-27T10:00:00Z",
      "content_preview": {
        "author_id": "bob@test.local",
        "author_display_name": "Bob",
        "body_snippet": "Check out this amazing video...",
        "image_url": "/mock/s3/uploads/post_img.jpg",
        "like_count": 42
      }
    }
  ],
  "next_cursor": "eyJHU0kxU0siOiAiMjAyNi0wNS0yN1QwOTowMDowMFoifQ==",
  "total_count": 47
}
```

### 6.5 GET `/ui/bookmarks/status`

**Query parameters:**
- `ids` (comma-separated: `post:p_abc,post:p_def,video:vid_xyz`) -- max 25 items

**curl example:**
```bash
curl "http://localhost:8000/ui/bookmarks/status?ids=post:p_abc,video:vid_def" \
  -H "Cookie: ui_session=...; ui_access_token=..."
```

**Response (200):**
```json
{
  "statuses": {
    "post:p_abc": true,
    "video:vid_def": false
  }
}
```

### 6.6 Collection Endpoints

**POST `/ui/bookmark-collections`:**
```json
{ "name": "Inspiration" }
```
Response (201): `{ "ok": true, "collection_id": "col_xyz", "name": "Inspiration", "item_count": 0, "created_at": "..." }`

**GET `/ui/bookmark-collections`:**
Response (200): `{ "collections": [{ "collection_id": "...", "name": "...", "item_count": N, "created_at": "..." }] }`

**PATCH `/ui/bookmark-collections/{collection_id}`:**
```json
{ "name": "New Name" }
```
Response (200): `{ "ok": true, "collection_id": "...", "name": "New Name" }`

**DELETE `/ui/bookmark-collections/{collection_id}`:**
Response (200): `{ "ok": true, "moved_count": 5 }`
Side effect: all bookmarks with this `collection_id` are updated to `collection_id="default"`.

---

## 7. Frontend Component Design

### 7.1 New Files

| File | Purpose | Est. Lines |
|------|---------|------------|
| `frontend/src/pages/saved/SavedPage.tsx` | Main saved content page with tabs, filters, grid | ~250 |
| `frontend/src/components/shared/BookmarkButton.tsx` | Reusable bookmark toggle button | ~80 |
| `frontend/src/api/endpoints/bookmarks.ts` | API client for bookmark/collection endpoints | ~80 |
| `frontend/e2e/bookmarks.spec.ts` | E2E tests | ~350 |

### 7.2 BookmarkButton Component

A reusable icon button used in PostCard and video card components:

```tsx
interface BookmarkButtonProps {
  contentType: "post" | "video";
  contentId: string;
  initialBookmarked?: boolean;
  className?: string;
}
```

**Behavior:**
- Renders `Bookmark` (outline) or `BookmarkCheck` (filled, amber/gold color) icon from lucide-react
- Uses `useQuery(["bookmark-status", contentType, contentId])` for initial state (or accepts `initialBookmarked` prop to avoid extra query)
- Uses `useMutation` for toggle with optimistic update:
  - On bookmark: `POST /ui/bookmarks`, then invalidate `["bookmarks"]`
  - On unbookmark: `DELETE /ui/bookmarks/{type}/{id}`, then invalidate `["bookmarks"]`
- Shows toast on success: "Saved" / "Removed from saved"

**React Query keys used:**
- `["bookmark-status", contentType, contentId]` -- single item status
- `["bookmarks"]` -- list (invalidated on add/remove)
- `["bookmark-collections"]` -- collection list (invalidated when collection count changes)

### 7.3 PostCard Integration

Add `BookmarkButton` to the action row in `PostCard.tsx` (after the Share2 button at line 554):

```tsx
<BookmarkButton contentType="post" contentId={post.post_id} />
```

Import `BookmarkButton` from `@/components/shared/BookmarkButton`.

### 7.4 SavedPage Layout

```
SavedPage
  |-- PageHeader
  |     |-- Title: "Saved"
  |     |-- Description: "Your bookmarked posts and videos"
  |
  |-- Tabs: All | Posts | Videos
  |
  |-- Content Area (flex row)
  |     |-- Sidebar (desktop only, hidden on mobile)
  |     |     |-- "All Collections" link
  |     |     |-- "Uncategorized" (default) link
  |     |     |-- User-created collections (with item_count badges)
  |     |     |-- "+ New Collection" button
  |     |
  |     |-- Main Grid
  |           |-- BookmarkCard[] (responsive grid: 1 col mobile, 2 col tablet, 3 col desktop)
  |                 |-- Thumbnail (image or video poster)
  |                 |-- Author name + avatar
  |                 |-- Body snippet (truncated)
  |                 |-- "Saved [date]" footer
  |                 |-- Dropdown menu: "Remove" | "Move to collection"
  |
  |-- Load More button (or infinite scroll)
  |-- Empty state: "No saved items yet. Bookmark posts and videos to see them here."
```

### 7.5 React Query Hooks

```typescript
// frontend/src/api/endpoints/bookmarks.ts
import api from "../client";

export interface BookmarkItem {
  content_type: "post" | "video";
  content_id: string;
  collection_id: string;
  created_at: string;
  content_preview: {
    author_id: string;
    author_display_name?: string;
    body_snippet?: string;
    image_url?: string;
    like_count?: number;
  };
}

export interface BookmarkCollection {
  collection_id: string;
  name: string;
  item_count: number;
  created_at: string;
}

export const getBookmarks = (params: {
  limit?: number; cursor?: string; content_type?: string; collection_id?: string;
}) => api.get<{ bookmarks: BookmarkItem[]; next_cursor?: string; total_count: number }>("/ui/bookmarks", { params });

export const getBookmarkStatus = (ids: string[]) =>
  api.get<{ statuses: Record<string, boolean> }>("/ui/bookmarks/status", { params: { ids: ids.join(",") } });

export const createBookmark = (body: { content_type: string; content_id: string; collection_id?: string }) =>
  api.post("/ui/bookmarks", body);

export const removeBookmark = (contentType: string, contentId: string) =>
  api.delete(`/ui/bookmarks/${contentType}/${contentId}`);

export const getCollections = () =>
  api.get<{ collections: BookmarkCollection[] }>("/ui/bookmark-collections");

export const createCollection = (body: { name: string }) =>
  api.post<{ ok: boolean; collection_id: string; name: string }>("/ui/bookmark-collections", body);

export const renameCollection = (collectionId: string, body: { name: string }) =>
  api.patch(`/ui/bookmark-collections/${collectionId}`, body);

export const deleteCollection = (collectionId: string) =>
  api.delete<{ ok: boolean; moved_count: number }>(`/ui/bookmark-collections/${collectionId}`);
```

### 7.6 Route and Navigation

**`frontend/src/App.tsx`** -- Add route (after line 115, the `discover` route):
```tsx
<Route path="saved" element={<SavedPage />} />
```

**`frontend/src/components/layout/Sidebar.tsx`** -- Add to Main group (after Discover at line 78):
```tsx
{ label: "Saved", i18nKey: "nav.saved", path: "/saved", icon: <Bookmark className="h-5 w-5" /> },
```

Import `Bookmark` from lucide-react in Sidebar.tsx (add to existing icon import at line 1-39).

**`frontend/src/components/layout/MobileNav.tsx`** -- Add to MORE_LINKS:
```tsx
{ label: "Saved", path: "/saved", icon: <Bookmark className="h-5 w-5" /> },
```

### 7.7 UI States

| State | SavedPage | BookmarkButton |
|-------|-----------|----------------|
| **Loading** | Skeleton grid (6 placeholder cards) | Disabled, subtle spinner |
| **Empty** | Illustration + "No saved items yet" message | N/A |
| **Populated** | Grid of BookmarkCards with content previews | Filled icon (amber) |
| **Error** | "Failed to load bookmarks. Try again." with retry button | Outline icon (fallback) |
| **Optimistic** | Item appears/disappears immediately | Icon toggles immediately |

---

## 8. Security & Privacy

### 8.1 Authorization

- All bookmark endpoints use `require_ui_session` (cookie auth + CSRF for non-GET).
- Users can only access their own bookmarks -- all queries are scoped to `BOOKMARK#{session.user_sub}` / `BMCOL#{session.user_sub}`.
- No admin override for bookmarks -- they are strictly private to each user.
- Path parameters (`content_type`, `content_id`, `collection_id`) are validated against injection: no `#`, no control characters, alphanumeric + underscore only.

### 8.2 Privacy

- Bookmark counts are NOT exposed to content authors. Unlike likes, bookmarks are a private signal. No `bookmark_count` field on posts.
- The bookmark status check endpoint only returns status for the authenticated user's bookmarks.
- Bookmarks to locked or deleted posts gracefully degrade: the `content_preview` shows `"[Post removed]"` or `"[Locked]"` instead of the actual content.
- Bookmark data is not included in user export or GDPR responses (future consideration).

### 8.3 Rate Limiting

- POST `/ui/bookmarks`: 60 per minute per user (prevent scripted mass-bookmarking).
- Max bookmarks per user: 5000 (configurable via `BOOKMARKS_MAX_PER_USER`). Enforced at creation time.
- Max collections per user: 50 (configurable via `BOOKMARKS_MAX_COLLECTIONS`). Enforced at creation time.
- Collection name: max 100 characters, stripped of HTML, trimmed.

### 8.4 Input Validation

```python
class CreateBookmarkRequest(BaseModel):
    content_type: Literal["post", "video"]
    content_id: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_]+$")
    collection_id: Optional[str] = Field(None, max_length=64, pattern=r"^[a-zA-Z0-9_]+$")

class CreateCollectionRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
```

---

## 9. Performance & Scalability

### 9.1 Query Costs

| Endpoint | DDB Operations | Expected Latency |
|----------|---------------|-----------------|
| POST /bookmarks | 1 get_item (dup check) + 1 put_item + 1 update_item (collection count) | ~15ms |
| DELETE /bookmarks/{type}/{id} | 1 get_item (existence) + 1 delete_item + 1 update_item (collection count) | ~12ms |
| GET /bookmarks (page of 24) | 1 GSI1 query + 1 BatchGetItem (content metadata, up to 25 keys) | ~30ms |
| GET /bookmarks/status (batch of 10) | 1 BatchGetItem (10 keys) | ~12ms |
| GET /bookmark-collections | 1 query (pk=BMCOL#{uid}, sk begins_with COL#) | ~8ms |

### 9.2 Bookmark Status Batching

The `GET /ui/bookmarks/status` endpoint accepts up to 25 content IDs and uses DynamoDB `BatchGetItem` to check existence in a single round-trip (25 keys per BatchGetItem call). The frontend calls this when rendering a feed page to populate bookmark icon states for all visible posts.

Implementation:
```python
keys = [
    {"pk": f"BOOKMARK#{user_id}", "sk": f"{ctype}#{cid}"}
    for ctype, cid in parsed_ids
]
resp = tbl.meta.client.batch_get_item(
    RequestItems={TABLE_NAME: {"Keys": keys, "ProjectionExpression": "pk, sk"}}
)
found = {f"{it['sk'].split('#')[0]}:{it['sk'].split('#', 1)[1]}" for it in resp["Responses"][TABLE_NAME]}
```

### 9.3 Content Preview Enrichment

When listing bookmarks, the backend batch-fetches content metadata (post body snippet, image, author) using `BatchGetItem` on the `app_single_table` (for posts: `pk=POST#{id}, sk=META`) or video metadata table (for videos). This avoids N+1 queries. Up to 25 items can be fetched in a single BatchGetItem call.

### 9.4 Hot Partition Analysis

Each user's bookmarks have their own GSI1 partition (`GSI1PK=BOOKMARK#{user_id}`). Write volume is low (bookmarks are infrequent user actions). Even a power user with 5000 bookmarks generates a GSI partition of ~2 MB (well within DDB's 10 GB limit per partition).

---

## 10. Migration & Rollback

### 10.1 Feature Flag

`BOOKMARKS_ENABLED` (default `true`). When false:
- All bookmark endpoints return 404
- `BookmarkButton` component renders nothing (`return null`)
- `/saved` page shows "Feature not available" message
- No DDB writes for bookmarks

### 10.2 Rollback Steps

1. Set `BOOKMARKS_ENABLED=false`. Bookmark data remains in DDB but is inaccessible via API.
2. No schema migration needed. Bookmark entities share the existing `app_single_table`.
3. Frontend `BookmarkButton` renders nothing; `/saved` page shows disabled message.
4. To fully remove data: scan and delete all items with `pk` starting with `BOOKMARK#` or `BMCOL#`.

### 10.3 Deployment Order

1. Deploy backend with bookmarks router + feature flag OFF.
2. Deploy frontend with BookmarkButton (hidden) and SavedPage (disabled message).
3. Enable `BOOKMARKS_ENABLED=true`.
4. Monitor DDB write capacity and API latency.

---

## 11. Testing Strategy

### 11.1 Unit Tests (pytest)

**File: `tests/test_bookmarks.py`**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `test_create_bookmark_writes_correct_ddb_item` | Item exists with correct pk/sk/GSI1 |
| 2 | `test_duplicate_bookmark_returns_409` | 409 response on second create |
| 3 | `test_delete_bookmark_removes_item` | get_item returns None after delete |
| 4 | `test_list_bookmarks_returns_newest_first` | First item has latest created_at |
| 5 | `test_list_bookmarks_filters_by_content_type` | Only matching type in response |
| 6 | `test_list_bookmarks_filters_by_collection_id` | Only matching collection in response |
| 7 | `test_bookmark_status_returns_correct_booleans` | True for bookmarked, false for not |
| 8 | `test_create_collection_writes_entity` | BMCOL item exists |
| 9 | `test_delete_collection_moves_bookmarks_to_default` | All affected bookmarks have collection_id="default" |
| 10 | `test_max_bookmarks_limit_enforced` | 5001st bookmark returns 400 |
| 11 | `test_max_collections_limit_enforced` | 51st collection returns 400 |
| 12 | `test_bookmark_nonexistent_content_returns_404` | 404 for fake post ID |
| 13 | `test_collection_name_max_length` | 101-char name returns 400 |
| 14 | `test_collection_item_count_increments_on_bookmark` | item_count goes from 0 to 1 |
| 15 | `test_collection_item_count_decrements_on_unbookmark` | item_count goes from 1 to 0 |
| 16 | `test_rename_collection_updates_name` | name field changed after PATCH |
| 17 | `test_content_preview_populated_for_post` | content_preview has author, body, image |
| 18 | `test_content_preview_for_deleted_post` | Shows "[Post removed]" |

### 11.2 E2E Tests

**Test File:** `frontend/e2e/bookmarks.spec.ts`

**Section 1: Bookmark CRUD API (6 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Alice bookmarks a post | 201; bookmark appears in GET /bookmarks |
| 2 | Duplicate bookmark returns 409 | 409 response |
| 3 | Alice removes bookmark | 200; bookmark no longer in GET /bookmarks |
| 4 | Bookmark status check returns correct state | `{ statuses: { "post:X": true, "post:Y": false } }` |
| 5 | List bookmarks with content_type filter | Only posts returned when type=post |
| 6 | List bookmarks pagination works | Second page returns different items |

**Section 2: Collections API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 7 | Create collection | 201; collection appears in GET /bookmark-collections |
| 8 | Rename collection | 200; name updated in subsequent GET |
| 9 | Bookmark into collection | Bookmark has collection_id; appears when filtered |
| 10 | Delete collection moves bookmarks to default | Bookmarks still exist with collection_id="default" |
| 11 | Max collections limit | 50th collection succeeds; 51st returns 400 |

**Section 3: Saved Page UI (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 12 | Saved page loads and shows bookmarks | Navigate to /saved; bookmark cards visible |
| 13 | Content type tabs filter correctly | Click "Posts" tab; only post bookmarks shown |
| 14 | Collection filter works | Select collection from dropdown; filtered results |
| 15 | Remove bookmark from saved page | Click remove; bookmark disappears from list |
| 16 | Empty state shown when no bookmarks | New user navigates to /saved; "No saved items yet" visible |

**Section 4: PostCard Bookmark Button (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 17 | Bookmark icon visible on PostCard | Feed page; bookmark icon (outline) visible |
| 18 | Click bookmark icon toggles state | Icon changes to filled after click |
| 19 | Bookmark persists on page reload | Reload feed; icon still filled for bookmarked post |

---

## 12. Open Questions & Risks

### 12.1 Unresolved Decisions

| # | Question | Recommendation | Status |
|---|----------|---------------|--------|
| 1 | Expose bookmark count to post authors? | No. Keep bookmarks private (like Instagram). | DECIDED |
| 2 | Cross-type collections? | Yes. A single collection can hold both posts and videos. Simpler for users. | DECIDED |
| 3 | Bookmark expiry on content deletion? | Keep the bookmark, show "[Content removed]" placeholder. Users expect saved items to persist. | DECIDED |
| 4 | Should "Saved" have a badge count in sidebar? | Yes. Show total bookmark count. Use `Select: COUNT` query (cheap). | DECIDED |
| 5 | Keyboard shortcut for bookmarking? | Deferred. Consider `Ctrl+D` or `B` in a future UX pass. | DEFERRED |

### 12.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| GSI1 hot partition for power users | Low | Medium | GSI1PK is per-user; write volume is low (bookmarks are infrequent) |
| Content preview stale after post edit | Medium | Low | Fetch live metadata on list (don't cache in bookmark item) |
| Batch status check slow for large feeds | Low | Medium | Cap at 25 items per call; frontend batches visible posts only |
| Collection count drift (concurrent bookmark/delete) | Low | Low | Atomic ADD on item_count; reconciliation function available |

---

## 13. Files to Create

| File | Purpose |
|------|---------|
| `app/services/bookmarks.py` | Bookmark and collection CRUD logic |
| `app/routers/bookmarks.py` | API endpoints for bookmarks and collections |
| `frontend/src/pages/saved/SavedPage.tsx` | Saved content page |
| `frontend/src/components/shared/BookmarkButton.tsx` | Reusable bookmark icon toggle |
| `frontend/src/api/endpoints/bookmarks.ts` | API client |
| `frontend/e2e/bookmarks.spec.ts` | E2E tests |
| `tests/test_bookmarks.py` | Backend unit tests |

## 14. Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register bookmarks router (import + `app.include_router`) |
| `app/core/settings.py` | Add `bookmarks_enabled`, `bookmarks_max_per_user`, `bookmarks_max_collections`, `bookmarks_collection_name_max_length` settings |
| `frontend/src/api/types.ts` | Add `BookmarkItem`, `BookmarkCollection`, `BookmarkListResponse` interfaces |
| `frontend/src/pages/feed/PostCard.tsx` | Add `BookmarkButton` to action row after Share2 icon (line 554) |
| `frontend/src/App.tsx` | Add `/saved` route (after Discover route) |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Saved" link with Bookmark icon to Main nav group (after Discover, line 78) |
| `frontend/src/components/layout/AppShell.tsx` | Add "Saved" to MobileSidebar links |
| `frontend/src/components/layout/MobileNav.tsx` | Add "Saved" to MORE_LINKS |

---

## 15. Dependencies

- **Newsfeed (existing)**: Post metadata lookup for content preview enrichment. Uses same `app_single_table` with `pk=POST#{post_id}, sk=META`.
- **Video system (existing)**: Video metadata lookup from video metadata table for video bookmark previews.
- **Social graph (existing)**: No direct dependency, but bookmark data could feed future recommendation signals.
- **GSI1 (existing)**: Already defined on `app_single_table`. Used for chronological bookmark listing.

---

## 16. Acceptance Criteria

1. Users can bookmark and un-bookmark posts via a bookmark icon on PostCard.
2. Users can bookmark and un-bookmark videos via a bookmark icon on video cards.
3. Bookmark icon shows filled state (amber) for already-bookmarked content.
4. `/saved` page shows all bookmarked content in reverse-chronological order.
5. Users can filter saved content by type (posts, videos) and by collection.
6. Users can create, rename, and delete bookmark collections (max 50).
7. Deleting a collection moves its bookmarks to the default (uncategorized) collection.
8. Bookmark state persists across page reloads and browser sessions.
9. Maximum 5000 bookmarks per user enforced server-side.
10. All bookmark data is private to the bookmarking user; authors cannot see who bookmarked their content.
11. Content preview is shown in the saved page (thumbnail, author, snippet).
12. Batch bookmark status check returns correct booleans for up to 25 items.

---


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_bookmarks.py`

| # | Function | Assertion |
|---|----------|-----------|
| 1 | `test_create_bookmark_writes_correct_ddb_item` | Create bookmark writes correct ddb item verified |
| 2 | `test_duplicate_bookmark_returns_409` | Duplicate bookmark returns 409 verified |
| 3 | `test_delete_bookmark_removes_item` | Delete bookmark removes item verified |
| 4 | `test_list_bookmarks_returns_newest_first` | List bookmarks returns newest first verified |
| 5 | `test_list_bookmarks_filters_by_content_type` | List bookmarks filters by content type verified |
| 6 | `test_list_bookmarks_filters_by_collection_id` | List bookmarks filters by collection id verified |
| 7 | `test_bookmark_status_returns_correct_booleans` | Bookmark status returns correct booleans verified |
| 8 | `test_create_collection_writes_entity` | Create collection writes entity verified |
| 9 | `test_delete_collection_moves_bookmarks_to_default` | Delete collection moves bookmarks to default verified |
| 10 | `test_max_bookmarks_limit_enforced` | Max bookmarks limit enforced verified |

**Mocking**: All DynamoDB tables mocked via `moto`; profile lookups patched via `unittest.mock.patch`.

### Integration Tests

1. Bookmark a post then verify content_preview populated from app_single_table POST#{id}/META
2. Delete a bookmarked post then verify bookmark list shows [Post removed] placeholder
3. Bookmark status batch check returns correct booleans for mix of bookmarked and non-bookmarked posts

### E2E Tests (Playwright)

**File**: `frontend/e2e/bookmarks.spec.ts`
**Sections**: 1-4 (19 tests)

**Auth pattern**: `injectAuth(page, identity)` for cookie auth; `x-csrf-token` header for POST/PUT/DELETE mutations.

| # | Test | Assertion |
|---|------|-----------|
| 1 | Alice bookmarks a post | 201; bookmark appears in GET /bookmarks |
| 2 | Duplicate bookmark returns 409 | 409 response |
| 3 | Alice removes bookmark | 200; bookmark gone from list |
| 4 | Bookmark status check returns correct state | statuses map with true/false |
| 5 | List bookmarks with content_type filter | Only posts returned |
| 6 | Create collection | 201; appears in GET /bookmark-collections |
| 7 | Rename collection | 200; name updated |
| 8 | Delete collection moves bookmarks to default | Bookmarks still exist with collection_id=default |
| 9 | Saved page loads and shows bookmarks | Navigate to /saved; bookmark cards visible |
| 10 | Content type tabs filter correctly | Click Posts tab; only post bookmarks |
| 11 | Bookmark icon visible on PostCard | Feed page; bookmark icon outline visible |
| 12 | Click bookmark icon toggles state | Icon changes to filled after click |

**Negative tests**: 409 duplicate bookmark, 404 non-existent content, 400 max bookmarks exceeded, 400 max collections exceeded, 400 collection name >100 chars

**Edge cases**: Bookmark a post then author deletes it, collection with 0 items, batch status check with 0 items

### Test Data Requirements

- **DDB seeds**: Seeded posts in app_single_table with POST#{id}/META; Alice and Bob sessions
- **Test users**: Alice (bookmarker), Bob (post author)

### CI/Pipeline Considerations

- **Feature flags**: BOOKMARKS_ENABLED=true (default)
- **Serial execution**: Collection delete test must run after bookmark-into-collection test
- **Retry safety**: All tests are idempotent; use unique per-run identifiers (`TS` suffix) to avoid cross-run conflicts.

---

## Dependencies & Merge Safety

### Depends On

| Ticket/Component | Reason |
|------------------|--------|
| Newsfeed (existing) | Post metadata lookup for content preview enrichment |

### Depended On By

No downstream tickets depend on this feature.

### Merge Strategy: **Independent**

Self-contained feature using existing app_single_table. No schema migration needed.

### Merge Checklist

- [ ] All unit tests pass (`just test`)
- [ ] All E2E tests pass (`just e2e`)
- [ ] Feature flag defaults to enabled in `.env.local.example`
- [ ] No breaking changes to existing API contracts
- [ ] DynamoDB table/GSI changes added to `scripts/local-ddb-init.py`
- [ ] Frontend types in `api/types.ts` match backend `models.py`
- [ ] New routes registered in `app/main.py` and `frontend/src/App.tsx`

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| FeedPost has no bookmark field | `frontend/src/api/types.ts` | 1969-1970 | **OUTDATED** — `bookmarked?: boolean` now exists |
| Newsfeed key builders have no bookmark prefix | `app/routers/newsfeed.py` | 5461-5465 | **OUTDATED** — `pk_bookmark`, `pk_bookmark_lookup` now exist |
| app_single_table GSIs (6 total) | `scripts/local-ddb-init.py` | 220-226 | VERIFIED: GSI1-GSI5 + GSI_SCHEDULE_DUE |
| PostCard action row location | `frontend/src/pages/feed/PostCard.tsx` | 586 | VERIFIED (was 512-560, now shifted due to bookmark code added) |
| PostCard Share2 button | `frontend/src/pages/feed/PostCard.tsx` | 635 | VERIFIED |
| PostCard BookmarkButton (now exists) | `frontend/src/pages/feed/PostCard.tsx` | 204, 232-242 | **ALREADY IMPLEMENTED** |
| Sidebar Main group includes "Saved" | `frontend/src/components/layout/Sidebar.tsx` | 89 | **ALREADY IMPLEMENTED** |
| No bookmark endpoints in codebase | `app/routers/newsfeed.py` | 5483-5729 | **OUTDATED** — full bookmark CRUD + collections endpoints exist |
| app_single_table used via APP_TABLE env var | `app/routers/newsfeed.py` | 54, 59 | VERIFIED |
| Social service uses same table pattern | `app/services/social.py` | 19-20 | VERIFIED |
| LIKE key pattern as reference | `app/routers/newsfeed.py` | 828-829 | VERIFIED: `pk_like(user_id) = LIKE#{user_id}` |
| Bookmark CRUD endpoints | `app/routers/newsfeed.py` | 5483 (POST), 5538 (DELETE), 5553 (GET list), 5624 (GET status) | **ALREADY IMPLEMENTED** |
| Collection endpoints | `app/routers/newsfeed.py` | 5658 (POST), 5695 (GET), 5712 (PATCH), 5729 (DELETE) | **ALREADY IMPLEMENTED** |
| SavedPage exists | `frontend/src/pages/saved/SavedPage.tsx` | — | **ALREADY IMPLEMENTED** |
| /saved route exists | `frontend/src/App.tsx` | 77, 154 | **ALREADY IMPLEMENTED** |
| bookmarks.ts API client exists | `frontend/src/api/endpoints/bookmarks.ts` | — | **ALREADY IMPLEMENTED** |
| `bookmarks_enabled` setting | `app/core/settings.py` | — | **DOES NOT EXIST** — no feature flag implemented |
| BookmarkButton as separate component | `frontend/src/components/shared/BookmarkButton.tsx` | — | **DOES NOT EXIST** — bookmark logic is inline in PostCard.tsx |

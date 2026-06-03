# GROUP-002: Group Page & Newsfeed

**Ticket**: GROUP-002
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days
**Dependencies**: GROUP-001 (User Group Creation & Membership)

---

## 1. Overview & Motivation

### 1.1 Purpose

GROUP-002 adds a public-facing group page and a group-scoped newsfeed. Each group gets a profile page displaying its name, description, member count, and cover image. The group newsfeed lets members create posts visible to other members or to anyone visiting the group page (public posts). This reuses the existing post infrastructure (`_post_to_dict`, `PostCard`, reactions, tips, comments) while scoping content to the group context. Admins and moderators can pin posts to the top of the feed.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Visitor | As a non-member, I want to view a group's public page. | Group page shows name, description, member count, public posts. |
| Visitor | As a non-member, I want to see public posts in the group feed. | Feed shows `audience=public` posts; members-only hidden behind CTA. |
| Member | As a member, I want to post in the group feed. | POST creates group post; appears in feed. |
| Member | As a member, I want to see all posts (public + members-only). | Full feed visible to members. |
| Member | As a member, I want to comment, react, and tip group posts. | Existing PostCard interactions work in group context. |
| Admin | As an admin, I want to pin a post to the top of the feed. | Pinned post appears first regardless of chronological order. |
| Moderator | As a moderator, I want to remove inappropriate posts. | DELETE post; removed from feed. |

### 1.3 Why This Is Needed

Groups without content are empty containers. The group newsfeed gives members a reason to engage. The public/members-only split lets groups attract new members via visible public content while reserving discussion for the community. Reusing post infrastructure avoids a parallel content system and ensures feature parity (reactions, tips, comments, locks, polls).

---

## 2. Architecture & Data Flow

### 2.1 Group Post Creation Flow

```
Member clicks "Post" in GroupPostComposer
  |
  v
POST /ui/groups/{group_id}/posts
  { text, audience, body_format, image_url, unlock_price_cents }
  |
  v
+-----------------------------+
| group_feed.py               |
| create_group_post()         |
+-----------------------------+
  |
  +---> 1. Verify membership via user_groups table
  |        PK=GROUP#{group_id}, SK=MEMBER#{user_id}
  |        If not found -> 403 "Not a member"
  |
  +---> 2. Create post record in app_single_table
  |        PK=POST#{post_id}, SK=META
  |        (same table as regular posts, with group_id + audience)
  |
  +---> 3. Write GROUPFEED index record
  |        PK=GROUPFEED#{group_id}, SK={created_at}#{post_id}
  |        (NO fan-out to personal FEED#{follower_id} records)
  |
  +---> 4. Return post via _post_to_dict(viewer_id=user_id)
  |
  v
201 Created { post_id, text, group_id, audience, ... }
```

### 2.2 Group Feed Query Flow

```
GET /ui/groups/{group_id}/feed?cursor=...&limit=20
  |
  v
+-----------------------------+
| group_feed.py               |
| list_group_feed()           |
+-----------------------------+
  |
  +---> 1. Query GROUPFEED#{group_id} (SK desc for chronological)
  |        Limit=limit, ExclusiveStartKey if cursor provided
  |
  +---> 2. BatchGetItem: fetch full post records
  |        Keys: [PK=POST#{post_id}, SK=META] for each index record
  |
  +---> 3. Check viewer membership
  |        |
  |        +--- Member: return ALL posts (public + members_only)
  |        +--- Non-member: filter to audience=public ONLY
  |
  +---> 4. Sort: pinned posts first (by pinned_at desc),
  |        then remaining chronological (by created_at desc)
  |
  +---> 5. Apply _post_to_dict(viewer_id) for each post
  |        (resolves reactions, tips, lock status, etc.)
  |
  v
200 { posts: [...], cursor, has_more }
```

### 2.3 Public Feed Flow (No Auth)

```
GET /public/groups/{group_id}/feed?cursor=...&limit=20
  |
  v
+-----------------------------+
| group_feed.py               |
| list_group_feed()           |
|   viewer_id=None            |
+-----------------------------+
  |
  +---> Query GROUPFEED#{group_id}
  +---> BatchGetItem for full posts
  +---> Filter: ONLY audience=public (viewer_id is None => non-member)
  +---> Sort: pinned first, then chronological
  +---> _post_to_dict(viewer_id=None)
  |     (no tip/reaction resolution for anonymous viewer)
  v
200 { posts: [...], cursor, has_more }
```

### 2.4 Pin/Unpin Flow

```
POST /ui/groups/{group_id}/posts/{post_id}/pin
  |
  v
+-----------------------------+
| group_feed.py               |
| pin_post()                  |
+-----------------------------+
  |
  +---> 1. Verify admin/mod role via user_groups table
  |        PK=GROUP#{group_id}, SK=MEMBER#{user_id}
  |        role must be "admin" or "moderator"
  |
  +---> 2. Verify post belongs to group
  |        PK=POST#{post_id}, SK=META -> group_id matches
  |
  +---> 3. Check max pinned limit (3 per group)
  |        Query GROUPFEED#{group_id} with FilterExpression pinned=true
  |        If count >= 3 -> 409 "Maximum pinned posts reached"
  |
  +---> 4. Update post record
  |        SET pinned=true, pinned_at=now_ts(), pinned_by=user_id
  |
  +---> 5. Update GROUPFEED index record (pinned=true)
  |
  v
200 { post_id, pinned: true, pinned_at, pinned_by }
```

---

## 3. Current State Analysis

### 3.1 Existing Infrastructure

- **Newsfeed** (`app/routers/newsfeed.py`): Posts stored in `app_single_table` (see `scripts/local-ddb-init.py:222`) with `PK=POST#{post_id}`, `SK=META`. `_post_to_dict()` (see `app/routers/newsfeed.py:1900`) maps DDB items to `FeedPost` shape with `viewer_id` for lock/reaction resolution. Table accessed via `APP_TABLE` env var (see `app/routers/newsfeed.py:54`).
- **Fan-out** (`app/services/newsfeed_fanout.py`): `fan_out_post_to_followers()` (see `app/services/newsfeed_fanout.py:43`) writes per-follower `FEED#{follower_id}` index records. Group posts use a different pattern — scoped to `GROUPFEED#{group_id}`, not fanned out.
- **PostCard** (`frontend/src/pages/feed/PostCard.tsx`): Renders posts with reactions, comments, tips, locks, overflow menu. Reusable for group context with additional badges. <!-- VERIFIED: file exists at frontend/src/pages/feed/PostCard.tsx -->
- **Comments & Reactions**: Comments at `PK=COMMENTS#{post_id}`, reactions as DDB map on post item. Both reference `post_id`, not feed context — group-agnostic.

### 3.2 Gaps

1. No `GROUPFEED#{group_id}` index for group-scoped posts.
2. No `audience` field (public vs. members-only) on posts.
3. No group post creation or feed query endpoints.
4. No pinned posts mechanism.
5. No group page UI or post composer.
6. No moderator deletion of group posts.

---

## 4. Detailed DynamoDB Access Patterns

| # | Operation | Table | PK | SK / GSI | Condition / Filter | Projection |
|---|-----------|-------|-----|----------|-------------------|------------|
| 1 | Create group post | `app_single_table` | `POST#{post_id}` | `SK=META` | `attribute_not_exists(pk)` (new item) | Full post record |
| 2 | Write group feed index | `app_single_table` | `GROUPFEED#{group_id}` | `{created_at}#{post_id}` | None | `post_id, user_id, audience, pinned` |
| 3 | Query group feed (chronological) | `app_single_table` | `GROUPFEED#{group_id}` | `ScanIndexForward=False` | `FilterExpression: audience=public` (for non-members) | `post_id, audience, pinned` |
| 4 | Batch-fetch full posts | `app_single_table` | `POST#{post_id}` (batch) | `SK=META` | None | All post fields |
| 5 | Check membership | `user_groups` | `GROUP#{group_id}` | `SK=MEMBER#{user_id}` | None | `role, status` | <!-- NOTE: user_groups table does not exist yet — must be created by GROUP-001 -->
| 6 | Pin post update | `app_single_table` | `POST#{post_id}` | `SK=META` | `attribute_exists(pk) AND group_id = :gid` | None |
| 7 | Update feed index (pin) | `app_single_table` | `GROUPFEED#{group_id}` | `{created_at}#{post_id}` | None | `pinned` field update |
| 8 | Delete post + index | `app_single_table` | Both `POST#{post_id}` and `GROUPFEED#{group_id}` | Two deletes | Verify author/admin/mod | None |
| 9 | Count pinned posts | `app_single_table` | `GROUPFEED#{group_id}` | Full scan with filter | `FilterExpression: pinned = :true` | Count only |
| 10 | Get group metadata | `user_groups` | `GROUP#{group_id}` | `SK=META` | None | `name, description, member_count, cover_image_url` | <!-- NOTE: user_groups table does not exist yet — must be created by GROUP-001 -->

**Key query example — group feed**:
```python
response = T.app_single.query(  # NOTE: T.app_single table handle not found in app/core/tables.py — newsfeed.py uses ddb.Table(APP_TABLE) directly (see app/routers/newsfeed.py:59); group_feed.py should follow same pattern
    KeyConditionExpression="pk = :pk",
    ExpressionAttributeValues={":pk": f"GROUPFEED#{group_id}"},
    ScanIndexForward=False,
    Limit=limit,
    **({"ExclusiveStartKey": decode_cursor(cursor)} if cursor else {}),
)
index_records = response.get("Items", [])
post_ids = [r["post_id"] for r in index_records]

# BatchGetItem for full posts
keys = [{"pk": f"POST#{pid}", "sk": "META"} for pid in post_ids]
posts = batch_get_items(T.app_single, keys)  # NOTE: batch_get_items is not a standalone function — newsfeed.py uses ddb.batch_get_item(RequestItems={APP_TABLE: {"Keys": keys}}) directly (see app/routers/newsfeed.py:3413)
```

---

## 5. Technical Design

### 5.1 Data Model

Group posts are stored in `app_single_table` alongside regular posts, with additional fields.

**Post record extension** (on `PK=POST#{post_id}`, `SK=META`):

| Field | Type | Description |
|-------|------|-------------|
| `group_id` | S (optional) | Group the post belongs to (null for personal feed) |
| `audience` | S | `public` or `members_only` (default: `public`) |
| `pinned` | BOOL | Whether pinned to top (default: false) |
| `pinned_at` | N | Timestamp when pinned |
| `pinned_by` | S | user_sub of admin/mod who pinned |

**Group feed index** (in `app_single_table`):

| PK | SK | Fields |
|----|----|--------|
| `GROUPFEED#{group_id}` | `{created_at}#{post_id}` | `post_id`, `user_id`, `audience`, `pinned` |

Written alongside the post record. Enables efficient group feed queries without scanning all posts.

### 5.2 Backend Service (`app/services/group_feed.py`)
<!-- NOTE: app/services/group_feed.py does not exist yet — new implementation required -->

```python
def create_group_post(*, group_id: str, user_id: str, text: str,
                       body_format: str = "plain", image_url: str | None = None,
                       audience: str = "public",
                       unlock_price_cents: int | None = None) -> dict:
    """Create a post in a group's feed."""
    # 1. Verify user is a member of the group
    # 2. Create post record with group_id + audience (same table as regular posts)
    # 3. Write GROUPFEED#{group_id} index record
    # 4. Do NOT fan out to personal feeds
    # 5. Return post dict via _post_to_dict

def list_group_feed(*, group_id: str, viewer_id: str | None = None,
                     cursor: str | None = None, limit: int = 20) -> dict:
    """Fetch group feed, respecting audience visibility."""
    # 1. Query GROUPFEED#{group_id} sorted by SK desc
    # 2. Batch-fetch full posts from POST#{post_id}
    # 3. If viewer is not a member, filter to audience=public
    # 4. Sort: pinned posts first (by pinned_at desc), then chronological
    # 5. Apply _post_to_dict for each post
    # 6. Return paginated results with cursor

def pin_post(*, group_id: str, post_id: str, user_id: str) -> dict:
    """Pin a post to top. Admin/moderator only."""
    # Verify admin/mod; set pinned=True, pinned_at, pinned_by

def unpin_post(*, group_id: str, post_id: str, user_id: str) -> dict:
    """Unpin a post. Admin/moderator only."""

def delete_group_post(*, group_id: str, post_id: str, user_id: str) -> dict:
    """Delete group post. Author, admin, or moderator can delete."""
    # Verify permissions; delete post + GROUPFEED index record
```

### 5.3 Post Interaction Reuse

Existing endpoints work without modification on group posts (same `post_id` pattern):
- `POST /ui/posts/{post_id}/reactions` — reactions
- `POST /ui/posts/{post_id}/tip` — tips
- `POST /ui/posts/{post_id}/comments` — comments
- `POST /ui/posts/{post_id}/unlock` — locked post unlock

### 5.4 `_post_to_dict` Enhancement (`app/routers/newsfeed.py`)
<!-- VERIFIED: _post_to_dict exists at app/routers/newsfeed.py:1900; return dict includes like_count, comment_count, tip_total_cents, reactions_counts, my_reactions (lines 1999-2004) -->

Add group context fields when `post.get("group_id")` is present:

```python
# Group context fields (GROUP-002)
if post.get("group_id"):
    out["group_id"] = post["group_id"]
    out["audience"] = post.get("audience", "public")
    out["pinned"] = post.get("pinned", False)
    out["pinned_at"] = int(post["pinned_at"]) if post.get("pinned_at") else None
    out["pinned_by"] = post.get("pinned_by")
```

### 5.5 Backend Router (`app/routers/group_feed.py`)
<!-- NOTE: app/routers/group_feed.py does not exist yet — new implementation required -->

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/groups/{group_id}/posts` | `require_ui_session` | Create group post |
| GET | `/ui/groups/{group_id}/feed` | `require_ui_session` | Group feed (all for members, public-only for non-members) |
| GET | `/public/groups/{group_id}/feed` | None | Public-only feed (no auth) |
| POST | `/ui/groups/{group_id}/posts/{post_id}/pin` | `require_ui_session` | Pin post (admin/mod) |
| DELETE | `/ui/groups/{group_id}/posts/{post_id}/pin` | `require_ui_session` | Unpin |
| DELETE | `/ui/groups/{group_id}/posts/{post_id}` | `require_ui_session` | Delete post |

Register both `router` (authenticated, prefix `/ui/groups`) and `public_group_feed_router` (prefix `/public/groups`) in `main.py` (see `app/main.py` for existing router registration pattern).

---

## 6. API Request/Response Examples

### 6.1 Create Group Post

**Request:**
```http
POST /ui/groups/grp_abc123/posts
Content-Type: application/json
Cookie: ui_session=...; ui_csrf=...; ui_access_token=...
x-csrf-token: csrf_token_value

{
  "text": "Welcome to our group! We're excited to start sharing updates.",
  "body_format": "plain",
  "audience": "public",
  "image_url": null,
  "unlock_price_cents": null
}
```

**Response (201):**
```json
{
  "post_id": "post_d4e5f6a7b8c9",
  "user_id": "alice-sub-123",
  "user_display_name": "Alice",
  "user_avatar_url": "/mock/s3/avatars/alice.jpg",
  "text": "Welcome to our group! We're excited to start sharing updates.",
  "body_format": "plain",
  "image_url": null,
  "group_id": "grp_abc123",
  "audience": "public",
  "pinned": false,
  "pinned_at": null,
  "pinned_by": null,
  "unlock_price_cents": null,
  "unlocked": true,
  "tip_total_cents": 0,
  "reactions_counts": {},
  "my_reactions": [],
  "comment_count": 0,
  "created_at": 1748534400,
  "updated_at": 1748534400
}
```

### 6.2 Get Group Feed (Member)

**Request:**
```http
GET /ui/groups/grp_abc123/feed?limit=20&cursor=
Cookie: ui_session=...; ui_access_token=...
```

**Response (200):**
```json
{
  "posts": [
    {
      "post_id": "post_pinned_001",
      "user_id": "alice-sub-123",
      "text": "IMPORTANT: Group rules update",
      "group_id": "grp_abc123",
      "audience": "members_only",
      "pinned": true,
      "pinned_at": 1748535000,
      "pinned_by": "alice-sub-123",
      "tip_total_cents": 0,
      "reactions_counts": {"thumbsup": 5},
      "my_reactions": ["thumbsup"],
      "comment_count": 3,
      "created_at": 1748530000
    },
    {
      "post_id": "post_d4e5f6a7b8c9",
      "user_id": "alice-sub-123",
      "text": "Welcome to our group!",
      "group_id": "grp_abc123",
      "audience": "public",
      "pinned": false,
      "created_at": 1748534400
    }
  ],
  "cursor": "eyJsYXN0X2tl...base64",
  "has_more": false
}
```

### 6.3 Public Group Feed (No Auth)

**Request:**
```http
GET /public/groups/grp_abc123/feed?limit=20
```

**Response (200):**
```json
{
  "posts": [
    {
      "post_id": "post_d4e5f6a7b8c9",
      "user_id": "alice-sub-123",
      "text": "Welcome to our group!",
      "group_id": "grp_abc123",
      "audience": "public",
      "pinned": false,
      "tip_total_cents": 0,
      "reactions_counts": {},
      "my_reactions": [],
      "comment_count": 0,
      "created_at": 1748534400
    }
  ],
  "cursor": null,
  "has_more": false
}
```

### 6.4 Pin Post

**Request:**
```http
POST /ui/groups/grp_abc123/posts/post_d4e5f6a7b8c9/pin
Cookie: ui_session=...; ui_csrf=...; ui_access_token=...
x-csrf-token: csrf_token_value
```

**Response (200):**
```json
{
  "post_id": "post_d4e5f6a7b8c9",
  "pinned": true,
  "pinned_at": 1748535500,
  "pinned_by": "alice-sub-123"
}
```

### 6.5 Unpin Post

**Request:**
```http
DELETE /ui/groups/grp_abc123/posts/post_d4e5f6a7b8c9/pin
Cookie: ui_session=...; ui_csrf=...; ui_access_token=...
x-csrf-token: csrf_token_value
```

**Response (200):**
```json
{
  "post_id": "post_d4e5f6a7b8c9",
  "pinned": false,
  "pinned_at": null,
  "pinned_by": null
}
```

### 6.6 Delete Group Post

**Request:**
```http
DELETE /ui/groups/grp_abc123/posts/post_d4e5f6a7b8c9
Cookie: ui_session=...; ui_csrf=...; ui_access_token=...
x-csrf-token: csrf_token_value
```

**Response (200):**
```json
{
  "ok": true,
  "post_id": "post_d4e5f6a7b8c9",
  "deleted_by": "alice-sub-123"
}
```

---

## 7. Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | Error Message | Recovery Action |
|---|----------|-------------|------------|---------------|-----------------|
| 1 | Group not found | 404 | `GROUP_NOT_FOUND` | "Group not found" | Verify group_id; group may be dissolved |
| 2 | Not a member (post creation) | 403 | `NOT_A_MEMBER` | "Not a member of this group" | Join the group first |
| 3 | Not admin/moderator (pin) | 403 | `INSUFFICIENT_ROLE` | "Only admins and moderators can pin posts" | Request role elevation from admin |
| 4 | Post not in group | 404 | `POST_NOT_IN_GROUP` | "Post not found in this group" | Verify post_id belongs to this group |
| 5 | Post already pinned | 409 | `ALREADY_PINNED` | "Post is already pinned" | Use unpin first if re-pinning |
| 6 | Max pinned posts reached | 409 | `MAX_PINNED` | "Maximum of 3 pinned posts reached" | Unpin an existing post first |
| 7 | Group dissolved | 410 | `GROUP_DISSOLVED` | "This group has been dissolved" | No recovery; group is permanently inactive |
| 8 | Post text too long | 422 | `VALIDATION_ERROR` | "text: ensure this value has at most 10000 characters" | Shorten text content |
| 9 | Invalid audience value | 422 | `VALIDATION_ERROR` | "audience: Input should be 'public' or 'members_only'" | Use valid audience enum |
| 10 | Invalid body_format | 422 | `VALIDATION_ERROR` | "body_format: Input should be 'plain', 'markdown' or 'richtext'" | Use valid format |
| 11 | Cannot delete (not author/admin/mod) | 403 | `DELETE_FORBIDDEN` | "Only the author, admin, or moderator can delete this post" | Contact admin for removal |
| 12 | Post not found (delete/pin) | 404 | `POST_NOT_FOUND` | "Post not found" | Verify post_id; post may already be deleted |
| 13 | CSRF token mismatch | 403 | `CSRF_MISMATCH` | "CSRF validation failed" | Refresh page to get new CSRF token |
| 14 | Rate limit exceeded | 429 | `RATE_LIMITED` | "Too many requests. Try again in 60 seconds." | Wait and retry |
| 15 | unlock_price_cents negative | 422 | `VALIDATION_ERROR` | "unlock_price_cents: Input should be greater than or equal to 0" | Use non-negative value |

---

## 8. Pydantic Model Definitions

```python
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Literal, List, Dict, Any


class CreateGroupPostIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)
    body_format: Literal["plain", "markdown", "richtext"] = "plain"
    image_url: Optional[str] = Field(default=None, max_length=2048)
    audience: Literal["public", "members_only"] = "public"
    unlock_price_cents: Optional[int] = Field(default=None, ge=0)

    @field_validator("text")
    @classmethod
    def text_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Post text cannot be blank or whitespace-only")
        return v

    @field_validator("image_url")
    @classmethod
    def validate_image_url(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not (v.startswith("http://") or v.startswith("https://") or v.startswith("/mock/")):
            raise ValueError("Invalid image URL format")
        return v


class GroupFeedPostOut(BaseModel):
    post_id: str
    user_id: str
    user_display_name: str = ""
    user_avatar_url: Optional[str] = None
    text: Optional[str] = None
    body_format: str = "plain"
    image_url: Optional[str] = None
    group_id: str
    audience: Literal["public", "members_only"] = "public"
    pinned: bool = False
    pinned_at: Optional[int] = None
    pinned_by: Optional[str] = None
    unlock_price_cents: Optional[int] = None
    unlocked: bool = True
    tip_total_cents: int = 0
    reactions_counts: Dict[str, int] = Field(default_factory=dict)
    my_reactions: List[str] = Field(default_factory=list)
    comment_count: int = 0
    created_at: int
    updated_at: Optional[int] = None


class GroupFeedResponse(BaseModel):
    posts: List[GroupFeedPostOut]
    cursor: Optional[str] = None
    has_more: bool = False


class PinPostOut(BaseModel):
    post_id: str
    pinned: bool
    pinned_at: Optional[int] = None
    pinned_by: Optional[str] = None


class DeleteGroupPostOut(BaseModel):
    ok: bool = True
    post_id: str
    deleted_by: str
```

---

## 9. Frontend Component Tree

```
GroupPage (route: /groups/:groupId)
├── GroupHeader
│   ├── CoverImage (cover_image_url from group metadata)
│   ├── GroupInfo (name, description, member count)
│   └── ActionButtons (Join / Leave / Settings)
├── GroupTabNav (Feed | Members | Treasury | Settings)
├── GroupPostComposer (members only)
│   ├── TextArea (text input)
│   ├── FormatSelector (plain / markdown / richtext)
│   ├── ImageUpload (optional)
│   ├── AudienceToggle (public / members_only)
│   ├── LockPriceInput (optional)
│   └── SubmitButton
├── GroupFeed
│   ├── PinnedSection
│   │   └── PostCard[] (pinned=true, with PinBadge)
│   ├── ChronologicalSection
│   │   └── PostCard[] (standard posts, newest first)
│   └── LoadMoreButton / InfiniteScroll
├── NonMemberCTA (shown when viewer is not a member)
│   └── "Join to see all posts" banner
└── EmptyState ("No posts yet. Be the first to share!")
```

### TypeScript Props Interfaces

```typescript
interface GroupPageProps {
  // From route params
}

interface GroupHeaderProps {
  group: {
    group_id: string;
    name: string;
    description: string;
    member_count: number;
    cover_image_url?: string;
    privacy: "public" | "private";
  };
  isMember: boolean;
  viewerRole?: "admin" | "moderator" | "member";
  onJoin: () => void;
  onLeave: () => void;
}

interface GroupPostComposerProps {
  groupId: string;
  onPostCreated: () => void;
}

interface GroupFeedProps {
  groupId: string;
  viewerId: string | null;
  isMember: boolean;
  viewerRole?: "admin" | "moderator" | "member";
}

interface PinBadgeProps {
  pinnedBy: string;
  pinnedAt: number;
}

interface NonMemberCTAProps {
  groupId: string;
  groupName: string;
  publicPostCount: number;
  membersOnlyCount: number;
  onJoinClick: () => void;
}

interface AudienceToggleProps {
  value: "public" | "members_only";
  onChange: (audience: "public" | "members_only") => void;
  disabled?: boolean;
}
```

---

## 10. Frontend Types (`frontend/src/api/types.ts`)
<!-- VERIFIED: FeedPost interface exists at frontend/src/api/types.ts:1915 -->

```typescript
export interface GroupFeedPost extends FeedPost {
  group_id: string;
  audience: "public" | "members_only";
  pinned: boolean;
  pinned_at?: number;
  pinned_by?: string;
}
export interface GroupFeedResponse {
  posts: GroupFeedPost[];
  cursor?: string;
  has_more: boolean;
}
```

### Frontend API (`frontend/src/api/endpoints/groups.ts`)
<!-- NOTE: frontend/src/api/endpoints/groups.ts does not exist yet — new implementation required -->

```typescript
export const createGroupPost = (groupId: string, data: {
  text: string; body_format?: string; image_url?: string;
  audience?: "public" | "members_only"; unlock_price_cents?: number;
}) => api.post(`/ui/groups/${groupId}/posts`, data);

export const getGroupFeed = (groupId: string, params?: {
  cursor?: string; limit?: number;
}) => api.get<GroupFeedResponse>(`/ui/groups/${groupId}/feed`, { params });

export const getPublicGroupFeed = (groupId: string, params?: {
  cursor?: string; limit?: number;
}) => axios.get<GroupFeedResponse>(`/public/groups/${groupId}/feed`, { params });

export const pinGroupPost = (groupId: string, postId: string) =>
  api.post(`/ui/groups/${groupId}/posts/${postId}/pin`);

export const unpinGroupPost = (groupId: string, postId: string) =>
  api.delete(`/ui/groups/${groupId}/posts/${postId}/pin`);

export const deleteGroupPost = (groupId: string, postId: string) =>
  api.delete(`/ui/groups/${groupId}/posts/${postId}`);
```

---

## 11. Frontend Pages

- **GroupPage** (`frontend/src/pages/groups/GroupPage.tsx`): <!-- NOTE: frontend/src/pages/groups/ directory does not exist yet — new implementation required --> Route `/groups/:groupId`. Header with cover image, name, description, member count. Join/Leave/Settings buttons. Feed section using `PostCard`. Post composer for members with audience toggle. Non-member view: public posts + "Join to see all posts" CTA. Pinned posts at top with "Pinned" badge. `data-testid="group-page"`.
- **GroupPostComposer** (`frontend/src/pages/groups/GroupPostComposer.tsx`): Inline composer above feed. Text area + body format + image upload + audience toggle + lock price. `data-testid="group-post-composer"`.

### PostCard Enhancement (`frontend/src/pages/feed/PostCard.tsx`)
<!-- VERIFIED: PostCard.tsx exists at frontend/src/pages/feed/PostCard.tsx -->

Add group context badge and pin badge:

```tsx
{post.group_id && (
  <Link to={`/groups/${post.group_id}`} className="text-xs text-muted-foreground">
    Posted in {post.group_name}
  </Link>
)}
{post.pinned && (
  <Badge variant="outline" className="text-xs">
    <Pin className="h-3 w-3 mr-1" /> Pinned
  </Badge>
)}
```

Add "Pin to top" / "Unpin" to overflow menu when viewer is admin/mod. "Delete" available for author, admin, or moderator.

---

## 12. Observability

### 12.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `group_feed_post_created_total` | Counter | `group_id`, `audience` | Posts created per group |
| `group_feed_query_total` | Counter | `group_id`, `viewer_type` (member/non-member/public) | Feed queries |
| `group_feed_query_latency_ms` | Histogram | `group_id` | Feed query latency |
| `group_feed_pin_total` | Counter | `group_id`, `action` (pin/unpin) | Pin/unpin operations |
| `group_feed_delete_total` | Counter | `group_id`, `deleted_by` (author/admin/mod) | Post deletions |
| `group_feed_batch_get_size` | Histogram | `group_id` | Number of posts fetched per BatchGetItem |
| `group_feed_audience_filter_ratio` | Gauge | `group_id` | Ratio of members-only posts filtered for non-members |

### 12.2 Structured Logging

```python
logger.info("group_feed.post_created",
    extra={
        "group_id": group_id,
        "post_id": post_id,
        "user_id": user_id,
        "audience": audience,
        "body_format": body_format,
        "has_image": image_url is not None,
        "has_lock": unlock_price_cents is not None,
    })

logger.info("group_feed.query",
    extra={
        "group_id": group_id,
        "viewer_id": viewer_id,
        "is_member": is_member,
        "post_count": len(posts),
        "pinned_count": sum(1 for p in posts if p.get("pinned")),
        "latency_ms": elapsed_ms,
    })

logger.warning("group_feed.pin_limit_reached",
    extra={
        "group_id": group_id,
        "user_id": user_id,
        "current_pinned_count": 3,
    })
```

### 12.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Feed query latency > 2s | `p99(group_feed_query_latency_ms) > 2000` for 5 min | Warning | Check BatchGetItem size; consider caching |
| High feed error rate | `rate(group_feed_errors) > 0.05` for 10 min | Critical | Check DDB throttling, table health |
| Large batch fetch | `group_feed_batch_get_size > 50` | Info | Review pagination limit |

---

## 13. Rollout Plan

### 13.1 Feature Flag

```python
# app/core/settings.py
group_feed_enabled: bool = True  # GROUP_FEED_ENABLED env var
```
<!-- NOTE: group_feed_enabled setting does not exist yet in app/core/settings.py — must be added -->

```python
# app/routers/group_feed.py
@router.post("/{group_id}/posts")
async def create_post(group_id: str, body: CreateGroupPostIn, session=Depends(require_ui_session)):
    if not S.group_feed_enabled:
        raise HTTPException(404, "Group feed is not enabled")
    ...
```

### 13.2 Phased Rollout

| Phase | Scope | Duration | Flag State | Success Criteria |
|-------|-------|----------|------------|-----------------|
| 1 - Internal | Dev team only | 3 days | `GROUP_FEED_ENABLED=true` only in dev | All E2E tests pass; no DDB errors |
| 2 - Beta | 5% of groups (by group_id hash) | 5 days | Percentage-based rollout | Feed latency p99 < 1s; no data integrity issues |
| 3 - General | All groups | 3 days | `GROUP_FEED_ENABLED=true` for all | Error rate < 0.1%; user engagement metrics healthy |
| 4 - Stable | Remove flag | 1 day | Flag removed from code | Clean up; monitor for regression |

### 13.3 Rollback Plan

1. Set `GROUP_FEED_ENABLED=false` in env config.
2. Group feed endpoints return 404; group pages show "Feed coming soon" placeholder.
3. Existing post data remains in DDB (no data loss).
4. PostCard group badges hidden when feature is off.

---

## 14. Performance Considerations

| # | Concern | Target | Mitigation |
|---|---------|--------|------------|
| 1 | N+1 post fetch (index then full post) | < 100ms for 20 posts | `BatchGetItem` for up to 25 posts per page; single DDB round-trip |
| 2 | Large group feeds | Consistent pagination | Cursor-based with `Limit=20`; DDB SK sort is efficient O(log N) |
| 3 | Pinned post ordering | < 5ms client-side sort | Client-side sort (pinned first by `pinned_at` desc, then by `created_at` desc); max 3 pinned |
| 4 | Public feed for popular groups | < 200ms p99 | Consider ElastiCache for top-100 groups by member count in future |
| 5 | Index record cleanup | Zero orphans | GROUPFEED index deleted atomically with post; no separate cleanup needed |
| 6 | BatchGetItem 25-item limit | Transparent to caller | Chunk post_ids into batches of 25; merge results; rare for single page |
| 7 | Feed rendering with reactions | < 50ms React render | PostCard memoized with `React.memo`; reactions resolved server-side |

### 14.1 Caching Strategy

- **Public feed**: Cache in React Query with `staleTime: 60_000` (1 minute) for unauthenticated visitors.
- **Member feed**: `staleTime: 30_000` (30 seconds) with `refetchOnWindowFocus: true`.
- **Server-side**: No cache initially. If p99 > 500ms for popular groups, add a 30-second ElastiCache layer for the `GROUPFEED#` query results.

### 14.2 Pagination Strategy

```typescript
const { data, fetchNextPage, hasNextPage, isFetchingNextPage } =
  useInfiniteQuery({
    queryKey: ["group-feed", groupId],
    queryFn: ({ pageParam }) => getGroupFeed(groupId, { cursor: pageParam, limit: 20 }),
    getNextPageParam: (lastPage) => lastPage.has_more ? lastPage.cursor : undefined,
    staleTime: 30_000,
  });
```

---

## 15. Implementation Plan

### 15.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/group_feed.py` | Group feed CRUD, pin/unpin, audience filtering | <!-- new -->
| `app/routers/group_feed.py` | Authenticated + public feed endpoints | <!-- new -->
| `frontend/src/pages/groups/GroupPage.tsx` | Group profile page with feed | <!-- new -->
| `frontend/src/pages/groups/GroupPostComposer.tsx` | Post composer | <!-- new -->

### 15.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/newsfeed.py` | Add group fields to `_post_to_dict()` (see `:1900`) |
| `app/main.py` | Register group_feed routers (see existing pattern `:326`) |
| `frontend/src/api/types.ts` | Add `GroupFeedPost`, `GroupFeedResponse` (extends `FeedPost` at `:1915`) |
| `frontend/src/api/endpoints/groups.ts` | Add feed API functions <!-- new file --> |
| `frontend/src/pages/feed/PostCard.tsx` | Group badge, pin badge, pin/unpin menu <!-- VERIFIED: exists --> |
| `frontend/src/App.tsx` | Add `/groups/:groupId` route |

---

## 16. E2E Test Plan

### 16.1 Test File

`frontend/e2e/group-feed.spec.ts` — 24 tests across 6 sections.

### 16.2 Test Setup

```typescript
const TS = Date.now();
let groupId: string;
let publicPostId: string;
let membersOnlyPostId: string;
let pinnedPostId: string;
// Alice = admin, Bob = member, Charlie = non-member
```

### 16.3 Section 451: Group Post Creation API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 451.1 | Member creates public post | POST `/ui/groups/{id}/posts` with `audience=public`; 201; `group_id`, `audience=public` |
| 451.2 | Member creates members-only post | POST with `audience=members_only`; 201 |
| 451.3 | Non-member cannot create post | POST as Charlie; 403 |
| 451.4 | Post appears in group feed | GET feed; includes new post |

### 16.4 Section 452: Group Feed Query API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 452.1 | Member sees all posts | GET feed as Bob; both public and members-only present |
| 452.2 | Non-member sees only public posts | GET feed as Charlie; only public post |
| 452.3 | Public feed endpoint returns public only | GET `/public/groups/{id}/feed` (no auth); only `audience=public` |
| 452.4 | Pinned post appears first | Pin a post; GET feed; pinned post first |

### 16.5 Section 453: Pin & Moderation API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 453.1 | Admin pins a post | POST pin; 200; `pinned=true` |
| 453.2 | Pinned post first in feed | GET feed; first entry is pinned |
| 453.3 | Admin unpins a post | DELETE pin; 200; `pinned=false` |
| 453.4 | Moderator deletes post | DELETE post as moderator; 200; gone from feed |

### 16.6 Section 454: Group Page UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 454.1 | Group page displays info | Navigate `/groups/{id}`; `[data-testid="group-page"]`; name, description, member count |
| 454.2 | Member sees composer | As Alice; composer visible with audience toggle |
| 454.3 | Non-member sees CTA | As Charlie; public post visible; "Join to see all posts" CTA |
| 454.4 | Pin badge displayed | Pin post; navigate; "Pinned" badge visible |

### 16.7 Section 455: Edge Cases & Negative Tests (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 455.1 | Create post with empty text fails | POST with `text: "   "`; 422 validation error |
| 455.2 | Pin more than 3 posts fails | Pin 3 posts; attempt 4th; 409 "Maximum pinned posts reached" |
| 455.3 | Delete non-existent post returns 404 | DELETE with random post_id; 404 |
| 455.4 | Feed for dissolved group returns 410 | Dissolve group; GET feed; 410 "Group has been dissolved" |

### 16.8 Section 456: Pagination & Audience Filtering (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 456.1 | Pagination returns correct page size | Create 25 posts; GET with limit=10; exactly 10 posts; `has_more=true` |
| 456.2 | Cursor continues from last page | Use cursor from first page; next page has different posts |
| 456.3 | Members-only posts excluded from public count | Create 5 public + 5 members-only; public feed returns 5 |
| 456.4 | Locked post visible but text hidden for non-author | Create locked post; GET as Bob; `text=null`, `unlocked=false` |

---

## 17. Security Considerations

- **Audience enforcement**: `list_group_feed` checks membership before including `members_only` posts. Public endpoint never returns `members_only` posts.
- **Moderation**: Author deletes own; admin deletes any; moderator deletes non-admin posts.
- **Content safety**: Group posts use the same content moderation pipeline as regular posts.
- **Information disclosure**: Non-members cannot see members-only post content, only metadata ("Members Only" label).

---

## 18. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| GROUP-001 (Membership) | GROUP-001 | Required |
| Newsfeed infrastructure | Existing | Available (`_post_to_dict`, PostCard, reactions, comments) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| GROUP-003 (Advertising) | Group feed for ad placement context |

---

## Codebase References

| Reference | File | Line(s) | Notes |
|-----------|------|---------|-------|
| `_post_to_dict()` | `app/routers/newsfeed.py` | 1900 | Maps DDB post item to FeedPost shape; returns like_count, comment_count, tip_total_cents, reactions_counts, my_reactions |
| `APP_TABLE` env var | `app/routers/newsfeed.py` | 54 | `os.environ.get("APP_TABLE", "app_single_table")` |
| `tbl = ddb.Table(APP_TABLE)` | `app/routers/newsfeed.py` | 59 | Direct DynamoDB resource table handle (not via T.app_single) |
| `ddb.batch_get_item()` | `app/routers/newsfeed.py` | 3413 | Existing BatchGetItem pattern for fetching multiple posts |
| `fan_out_post_to_followers()` | `app/services/newsfeed_fanout.py` | 43 | Writes FEED#{follower_id} index records; group posts should NOT use this |
| `app_single_table` DDB definition | `scripts/local-ddb-init.py` | 222 | PK=pk, SK=sk; stores POST#{post_id}/META records |
| `FeedPost` interface | `frontend/src/api/types.ts` | 1915 | Base interface for GroupFeedPost extension |
| `PostCard` component | `frontend/src/pages/feed/PostCard.tsx` | — | Existing post renderer; needs group badge + pin badge additions |
| `user_groups` table | — | — | Does not exist yet; created by GROUP-001 dependency |
| `group_feed_enabled` setting | — | — | Does not exist yet in `app/core/settings.py`; must be added |
| `app/services/group_feed.py` | — | — | Does not exist yet; new implementation |
| `app/routers/group_feed.py` | — | — | Does not exist yet; new implementation |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_group_feed.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_create_group_post_member_only`
  - `test_create_group_post_non_member_403`
  - `test_list_group_feed_member_sees_all`
  - `test_list_group_feed_non_member_sees_public_only`
  - `test_pin_post_admin_only`
  - `test_pinned_posts_appear_first`
  - `test_delete_post_by_moderator`
  - `test_delete_post_non_mod_403`

### Integration Tests

  - Group post creation writes GROUPFEED index record and POST record
  - Feed query applies membership-based audience filtering
  - Pin/unpin updates pinned_at field and affects sort order

### E2E Tests (Playwright)

**File**: `frontend/e2e/group-feed.spec.ts`
**Test count**: 14

**Auth pattern**: Use `injectAuth(page, "root")` for admin endpoints; use `injectAuth(page, "alice")` for user-level endpoints. All POST/PATCH/DELETE requests include `x-csrf-token` header matching the session's CSRF token.

**Negative tests**:
- 401: Unauthenticated request returns 401
- 403: Non-admin/non-owner access returns 403
- 404: Non-existent resource returns 404
- 409: Conflict on duplicate or already-processed resource
- 422: Invalid input (bad field values, missing required fields)

**Edge cases**:
- Empty result sets return 200 with empty arrays (not 404)
- Pagination cursor works correctly across pages
- Concurrent requests do not produce inconsistent state

### Test Data Requirements

- **DDB seeds**: Seed `app_single_table (GROUPFEED index records)` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `GROUP_FEED_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| GROUP-001 | User Group Creation & Membership | Requires group membership for post creation and feed access |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| (none) | — | No other tickets depend on this one |

### Merge Strategy

**Sequential**

Merge after GROUP-001. This ticket depends on tables/services introduced by those tickets.

### Merge Checklist

- [ ] All new DDB tables added to `scripts/local-ddb-init.py` with correct `attr_types` for numeric GSI keys
- [ ] New settings added to `app/core/settings.py` and `.env.local.example`
- [ ] New table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Pydantic models added to `app/models.py`
- [ ] TypeScript types added to `frontend/src/api/types.ts`
- [ ] Route added to `frontend/src/App.tsx`
- [ ] Feature flag defaults to `true` in `.env.local.example`
- [ ] E2E session setup updated if new test identities needed
- [ ] `just restart` completes cleanly with new tables
- [ ] All 14 E2E tests pass with `npx playwright test group-feed.spec.ts`

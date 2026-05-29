# SYND-005: Syndicate Page & Newsfeed

**Ticket**: SYND-005
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

SYND-005 adds a public-facing syndicate profile page and a syndicate-scoped newsfeed. Each syndicate gets a discoverable page showing its name, description, member list, and bundle subscription options. Members can post to the syndicate's shared newsfeed, with posts marked as either `public` (visible to anyone) or `members_only` (visible only to syndicate members). Non-members see public posts plus a call-to-action to join or subscribe for full access.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Visitor | As any authenticated user, I want to view a syndicate's public profile page. | Navigate to `/syndicates/{id}`; see name, description, member list, public posts. |
| Visitor | As a non-member, I want to see public syndicate posts and a CTA to join. | Public posts visible; `members_only` posts hidden; "Join to see all posts" banner shown. |
| Member | As a member, I want to see all syndicate posts including members-only content. | Both `public` and `members_only` posts visible; no CTA banner. |
| Member | As a member, I want to post to the syndicate newsfeed. | Compose post with visibility toggle (public/members-only); post appears in feed. |
| Member | As a member, I want to choose post visibility: public or members-only. | Toggle control in compose form; `visibility` field saved on post; non-members can't see `members_only` posts. |
| Admin | As an admin, I want to moderate syndicate posts (delete inappropriate content). | Delete button visible on all posts for admin; delete removes post from feed. |
| Visitor | As a visitor, I want to subscribe to the syndicate's bundle from the profile page. | "Subscribe" button links to bundle plan selection (SYND-002). |
| Visitor | As a visitor, I want to see the list of member creators and visit their profiles. | Member cards with avatars, names, and links to individual creator profiles. |

### 1.3 How It Differs from the Main Newsfeed

| Feature | Main Newsfeed (existing) | Syndicate Newsfeed (this ticket) |
|---------|-------------------------|----------------------------------|
| Scope | User-specific: shows posts from followed creators | Syndicate-scoped: shows posts by any syndicate member |
| Posting | Users post to their own feed | Members post to the shared syndicate feed |
| Visibility | Public/locked (paywall) | Public/members-only (membership gated) |
| Fan-out | Posts fan out to followers via `newsfeed_fanout.py` | No fan-out; syndicate feed is queried directly |
| Discovery | Via follow relationships | Via syndicate profile page URL |

### 1.4 Why This Is Needed

Syndicates need a visible presence on the platform where potential subscribers can discover them, browse member content, and decide whether to subscribe to the bundle. The newsfeed gives syndicate members a space to share content that is contextually relevant to the syndicate's theme, rather than mixing it with their individual feeds. The `members_only` visibility tier incentivizes bundle subscriptions by previewing public content while gating premium posts.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Newsfeed router | `app/routers/newsfeed.py` | Post CRUD, comments, reactions, tips, unlock; `/ui/feed/*` endpoints |
| Newsfeed fanout | `app/services/newsfeed_fanout.py` | Fan-out to followers; `fan_out_post_to_followers` for individual posts |
| Newsfeed feed query | `app/services/newsfeed_feed_query.py` | `FeedFilterParams`, `post_matches_filters`, `sort_posts_deterministically` |
| Newsfeed polls | `app/services/newsfeed_polls.py` | Poll creation/voting within posts |
| Newsfeed scheduler | `app/services/newsfeed_scheduler.py` | Scheduled post publication |
| PostCard component | `frontend/src/pages/feed/PostCard.tsx` | Renders individual posts with reactions, tips, comments |
| CreatePost component | `frontend/src/pages/feed/CreatePost.tsx` | Post composition with image attachment, lock toggle |
| Feed page | `frontend/src/pages/feed/FeedPage.tsx` | Main newsfeed page layout |
| Syndicates service | `app/services/syndicates.py` (SYND-001) | `get_syndicate`, `list_members`, `_require_is_member` |

### 2.2 Post Storage Pattern

Posts are stored in a `posts` DDB table with:
- **PK**: `USER#{user_id}` (post author)
- **SK**: `POST#{post_id}`
- **GSI1PK**: `FEED#{user_id}` for feed queries

The syndicate newsfeed requires a separate index:
- **New GSI**: `SYND_FEED#{syndicate_id}` for querying syndicate posts

### 2.3 Gaps

1. **No syndicate profile page** -- the `/syndicates/{id}` route (SYND-001) shows management UI; there is no public-facing profile view.
2. **No syndicate-scoped posts** -- posts belong to individual users; there is no `syndicate_id` field on posts.
3. **No `members_only` visibility** -- posts have `lock_price_cents` (paywall) but no membership-gated visibility.
4. **No syndicate feed query** -- `newsfeed_feed_query.py` queries by user feed index, not by syndicate.
5. **No post moderation by syndicate admin** -- only the post author can delete their own posts.

---

## 3. Technical Design

### 3.1 Data Model Extensions

#### 3.1.1 Syndicate Post Fields (Posts Table)

Add to existing post items:

| Field | Type | Description |
|-------|------|-------------|
| `syndicate_id` | S | Set when posting to a syndicate feed (empty for personal posts) |
| `visibility` | S | `"public"` or `"members_only"` (defaults to `"public"` for non-syndicate posts) |
| `GSSYND_PK` | S | `SYNDFEED#{syndicate_id}` (GSI partition key for syndicate feed queries) |
| `GSSYND_SK` | N | `created_at` timestamp (GSI sort key for chronological ordering) |

#### 3.1.2 New GSI on Posts Table

**GSSYND** (`GSSYND_PK` / `GSSYND_SK`): Query all posts for a syndicate by creation time.

```python
# In scripts/local-ddb-init.py, update posts TableDef:
TableDef(
    "posts", "pk", "sk",
    gsis=[
        # ... existing GSIs ...
        {"name": "GSSYND", "pk": "GSSYND_PK", "sk": "GSSYND_SK"},
    ],
    attr_types={"GSSYND_SK": "N"},  # numeric sort key
),
```

#### 3.1.3 Syndicate Profile Data (Syndicates Table)

Extend the `META` item from SYND-001:

| Field | Type | Description |
|-------|------|-------------|
| `avatar_url` | S | Syndicate logo/avatar (optional) |
| `banner_url` | S | Profile banner image (optional) |
| `website_url` | S | External website link (optional) |
| `tags` | L | Descriptive tags for discovery (e.g., `["gaming", "music"]`) |
| `post_count` | N | Number of syndicate posts (denormalized counter) |

### 3.2 Backend Service

**New file**: `app/services/syndicate_feed.py` (~250 lines)

```python
"""Syndicate newsfeed management (SYND-005)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4
from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.core.time import now_ts
from app.services import syndicates as syndicate_svc
from app.services.newsfeed_feed_query import sort_posts_deterministically

logger = logging.getLogger(__name__)


def create_syndicate_post(
    *,
    syndicate_id: str,
    author_sub: str,
    text: str,
    visibility: str = "public",
    image_url: Optional[str] = None,
    poll_data: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Create a post in the syndicate newsfeed."""
    syndicate_svc._require_is_member(syndicate_id, author_sub)

    if visibility not in ("public", "members_only"):
        raise ValueError("visibility must be 'public' or 'members_only'")

    post_id = f"sp_{uuid4().hex}"
    ts = now_ts()
    profile = syndicate_svc.get_profile_cached(author_sub)

    post = {
        "pk": f"USER#{author_sub}",
        "sk": f"POST#{post_id}",
        "post_id": post_id,
        "author_id": author_sub,
        "author_name": profile.get("display_name", author_sub),
        "author_avatar": profile.get("avatar_url", ""),
        "text": text,
        "image_url": image_url or "",
        "syndicate_id": syndicate_id,
        "visibility": visibility,
        "created_at": ts,
        "updated_at": ts,
        "comment_count": 0,
        "reaction_counts": {},
        "tip_total_cents": 0,
        # GSI for syndicate feed
        "GSSYND_PK": f"SYNDFEED#{syndicate_id}",
        "GSSYND_SK": ts,
    }

    if poll_data:
        post["poll"] = poll_data

    T.posts.put_item(Item=post)

    # Increment post count on syndicate meta
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": "META"},
        UpdateExpression="SET post_count = if_not_exists(post_count, :z) + :one",
        ExpressionAttributeValues={":z": 0, ":one": 1},
    )

    return post


def list_syndicate_posts(
    syndicate_id: str,
    *,
    viewer_sub: Optional[str] = None,
    limit: int = 20,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List posts in a syndicate's newsfeed, respecting visibility."""
    query_kwargs = {
        "IndexName": "GSSYND",
        "KeyConditionExpression": Key("GSSYND_PK").eq(f"SYNDFEED#{syndicate_id}"),
        "ScanIndexForward": False,  # Newest first
        "Limit": limit,
    }

    if cursor:
        from app.core.cursor import decode_cursor
        query_kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.posts.query(**query_kwargs)
    posts = resp.get("Items", [])

    # Filter by visibility
    is_member = False
    if viewer_sub:
        try:
            syndicate_svc._require_is_member(syndicate_id, viewer_sub)
            is_member = True
        except Exception:
            pass

    if not is_member:
        posts = [p for p in posts if p.get("visibility") != "members_only"]

    # Build next cursor
    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        from app.core.cursor import encode_cursor
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])

    return {
        "posts": posts,
        "next_cursor": next_cursor,
        "is_member": is_member,
    }


def delete_syndicate_post(
    *,
    syndicate_id: str,
    post_id: str,
    user_sub: str,
) -> None:
    """Delete a syndicate post. Author or syndicate admin can delete."""
    post = _get_post(post_id)

    if post.get("syndicate_id") != syndicate_id:
        raise ValueError("Post does not belong to this syndicate")

    is_author = post.get("author_id") == user_sub
    is_admin = False
    try:
        syndicate_svc._require_admin(syndicate_id, user_sub)
        is_admin = True
    except Exception:
        pass

    if not is_author and not is_admin:
        raise PermissionError("Only the author or syndicate admin can delete this post")

    T.posts.delete_item(Key={"pk": post["pk"], "sk": post["sk"]})

    # Decrement post count
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": "META"},
        UpdateExpression="SET post_count = post_count - :one",
        ExpressionAttributeValues={":one": 1},
    )


def update_syndicate_profile(
    *,
    syndicate_id: str,
    admin_sub: str,
    avatar_url: Optional[str] = None,
    banner_url: Optional[str] = None,
    website_url: Optional[str] = None,
    tags: Optional[List[str]] = None,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Update syndicate profile fields (admin only)."""
    syndicate_svc._require_admin(syndicate_id, admin_sub)
    updates = {}
    if avatar_url is not None:
        updates["avatar_url"] = avatar_url
    if banner_url is not None:
        updates["banner_url"] = banner_url
    if website_url is not None:
        updates["website_url"] = website_url
    if tags is not None:
        updates["tags"] = tags[:10]  # Max 10 tags
    if description is not None:
        updates["description"] = description[:500]

    if not updates:
        return syndicate_svc.get_syndicate(syndicate_id)

    update_expr = "SET " + ", ".join(f"{k} = :{k}" for k in updates)
    update_expr += ", updated_at = :ts"
    expr_values = {f":{k}": v for k, v in updates.items()}
    expr_values[":ts"] = now_ts()

    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": "META"},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_values,
    )
    return syndicate_svc.get_syndicate(syndicate_id)


def _get_post(post_id: str) -> Dict[str, Any]:
    """Get a post by scanning for its post_id. Needed because PK is author-based."""
    # In production, use a GSI on post_id. For v1, query by post_id attribute filter.
    # Alternative: store a reverse lookup SYNDPOST#{post_id} → pk/sk in syndicates table.
```

### 3.3 Backend Router

**New file**: `app/routers/syndicate_feed.py` (~120 lines)

### 3.4 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/syndicates/{syndicate_id}/profile` | `require_ui_session` | Get public syndicate profile (metadata + members + plans) |
| `PUT` | `/ui/syndicates/{syndicate_id}/profile` | `require_ui_session` | Update syndicate profile (admin only) |
| `GET` | `/ui/syndicates/{syndicate_id}/feed` | `require_ui_session` | Get syndicate newsfeed (filtered by visibility) |
| `POST` | `/ui/syndicates/{syndicate_id}/feed` | `require_ui_session` | Create post in syndicate feed (members only) |
| `DELETE` | `/ui/syndicates/{syndicate_id}/feed/{post_id}` | `require_ui_session` | Delete syndicate post (author or admin) |

### 3.5 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Syndicate Page & Newsfeed (SYND-005) --

class SyndicateProfileUpdateIn(BaseModel):
    avatar_url: Optional[str] = None
    banner_url: Optional[str] = None
    website_url: Optional[str] = Field(default=None, max_length=200)
    tags: Optional[List[str]] = Field(default=None, max_length=10)
    description: Optional[str] = Field(default=None, max_length=500)

class SyndicateProfileOut(BaseModel):
    syndicate_id: str
    name: str
    description: str = ""
    avatar_url: str = ""
    banner_url: str = ""
    website_url: str = ""
    tags: List[str] = Field(default_factory=list)
    admin_user_id: str
    status: str
    member_count: int = 0
    post_count: int = 0
    members: List[SyndicateMemberOut] = Field(default_factory=list)
    bundle_plans: List[BundlePlanOut] = Field(default_factory=list)
    is_member: bool = False
    created_at: int = 0

class SyndicatePostCreateIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    visibility: str = Field(default="public", pattern="^(public|members_only)$")
    image_url: Optional[str] = None

class SyndicatePostOut(BaseModel):
    post_id: str
    author_id: str
    author_name: str = ""
    author_avatar: str = ""
    text: str = ""
    image_url: str = ""
    syndicate_id: str
    visibility: str = "public"
    created_at: int = 0
    comment_count: int = 0
    reaction_counts: Dict[str, int] = Field(default_factory=dict)
    tip_total_cents: int = 0

class SyndicateFeedOut(BaseModel):
    posts: List[SyndicatePostOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None
    is_member: bool = False
```

### 3.6 Frontend Components

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/syndicates/SyndicateProfilePage.tsx` | Public syndicate profile page | ~300 |
| `frontend/src/pages/syndicates/SyndicateFeed.tsx` | Syndicate newsfeed component | ~200 |
| `frontend/src/pages/syndicates/SyndicatePostComposer.tsx` | Post composer with visibility toggle | ~120 |
| `frontend/src/pages/syndicates/SyndicateMemberCard.tsx` | Member profile card for member list | ~60 |

**Component tree for SyndicateProfilePage**:

```
SyndicateProfilePage
├── ProfileHeader
│   ├── Banner image (or gradient placeholder)
│   ├── Avatar
│   ├── Syndicate name (h1)
│   ├── Description text
│   ├── Tags (badge pills)
│   ├── Stats: X members, Y posts
│   └── Actions
│       ├── "Request to Join" button (non-member)
│       ├── "Subscribe to Bundle" button (non-member, links to SYND-002)
│       └── "Edit Profile" button (admin only, opens edit dialog)
├── Tabs
│   ├── "Feed" Tab
│   │   ├── SyndicatePostComposer (members only)
│   │   │   ├── Text area
│   │   │   ├── Image attachment button
│   │   │   ├── Visibility toggle: "Public" / "Members Only"
│   │   │   └── "Post" button
│   │   ├── SyndicateFeed
│   │   │   ├── PostCard (reused from existing feed) for each post
│   │   │   └── InfiniteScroll pagination
│   │   └── JoinBanner (non-members only)
│   │       └── "Join this syndicate to see members-only posts"
│   └── "Members" Tab
│       └── Grid of SyndicateMemberCards
│           └── For each member:
│               ├── Avatar
│               ├── Display name
│               ├── Role badge (Admin / Member)
│               └── Link to creator profile
└── Sidebar (desktop only)
    ├── "Bundle Plans" card
    │   └── For each plan: name, price, "Subscribe" button
    └── "About" card
        └── Website link, created date, member count
```

### 3.7 Frontend Routes

Update `frontend/src/App.tsx`:

The existing `/syndicates/:syndicateId` route (SYND-001 management view) should be at `/syndicates/:syndicateId/manage`. The profile page takes the primary route:

```typescript
<Route path="/syndicates/:syndicateId" element={<SyndicateProfilePage />} />
<Route path="/syndicates/:syndicateId/manage" element={<SyndicateDetailPage />} />
```

### 3.8 Visibility Filtering Logic

```
GET /ui/syndicates/{syndicate_id}/feed
│
├── Query GSSYND index: GSSYND_PK = SYNDFEED#{syndicate_id}
│
├── Is viewer a syndicate member?
│   ├── Yes → return ALL posts (public + members_only)
│   └── No → filter out posts where visibility = "members_only"
│
├── Attach is_member flag to response
│   └── Frontend uses this to show/hide composer + join CTA
│
└── Return posts + next_cursor + is_member
```

### 3.9 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/syndicate_feed.py` | Syndicate feed service | ~250 |
| `app/routers/syndicate_feed.py` | Feed + profile router | ~120 |
| `frontend/src/pages/syndicates/SyndicateProfilePage.tsx` | Public profile page | ~300 |
| `frontend/src/pages/syndicates/SyndicateFeed.tsx` | Newsfeed component | ~200 |
| `frontend/src/pages/syndicates/SyndicatePostComposer.tsx` | Post composer | ~120 |
| `frontend/src/pages/syndicates/SyndicateMemberCard.tsx` | Member card | ~60 |
| `frontend/e2e/syndicates-feed.spec.ts` | E2E tests | ~400 |

### 3.10 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `syndicate_feed_router` |
| `app/models.py` | Add SyndicateProfile*, SyndicatePost*, SyndicateFeed* models |
| `scripts/local-ddb-init.py` | Add GSSYND GSI to posts table TableDef |
| `frontend/src/api/types.ts` | Add SyndicateProfile, SyndicatePost, SyndicateFeed interfaces |
| `frontend/src/api/endpoints/syndicates.ts` | Add feed + profile API wrappers |
| `frontend/src/App.tsx` | Update syndicate routes (profile vs manage) |

---

## 4. Post Reuse Strategy

### 4.1 Reusing PostCard

The existing `PostCard` component renders posts with reactions, tips, comments, and lock/unlock. Syndicate posts reuse `PostCard` with these additions:

1. **Visibility badge**: Show "Members Only" badge on `members_only` posts (similar to the "Locked" badge pattern).
2. **Syndicate context**: Show "Posted in {syndicate_name}" subtitle below author name.
3. **Delete button**: Visible to post author AND syndicate admin (additional check).

### 4.2 Not Using Fan-out

The main newsfeed uses `newsfeed_fanout.py` to copy posts to each follower's feed index. Syndicate feeds do NOT use fan-out because:
- Posts are queried by syndicate, not by follower.
- The GSSYND GSI provides direct syndicate-scoped queries.
- Fan-out would duplicate posts across potentially thousands of subscriber feeds.

Syndicate posts do NOT appear in members' individual feeds (the `/feed` main newsfeed). They are only visible on the syndicate page. This is intentional -- it keeps syndicate content contextual.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/syndicates-feed.spec.ts`

### Section 439: Syndicate Profile API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 439.1 | GET syndicate profile returns metadata and members | GET profile; 200; response has `name`, `members`, `post_count` |
| 439.2 | Admin updates profile with tags and description | PUT profile; 200; updated fields reflected in GET |
| 439.3 | Non-admin cannot update profile | Bob (member) PUT; 403 |
| 439.4 | Profile includes bundle plans | GET profile; `bundle_plans` array present (from SYND-002) |

### Section 440: Syndicate Feed Post API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 440.1 | Member creates public post | POST feed; 200; `visibility=public`; post appears in GET feed |
| 440.2 | Member creates members-only post | POST feed with `visibility=members_only`; 200; `visibility=members_only` |
| 440.3 | Non-member cannot post | Non-member POST; 403 or 404 |
| 440.4 | Author can delete own post | DELETE; 200; post no longer in GET feed |
| 440.5 | Admin can delete any member's post | Admin DELETE of Bob's post; 200; post removed |

### Section 441: Visibility Filtering API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 441.1 | Member sees all posts (public + members_only) | GET feed as member; response includes both visibility types; `is_member=true` |
| 441.2 | Non-member sees only public posts | GET feed as non-member; no `members_only` posts in response; `is_member=false` |
| 441.3 | Members-only post text hidden from non-members | POST `members_only` post; GET as non-member; post not in response |
| 441.4 | Pagination works with visibility filtering | Create 25 posts (mix of public/members_only); GET with limit=10; `next_cursor` present |

### Section 442: Syndicate Profile UI (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 442.1 | Profile page renders syndicate name and description | Navigate to `/syndicates/{id}`; heading with syndicate name visible |
| 442.2 | Members tab shows member list | Click "Members" tab; member cards visible with names and roles |
| 442.3 | Post composer visible for members only | Member sees text area + "Post" button; non-member does not see composer |
| 442.4 | Visibility toggle switches between public and members-only | Member toggles visibility; label changes; post created with correct visibility |
| 442.5 | Join CTA visible for non-members | Non-member sees "Join to see all posts" banner; members do not see it |

**Total E2E tests: 18**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| GET profile | `require_ui_session` | Any authenticated user |
| PUT profile | `require_ui_session` | Syndicate admin only |
| GET feed | `require_ui_session` | Any authenticated user (visibility filtering applied) |
| POST feed | `require_ui_session` | Syndicate members only |
| DELETE feed post | `require_ui_session` | Post author or syndicate admin |

### 6.2 Content Filtering

- `members_only` posts are filtered at the service layer, not via DDB `FilterExpression`. This prevents any leakage through API response manipulation.
- The `is_member` flag in the response is informational for the frontend; actual visibility enforcement happens server-side.
- Post text for `members_only` posts is never included in non-member responses (entire post item is excluded, not just obfuscated).

### 6.3 Post Moderation

- Syndicate admin can delete any post in the syndicate feed (moderation power).
- Post deletion is a hard delete (item removed from DDB), not a soft delete.
- Deletion is logged in the syndicate audit trail (SYND-001).

### 6.4 Input Validation

- Post text: 1-5000 characters.
- Visibility: must be `"public"` or `"members_only"`.
- Tags on profile: max 10 tags, each max 30 characters.
- Description: max 500 characters.
- URLs: validated as non-empty strings (no URL format validation in v1).

### 6.5 Rate Limiting

- Post creation: max 10 posts per member per hour per syndicate.
- Profile updates: max 10 per day.

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| SYND-001 | Required | Syndicate metadata, membership checks, admin authorization |
| SYND-002 | Required (for profile page) | Bundle plans displayed on profile page |
| Posts table | Exists | Store syndicate posts with GSSYND GSI |
| PostCard component | Exists | Reused for rendering syndicate posts |
| `app/services/newsfeed_feed_query.py` | Exists | Sorting utilities for posts |
| `app/core/cursor.py` | Exists | Pagination cursor encode/decode |

---

## 8. Acceptance Criteria

1. Each syndicate has a public profile page showing name, description, members, and bundle plans.
2. Admin can update syndicate profile (avatar, banner, tags, description).
3. Members can post to the syndicate newsfeed with public or members-only visibility.
4. Non-members see only public posts; members see all posts.
5. Non-members see a "Join to see all posts" CTA banner.
6. Post composer is visible only to members.
7. Admin can delete any syndicate post (moderation).
8. Syndicate posts are paginated with cursor-based pagination.
9. Profile page shows bundle subscription options (SYND-002 integration).
10. All 18 E2E tests pass.

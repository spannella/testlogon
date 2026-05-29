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

### 3.1 Architecture Diagram

```
  +-------------------+
  |  SyndicateProfile |
  |     Page (React)  |
  +-------------------+
         |                    +--------------------+
         | GET /profile       |  SyndicateFeed     |
         | GET /feed          |    Component        |
         |                    +--------------------+
         v                           |
  +-------------------+              | POST /feed (member)
  |  syndicate_feed   |              | DELETE /feed/{id} (admin/author)
  |   Router          |<-------------+
  +-------------------+
         |
         | (reads/writes)
         v
  +-------------------+     +-------------------+     +-------------------+
  | syndicate_feed    |     |  syndicates       |     |     posts         |
  |   Service         |---->|    Service         |     |     Table (DDB)   |
  +-------------------+     | (SYND-001)        |     +-------------------+
         |                  +-------------------+          |
         |                        |                        |
         | create_syndicate_post  | _require_is_member     | GSSYND index
         | list_syndicate_posts   | _require_admin         | PK: SYNDFEED#{id}
         | delete_syndicate_post  | get_syndicate          | SK: created_at (N)
         | update_profile         | list_members           |
         v                        v                        v
  +-------------------+     +-------------------+
  |  Visibility       |     |  syndicates       |
  |  Filter           |     |    Table (DDB)    |
  +-------------------+     +-------------------+
         |
         | is_member? --> show all posts
         | not member? --> filter out members_only
         v
  +-------------------+
  |  Response with    |
  |  is_member flag   |
  +-------------------+

Post Creation Flow:
  Member --> SyndicatePostComposer --> POST /feed --> syndicate_feed.create_syndicate_post()
    1. _require_is_member(syndicate_id, author_sub)
    2. Validate visibility ("public" | "members_only")
    3. Build post item with GSSYND_PK / GSSYND_SK
    4. T.posts.put_item(...)
    5. Increment post_count on syndicate META
    6. Return SyndicatePostOut

Visibility Filtering Flow:
  Viewer --> GET /feed --> syndicate_feed.list_syndicate_posts()
    1. Query GSSYND index (ScanIndexForward=False)
    2. Check viewer membership (try _require_is_member)
    3. If NOT member: filter posts where visibility == "members_only"
    4. Encode next_cursor if LastEvaluatedKey present
    5. Return {posts, next_cursor, is_member}

Post Moderation Flow:
  Admin --> DELETE /feed/{post_id} --> syndicate_feed.delete_syndicate_post()
    1. Fetch post by post_id
    2. Verify post.syndicate_id matches
    3. Check: is_author OR is_admin (try _require_admin)
    4. T.posts.delete_item(...)
    5. Decrement post_count on syndicate META
```

### 3.2 Data Model Extensions

#### 3.2.1 Syndicate Post Fields (Posts Table)

Add to existing post items:

| Field | Type | Description |
|-------|------|-------------|
| `syndicate_id` | S | Set when posting to a syndicate feed (empty for personal posts) |
| `visibility` | S | `"public"` or `"members_only"` (defaults to `"public"` for non-syndicate posts) |
| `GSSYND_PK` | S | `SYNDFEED#{syndicate_id}` (GSI partition key for syndicate feed queries) |
| `GSSYND_SK` | N | `created_at` timestamp (GSI sort key for chronological ordering) |

#### 3.2.2 New GSI on Posts Table

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

#### 3.2.3 Syndicate Profile Data (Syndicates Table)

Extend the `META` item from SYND-001:

| Field | Type | Description |
|-------|------|-------------|
| `avatar_url` | S | Syndicate logo/avatar (optional) |
| `banner_url` | S | Profile banner image (optional) |
| `website_url` | S | External website link (optional) |
| `tags` | L | Descriptive tags for discovery (e.g., `["gaming", "music"]`) |
| `post_count` | N | Number of syndicate posts (denormalized counter) |

### 3.3 DynamoDB Access Patterns

| Access Pattern | Table | PK | SK / Index | Operation | Frequency |
|---------------|-------|-----|------------|-----------|-----------|
| List syndicate posts (newest first) | posts | `GSSYND_PK=SYNDFEED#{id}` | GSSYND GSI, `ScanIndexForward=False` | `query` | Per page load |
| Create syndicate post | posts | `USER#{author_id}` | `POST#{post_id}` | `put_item` | Per post create |
| Delete syndicate post | posts | `USER#{author_id}` | `POST#{post_id}` | `delete_item` | Per moderation action |
| Get syndicate profile | syndicates | `SYND#{syndicate_id}` | `META` | `get_item` | Per profile view |
| Update syndicate profile | syndicates | `SYND#{syndicate_id}` | `META` | `update_item` | Per admin edit |
| Check membership | syndicates | `MEMBER#{syndicate_id}` | `USER#{user_id}` | `get_item` | Per feed/post request |
| Increment post count | syndicates | `SYND#{syndicate_id}` | `META` | `update_item` (atomic) | Per post create/delete |
| List syndicate members | syndicates | `MEMBER#{syndicate_id}` | begins_with `USER#` | `query` | Per profile view |

#### Example DynamoDB Items

**Syndicate post** (`posts` table):
```json
{
  "pk": "USER#creator_bob",
  "sk": "POST#sp_f2a1b3c4d5e6f7a8",
  "post_id": "sp_f2a1b3c4d5e6f7a8",
  "author_id": "creator_bob",
  "author_name": "Bob",
  "author_avatar": "https://cdn.example/avatars/bob.jpg",
  "text": "New tutorial video just dropped! Check it out.",
  "image_url": "",
  "syndicate_id": "synd_abc123",
  "visibility": "public",
  "created_at": 1748500000,
  "updated_at": 1748500000,
  "comment_count": 0,
  "reaction_counts": {},
  "tip_total_cents": 0,
  "GSSYND_PK": "SYNDFEED#synd_abc123",
  "GSSYND_SK": 1748500000
}
```

**Members-only syndicate post** (`posts` table):
```json
{
  "pk": "USER#creator_alice",
  "sk": "POST#sp_a9b8c7d6e5f4a3b2",
  "post_id": "sp_a9b8c7d6e5f4a3b2",
  "author_id": "creator_alice",
  "author_name": "Alice",
  "author_avatar": "https://cdn.example/avatars/alice.jpg",
  "text": "Exclusive behind-the-scenes content for syndicate members!",
  "image_url": "https://cdn.example/posts/bts-preview.jpg",
  "syndicate_id": "synd_abc123",
  "visibility": "members_only",
  "created_at": 1748501000,
  "updated_at": 1748501000,
  "comment_count": 3,
  "reaction_counts": {"heart": 5, "fire": 2},
  "tip_total_cents": 500,
  "GSSYND_PK": "SYNDFEED#synd_abc123",
  "GSSYND_SK": 1748501000
}
```

**Syndicate profile** (`syndicates` table, extended META item):
```json
{
  "pk": "SYND#synd_abc123",
  "sk": "META",
  "syndicate_id": "synd_abc123",
  "name": "Creative Collective",
  "description": "A group of top creators sharing premium content",
  "admin_user_id": "creator_alice",
  "status": "active",
  "avatar_url": "https://cdn.example/syndicates/collective-logo.png",
  "banner_url": "https://cdn.example/syndicates/collective-banner.jpg",
  "website_url": "https://creativecollective.example",
  "tags": ["gaming", "tutorials", "entertainment"],
  "post_count": 47,
  "member_count": 5,
  "created_at": 1748000000,
  "updated_at": 1748501000
}
```

### 3.4 Backend Service

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
    # Alternative: store a reverse lookup SYNDPOST#{post_id} -> pk/sk in syndicates table.
```

### 3.5 Backend Router

**New file**: `app/routers/syndicate_feed.py` (~120 lines)

### 3.6 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/syndicates/{syndicate_id}/profile` | `require_ui_session` | Get public syndicate profile (metadata + members + plans) |
| `PUT` | `/ui/syndicates/{syndicate_id}/profile` | `require_ui_session` | Update syndicate profile (admin only) |
| `GET` | `/ui/syndicates/{syndicate_id}/feed` | `require_ui_session` | Get syndicate newsfeed (filtered by visibility) |
| `POST` | `/ui/syndicates/{syndicate_id}/feed` | `require_ui_session` | Create post in syndicate feed (members only) |
| `DELETE` | `/ui/syndicates/{syndicate_id}/feed/{post_id}` | `require_ui_session` | Delete syndicate post (author or admin) |

### 3.7 API Request/Response Examples

**Get syndicate profile**:
```bash
curl http://localhost:8000/ui/syndicates/synd_abc123/profile \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx"

# 200 OK
{
  "syndicate_id": "synd_abc123",
  "name": "Creative Collective",
  "description": "A group of top creators sharing premium content",
  "avatar_url": "https://cdn.example/syndicates/collective-logo.png",
  "banner_url": "https://cdn.example/syndicates/collective-banner.jpg",
  "website_url": "https://creativecollective.example",
  "tags": ["gaming", "tutorials", "entertainment"],
  "admin_user_id": "creator_alice",
  "status": "active",
  "member_count": 5,
  "post_count": 47,
  "members": [
    {"user_id": "creator_alice", "display_name": "Alice", "role": "admin", "avatar_url": "..."},
    {"user_id": "creator_bob", "display_name": "Bob", "role": "member", "avatar_url": "..."}
  ],
  "bundle_plans": [
    {"plan_id": "plan_xxx", "name": "All-Access Bundle", "price_cents": 2000, "interval": "month"}
  ],
  "is_member": false,
  "created_at": 1748000000
}
```

**Update syndicate profile** (admin):
```bash
curl -X PUT http://localhost:8000/ui/syndicates/synd_abc123/profile \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "The best creators in gaming and tutorials",
    "tags": ["gaming", "tutorials", "live-streams"],
    "website_url": "https://creativecollective.example"
  }'

# 200 OK
{
  "syndicate_id": "synd_abc123",
  "name": "Creative Collective",
  "description": "The best creators in gaming and tutorials",
  "tags": ["gaming", "tutorials", "live-streams"],
  "website_url": "https://creativecollective.example",
  "updated_at": 1748510000
}
```

**Create syndicate post** (member):
```bash
curl -X POST http://localhost:8000/ui/syndicates/synd_abc123/feed \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "New tutorial video just dropped! Check it out.",
    "visibility": "public",
    "image_url": null
  }'

# 200 OK
{
  "post_id": "sp_f2a1b3c4d5e6f7a8",
  "author_id": "creator_bob",
  "author_name": "Bob",
  "author_avatar": "https://cdn.example/avatars/bob.jpg",
  "text": "New tutorial video just dropped! Check it out.",
  "image_url": "",
  "syndicate_id": "synd_abc123",
  "visibility": "public",
  "created_at": 1748500000,
  "comment_count": 0,
  "reaction_counts": {},
  "tip_total_cents": 0
}
```

**Get syndicate feed** (member -- sees all posts):
```bash
curl "http://localhost:8000/ui/syndicates/synd_abc123/feed?limit=10" \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx"

# 200 OK
{
  "posts": [
    {
      "post_id": "sp_a9b8c7d6e5f4a3b2",
      "author_id": "creator_alice",
      "author_name": "Alice",
      "text": "Exclusive behind-the-scenes content for syndicate members!",
      "visibility": "members_only",
      "created_at": 1748501000,
      "comment_count": 3,
      "reaction_counts": {"heart": 5, "fire": 2},
      "tip_total_cents": 500
    },
    {
      "post_id": "sp_f2a1b3c4d5e6f7a8",
      "author_id": "creator_bob",
      "author_name": "Bob",
      "text": "New tutorial video just dropped! Check it out.",
      "visibility": "public",
      "created_at": 1748500000,
      "comment_count": 0,
      "reaction_counts": {},
      "tip_total_cents": 0
    }
  ],
  "next_cursor": null,
  "is_member": true
}
```

**Get syndicate feed** (non-member -- only public posts):
```bash
curl "http://localhost:8000/ui/syndicates/synd_abc123/feed?limit=10" \
  -H "Cookie: ui_session=sess_visitor; ui_csrf=csrf_visitor; ui_access_token=jwt_visitor"

# 200 OK
{
  "posts": [
    {
      "post_id": "sp_f2a1b3c4d5e6f7a8",
      "author_id": "creator_bob",
      "author_name": "Bob",
      "text": "New tutorial video just dropped! Check it out.",
      "visibility": "public",
      "created_at": 1748500000,
      "comment_count": 0,
      "reaction_counts": {},
      "tip_total_cents": 0
    }
  ],
  "next_cursor": null,
  "is_member": false
}
```

**Delete syndicate post** (admin moderation):
```bash
curl -X DELETE http://localhost:8000/ui/syndicates/synd_abc123/feed/sp_f2a1b3c4d5e6f7a8 \
  -H "Cookie: ui_session=sess_admin; ui_csrf=csrf_admin; ui_access_token=jwt_admin" \
  -H "x-csrf-token: csrf_admin"

# 200 OK
{"ok": true, "post_id": "sp_f2a1b3c4d5e6f7a8"}
```

### 3.8 Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---------------|-------------|------------|---------------------|-----------------|
| Syndicate not found | 404 | `SYNDICATE_NOT_FOUND` | "Syndicate not found" | Verify syndicate ID |
| Non-member tries to post | 403 | `NOT_SYNDICATE_MEMBER` | "Only syndicate members can post" | Join the syndicate |
| Non-admin tries to update profile | 403 | `SYNDICATE_NOT_ADMIN` | "Only syndicate admins can update the profile" | Contact admin |
| Non-author/non-admin tries to delete | 403 | `DELETE_NOT_AUTHORIZED` | "Only the author or admin can delete this post" | None |
| Post not found for deletion | 404 | `POST_NOT_FOUND` | "Post not found" | Verify post ID |
| Post does not belong to syndicate | 400 | `POST_WRONG_SYNDICATE` | "Post does not belong to this syndicate" | Verify syndicate/post |
| Invalid visibility value | 422 | `VALIDATION_ERROR` | "Visibility must be 'public' or 'members_only'" | Fix request body |
| Post text too short (< 1 char) | 422 | `VALIDATION_ERROR` | "Post text must be at least 1 character" | Add content |
| Post text too long (> 5000 chars) | 422 | `VALIDATION_ERROR` | "Post text must be under 5000 characters" | Shorten text |
| Tags exceed maximum (> 10) | 422 | `VALIDATION_ERROR` | "Maximum 10 tags allowed" | Remove extra tags |
| Description too long (> 500 chars) | 422 | `VALIDATION_ERROR` | "Description must be under 500 characters" | Shorten description |
| Rate limit exceeded (posting) | 429 | `RATE_LIMIT_EXCEEDED` | "Too many posts. Try again later." | Wait and retry |
| Rate limit exceeded (profile update) | 429 | `RATE_LIMIT_EXCEEDED` | "Too many profile updates. Try again later." | Wait and retry |

### 3.9 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Syndicate Page & Newsfeed (SYND-005) --

class SyndicateProfileUpdateIn(BaseModel):
    avatar_url: Optional[str] = None
    banner_url: Optional[str] = None
    website_url: Optional[str] = Field(default=None, max_length=200)
    tags: Optional[List[str]] = Field(default=None, max_length=10)
    description: Optional[str] = Field(default=None, max_length=500)

    @model_validator(mode="before")
    @classmethod
    def at_least_one_field(cls, values):
        if isinstance(values, dict):
            non_none = {k: v for k, v in values.items() if v is not None}
            if not non_none:
                raise ValueError("At least one field must be provided for update")
        return values

    class Config:
        json_schema_extra = {
            "example": {
                "description": "The best gaming syndicate on the platform",
                "tags": ["gaming", "esports", "tutorials"],
                "website_url": "https://example.com",
            }
        }

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

    class Config:
        json_schema_extra = {
            "example": {
                "syndicate_id": "synd_abc123",
                "name": "Creative Collective",
                "description": "Top creators sharing premium content",
                "avatar_url": "",
                "banner_url": "",
                "website_url": "https://example.com",
                "tags": ["gaming"],
                "admin_user_id": "creator_alice",
                "status": "active",
                "member_count": 5,
                "post_count": 47,
                "members": [],
                "bundle_plans": [],
                "is_member": False,
                "created_at": 1748000000,
            }
        }

class SyndicatePostCreateIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    visibility: str = Field(default="public", pattern="^(public|members_only)$")
    image_url: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "text": "New tutorial just dropped!",
                "visibility": "public",
                "image_url": None,
            }
        }

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

    class Config:
        json_schema_extra = {
            "example": {
                "post_id": "sp_f2a1b3c4d5e6f7a8",
                "author_id": "creator_bob",
                "author_name": "Bob",
                "text": "New tutorial just dropped!",
                "syndicate_id": "synd_abc123",
                "visibility": "public",
                "created_at": 1748500000,
                "comment_count": 0,
                "reaction_counts": {},
                "tip_total_cents": 0,
            }
        }

class SyndicateFeedOut(BaseModel):
    posts: List[SyndicatePostOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None
    is_member: bool = False

    class Config:
        json_schema_extra = {
            "example": {
                "posts": [],
                "next_cursor": None,
                "is_member": False,
            }
        }
```

### 3.10 Frontend Components

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/syndicates/SyndicateProfilePage.tsx` | Public syndicate profile page | ~300 |
| `frontend/src/pages/syndicates/SyndicateFeed.tsx` | Syndicate newsfeed component | ~200 |
| `frontend/src/pages/syndicates/SyndicatePostComposer.tsx` | Post composer with visibility toggle | ~120 |
| `frontend/src/pages/syndicates/SyndicateMemberCard.tsx` | Member profile card for member list | ~60 |

### 3.11 Frontend Component Tree

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
│   │   │   ├── Textarea (min 1, max 5000 chars)
│   │   │   ├── Image attachment button (optional)
│   │   │   ├── Visibility toggle: Switch with labels "Public" / "Members Only"
│   │   │   │   ├── Switch component (shadcn/ui)
│   │   │   │   └── Label text changes based on toggle state
│   │   │   └── "Post" button (disabled while submitting or text empty)
│   │   ├── SyndicateFeed
│   │   │   ├── PostCard (reused from existing feed) for each post
│   │   │   │   ├── [Additional] Badge: "Members Only" (if visibility=members_only)
│   │   │   │   ├── [Additional] Subtitle: "Posted in {syndicate_name}"
│   │   │   │   └── [Additional] Delete button (visible to author + admin)
│   │   │   └── InfiniteScroll pagination (useInfiniteQuery)
│   │   └── JoinBanner (non-members only)
│   │       ├── Icon: Users
│   │       ├── Text: "Join this syndicate to see members-only posts"
│   │       └── Button: "Request to Join" / "Subscribe to Bundle"
│   └── "Members" Tab
│       └── Grid of SyndicateMemberCards (2-col on mobile, 3-col on desktop)
│           └── For each member: SyndicateMemberCard
│               ├── Avatar (48x48)
│               ├── Display name (Link to /profile/{userId})
│               ├── Role badge: "Admin" (orange) / "Member" (blue)
│               └── Join date text
└── Sidebar (desktop only, lg:block)
    ├── "Bundle Plans" card
    │   └── For each plan: name, "$X.XX/month", "Subscribe" button
    └── "About" card
        ├── Website link (external, opens in new tab)
        ├── Created date (formatted)
        └── Member count
```

**State management (React Query keys)**:

| Query Key | Endpoint | Invalidated By |
|-----------|----------|----------------|
| `["syndicate-profile", syndicateId]` | `GET /ui/syndicates/{id}/profile` | Profile update, member join/leave |
| `["syndicate-feed", syndicateId]` | `GET /ui/syndicates/{id}/feed` | Create post, delete post |
| `["syndicate-feed", syndicateId, "infinite"]` | `useInfiniteQuery` for paginated feed | Create post, delete post |

**Mutations**:

| Mutation | Endpoint | `onSuccess` |
|----------|----------|-------------|
| `useCreateSyndicatePost` | `POST /ui/syndicates/{id}/feed` | Invalidate `["syndicate-feed", id]` |
| `useDeleteSyndicatePost` | `DELETE /ui/syndicates/{id}/feed/{postId}` | Invalidate `["syndicate-feed", id]` |
| `useUpdateSyndicateProfile` | `PUT /ui/syndicates/{id}/profile` | Invalidate `["syndicate-profile", id]` |

### 3.12 Frontend Routes

Update `frontend/src/App.tsx`:

The existing `/syndicates/:syndicateId` route (SYND-001 management view) should be at `/syndicates/:syndicateId/manage`. The profile page takes the primary route:

```typescript
<Route path="/syndicates/:syndicateId" element={<SyndicateProfilePage />} />
<Route path="/syndicates/:syndicateId/manage" element={<SyndicateDetailPage />} />
```

### 3.13 Visibility Filtering Logic

```
GET /ui/syndicates/{syndicate_id}/feed
|
+-- Query GSSYND index: GSSYND_PK = SYNDFEED#{syndicate_id}
|
+-- Is viewer a syndicate member?
|   +-- Yes --> return ALL posts (public + members_only)
|   +-- No --> filter out posts where visibility = "members_only"
|
+-- Attach is_member flag to response
|   +-- Frontend uses this to show/hide composer + join CTA
|
+-- Return posts + next_cursor + is_member
```

### 3.14 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/syndicate_feed.py` | Syndicate feed service | ~250 |
| `app/routers/syndicate_feed.py` | Feed + profile router | ~120 |
| `frontend/src/pages/syndicates/SyndicateProfilePage.tsx` | Public profile page | ~300 |
| `frontend/src/pages/syndicates/SyndicateFeed.tsx` | Newsfeed component | ~200 |
| `frontend/src/pages/syndicates/SyndicatePostComposer.tsx` | Post composer | ~120 |
| `frontend/src/pages/syndicates/SyndicateMemberCard.tsx` | Member card | ~60 |
| `frontend/e2e/syndicates-feed.spec.ts` | E2E tests | ~400 |

### 3.15 Files to Modify

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

## 5. Observability & Monitoring

### 5.1 Metrics to Track

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `syndicate_post_created_total` | Counter | `syndicate_id`, `visibility` | Posts created |
| `syndicate_post_deleted_total` | Counter | `syndicate_id`, `deleted_by` (author/admin) | Posts deleted (moderation tracking) |
| `syndicate_feed_viewed_total` | Counter | `syndicate_id`, `is_member` | Feed page views |
| `syndicate_profile_viewed_total` | Counter | `syndicate_id` | Profile page views |
| `syndicate_profile_updated_total` | Counter | `syndicate_id` | Profile updates |
| `syndicate_feed_query_duration_ms` | Histogram | `syndicate_id` | GSSYND query latency |
| `syndicate_visibility_filtered_total` | Counter | `syndicate_id` | Posts filtered by visibility for non-members |

### 5.2 Log Events

| Event | Level | Fields | When |
|-------|-------|--------|------|
| `syndicate_post.created` | INFO | `syndicate_id`, `post_id`, `author_id`, `visibility` | Post created |
| `syndicate_post.deleted` | INFO | `syndicate_id`, `post_id`, `deleted_by`, `was_author` | Post deleted |
| `syndicate_post.moderated` | WARN | `syndicate_id`, `post_id`, `admin_id`, `reason` | Admin deletes non-own post |
| `syndicate_feed.viewed` | DEBUG | `syndicate_id`, `viewer_id`, `is_member`, `post_count` | Feed fetched |
| `syndicate_profile.updated` | INFO | `syndicate_id`, `admin_id`, `changed_fields` | Profile updated |
| `syndicate_feed.visibility_filtered` | DEBUG | `syndicate_id`, `viewer_id`, `filtered_count` | Posts hidden from non-member |
| `syndicate_post.rate_limited` | WARN | `syndicate_id`, `author_id`, `posts_this_hour` | Post rate limit hit |

### 5.3 Alert Thresholds

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High moderation rate | > 5 admin deletes in 1h for one syndicate | Warning | Review syndicate content quality |
| Feed query latency | p99 > 500ms for GSSYND query | Warning | Check DDB capacity / index health |
| Post rate limit spike | > 20 rate-limited posts in 1h | Info | May indicate spam; review rate limits |
| Zero posts in 30 days | Active syndicate with no posts in 30 days | Info | Syndicate may be inactive |
| Profile view surge | > 1000 views in 1h for single syndicate | Info | May be going viral; monitor load |

### 5.4 Dashboard Queries

**Syndicate engagement overview**:
```
SELECT syndicate_id,
       COUNT(*) as total_posts,
       SUM(CASE WHEN visibility = 'members_only' THEN 1 ELSE 0 END) as members_only_posts,
       AVG(comment_count) as avg_comments,
       SUM(tip_total_cents) / 100.0 as total_tips_usd
FROM syndicate_posts
WHERE created_at > now() - interval '30 days'
GROUP BY syndicate_id
ORDER BY total_posts DESC
```

---

## 6. Rollout Plan

### 6.1 Feature Flag Strategy

| Flag | Default | Description |
|------|---------|-------------|
| `SYNDICATE_FEED_ENABLED` | `false` (prod), `true` (dev) | Master switch for syndicate feed endpoints |
| `SYNDICATE_PROFILE_ENABLED` | `false` (prod), `true` (dev) | Enable public profile page |
| `SYNDICATE_MEMBERS_ONLY_POSTS` | `true` | Enable members-only visibility option |

### 6.2 Migration Steps

1. **Phase 1 -- GSI deployment**: Add GSSYND GSI to posts table. This is a non-blocking operation; GSI builds in background.
2. **Phase 2 -- Profile and feed API**: Deploy endpoints behind feature flags. Internal testing.
3. **Phase 3 -- Frontend deployment**: Ship SyndicateProfilePage and feed components. Profile page accessible via direct URL only.
4. **Phase 4 -- Navigation integration**: Add syndicate profile links in syndicate management page and discovery.

### 6.3 Canary Deployment

- Enable for 3-5 pilot syndicates first using a syndicate-level override (`SYNDICATE_FEED_PILOT_IDS`).
- Monitor GSSYND query latency and post creation rate for 48 hours.
- If p99 latency < 200ms and no errors, proceed to full rollout.

### 6.4 Rollback Procedure

1. Set `SYNDICATE_FEED_ENABLED=false` to disable feed endpoints (returns 503).
2. Set `SYNDICATE_PROFILE_ENABLED=false` to disable profile page.
3. Existing posts remain in DDB; GSSYND GSI items are inert.
4. To remove GSI: this requires a table update (non-destructive; can remain dormant).
5. Frontend components are lazy-loaded; disabling the route in App.tsx prevents loading.

---

## 7. Performance Considerations

### 7.1 Query Cost Analysis

| Operation | DDB Reads | DDB Writes | Expected Latency |
|-----------|-----------|------------|-------------------|
| List syndicate feed (20 posts) | 1 query (GSSYND) + 1 get (membership) | 0 | ~15-25ms |
| Create post | 1 get (membership) | 2 (post + counter update) | ~20ms |
| Delete post | 1 scan/query (find post) + 1 get (membership/admin) | 2 (delete + counter) | ~25ms |
| Get syndicate profile | 1 get (META) + 1 query (members) + 1 query (plans) | 0 | ~20-30ms |
| Update profile | 1 get (admin check) | 1 update | ~15ms |

### 7.2 Caching Strategy

| Cache Target | TTL | Invalidation | Storage |
|-------------|-----|-------------|---------|
| Syndicate profile | 30s | On profile update | React Query (client) |
| Syndicate feed (page 1) | 15s | On post create/delete | React Query (client) |
| Member list | 60s | On member join/leave | React Query (client) |
| Membership check result | Per-request | N/A (always fresh) | None (not cached) |

Note: Visibility filtering happens server-side, so caching feed results is safe -- the cache key includes the viewer's session, and the server returns only authorized posts.

### 7.3 Pagination Limits

| Endpoint | Default Limit | Max Limit | Cursor Support |
|----------|---------------|-----------|----------------|
| Syndicate feed | 20 | 50 | Yes (DDB cursor via `encode_cursor`) |
| Members list | 100 | 100 | No (syndicates rarely exceed 100 members) |
| Bundle plans | 20 | 50 | No (typically < 10 plans) |

### 7.4 Rate Limiting

| Endpoint | Rate Limit | Window | Key |
|----------|-----------|--------|-----|
| Create post | 10 posts | 1 hour | `user_sub + syndicate_id` |
| Update profile | 10 updates | 24 hours | `syndicate_id` |
| Get feed | 120 requests | 1 minute | `user_sub` |
| Delete post | 30 deletes | 1 hour | `user_sub + syndicate_id` |

### 7.5 GSSYND Query Considerations

The GSSYND GSI uses `GSSYND_SK` (numeric `created_at`) as sort key with `ScanIndexForward=False` for newest-first ordering. DynamoDB returns items in descending timestamp order within a single partition. Since all syndicate posts share the same `GSSYND_PK`, this is a single-partition query -- efficient even for syndicates with thousands of posts.

**Visibility filtering is post-query**: The `members_only` filter is applied in Python after the DDB query returns. This means if a syndicate has 50% members-only posts and a non-member requests `limit=20`, the query may need to fetch up to 40 items from DDB to fill 20 visible results. For the worst case (all members-only except 1 public), the query would need to loop with `LastEvaluatedKey`. The implementation handles this by accepting the filtered count (may be < limit) and always returning `next_cursor` if `LastEvaluatedKey` exists, letting the client paginate.

---

## 8. E2E Test Plan

**File**: `frontend/e2e/syndicates-feed.spec.ts`

### Section 439: Syndicate Profile API (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 439.1 | GET syndicate profile returns metadata and members | GET profile; 200; response has `name`, `members`, `post_count` |
| 439.2 | Admin updates profile with tags and description | PUT profile; 200; updated fields reflected in GET |
| 439.3 | Non-admin cannot update profile | Bob (member) PUT; 403 |
| 439.4 | Profile includes bundle plans | GET profile; `bundle_plans` array present (from SYND-002) |
| 439.5 | Profile shows is_member=true for members | GET as member; `is_member=true` |
| 439.6 | Profile shows is_member=false for non-members | GET as non-member; `is_member=false` |

### Section 440: Syndicate Feed Post API (7 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 440.1 | Member creates public post | POST feed; 200; `visibility=public`; post appears in GET feed |
| 440.2 | Member creates members-only post | POST feed with `visibility=members_only`; 200; `visibility=members_only` |
| 440.3 | Non-member cannot post | Non-member POST; 403 or 404 |
| 440.4 | Author can delete own post | DELETE; 200; post no longer in GET feed |
| 440.5 | Admin can delete any member's post | Admin DELETE of Bob's post; 200; post removed |
| 440.6 | Non-author non-admin cannot delete | Charlie (member, not author) DELETE; 403 |
| 440.7 | Post text validation enforced | POST with empty text; 422; POST with 5001-char text; 422 |

### Section 441: Visibility Filtering API (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 441.1 | Member sees all posts (public + members_only) | GET feed as member; response includes both visibility types; `is_member=true` |
| 441.2 | Non-member sees only public posts | GET feed as non-member; no `members_only` posts in response; `is_member=false` |
| 441.3 | Members-only post text hidden from non-members | POST `members_only` post; GET as non-member; post not in response |
| 441.4 | Pagination works with visibility filtering | Create 25 posts (mix of public/members_only); GET with limit=10; `next_cursor` present |
| 441.5 | Empty feed returns empty array | GET feed for syndicate with no posts; `posts=[]` |
| 441.6 | Post count matches visible posts | Non-member GET; visible post count matches response length |

### Section 442: Syndicate Profile UI (7 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 442.1 | Profile page renders syndicate name and description | Navigate to `/syndicates/{id}`; heading with syndicate name visible |
| 442.2 | Members tab shows member list | Click "Members" tab; member cards visible with names and roles |
| 442.3 | Post composer visible for members only | Member sees text area + "Post" button; non-member does not see composer |
| 442.4 | Visibility toggle switches between public and members-only | Member toggles visibility; label changes; post created with correct visibility |
| 442.5 | Join CTA visible for non-members | Non-member sees "Join to see all posts" banner; members do not see it |
| 442.6 | Members-only badge visible on restricted posts | Member sees "Members Only" badge on members_only posts |
| 442.7 | Admin delete button visible on all posts | Admin sees delete button on other members' posts; regular member does not |

**Total E2E tests: 26**

### Expanded Edge Cases and Negative Tests

| # | Test Title | Category |
|---|-----------|----------|
| E1 | Create post with maximum 5000 characters | Boundary; 200 accepted |
| E2 | Create post with image_url | Image post appears in feed with image |
| E3 | Concurrent posts from two members | Both succeed; both appear in feed ordered by created_at |
| E4 | Delete already-deleted post | 404 POST_NOT_FOUND |
| E5 | Feed pagination returns all pages | Create 30 posts; paginate with limit=10; collect all 3 pages; total=30 |
| E6 | Syndicate dissolved -- feed returns empty | Delete syndicate; GET feed returns 404 or empty |

---

## 9. Security Considerations

### 9.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| GET profile | `require_ui_session` | Any authenticated user |
| PUT profile | `require_ui_session` | Syndicate admin only |
| GET feed | `require_ui_session` | Any authenticated user (visibility filtering applied) |
| POST feed | `require_ui_session` | Syndicate members only |
| DELETE feed post | `require_ui_session` | Post author or syndicate admin |

### 9.2 Content Filtering

- `members_only` posts are filtered at the service layer, not via DDB `FilterExpression`. This prevents any leakage through API response manipulation.
- The `is_member` flag in the response is informational for the frontend; actual visibility enforcement happens server-side.
- Post text for `members_only` posts is never included in non-member responses (entire post item is excluded, not just obfuscated).

### 9.3 Post Moderation

- Syndicate admin can delete any post in the syndicate feed (moderation power).
- Post deletion is a hard delete (item removed from DDB), not a soft delete.
- Deletion is logged in the syndicate audit trail (SYND-001).

### 9.4 Input Validation

- Post text: 1-5000 characters.
- Visibility: must be `"public"` or `"members_only"`.
- Tags on profile: max 10 tags, each max 30 characters.
- Description: max 500 characters.
- URLs: validated as non-empty strings (no URL format validation in v1).

### 9.5 Rate Limiting

- Post creation: max 10 posts per member per hour per syndicate.
- Profile updates: max 10 per day.

---

## 10. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| SYND-001 | Required | Syndicate metadata, membership checks, admin authorization |
| SYND-002 | Required (for profile page) | Bundle plans displayed on profile page |
| Posts table | Exists | Store syndicate posts with GSSYND GSI |
| PostCard component | Exists | Reused for rendering syndicate posts |
| `app/services/newsfeed_feed_query.py` | Exists | Sorting utilities for posts |
| `app/core/cursor.py` | Exists | Pagination cursor encode/decode |

---

## 11. Acceptance Criteria

1. Each syndicate has a public profile page showing name, description, members, and bundle plans.
2. Admin can update syndicate profile (avatar, banner, tags, description).
3. Members can post to the syndicate newsfeed with public or members-only visibility.
4. Non-members see only public posts; members see all posts.
5. Non-members see a "Join to see all posts" CTA banner.
6. Post composer is visible only to members.
7. Admin can delete any syndicate post (moderation).
8. Syndicate posts are paginated with cursor-based pagination.
9. Profile page shows bundle subscription options (SYND-002 integration).
10. All 26 E2E tests pass.

---

## Codebase References

### Verified Existing Infrastructure

| Reference in Ticket | Verified | Notes |
|---------------------|----------|-------|
| `app/services/newsfeed_fanout.py` | Yes (173 lines) | Exists; fan-out logic for newsfeed |
| `app/services/newsfeed_feed_query.py` | Yes (93 lines) | Exists; sorting utilities for posts |
| `app/core/cursor.py` | Yes (120 lines) | Exists; cursor encode/decode for pagination |
| `PostCard` component | Yes — `frontend/src/pages/feed/PostCard.tsx` (948 lines) | Ticket says "Exists"; confirmed. Note: located under `pages/feed/`, not `components/feed/` |
| `app/core/tables.py` | Yes | Table handles wired from settings |

### New Code (Correctly Identified as Not Yet Existing)

| Item | Status |
|------|--------|
| `app/services/syndicates.py` | Does not exist — new implementation required (SYND-001) |
| `app/routers/syndicates.py` | Does not exist — new implementation required (SYND-001) |
| `frontend/src/pages/syndicates/` | Does not exist — new directory |
| Syndicates DynamoDB table | Not defined in `scripts/local-ddb-init.py` — must be added |
| `GSSYND` GSI on posts table | Does not exist — new GSI required |

### Notes

- No syndicate-related code exists anywhere in `app/services/` or `app/routers/` (grep confirmed zero results).
- The posts table exists but has no `GSSYND` GSI; this must be added to `scripts/local-ddb-init.py`.
- The ticket correctly identifies all syndicate infrastructure as new and depending on SYND-001.

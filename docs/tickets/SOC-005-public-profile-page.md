# SOC-005: Public-Facing Profile Page — Posts Grid, Follow/Subscribe CTAs, SEO Meta Tags

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-26  
**Priority**: Medium  
**Estimated effort**: 5-7 days

---

## 1. Overview & Motivation

### The Gap

A public user profile page exists at `/u/:identifier` (`frontend/src/pages/profile/PublicUserProfilePage.tsx`), but it is a minimal card showing only basic profile data with "Add to Contacts" and "Message" buttons. It lacks:

1. **No post grid** — The profile page does not show any of the user's posts. Visitors cannot browse a user's content without navigating to the feed and filtering by author.
2. **No follower/following counts** — The profile card has no social metrics. Visitors cannot gauge a creator's popularity or community size.
3. **No follow button** — There is no way to follow a user from their profile page. The only follow mechanism is the `follow()`/`unfollow()` API called from feed components.
4. **No subscription CTA** — If the user is a creator with subscription plans, there is no "Subscribe" button on their profile. Visitors must discover subscription plans separately.
5. **No profile tabs** — The page is a single card. There are no tabs for "Posts", "Videos", "About" to organize the creator's content.
6. **No SEO optimization** — The page uses client-side rendering only. There are no server-side meta tags (`<title>`, `<meta name="description">`, `og:image`) for social sharing/link previews.
7. **No responsive grid layout** — The page uses a simple centered card. On desktop, a creator's posts should display in a visual grid (like Instagram).

### Why This Is Needed

The public profile page is the primary surface for:
- **Creator identity**: Where followers go to see a creator's content catalog.
- **Conversion funnel**: Discovery (SOC-003) -> Profile -> Follow/Subscribe.
- **Sharing**: When a user shares their profile URL, the link preview should show their name, avatar, and bio.
- **SEO**: Crawlable profile pages improve platform visibility in search engines.

### Architecture After This Change

```
Route: /u/:identifier
                                                                            
  ┌──────────────────────────────────────────────────────────────────┐     
  │  Profile Header                                                   │     
  │  ┌──────────┐                                                     │     
  │  │  Avatar   │  Display Name                                      │     
  │  │  (large)  │  @username · Location                              │     
  │  └──────────┘  Bio / Description text                             │     
  │                                                                    │     
  │  1,234 Followers  ·  567 Following  ·  89 Posts                   │     
  │                                                                    │     
  │  [ Follow ]  [ Subscribe - $9.99/mo ]  [ Message ]                │     
  │                                                                    │     
  ├──────────────────────────────────────────────────────────────────┤     
  │  [ Posts ]  [ Videos ]  [ About ]                                 │     
  ├──────────────────────────────────────────────────────────────────┤     
  │                                                                    │     
  │  Posts Tab (default):                                              │     
  │  ┌──────┐ ┌──────┐ ┌──────┐                                      │     
  │  │ Post │ │ Post │ │ Post │                                      │     
  │  │ Card │ │ Card │ │ Card │                                      │     
  │  └──────┘ └──────┘ └──────┘                                      │     
  │  ┌──────┐ ┌──────┐ ┌──────┐                                      │     
  │  │ Post │ │ Post │ │ Post │                                      │     
  │  │ Card │ │ Card │ │ Card │                                      │     
  │  └──────┘ └──────┘ └──────┘                                      │     
  │                                                                    │     
  │  Videos Tab:                                                       │     
  │  Grid of video posts with thumbnails                               │     
  │                                                                    │     
  │  About Tab:                                                        │     
  │  Extended bio, location, links                                     │     
  │                                                                    │     
  └──────────────────────────────────────────────────────────────────┘     
                                                                            
Backend API:
  GET /ui/profile/public/{identifier}     → Profile data + counts          
  GET /ui/profile/public/{identifier}/posts → Paginated post list          
  GET /api/creators/{user_id}/plans       → Subscription plans (existing)  
```

### Data Flow Diagram — Profile Page Load

```
Browser                          Backend                         DDB
  │                                │                              │
  │  GET /u/alice_creator          │                              │
  │  (initial page load)           │                              │
  │ ──────────────────────────────>│                              │
  │                                │                              │
  │  (Vite serves index.html,     │                              │
  │   React Router matches         │                              │
  │   /u/:identifier)             │                              │
  │                                │                              │
  │  useQuery: GET /ui/profile/   │                              │
  │  public/alice_creator         │                              │
  │ ──────────────────────────────>│                              │
  │                                │                              │
  │                                │ resolve identifier           │
  │                                │ (cache -> alias scan)        │
  │                                │ ─────────────────────────────>│
  │                                │ <── user_sub ────────────────│
  │                                │                              │
  │                                │ check discoverability        │
  │                                │ ─────────────────────────────>│
  │                                │ <── ACTIVE ──────────────────│
  │                                │                              │
  │                                │ get profile fields           │
  │                                │ ─────────────────────────────>│
  │                                │ <── {name, bio, counts...} ──│
  │                                │                              │
  │                                │ check follow status          │
  │                                │ (if viewer authenticated)    │
  │                                │ ─────────────────────────────>│
  │                                │ <── {is_following: true} ────│
  │                                │                              │
  │                                │ check subscription plans     │
  │                                │ ─────────────────────────────>│
  │                                │ <── [{plan_id, price}] ──────│
  │                                │                              │
  │  <── PublicProfileResponse ────│                              │
  │                                │                              │
  │  useInfiniteQuery: GET         │                              │
  │  /ui/profile/public/           │                              │
  │  alice_creator/posts?limit=12  │                              │
  │ ──────────────────────────────>│                              │
  │                                │ query GSI2:                  │
  │                                │ POST_AUTHOR#{user_sub}       │
  │                                │ ─────────────────────────────>│
  │                                │ <── [post items...] ─────────│
  │                                │                              │
  │                                │ filter by visibility          │
  │                                │ build previews               │
  │                                │                              │
  │  <── PublicPostListResponse ───│                              │
  │                                │                              │
  │  Render ProfileHeader +        │                              │
  │  PostGrid + Tabs               │                              │
```

### Sequence Diagram — Follow Button Click

```
User (Viewer)     Frontend                Backend              DDB (social)
  │                  │                       │                     │
  │  Click "Follow"  │                       │                     │
  │ ────────────────>│                       │                     │
  │                  │                       │                     │
  │                  │ Optimistic update:    │                     │
  │                  │ is_following = true   │                     │
  │                  │ follower_count += 1   │                     │
  │                  │                       │                     │
  │                  │ POST /social/follow   │                     │
  │                  │ {target_user_id}      │                     │
  │                  │ ─────────────────────>│                     │
  │                  │                       │ write FOLLOW record │
  │                  │                       │ ───────────────────>│
  │                  │                       │                     │
  │                  │                       │ increment counts    │
  │                  │                       │ ───────────────────>│
  │                  │                       │                     │
  │                  │                       │ emit_social_alert   │
  │                  │                       │ (new_follower)      │
  │                  │                       │                     │
  │                  │ <── 200 ok ───────────│                     │
  │                  │                       │                     │
  │                  │ invalidateQueries     │                     │
  │                  │ (["profile", id])     │                     │
  │                  │                       │                     │
  │  Button shows    │                       │                     │
  │  "Following"     │                       │                     │
```

---

## 2. Current State Analysis

### 2.1 Existing Public Profile Page (`frontend/src/pages/profile/PublicUserProfilePage.tsx`)

The current page (route `/u/:identifier`) is approximately 224 lines. It:

1. Fetches profile data via `getProfileByIdentifier(identifier)` from `api/endpoints/profile.ts`.
2. Handles canonical identifier redirect (line 38-42) — if the resolved canonical identifier differs from the URL, it redirects.
3. Displays a single `Card` with:
   - Display name as `CardTitle`.
   - Title/description as `CardDescription`.
   - "Message" button (using `findOrCreateDm` to start a DM).
   - "Add contact" button (using `addContact` mutation).
   - "Sign in to view more" button (for unauthenticated users).
4. Error handling: 404 for not found, 429 for rate limited.

**Missing**: No follower counts, no follow button, no posts, no tabs. (Note: avatar IS displayed, either as profile photo or a fallback initial.)

### 2.2 Profile API (`app/routers/profile.py`)

**`GET /ui/profiles/{identifier}`** (line 50-51):
```python
async def ui_get_profile_by_identifier(identifier: str, req: Request):
```

Returns profile fields filtered by audience (public/member/owner). Public fields include: `display_name`, `title`, `description`, `location`, `profile_photo_url`, `cover_photo_url`.

**Missing**: No follower/following counts, no post count, no follow status relative to the viewer.

### 2.3 Profile Identifier Resolution (`app/routers/profile.py`, line 177)

`_resolve_profile_identifier_to_user_sub(identifier)` supports:
- Direct `user_sub` lookup (users table).
- Email lookup (users table scan — expensive).
- Username/handle alias lookup (profiles table scan — expensive).
- Caching via `_profile_identifier_cache_get/set` for resolved identifiers.

### 2.4 Posts by Author (`app/routers/newsfeed.py`)

The `GET /feed` endpoint with `author` query parameter queries GSI2 (`POST_AUTHOR#{author_id}`):
```python
# Line 4028-4036
if author_filter:
    resp = ddb_query(
        IndexName="GSI2",
        KeyConditionExpression="GSI2PK = :pk",
        ExpressionAttributeValues={":pk": f"POST_AUTHOR#{author_filter}"},
        ScanIndexForward=False,
        Limit=limit,
        ExclusiveStartKey=next_eks if next_eks else None,
    )
```

This returns the author's posts in reverse chronological order. However, this is part of the authenticated feed endpoint — it requires session auth and applies the full feed query logic (budget, filtering, etc.).

### 2.5 Subscription Plans (`app/routers/subscription_server.py`)

`GET /api/creators/{creator_id}/plans` is a public endpoint (no auth required) that returns subscription plans for a creator. This can be used on the profile page to show subscription pricing.

### 2.6 Frontend Route and Nav

The route is conditionally rendered in `App.tsx` (line 74):
```typescript
{showCanonicalProfileRoute && <Route path="/u/:identifier" element={<PublicUserProfilePage />} />}
```

There is no sidebar link to a "Profile" page. Users navigate to profiles via direct URL, search results, or user mentions.

### 2.7 Vite Config for SEO

The Vite dev server (`frontend/vite.config.ts`) serves `index.html` for all routes. There is no server-side rendering (SSR) or static site generation (SSG). For SEO meta tags, the options are:
1. **Client-side `<Helmet>`** — Sets meta tags after React renders. Works for sharing but not for initial crawler indexing (though most modern crawlers execute JS).
2. **Backend HTML injection** — The backend serves a customized `index.html` for `/u/:identifier` routes with pre-filled meta tags. This requires a new backend endpoint.

### 2.8 Profile Service (`app/services/profile.py`)

The `PROFILE_FIELDS` tuple (line 16) defines all stored profile fields:
```python
PROFILE_FIELDS = (
    "display_name", "first_name", "middle_name", "last_name",
    "title", "description", "birthday", "gender", "location",
    "displayed_email", "displayed_telephone_number", "mailing_address",
    "languages", "profile_photo_url", "cover_photo_url",
)
```

Note: `alias` and `timezone` are NOT in `PROFILE_FIELDS`. The field is `birthday` (not `date_of_birth`).

Notably absent: `follower_count`, `following_count`, `post_count`. These need to be added as maintained counters (SOC-001 adds follower/following counts; this ticket adds `post_count`).

### 2.9 Profile Discoverability (`app/services/profile_discoverability.py`)

The `DiscoverabilityState` enum (line 10) has four states:
- `ACTIVE`: Profile is publicly visible.
- `HIDDEN`: Profile is not discoverable via search but accessible via direct URL.
- `DEACTIVATED`: User-initiated deactivation. Profile returns 404.
- `DELETED`: Admin-initiated deletion. Profile returns 404.

The `get_profile_discoverability_state(user_sub)` function (line 46) reads the discoverability state. Note: this function returns a `Dict` (with keys `user_sub`, `discoverability_status`, `source`), not a `DiscoverabilityState` enum directly. The public profile endpoint must check this before returning data.

---

## 3. Technical Design

### 3.1 Enhanced Profile API — Full Implementation

#### 3.1.1 `GET /ui/profile/public/{identifier}` — Backend Code

```python
# app/routers/profile.py — new endpoint

from typing import Optional, Dict, Any, List, Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from app.core.tables import T
from app.core.cursor import decode_cursor, encode_cursor
from app.services.profile import get_profile, get_profile_identity
from app.services.profile_discoverability import (
    get_profile_discoverability_state,
    DiscoverabilityState,
)
from app.auth.deps import get_authenticated_user
from app.services.sessions import require_ui_session


@router.get("/profile/public/{identifier}")
async def get_public_profile(identifier: str, req: Request):
    """Public profile endpoint with social metrics and follow status.

    Auth: Optional. Unauthenticated callers receive follow fields as False.
    Authenticated callers receive follow status relative to their identity.

    The endpoint performs these DDB operations:
      1. Resolve identifier to user_sub (cached, 1 read on miss)
      2. Check discoverability state (1 read)
      3. Fetch profile fields (1 read)
      4. [If authenticated] Check follow status (2 reads: follower + following)
      5. Check subscription plans (1 read)
    Total: 3-6 DDB reads depending on auth and cache.
    """
    # Step 1: Resolve identifier
    requested_identifier = (identifier or "").strip()
    if not requested_identifier or len(requested_identifier) > _MAX_PROFILE_IDENTIFIER_LEN:
        raise HTTPException(status_code=404, detail="Profile not found")

    try:
        user_sub = _resolve_profile_identifier_to_user_sub(requested_identifier)
    except Exception:
        raise HTTPException(status_code=404, detail="Profile not found")

    if not user_sub:
        raise HTTPException(status_code=404, detail="Profile not found")

    # Step 2: Check discoverability
    # Note: get_profile_discoverability_state() returns a Dict, not an enum.
    # The discoverability_status value is a string (e.g., "active", "deactivated").
    disc_result = get_profile_discoverability_state(user_sub)
    disc_status = disc_result.get("discoverability_status", "active")
    if disc_status in (DiscoverabilityState.DEACTIVATED.value, DiscoverabilityState.DELETED.value):
        raise HTTPException(status_code=404, detail="Profile not found")

    # Step 3: Fetch profile
    profile = get_profile(user_sub)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    # Determine canonical identifier for redirect hints
    canonical = profile.get("alias") or user_sub
    if canonical != requested_identifier:
        canonical_identifier = canonical
    else:
        canonical_identifier = None

    # Step 4: Check follow status (if viewer is authenticated)
    viewer_sub = None
    is_following = False
    is_followed_by = False
    try:
        auth_user = await get_authenticated_user(req)
        ctx = await require_ui_session(req, auth_user=auth_user)
        viewer_sub = ctx.get("user_sub")
    except Exception:
        pass

    if viewer_sub and viewer_sub != user_sub:
        # Check if viewer follows this user
        from app.services.social import get_follow_status
        status = get_follow_status(viewer_sub, user_sub)
        is_following = status.get("is_following", False)
        is_followed_by = status.get("is_followed_by", False)

    # Step 5: Check subscription plans
    # Plans are stored in T.subscriptions with pk=CREATOR#{user_sub}, sk=PLAN#{plan_id}
    has_subscription_plans = False
    try:
        plans_resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(f"CREATOR#{user_sub}"),
            Select="COUNT",
            Limit=1,
        )
        has_subscription_plans = plans_resp.get("Count", 0) > 0
    except Exception:
        pass

    # Build response
    return {
        "user_id": user_sub,
        "identifier": requested_identifier,
        "canonical_identifier": canonical_identifier,
        "display_name": profile.get("display_name") or "User",
        "title": profile.get("title"),
        "description": profile.get("description"),
        "location": profile.get("location"),
        "profile_photo_url": profile.get("profile_photo_url"),
        "cover_photo_url": profile.get("cover_photo_url"),
        "follower_count": int(profile.get("follower_count", 0)),
        "following_count": int(profile.get("following_count", 0)),
        "post_count": int(profile.get("post_count", 0)),
        "is_following": is_following,
        "is_followed_by": is_followed_by,
        "is_mutual": is_following and is_followed_by,
        "has_subscription_plans": has_subscription_plans,
        "created_at": profile.get("created_at"),
        "discoverability": disc_status if disc_status == DiscoverabilityState.HIDDEN.value else None,
    }


@router.get("/profile/public/{identifier}/posts")
async def get_public_profile_posts(
    identifier: str,
    req: Request,
    limit: int = Query(default=12, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    filter: Optional[Literal["all", "text", "image", "video", "locked"]] = Query(default="all"),
):
    """Return paginated posts for a public profile.

    Auth: Optional. Authenticated viewers can see followers-only posts
    if they follow the author.

    Visibility rules:
      - visibility="public": visible to everyone.
      - visibility="followers": visible only to authenticated followers.
      - locked=True: metadata visible (title, thumbnail); body hidden.
        Shows unlock_price_cents.
    """
    # Resolve identifier
    requested_identifier = (identifier or "").strip()
    if not requested_identifier:
        raise HTTPException(status_code=404, detail="Profile not found")

    try:
        user_sub = _resolve_profile_identifier_to_user_sub(requested_identifier)
    except Exception:
        raise HTTPException(status_code=404, detail="Profile not found")

    if not user_sub:
        raise HTTPException(status_code=404, detail="Profile not found")

    # Check discoverability (returns Dict, not enum)
    disc_result = get_profile_discoverability_state(user_sub)
    disc_status = disc_result.get("discoverability_status", "active")
    if disc_status in (DiscoverabilityState.DEACTIVATED.value, DiscoverabilityState.DELETED.value):
        raise HTTPException(status_code=404, detail="Profile not found")

    # Determine viewer and follow status
    viewer_sub = None
    viewer_follows_author = False
    try:
        auth_user = await get_authenticated_user(req)
        ctx = await require_ui_session(req, auth_user=auth_user)
        viewer_sub = ctx.get("user_sub")
        if viewer_sub and viewer_sub != user_sub:
            from app.services.social import is_following
            viewer_follows_author = is_following(viewer_sub, user_sub)
        elif viewer_sub == user_sub:
            viewer_follows_author = True  # Author can see own posts
    except Exception:
        pass

    # Query posts via GSI2
    lek = decode_cursor(cursor) if cursor else None
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI2",
        "KeyConditionExpression": Key("GSI2PK").eq(f"POST_AUTHOR#{user_sub}"),
        "ScanIndexForward": False,  # Newest first
        "Limit": limit * 2,  # Over-fetch to account for filtered posts
    }
    if lek:
        kwargs["ExclusiveStartKey"] = lek

    # Note: app_single_table is NOT in the Tables dataclass.
    # Access via: tbl = ddb.Table(os.environ.get("APP_TABLE", "app_single_table"))
    resp = tbl.query(**kwargs)
    raw_items = resp.get("Items", [])
    next_lek = resp.get("LastEvaluatedKey")

    # Filter and transform posts
    items: List[Dict[str, Any]] = []
    for item in raw_items:
        if len(items) >= limit:
            break

        visibility = item.get("visibility", "public")
        is_locked = item.get("locked", False)

        # Visibility check
        if visibility == "followers" and not viewer_follows_author:
            continue

        # Apply type filter
        has_image = bool(item.get("image_urls"))
        has_video = bool(item.get("video_id"))
        if filter == "image" and not has_image:
            continue
        if filter == "video" and not has_video:
            continue
        if filter == "text" and (has_image or has_video):
            continue
        if filter == "locked" and not is_locked:
            continue

        # Build post summary
        body = item.get("body") or ""
        post_summary = {
            "post_id": item.get("post_id") or item.get("sk", "").replace("POST#", ""),
            "created_at": item.get("created_at", ""),
            "body_preview": body[:200] if not is_locked else None,
            "image_urls": item.get("image_urls", [])[:1] if not is_locked else [],
            "video_id": item.get("video_id") if not is_locked else None,
            "has_video": has_video,
            "locked": is_locked,
            "unlock_price_cents": int(item.get("lock_price_cents", 0)) if is_locked else None,
            "like_count": int(item.get("like_count", 0)),
            "comment_count": int(item.get("comment_count", 0)),
            "tip_total_cents": int(item.get("tip_total_cents", 0)),
        }
        items.append(post_summary)

    # Count total posts (for display)
    profile = get_profile(user_sub)
    total_count = int(profile.get("post_count", 0)) if profile else 0

    return {
        "items": items,
        "next_cursor": encode_cursor(next_lek) if next_lek and len(items) == limit else None,
        "total_count": total_count,
    }
```

#### 3.1.2 Response Models

```python
# In app/models.py

class PublicProfileResponse(BaseModel):
    user_id: str
    identifier: str
    canonical_identifier: Optional[str] = None
    display_name: str
    title: Optional[str] = None
    description: Optional[str] = None
    location: Optional[str] = None
    profile_photo_url: Optional[str] = None
    cover_photo_url: Optional[str] = None
    follower_count: int = 0
    following_count: int = 0
    post_count: int = 0
    is_following: bool = False        # Viewer follows this user
    is_followed_by: bool = False      # This user follows the viewer
    is_mutual: bool = False
    has_subscription_plans: bool = False
    created_at: Optional[str] = None  # Account age (for credibility)
    discoverability: Optional[str] = None  # "hidden" if profile is hidden

    @field_validator("follower_count", "following_count", "post_count", mode="before")
    @classmethod
    def coerce_to_int(cls, v: Any) -> int:
        """DDB stores numbers as Decimal; coerce to int."""
        if v is None:
            return 0
        return int(v)


class PublicPostSummary(BaseModel):
    post_id: str
    created_at: str
    body_preview: Optional[str] = None  # First 200 chars of text
    image_urls: List[str] = Field(default_factory=list)
    video_id: Optional[str] = None
    has_video: bool = False
    locked: bool = False
    unlock_price_cents: Optional[int] = None
    like_count: int = 0
    comment_count: int = 0
    tip_total_cents: int = 0

    @field_validator("like_count", "comment_count", "tip_total_cents", mode="before")
    @classmethod
    def coerce_counts_to_int(cls, v: Any) -> int:
        if v is None:
            return 0
        return int(v)


class PublicPostListResponse(BaseModel):
    items: List[PublicPostSummary]
    next_cursor: Optional[str] = None
    total_count: int = 0
```

### 3.2 Post Count Maintenance

Rather than counting posts on every profile view (expensive GSI query), maintain an atomic `post_count` on the user's profile record:

**On post create** (`create_post` in `app/routers/newsfeed.py`):
```python
# After writing the post item to DDB:
try:
    T.profile.update_item(
        Key={"user_sub": user_id},
        UpdateExpression="ADD post_count :one",
        ExpressionAttributeValues={":one": 1},
    )
except Exception:
    logger.warning("Failed to increment post_count", extra={"user_sub": user_id})
```

**On post delete**:
```python
# After soft-deleting or hard-deleting the post:
try:
    T.profile.update_item(
        Key={"user_sub": user_id},
        UpdateExpression="ADD post_count :neg_one",
        ExpressionAttributeValues={":neg_one": -1},
        ConditionExpression="attribute_exists(post_count) AND post_count > :zero",
        ExpressionAttributeValues={":neg_one": -1, ":zero": 0},
    )
except T.profile.meta.client.exceptions.ConditionalCheckFailedException:
    pass  # Count already at 0; do not go negative
except Exception:
    logger.warning("Failed to decrement post_count", extra={"user_sub": user_id})
```

**Reconciliation script** (for backfilling existing posts):
```python
# scripts/reconcile_post_counts.py
"""Scan all posts and update post_count on each author's profile."""

import boto3
from collections import Counter

def reconcile_post_counts():
    ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001")
    table = ddb.Table("app_single_table")
    profiles = ddb.Table("profiles")

    # Count posts per author
    author_counts: Counter = Counter()
    lek = None
    while True:
        kwargs = {
            "IndexName": "GSI2",
            "ProjectionExpression": "GSI2PK",
            "Select": "SPECIFIC_ATTRIBUTES",
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            gsi2pk = item.get("GSI2PK", "")
            if gsi2pk.startswith("POST_AUTHOR#"):
                author_id = gsi2pk.replace("POST_AUTHOR#", "")
                author_counts[author_id] += 1
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break

    # Update each author's profile
    for author_id, count in author_counts.items():
        profiles.update_item(
            Key={"user_sub": author_id},
            UpdateExpression="SET post_count = :count",
            ExpressionAttributeValues={":count": count},
        )
        print(f"  {author_id}: {count} posts")

    print(f"Reconciled {len(author_counts)} authors")
```

### 3.3 SEO Meta Tag Injection

#### 3.3.1 Backend Meta Tag Endpoint

```python
# app/routers/profile.py

@router.get("/profile/meta/{identifier}")
async def profile_meta_tags(identifier: str):
    """Return pre-rendered meta tags for profile SEO.

    This lightweight endpoint is called by the frontend to set
    document meta tags via react-helmet-async.  It returns only
    the fields needed for <title>, <meta description>, and og:tags.

    The endpoint does NOT require authentication, since meta tags
    must be accessible to social media crawlers.
    """
    try:
        user_sub = _resolve_profile_identifier_to_user_sub(identifier)
    except Exception:
        return {"title": "Profile", "description": "", "image": ""}

    if not user_sub:
        return {"title": "Profile", "description": "", "image": ""}

    # Check discoverability — hidden profiles should still have meta tags
    # (they're accessible via direct URL), but deactivated/deleted should not
    disc_result = get_profile_discoverability_state(user_sub)
    disc_status = disc_result.get("discoverability_status", "active")
    if disc_status in (DiscoverabilityState.DEACTIVATED.value, DiscoverabilityState.DELETED.value):
        return {"title": "Profile", "description": "", "image": ""}

    profile = get_profile(user_sub)
    if not profile:
        return {"title": "Profile", "description": "", "image": ""}

    display_name = profile.get("display_name") or "User"
    description = (profile.get("description") or profile.get("title") or "")[:160]
    photo_url = profile.get("profile_photo_url") or ""
    follower_count = int(profile.get("follower_count", 0))

    return {
        "title": f"{display_name} - Profile",
        "description": f"{description} | {follower_count:,} followers",
        "image": photo_url,
        "url": f"/u/{identifier}",
    }
```

#### 3.3.2 Frontend Meta Tags via react-helmet-async

```typescript
import { Helmet } from "react-helmet-async";

// In PublicUserProfilePage component:
<Helmet>
  <title>{profile.display_name} - Profile</title>
  <meta name="description" content={`${profile.description || ""} | ${profile.follower_count.toLocaleString()} followers`} />
  <meta property="og:title" content={`${profile.display_name}`} />
  <meta property="og:description" content={profile.description || ""} />
  <meta property="og:image" content={profile.profile_photo_url || ""} />
  <meta property="og:url" content={`/u/${profile.canonical_identifier}`} />
  <meta property="og:type" content="profile" />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content={profile.display_name} />
  <meta name="twitter:description" content={profile.description || ""} />
  <meta name="twitter:image" content={profile.profile_photo_url || ""} />
</Helmet>
```

Note: Client-side meta tags work for Facebook/Twitter crawlers (which execute JavaScript) but not for all search engine crawlers. For full SEO, server-side rendering or a prerender service is recommended as a future enhancement.

### 3.4 Frontend Component Design

#### 3.4.1 Profile Header Component — Full Implementation

```typescript
// frontend/src/pages/profile/ProfileHeader.tsx

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { MessageSquare, UserPlus, UserCheck, MapPin, Calendar } from "lucide-react";
import { cn } from "@/lib/utils";
import api from "@/api/client";

interface PublicProfile {
  user_id: string;
  identifier: string;
  canonical_identifier?: string;
  display_name: string;
  title?: string;
  description?: string;
  location?: string;
  profile_photo_url?: string;
  cover_photo_url?: string;
  follower_count: number;
  following_count: number;
  post_count: number;
  is_following: boolean;
  is_followed_by: boolean;
  is_mutual: boolean;
  has_subscription_plans: boolean;
  created_at?: string;
}

interface ProfileHeaderProps {
  profile: PublicProfile;
  isOwnProfile: boolean;
  onFollow: () => void;
  onUnfollow: () => void;
  onMessage: () => void;
  onSubscribe: () => void;
}

export function ProfileHeader({
  profile,
  isOwnProfile,
  onFollow,
  onUnfollow,
  onMessage,
  onSubscribe,
}: ProfileHeaderProps) {
  const queryClient = useQueryClient();

  const followMut = useMutation({
    mutationFn: () => api.post("/social/follow", { target_user_id: profile.user_id }),
    onMutate: async () => {
      // Optimistic update
      await queryClient.cancelQueries({ queryKey: ["public-profile", profile.identifier] });
      queryClient.setQueryData(["public-profile", profile.identifier], (old: any) => ({
        ...old,
        is_following: true,
        follower_count: (old?.follower_count ?? 0) + 1,
      }));
    },
    onError: () => {
      queryClient.invalidateQueries({ queryKey: ["public-profile", profile.identifier] });
    },
    onSuccess: () => {
      onFollow();
    },
  });

  const unfollowMut = useMutation({
    mutationFn: () => api.post("/social/unfollow", { target_user_id: profile.user_id }),
    onMutate: async () => {
      await queryClient.cancelQueries({ queryKey: ["public-profile", profile.identifier] });
      queryClient.setQueryData(["public-profile", profile.identifier], (old: any) => ({
        ...old,
        is_following: false,
        follower_count: Math.max((old?.follower_count ?? 1) - 1, 0),
      }));
    },
    onError: () => {
      queryClient.invalidateQueries({ queryKey: ["public-profile", profile.identifier] });
    },
    onSuccess: () => {
      onUnfollow();
    },
  });

  const memberSince = profile.created_at
    ? new Date(profile.created_at).toLocaleDateString("en-US", { month: "long", year: "numeric" })
    : null;

  return (
    <div className="space-y-4">
      {/* Cover photo */}
      {profile.cover_photo_url ? (
        <div
          className="h-48 w-full rounded-lg bg-cover bg-center"
          style={{ backgroundImage: `url(${profile.cover_photo_url})` }}
          role="img"
          aria-label={`${profile.display_name}'s cover photo`}
        />
      ) : (
        <div className="h-32 w-full rounded-lg bg-gradient-to-r from-primary/20 to-primary/5" />
      )}

      {/* Avatar + info */}
      <div className="flex items-start gap-4 -mt-10 px-4">
        <Avatar className="h-20 w-20 border-4 border-background shadow-md">
          <AvatarImage src={profile.profile_photo_url} alt={profile.display_name} />
          <AvatarFallback className="text-2xl">{profile.display_name?.[0]?.toUpperCase()}</AvatarFallback>
        </Avatar>
        <div className="flex-1 pt-10">
          <h1 className="text-2xl font-bold">{profile.display_name}</h1>
          {profile.title && <p className="text-muted-foreground">{profile.title}</p>}
          {profile.location && (
            <p className="text-sm text-muted-foreground flex items-center gap-1 mt-1">
              <MapPin className="h-3 w-3" />
              {profile.location}
            </p>
          )}
          {memberSince && (
            <p className="text-sm text-muted-foreground flex items-center gap-1">
              <Calendar className="h-3 w-3" />
              Member since {memberSince}
            </p>
          )}
        </div>
      </div>

      {/* Bio */}
      {profile.description && (
        <p className="px-4 text-sm leading-relaxed">{profile.description}</p>
      )}

      {/* Stats */}
      <div className="flex gap-6 text-sm px-4">
        <button className="hover:underline">
          <strong>{profile.follower_count.toLocaleString()}</strong>{" "}
          <span className="text-muted-foreground">Followers</span>
        </button>
        <button className="hover:underline">
          <strong>{profile.following_count.toLocaleString()}</strong>{" "}
          <span className="text-muted-foreground">Following</span>
        </button>
        <span>
          <strong>{profile.post_count.toLocaleString()}</strong>{" "}
          <span className="text-muted-foreground">Posts</span>
        </span>
      </div>

      {/* Mutual badge */}
      {profile.is_mutual && (
        <div className="px-4">
          <span className="text-xs bg-primary/10 text-primary px-2 py-1 rounded-full">
            Mutual — follows you back
          </span>
        </div>
      )}

      {/* Action buttons */}
      {!isOwnProfile && (
        <div className="flex gap-2 px-4">
          {profile.is_following ? (
            <Button
              variant="outline"
              onClick={() => unfollowMut.mutate()}
              disabled={unfollowMut.isPending}
              aria-pressed={true}
            >
              <UserCheck className="h-4 w-4 mr-2" />
              Following
            </Button>
          ) : (
            <Button
              onClick={() => followMut.mutate()}
              disabled={followMut.isPending}
            >
              <UserPlus className="h-4 w-4 mr-2" />
              Follow
            </Button>
          )}
          {profile.has_subscription_plans && (
            <Button variant="secondary" onClick={onSubscribe}>
              Subscribe
            </Button>
          )}
          <Button variant="outline" onClick={onMessage}>
            <MessageSquare className="h-4 w-4 mr-2" />
            Message
          </Button>
        </div>
      )}

      {/* Own profile: Edit button */}
      {isOwnProfile && (
        <div className="flex gap-2 px-4">
          <Button variant="outline" onClick={() => window.location.href = "/settings"}>
            Edit Profile
          </Button>
        </div>
      )}
    </div>
  );
}
```

#### 3.4.2 Post Grid Component — Full Implementation

```typescript
// frontend/src/pages/profile/PostGrid.tsx

import { useInfiniteQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Loader2 } from "lucide-react";
import { getProfilePosts } from "@/api/endpoints/profile";
import { ProfilePostCard } from "./ProfilePostCard";

interface PostGridProps {
  identifier: string;
  filter?: "all" | "text" | "image" | "video" | "locked";
}

export function PostGrid({ identifier, filter = "all" }: PostGridProps) {
  const {
    data,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
    isLoading,
    isError,
  } = useInfiniteQuery({
    queryKey: ["profile-posts", identifier, filter],
    queryFn: ({ pageParam }) =>
      getProfilePosts(identifier, { cursor: pageParam, limit: 12, filter }).then((r) => r.data),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    initialPageParam: undefined as string | undefined,
  });

  const posts = data?.pages.flatMap((p) => p.items) ?? [];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        Failed to load posts. Please try again.
      </div>
    );
  }

  if (posts.length === 0) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        No posts yet.
      </div>
    );
  }

  return (
    <div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {posts.map((post) => (
          <ProfilePostCard key={post.post_id} post={post} />
        ))}
      </div>
      {hasNextPage && (
        <div className="flex justify-center mt-6">
          <Button
            variant="ghost"
            onClick={() => fetchNextPage()}
            disabled={isFetchingNextPage}
          >
            {isFetchingNextPage ? (
              <Loader2 className="h-4 w-4 animate-spin mr-2" />
            ) : null}
            Load more
          </Button>
        </div>
      )}
    </div>
  );
}
```

#### 3.4.3 Profile Post Card

A compact card for the grid display:

```typescript
// frontend/src/pages/profile/ProfilePostCard.tsx

import { useNavigate } from "react-router-dom";
import { Card, CardContent } from "@/components/ui/card";
import { Lock, Video, Heart, MessageCircle } from "lucide-react";

interface PublicPostSummary {
  post_id: string;
  created_at: string;
  body_preview?: string;
  image_urls: string[];
  video_id?: string;
  has_video: boolean;
  locked: boolean;
  unlock_price_cents?: number;
  like_count: number;
  comment_count: number;
  tip_total_cents: number;
}

export function ProfilePostCard({ post }: { post: PublicPostSummary }) {
  const navigate = useNavigate();

  return (
    <Card
      className="cursor-pointer hover:shadow-md transition-shadow overflow-hidden group"
      onClick={() => navigate(`/feed/${post.post_id}`)}
      role="listitem"
    >
      {/* Image or video thumbnail */}
      {post.image_urls[0] ? (
        <div className="relative aspect-square">
          <img
            src={post.image_urls[0]}
            alt=""
            className="w-full h-full object-cover"
            loading="lazy"
          />
          {/* Hover overlay with stats */}
          <div className="absolute inset-0 bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center gap-4 text-white">
            {post.like_count > 0 && (
              <span className="flex items-center gap-1">
                <Heart className="h-4 w-4" /> {post.like_count}
              </span>
            )}
            {post.comment_count > 0 && (
              <span className="flex items-center gap-1">
                <MessageCircle className="h-4 w-4" /> {post.comment_count}
              </span>
            )}
          </div>
          {/* Lock badge */}
          {post.locked && (
            <div className="absolute top-2 right-2 bg-amber-500/90 text-white text-xs px-2 py-1 rounded flex items-center gap-1">
              <Lock className="h-3 w-3" />
              ${((post.unlock_price_cents ?? 0) / 100).toFixed(2)}
            </div>
          )}
        </div>
      ) : post.has_video ? (
        <div className="aspect-square bg-muted flex items-center justify-center">
          <Video className="h-8 w-8 text-muted-foreground" />
        </div>
      ) : null}

      {/* Text preview */}
      <CardContent className="p-3">
        {post.body_preview && (
          <p className="text-sm line-clamp-3">{post.body_preview}</p>
        )}

        {/* Stats row (for text-only posts without hover overlay) */}
        {!post.image_urls[0] && !post.has_video && (
          <div className="flex gap-3 mt-2 text-xs text-muted-foreground">
            {post.like_count > 0 && (
              <span className="flex items-center gap-1">
                <Heart className="h-3 w-3" /> {post.like_count}
              </span>
            )}
            {post.comment_count > 0 && (
              <span className="flex items-center gap-1">
                <MessageCircle className="h-3 w-3" /> {post.comment_count}
              </span>
            )}
          </div>
        )}

        {/* Locked text-only post */}
        {post.locked && !post.image_urls[0] && (
          <div className="flex items-center gap-1 mt-2 text-xs text-amber-600">
            <Lock className="h-3 w-3" />
            <span>${((post.unlock_price_cents ?? 0) / 100).toFixed(2)} to unlock</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
```

#### 3.4.4 Profile Tabs

```typescript
// In PublicUserProfilePage:
<Tabs defaultValue="posts">
  <TabsList>
    <TabsTrigger value="posts">Posts</TabsTrigger>
    <TabsTrigger value="videos">Videos</TabsTrigger>
    <TabsTrigger value="about">About</TabsTrigger>
  </TabsList>
  
  <TabsContent value="posts">
    <PostGrid identifier={profile.identifier} filter="all" />
  </TabsContent>
  
  <TabsContent value="videos">
    <PostGrid identifier={profile.identifier} filter="video" />
  </TabsContent>
  
  <TabsContent value="about">
    <AboutTab profile={profile} />
  </TabsContent>
</Tabs>
```

#### 3.4.5 About Tab Component

```typescript
// frontend/src/pages/profile/AboutTab.tsx

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { MapPin, Calendar, Globe, Mail } from "lucide-react";

interface AboutTabProps {
  profile: {
    display_name: string;
    description?: string;
    location?: string;
    created_at?: string;
    title?: string;
  };
}

export function AboutTab({ profile }: AboutTabProps) {
  const memberSince = profile.created_at
    ? new Date(profile.created_at).toLocaleDateString("en-US", {
        month: "long",
        day: "numeric",
        year: "numeric",
      })
    : null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">About {profile.display_name}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {profile.description && (
          <div>
            <h3 className="text-sm font-medium text-muted-foreground mb-1">Bio</h3>
            <p className="text-sm whitespace-pre-wrap">{profile.description}</p>
          </div>
        )}
        {profile.title && (
          <div>
            <h3 className="text-sm font-medium text-muted-foreground mb-1">Title</h3>
            <p className="text-sm">{profile.title}</p>
          </div>
        )}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {profile.location && (
            <div className="flex items-center gap-2 text-sm">
              <MapPin className="h-4 w-4 text-muted-foreground" />
              {profile.location}
            </div>
          )}
          {memberSince && (
            <div className="flex items-center gap-2 text-sm">
              <Calendar className="h-4 w-4 text-muted-foreground" />
              Member since {memberSince}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
```

### 3.5 Subscription CTA Integration

If `has_subscription_plans` is true, show a "Subscribe" button that opens a dialog or navigates to the subscription page:

```typescript
const plansQuery = useQuery({
  queryKey: ["creator-plans", profile.user_id],
  queryFn: () => api.get(`/api/creators/${profile.user_id}/plans`).then(r => r.data),
  enabled: profile.has_subscription_plans,
});
```

The dialog shows plan cards with pricing and a "Subscribe" button that initiates the subscription flow (existing `POST /api/subscriptions` endpoint).

```typescript
// SubscriptionDialog component (simplified)
function SubscriptionDialog({
  plans,
  creatorName,
  open,
  onClose,
}: {
  plans: Array<{ plan_id: string; name: string; price_cents: number; interval: string }>;
  creatorName: string;
  open: boolean;
  onClose: () => void;
}) {
  const subscribeMut = useMutation({
    mutationFn: (planId: string) =>
      api.post("/api/subscriptions", { plan_id: planId }),
    onSuccess: () => {
      toast.success("Subscribed successfully!");
      onClose();
    },
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Subscribe to {creatorName}</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          {plans.map((plan) => (
            <Card key={plan.plan_id} className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">{plan.name}</p>
                  <p className="text-sm text-muted-foreground">
                    ${(plan.price_cents / 100).toFixed(2)}/{plan.interval}
                  </p>
                </div>
                <Button
                  size="sm"
                  onClick={() => subscribeMut.mutate(plan.plan_id)}
                  disabled={subscribeMut.isPending}
                >
                  Subscribe
                </Button>
              </div>
            </Card>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  );
}
```

### 3.6 Responsive Design

| Viewport | Layout |
|----------|--------|
| Mobile (<640px) | Single column. Avatar + name stacked. Full-width post cards. |
| Tablet (640-1024px) | 2-column post grid. Side-by-side avatar + stats. |
| Desktop (>1024px) | 3-column post grid. Cover photo full-width. Stats in header. |

CSS uses Tailwind responsive prefixes: `grid-cols-1 sm:grid-cols-2 lg:grid-cols-3`.

### 3.7 Profile URL Patterns

| Pattern | Resolution |
|---------|------------|
| `/u/{username}` | Lookup by username/handle alias |
| `/u/{user_sub}` | Direct user_sub lookup |
| `/u/{email}` | Email lookup (if profile is public) |

The existing `_resolve_profile_identifier_to_user_sub()` handles all three patterns. Canonical redirect ensures the URL always resolves to the preferred identifier.

### 3.8 DDB Access Pattern Summary

| Access Pattern | Table | Key / Index | Operation | Cost |
|---|---|---|---|---|
| Resolve identifier (cache miss) | `profiles` | Scan with `alias` filter | scan (bounded) | ~10ms |
| Resolve identifier (cache hit) | In-memory | — | dict lookup | ~0ms |
| Check discoverability | `account_state` | PK=`user_sub` | get_item | ~5ms |
| Fetch profile fields | `profiles` | PK=`user_sub` | get_item | ~5ms |
| Check follow status | `app_single_table` | GSI5: `FOLLOWER#{viewer}` | 2x get_item | ~10ms |
| Count subscription plans | `subscription_plans` | PK=`creator_id` | query COUNT | ~5ms |
| Query posts (page) | `app_single_table` | GSI2: `POST_AUTHOR#{user_sub}` | query (Limit=24) | ~10ms |
| Increment post_count | `profiles` | PK=`user_sub` | update_item (ADD) | ~5ms |
| Decrement post_count | `profiles` | PK=`user_sub` | update_item (ADD, cond) | ~5ms |
| Meta tags | `profiles` | PK=`user_sub` | get_item | ~5ms |

---

## 4. Implementation Plan

### Step 1: Add Enhanced Profile API Endpoint

**File**: `app/routers/profile.py`

Add `GET /ui/profile/public/{identifier}` returning `PublicProfileResponse` (~60 lines).

This endpoint combines:
- Profile data from profiles table.
- Follower/following counts (from SOC-001 count fields on profile).
- Post count (atomic counter on profile or GSI2 count query).
- Follow status (if viewer authenticated).
- Subscription plans check.

### Step 2: Add Profile Posts Endpoint

**File**: `app/routers/profile.py` (or `app/routers/newsfeed.py`)

Add `GET /ui/profile/public/{identifier}/posts` returning `PublicPostListResponse` (~80 lines).

Queries GSI2 `POST_AUTHOR#{user_sub}` with pagination and visibility filtering.

### Step 3: Add Post Count Maintenance

**File**: `app/routers/newsfeed.py`

In `create_post()` (after writing the post): atomic increment `post_count` on profiles table.
In the delete handler: atomic decrement `post_count`.

**Lines modified**: ~15.

### Step 4: Add SEO Meta Tag Endpoint

**File**: `app/routers/profile.py`

Add `GET /profile/meta/{identifier}` (~25 lines).

### Step 5: Rewrite PublicUserProfilePage

**File**: `frontend/src/pages/profile/PublicUserProfilePage.tsx`

Complete rewrite to include:
- ProfileHeader component (avatar, name, bio, counts, action buttons).
- Tabs (Posts, Videos, About).
- PostGrid with infinite scroll.
- FollowButton integration (from SOC-001).
- Subscription CTA.
- SEO meta tags via react-helmet-async.

**Estimated size**: ~250 lines (up from current ~160).

### Step 6: Create ProfileHeader Component

**File**: `frontend/src/pages/profile/ProfileHeader.tsx` (new file, ~120 lines)

### Step 7: Create PostGrid Component

**File**: `frontend/src/pages/profile/PostGrid.tsx` (new file, ~100 lines)

### Step 8: Create ProfilePostCard Component

**File**: `frontend/src/pages/profile/ProfilePostCard.tsx` (new file, ~80 lines)

### Step 9: Create AboutTab Component

**File**: `frontend/src/pages/profile/AboutTab.tsx` (new file, ~60 lines)

### Step 10: Add Frontend API Endpoints

**File**: `frontend/src/api/endpoints/profile.ts` (modify existing)

Add:
```typescript
export interface PublicProfile {
  user_id: string;
  identifier: string;
  canonical_identifier?: string;
  display_name: string;
  title?: string;
  description?: string;
  location?: string;
  profile_photo_url?: string;
  cover_photo_url?: string;
  follower_count: number;
  following_count: number;
  post_count: number;
  is_following: boolean;
  is_followed_by: boolean;
  is_mutual: boolean;
  has_subscription_plans: boolean;
}

export interface PublicPostSummary {
  post_id: string;
  created_at: string;
  body_preview?: string;
  image_urls: string[];
  video_id?: string;
  has_video: boolean;
  locked: boolean;
  unlock_price_cents?: number;
  like_count: number;
  comment_count: number;
  tip_total_cents: number;
}

export const getPublicProfile = (identifier: string) =>
  api.get<PublicProfile>(`/profile/public/${encodeURIComponent(identifier)}`);

export const getProfilePosts = (identifier: string, params: { cursor?: string; limit?: number; filter?: string }) =>
  api.get<{ items: PublicPostSummary[]; next_cursor?: string; total_count: number }>(
    `/profile/public/${encodeURIComponent(identifier)}/posts`,
    { params }
  );

export const getProfileMeta = (identifier: string) =>
  api.get<{ title: string; description: string; image: string; url: string }>(
    `/profile/meta/${encodeURIComponent(identifier)}`
  );
```

### Step 11: Install react-helmet-async

**File**: `frontend/package.json`

```bash
npm install react-helmet-async
```

Wrap `App` with `<HelmetProvider>` in `main.tsx`.

### Step 12: Add Frontend Types

**File**: `frontend/src/api/types.ts`

Add `PublicProfile` and `PublicPostSummary` interfaces (if not co-located with API endpoints).

### Summary of Files Modified/Created

| File | Change Type | Estimated Lines |
|------|-------------|-----------------|
| `app/routers/profile.py` | Add public profile + posts + meta endpoints | ~170 |
| `app/routers/newsfeed.py` | Add post_count maintenance | ~15 |
| `app/models.py` | Add response models | ~60 |
| `frontend/src/pages/profile/PublicUserProfilePage.tsx` | Complete rewrite | ~250 |
| `frontend/src/pages/profile/ProfileHeader.tsx` | New file | ~170 |
| `frontend/src/pages/profile/PostGrid.tsx` | New file | ~100 |
| `frontend/src/pages/profile/ProfilePostCard.tsx` | New file | ~120 |
| `frontend/src/pages/profile/AboutTab.tsx` | New file | ~60 |
| `frontend/src/api/endpoints/profile.ts` | Add new endpoints + types | ~60 |
| `frontend/src/main.tsx` | Add HelmetProvider | ~5 |
| **Total** | | **~1010** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_public_profile.py`)

New file, ~500 lines.

**Test cases with full signatures and assertions**:

```python
# tests/test_public_profile.py

import pytest
from unittest.mock import patch, MagicMock
from decimal import Decimal
from moto import mock_dynamodb
from fastapi.testclient import TestClient


@pytest.fixture
def profile_tables(ddb_resource):
    """Create profiles and related tables for testing."""
    ddb_resource.create_table(
        TableName="profiles",
        KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    # app_single_table with GSI2 for POST_AUTHOR
    # Note: actual table uses lowercase pk/sk (not PK/SK)
    ddb_resource.create_table(
        TableName="app_single_table",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI2PK", "AttributeType": "S"},
            {"AttributeName": "GSI2SK", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "GSI2",
            "KeySchema": [
                {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )
    yield


def _seed_profile(user_sub, display_name="Test User", **kwargs):
    """Seed a profile record in the profiles table."""
    item = {
        "user_sub": user_sub,
        "display_name": display_name,
        "follower_count": Decimal("0"),
        "following_count": Decimal("0"),
        "post_count": Decimal("0"),
        **kwargs,
    }
    T.profile.put_item(Item=item)
    return item


def _seed_post(author_id, post_id, **kwargs):
    """Seed a post in app_single_table with GSI2 projection."""
    item = {
        "pk": f"POST#{post_id}",
        "sk": f"POST#{post_id}",
        "GSI2PK": f"POST_AUTHOR#{author_id}",
        "GSI2SK": f"POST#{post_id}",
        "post_id": post_id,
        "author_id": author_id,
        "visibility": "public",
        "body": "Test post body content",
        "created_at": "2026-05-26T12:00:00Z",
        "like_count": Decimal("0"),
        "comment_count": Decimal("0"),
        "tip_total_cents": Decimal("0"),
        **kwargs,
    }
    # app_single_table accessed via ddb.Table(APP_TABLE), not through T dataclass
    ddb.Table("app_single_table").put_item(Item=item)
    return item


class TestPublicProfileEndpoint:
    def test_returns_full_data(self, client, profile_tables):
        """Create user with profile, followers, posts -> all fields present."""
        _seed_profile("user_1", display_name="Alice", follower_count=Decimal("100"),
                       following_count=Decimal("50"), post_count=Decimal("10"),
                       description="I am Alice", location="NYC")
        resp = client.get("/ui/profile/public/user_1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["user_id"] == "user_1"
        assert data["display_name"] == "Alice"
        assert data["follower_count"] == 100
        assert data["following_count"] == 50
        assert data["post_count"] == 10
        assert data["description"] == "I am Alice"
        assert data["location"] == "NYC"
        assert data["is_following"] is False  # No viewer auth

    def test_not_found_returns_404(self, client, profile_tables):
        """Non-existent identifier -> 404."""
        resp = client.get("/ui/profile/public/nonexistent_user")
        assert resp.status_code == 404

    @patch("app.services.profile_discoverability.get_profile_discoverability_state")
    def test_hidden_profile_returns_404(self, mock_disc, client, profile_tables):
        """Discoverability=HIDDEN -> 404 for profile view."""
        from app.services.profile_discoverability import DiscoverabilityState
        _seed_profile("user_hidden")
        mock_disc.return_value = DiscoverabilityState.DEACTIVATED
        resp = client.get("/ui/profile/public/user_hidden")
        assert resp.status_code == 404

    def test_suppressed_profile_returns_404(self, client, profile_tables):
        """Moderation suppression -> 404."""
        # Similar to hidden but with DELETED state
        pass  # Implementation follows same pattern

    def test_follower_counts_from_profile(self, client, profile_tables):
        """Follow users -> counts in response."""
        _seed_profile("creator", follower_count=Decimal("250"), following_count=Decimal("42"))
        resp = client.get("/ui/profile/public/creator")
        assert resp.status_code == 200
        assert resp.json()["follower_count"] == 250
        assert resp.json()["following_count"] == 42

    def test_post_count_accuracy(self, client, profile_tables):
        """Create 5 posts -> post_count=5."""
        _seed_profile("author", post_count=Decimal("5"))
        resp = client.get("/ui/profile/public/author")
        assert resp.json()["post_count"] == 5

    def test_post_count_after_delete(self, client, profile_tables):
        """Delete 1 post -> post_count=4."""
        _seed_profile("author", post_count=Decimal("5"))
        # Simulate decrement
        T.profile.update_item(
            Key={"user_sub": "author"},
            UpdateExpression="ADD post_count :neg_one",
            ExpressionAttributeValues={":neg_one": Decimal("-1")},
        )
        resp = client.get("/ui/profile/public/author")
        assert resp.json()["post_count"] == 4

    def test_follow_status_when_authenticated(self, auth_client, profile_tables):
        """Viewer follows target -> is_following=true."""
        _seed_profile("target")
        # Mock follow status check
        with patch("app.services.social.get_follow_status") as mock_fs:
            mock_fs.return_value = {"is_following": True, "is_followed_by": False}
            resp = auth_client.get("/ui/profile/public/target")
            assert resp.json()["is_following"] is True
            assert resp.json()["is_mutual"] is False

    def test_follow_status_not_authenticated(self, client, profile_tables):
        """Unauthenticated -> follow fields default to false."""
        _seed_profile("target")
        resp = client.get("/ui/profile/public/target")
        assert resp.json()["is_following"] is False
        assert resp.json()["is_followed_by"] is False
        assert resp.json()["is_mutual"] is False

    def test_has_subscription_plans(self, client, profile_tables):
        """Creator with plans -> has_subscription_plans=true."""
        _seed_profile("creator")
        # Seed a subscription plan
        # Plans stored in T.subscriptions with pk=CREATOR#{id}, sk=PLAN#{plan_id}
        T.subscriptions.put_item(Item={
            "pk": "CREATOR#creator",
            "sk": "PLAN#plan_1",
            "creator_id": "creator",
            "plan_id": "plan_1",
            "price_cents": 999,
        })
        resp = client.get("/ui/profile/public/creator")
        assert resp.json()["has_subscription_plans"] is True

    def test_canonical_redirect_field(self, client, profile_tables):
        """Identifier != canonical -> canonical_identifier is set."""
        _seed_profile("user_abc", alias="alice")
        resp = client.get("/ui/profile/public/user_abc")
        data = resp.json()
        assert data["canonical_identifier"] == "alice"


class TestProfilePostsEndpoint:
    def test_public_posts_visible(self, client, profile_tables):
        """Public posts visible to all."""
        _seed_profile("author", post_count=Decimal("3"))
        for i in range(3):
            _seed_post("author", f"post_{i}", visibility="public")
        resp = client.get("/ui/profile/public/author/posts?limit=12")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 3

    def test_followers_only_hidden_from_non_followers(self, client, profile_tables):
        """Followers-only posts hidden from unauthenticated viewers."""
        _seed_profile("author")
        _seed_post("author", "public_1", visibility="public")
        _seed_post("author", "followers_1", visibility="followers")
        resp = client.get("/ui/profile/public/author/posts")
        data = resp.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["post_id"] == "public_1"

    def test_locked_post_metadata(self, client, profile_tables):
        """Locked posts show locked=true and price, but body_preview=null."""
        _seed_profile("author")
        _seed_post("author", "locked_1", locked=True, lock_price_cents=Decimal("500"),
                   body="Secret content")
        resp = client.get("/ui/profile/public/author/posts")
        data = resp.json()
        assert len(data["items"]) == 1
        item = data["items"][0]
        assert item["locked"] is True
        assert item["unlock_price_cents"] == 500
        assert item["body_preview"] is None

    def test_pagination(self, client, profile_tables):
        """Create 30 posts -> cursor pagination with limit=12."""
        _seed_profile("author", post_count=Decimal("30"))
        for i in range(30):
            _seed_post("author", f"post_{i:03d}")
        resp = client.get("/ui/profile/public/author/posts?limit=12")
        data = resp.json()
        assert len(data["items"]) == 12
        assert data["next_cursor"] is not None
        # Fetch next page
        resp2 = client.get(f"/ui/profile/public/author/posts?limit=12&cursor={data['next_cursor']}")
        data2 = resp2.json()
        assert len(data2["items"]) == 12

    def test_video_filter(self, client, profile_tables):
        """Filter 'video' returns only video posts."""
        _seed_profile("author")
        _seed_post("author", "text_1")
        _seed_post("author", "video_1", video_id="vid_123", has_video=True)
        resp = client.get("/ui/profile/public/author/posts?filter=video")
        data = resp.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["has_video"] is True

    def test_post_count_clamp_at_zero(self, client, profile_tables):
        """Delete more than created -> count stays at 0."""
        _seed_profile("author", post_count=Decimal("0"))
        # Attempt decrement — should be caught by ConditionExpression
        try:
            T.profile.update_item(
                Key={"user_sub": "author"},
                UpdateExpression="ADD post_count :neg_one",
                ExpressionAttributeValues={":neg_one": Decimal("-1")},
                ConditionExpression="post_count > :zero",
                ExpressionAttributeValues={":neg_one": Decimal("-1"), ":zero": Decimal("0")},
            )
        except Exception:
            pass
        resp = client.get("/ui/profile/public/author")
        assert resp.json()["post_count"] == 0


class TestMetaTagEndpoint:
    def test_returns_meta_fields(self, client, profile_tables):
        """Verify title, description, image fields."""
        _seed_profile("alice", display_name="Alice Creator",
                       description="Photographer", follower_count=Decimal("1234"),
                       profile_photo_url="https://example.com/alice.jpg")
        resp = client.get("/ui/profile/meta/alice")
        assert resp.status_code == 200
        data = resp.json()
        assert "Alice Creator" in data["title"]
        assert "1,234 followers" in data["description"]
        assert data["image"] == "https://example.com/alice.jpg"

    def test_nonexistent_returns_defaults(self, client, profile_tables):
        """Non-existent identifier -> default meta."""
        resp = client.get("/ui/profile/meta/nonexistent")
        data = resp.json()
        assert data["title"] == "Profile"
```

### 5.2 E2E Tests (`frontend/e2e/public-profile.spec.ts`)

New file, ~500 lines.

**Section 110: Public Profile API (7 tests)**:

1. `Get public profile by user_sub` — Create profile, fetch by user_sub, verify all fields.
2. `Get public profile by username` — Set username, fetch by username, verify resolved.
3. `Hidden profile returns 404` — Set discoverability hidden, verify 404.
4. `Profile includes follower counts` — Follow target, verify counts in response.
5. `Profile includes follow status for authenticated viewer` — Verify `is_following` field.
6. `Profile posts returns paginated list` — Create posts, verify pagination.
7. `Locked posts show metadata but not content` — Locked post has `locked=true`, `body_preview=null`.

**Section 111: Profile Posts API (5 tests)**:

1. `Posts sorted by reverse chronological` — Verify most recent first.
2. `Followers-only posts hidden from non-followers` — Non-follower viewer does not see followers-only posts.
3. `Followers-only posts visible to followers` — Follower viewer sees all posts.
4. `Video filter returns only video posts` — Verify filter parameter.
5. `Post count matches actual posts` — Verify `total_count` field accuracy.

**Section 112: Public Profile UI (8 tests)**:

1. `Profile page loads with header and stats` — Navigate to `/u/{identifier}`, verify display name, avatar area, follower count visible.
2. `Follow button works` — Click Follow, verify button changes to Following, count increments.
3. `Unfollow works` — Click Following/Unfollow, verify reverts.
4. `Message button opens DM` — Click Message, verify navigated to messages.
5. `Posts tab shows post grid` — Verify post cards rendered in grid.
6. `Video tab shows only video posts` — Switch to Videos tab, verify filter applied.
7. `About tab shows bio and location` — Switch to About tab, verify content.
8. `Post card click navigates to post detail` — Click a post card, verify navigated to `/feed/{post_id}`.

**Section 113: Profile SEO (3 tests)**:

1. `Page title includes display name` — Verify `document.title` contains the user's name.
2. `OG meta tags set correctly` — Check `meta[property="og:title"]`, `og:description`, `og:image`.
3. `Canonical URL uses preferred identifier` — Verify redirect to canonical when accessing via non-canonical identifier.

**Section 114: Subscribe CTA (4 tests)**:

1. `Subscribe button shown for creator with plans` — Verify button visible.
2. `Subscribe button hidden for user without plans` — Verify button absent.
3. `Subscribe button opens plan selection` — Click, verify dialog/page shows plans.
4. `Non-authenticated user sees subscribe prompt` — Not logged in, Subscribe button prompts login.

### 5.3 Edge Cases

1. **Profile with no posts** — PostGrid shows "No posts yet" placeholder.
2. **Profile with no avatar** — AvatarFallback shows first letter of display_name.
3. **Very long bio** — Truncated to 500 chars in the header, full text in About tab.
4. **Locked posts in grid** — Show a lock overlay on the thumbnail. Clicking reveals unlock price dialog.
5. **Private account (future)** — If the user has a "private" account setting, show only public posts and display "This account is private" for the posts tab. Follow button becomes "Request to Follow".
6. **Own profile view** — If the viewer navigates to their own profile URL, show "Edit Profile" button instead of Follow/Message buttons.
7. **Deleted account** — If the user account is deleted/deactivated, show "This profile is no longer available" instead of 404.
8. **Concurrent post count updates** — Two posts created simultaneously both increment `post_count`. DDB atomic `ADD` handles this correctly.
9. **Cover photo missing** — No cover photo: header has reduced height with a gradient background fallback.
10. **Mobile viewport** — Post grid collapses to single column. Cover photo takes full width. Action buttons stack vertically.

### 5.4 Performance Considerations

| Operation | DDB Reads | Expected Latency |
|-----------|-----------|-------------------|
| Public profile (cold) | 3 (profile + discoverability + plans check) + 2 (follow status) | ~30ms |
| Public profile (cached identifier) | Same | ~25ms (skip identifier resolution) |
| Profile posts (page) | 1 GSI2 query + N batch_get for full posts | ~40ms |
| Post count (from profile field) | 0 (included in profile read) | +0ms |
| Meta tags | 1 (profile read) | ~10ms |

### 5.5 Accessibility

- Avatar has `alt` text with display name.
- Follow button has `aria-pressed` reflecting state.
- Post grid uses `role="list"` with `role="listitem"` on each card.
- Tab navigation is keyboard-accessible (shadcn `Tabs` component handles this).
- Color contrast meets WCAG 2.1 AA for all text on profile header.

---

## 6. Security Considerations

### 6.1 Profile Data Exposure

The public profile endpoint returns a curated subset of profile fields. Sensitive fields are never exposed:

| Field | Exposed? | Notes |
|-------|----------|-------|
| `display_name` | Yes | Public |
| `title` | Yes | Public |
| `description` | Yes | Public |
| `location` | Yes | Public (user opt-in) |
| `profile_photo_url` | Yes | Public |
| `cover_photo_url` | Yes | Public |
| `email` | **No** | Never in public response |
| `phone` | **No** | Never in public response |
| `birthday` | **No** | Never in public response |
| `mfa_enabled` | **No** | Security-sensitive |
| `api_keys` | **No** | Security-sensitive |
| `address` | **No** | Privacy-sensitive |

The endpoint reads from `get_profile(user_sub)` which returns all fields, but only the whitelisted public fields are included in the response dict.

### 6.2 Rate Limiting

The existing `rate_limit_profile_lookup` function (imported in `app/routers/profile.py`) protects against scraping. The public profile endpoint should apply the same rate limit:

```python
@router.get("/profile/public/{identifier}")
async def get_public_profile(identifier: str, req: Request):
    ip = client_ip_from_request(req)
    if not rate_limit_profile_lookup(ip):
        raise HTTPException(status_code=429, detail="Too many requests")
    # ...
```

Rate limits:
- 60 profile lookups per minute per IP address.
- 10 profile lookups per minute per authenticated user (to prevent enumeration).

### 6.3 Identifier Enumeration Prevention

The `_resolve_profile_identifier_to_user_sub` function does a scan when resolving by email or alias. An attacker could enumerate usernames by checking which return 200 vs 404. Mitigations:

- Rate limiting (above).
- The negative cache (`_PROFILE_IDENTIFIER_NEGATIVE_CACHE_TTL_SECONDS = 5.0`) prevents repeated lookups for non-existent identifiers.
- Consider returning consistent response times (add artificial delay for 404 responses to match 200 timing).

### 6.4 Locked Post Content Protection

Locked posts must never leak their body text through the public profile posts endpoint:
- `body_preview` is set to `None` when `locked=True`.
- `image_urls` is set to empty list when `locked=True` (no thumbnail leak).
- `video_id` is set to `None` when `locked=True`.
- Only `unlock_price_cents` is exposed so the viewer knows the price.

### 6.5 CSRF and Auth

- `GET /ui/profile/public/{identifier}`: No auth required, no CSRF. Public endpoint.
- `GET /ui/profile/public/{identifier}/posts`: No auth required, no CSRF. Public endpoint.
- `GET /profile/meta/{identifier}`: No auth required. Crawler-accessible.
- The follow/unfollow actions use `POST /social/follow` and `POST /social/unfollow` which require `require_ui_session` + CSRF.

---

## 7. Migration & Rollback Plan

### 7.1 Forward Migration

**Phase 1: Backend (no frontend changes)**

1. Add `post_count` field support to profiles table. The field is auto-created on first `ADD` operation (DDB schemaless). No table migration needed.
2. Run `scripts/reconcile_post_counts.py` to backfill `post_count` for all existing authors.
3. Deploy `GET /ui/profile/public/{identifier}` endpoint. This is a new endpoint — no existing endpoint is modified.
4. Deploy `GET /ui/profile/public/{identifier}/posts` endpoint.
5. Deploy `GET /profile/meta/{identifier}` endpoint.
6. Hook `post_count` increment into `create_post` and decrement into delete handler.

**Phase 2: Frontend**

7. Install `react-helmet-async`, add `<HelmetProvider>` to `main.tsx`.
8. Deploy rewritten `PublicUserProfilePage.tsx` with new components.

### 7.2 Rollback

**If the new profile page causes issues**:
- Revert `PublicUserProfilePage.tsx` to the previous single-card version. The backend endpoints remain but are unused.
- The `post_count` field remains on profile records (harmless).

**If post_count drifts**:
- Re-run `scripts/reconcile_post_counts.py` to correct counts.
- Monitor for the condition where `post_count` goes negative (caught by `ConditionExpression`).

### 7.3 Data Migration Script

```python
# scripts/reconcile_post_counts.py
# (Full implementation shown in section 3.2 above)
# Run: python scripts/reconcile_post_counts.py
# Idempotent: can be run multiple times safely (SET overwrites previous value)
```

### 7.4 Feature Flag

```python
# .env.local
PUBLIC_PROFILE_ENHANCED=true
```

When `false`, the `GET /ui/profile/public/{identifier}` endpoint falls through to the existing `GET /ui/profiles/{identifier}` behavior, and the frontend renders the legacy card layout.

---

## 8. Operational Runbook

### 8.1 Monitoring

| Metric | Threshold | Action |
|--------|-----------|--------|
| `profile_public_endpoint_latency_p99` | > 500ms | Check DDB throttling; identifier cache hit rate |
| `profile_posts_endpoint_latency_p99` | > 300ms | Check GSI2 query cost; reduce over-fetch multiplier |
| `profile_identifier_cache_hit_rate` | < 80% | Increase cache TTL or max entries |
| `profile_404_rate` | > 30% of requests | Possible scraping; check rate limiter |
| `post_count_reconcile_drift` | > 5% of profiles | Run reconciliation script; investigate create/delete race |

### 8.2 Common Issues

**Issue: "Profile shows wrong follower count"**
1. The `follower_count` and `following_count` fields are maintained by SOC-001's atomic counters. If they drift, run the reconciliation script from SOC-001.
2. Check if the follow/unfollow handlers are correctly calling `_increment_counts` / `_decrement_counts`.

**Issue: "Posts not appearing on profile"**
1. Verify the post has `GSI2PK = POST_AUTHOR#{user_sub}` set. Check GSI2 projection.
2. Check `visibility` — `followers` visibility posts are hidden from unauthenticated viewers.
3. Verify `post_count` matches actual post count: `aws dynamodb query --table-name app_single_table --index-name GSI2 --key-condition-expression "GSI2PK = :pk" --expression-attribute-values '{":pk": {"S": "POST_AUTHOR#USER_SUB"}}' --select COUNT --endpoint-url http://localhost:8001`

**Issue: "Canonical redirect loop"**
1. If `alias` field has a value different from the URL identifier, the frontend redirects. If the alias itself doesn't resolve back to the same user, an infinite redirect occurs.
2. Check the `_profile_identifier_cache` for stale entries. Clear by restarting the backend.

### 8.3 Performance Tuning

For high-traffic profiles (popular creators):
- The `GET /profile/public/{identifier}` endpoint makes 3-6 DDB reads. For a creator with 1M followers, this is fine — the reads are point lookups, not scans.
- The `GET /profile/public/{identifier}/posts` endpoint queries GSI2 which returns posts in SK order. For a creator with 10K posts, the first page (12 items) is fast (~10ms).
- Enable DynamoDB DAX for read-heavy profile patterns if latency becomes an issue.

---

## 9. Performance & Capacity Planning

### 9.1 Page Load Budget

| Resource | Target | Notes |
|----------|--------|-------|
| Public profile API | < 100ms | 3-6 DDB reads |
| Profile posts API (first page) | < 80ms | 1 GSI2 query |
| Meta tags API | < 50ms | 1 DDB read |
| Total backend time | < 230ms | Parallel queries can reduce to ~120ms |
| Frontend render (LCP) | < 1.5s | Includes avatar + cover photo load |
| Total page load (TTI) | < 2.5s | Including JS bundle |

### 9.2 Image Loading Strategy

Profile pages are image-heavy (cover photo, avatar, post grid thumbnails). Strategy:
- **Cover photo**: Eager load (above fold). Max 1200px width.
- **Avatar**: Eager load (above fold). 80x80px served.
- **Post grid images**: `loading="lazy"` on all grid images. Only first 6 images load eagerly (2 rows on desktop).
- **Image format**: Prefer WebP with JPEG fallback.

### 9.3 Infinite Scroll Memory

Each post page loads 12 items. After 10 pages (120 items), React holds 120 post card components in memory. With image thumbnails, this could be 50-100MB of browser memory.

Mitigation: Consider virtualizing the post grid with `react-window` or `@tanstack/react-virtual` if profiles commonly have 100+ posts. Initially, cap at 5 pages (60 posts) and show a "View all posts" link.

### 9.4 CDN Caching for Public Profiles

Public profile data (for unauthenticated viewers) can be CDN-cached:
- `GET /profile/public/{identifier}`: Cache for 60 seconds (follower counts change slowly).
- `GET /profile/public/{identifier}/posts`: Cache for 120 seconds (post list changes rarely).
- `GET /profile/meta/{identifier}`: Cache for 300 seconds (meta tags change very rarely).

Add `Cache-Control` headers in the response:
```python
return JSONResponse(
    content=response_data,
    headers={"Cache-Control": "public, max-age=60, s-maxage=60"},
)
```

---

## 10. Dependency Analysis

### 10.1 Upstream Dependencies

| Dependency | Type | Impact if Unavailable |
|------------|------|----------------------|
| SOC-001 (Follow System) | Required for follow button + counts | Profile renders without follow button; counts show 0 |
| SOC-003 (User Search) | Optional | Discovery links to profile; profile works independently |
| `app/routers/profile.py` | Core | Extended with new endpoints |
| `app/services/profile.py` | Core | `get_profile()` provides all profile data |
| `app/services/profile_discoverability.py` | Required | Discoverability check gates profile visibility |
| `app/routers/subscription_server.py` | Optional | `has_subscription_plans` defaults to false if unavailable |
| `react-helmet-async` | Required (frontend) | SEO meta tags; page still works without it |
| DynamoDB `profiles` table | Data store | Profile reads fail without it |
| DynamoDB `app_single_table` (GSI2) | Data store | Post grid fails without it |

### 10.2 Downstream Dependents

| Dependent | How It Uses This Feature |
|-----------|------------------------|
| SOC-003 (User Search) | Search results link to `/u/{identifier}` profile pages |
| SOC-004 (Notifications) | Notification actor avatars link to profile pages |
| Feed/Newsfeed | Post author names link to profile pages |
| Messaging | User profile cards in conversation headers |
| Social sharing | Profile URL generates og:tags for link previews |

### 10.3 Cross-Ticket Integration Points

```
SOC-001 (Follow)  ──── provides ────> follower_count, following_count, is_following
                                       FollowButton component

SOC-002 (Fan-out) ──── provides ────> Post items that appear in the post grid

SOC-003 (Search)  ──── links to  ────> /u/{identifier} from search results

SOC-004 (Notif)   ──── links to  ────> /u/{actor_user_id} from notification actors

SOC-005 (Profile)  ──── consumes ────> All of the above
```

---

## 11. Acceptance Criteria

### 11.1 Must Have

- [ ] `GET /ui/profile/public/{identifier}` returns `PublicProfileResponse` with follower/following/post counts
- [ ] Discoverability check: DEACTIVATED/DELETED profiles return 404
- [ ] Follow status included when viewer is authenticated
- [ ] `has_subscription_plans` flag correctly detects creator plans
- [ ] `GET /ui/profile/public/{identifier}/posts` returns paginated post list
- [ ] Locked posts show `locked=true` and `unlock_price_cents` but no body/images
- [ ] Followers-only posts hidden from non-followers
- [ ] `post_count` maintained atomically on create/delete
- [ ] ProfileHeader shows avatar, name, bio, location, stats, action buttons
- [ ] PostGrid shows 3-column responsive grid with lazy-loading images
- [ ] Follow button works with optimistic update
- [ ] Profile tabs: Posts, Videos, About
- [ ] SEO meta tags set via react-helmet-async

### 11.2 Should Have

- [ ] Canonical identifier redirect
- [ ] Subscribe button for creators with plans
- [ ] Message button opens DM
- [ ] Mutual badge when both users follow each other
- [ ] Cover photo with gradient fallback
- [ ] "Member since" date display
- [ ] Hover overlay on post cards showing like/comment counts

### 11.3 Nice to Have

- [ ] Pin posts to top of grid
- [ ] Verification badge
- [ ] Social links section in About tab
- [ ] Highlight/story strip at top of profile
- [ ] Profile customization (banner color, layout preference)

---

## 12. Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery |
|---|---|---|---|---|
| Identifier not found | 404 | `NOT_FOUND` | "Profile not found" | Show 404 page with search link |
| Profile deactivated | 404 | `NOT_FOUND` | "Profile not found" | Same as above |
| Rate limited | 429 | `RATE_LIMITED` | "Too many requests. Please try again." | Auto-retry after delay |
| DDB read fails | 500 | `INTERNAL_ERROR` | "Unable to load profile" | Show error boundary with retry |
| Identifier too long | 404 | `NOT_FOUND` | "Profile not found" | Input validation |
| Follow API fails | 500 | `INTERNAL_ERROR` | "Failed to follow" | Revert optimistic update |
| Posts query fails | 500 | `INTERNAL_ERROR` | "Unable to load posts" | Show error state in PostGrid |
| Subscription plans check fails | — | — | `has_subscription_plans=false` | Silent fallback; Subscribe button hidden |
| Post count decrement below 0 | — | — | None (caught by condition) | Count stays at 0 |
| Image load fails | — | — | Placeholder shown | `AvatarFallback` / broken image fallback |
| Meta tag endpoint fails | — | — | Default generic meta tags | Page still renders |

---

## 13. Frontend Component Specifications

### 13.1 Component Tree

```
PublicUserProfilePage
  ├── Helmet (SEO meta tags)
  ├── ProfileHeader
  │     ├── Cover photo (or gradient fallback)
  │     ├── Avatar + AvatarFallback
  │     ├── Display name (h1)
  │     ├── Title (subtitle)
  │     ├── Location (MapPin icon)
  │     ├── Member since (Calendar icon)
  │     ├── Bio/description
  │     ├── Stats bar (followers / following / posts)
  │     ├── Mutual badge (conditional)
  │     ├── FollowButton (or "Edit Profile" for own profile)
  │     ├── Subscribe button (conditional)
  │     └── Message button
  ├── Tabs (shadcn)
  │     ├── TabsTrigger "Posts"
  │     ├── TabsTrigger "Videos"
  │     └── TabsTrigger "About"
  ├── TabsContent "posts"
  │     └── PostGrid
  │           ├── ProfilePostCard (repeating)
  │           │     ├── Image/Video thumbnail (aspect-square)
  │           │     ├── Hover overlay (likes + comments)
  │           │     ├── Lock badge (conditional)
  │           │     ├── Body preview (text-only posts)
  │           │     └── Stats row (text-only posts)
  │           └── "Load more" button
  ├── TabsContent "videos"
  │     └── PostGrid (filter="video")
  ├── TabsContent "about"
  │     └── AboutTab
  │           ├── Bio section
  │           ├── Title section
  │           ├── Location
  │           └── Member since
  └── SubscriptionDialog (conditional)
        ├── Plan cards
        │     ├── Plan name
        │     ├── Price / interval
        │     └── Subscribe button
        └── Close button
```

### 13.2 State Management

```typescript
// PublicUserProfilePage state and queries

const { identifier } = useParams<{ identifier: string }>();
const { user_sub: viewerSub } = useAuthStore();
const navigate = useNavigate();

// Profile data
const profileQuery = useQuery({
  queryKey: ["public-profile", identifier],
  queryFn: () => getPublicProfile(identifier!).then(r => r.data),
  enabled: !!identifier,
});

// Subscription plans (lazy, only if has_subscription_plans)
const plansQuery = useQuery({
  queryKey: ["creator-plans", profileQuery.data?.user_id],
  queryFn: () => api.get(`/api/creators/${profileQuery.data!.user_id}/plans`).then(r => r.data),
  enabled: !!profileQuery.data?.has_subscription_plans,
});

// Derived state
const isOwnProfile = viewerSub === profileQuery.data?.user_id;
const [showSubscribeDialog, setShowSubscribeDialog] = useState(false);

// Canonical redirect
useEffect(() => {
  if (profileQuery.data?.canonical_identifier && profileQuery.data.canonical_identifier !== identifier) {
    navigate(`/u/${profileQuery.data.canonical_identifier}`, { replace: true });
  }
}, [profileQuery.data?.canonical_identifier, identifier, navigate]);
```

### 13.3 Error Boundary

```typescript
// Error states
if (profileQuery.isError) {
  const status = (profileQuery.error as any)?.response?.status;
  if (status === 404) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-4">
        <h1 className="text-2xl font-bold">Profile not found</h1>
        <p className="text-muted-foreground">This profile doesn't exist or has been removed.</p>
        <Button onClick={() => navigate("/discover")}>Discover creators</Button>
      </div>
    );
  }
  if (status === 429) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-4">
        <h1 className="text-2xl font-bold">Slow down</h1>
        <p className="text-muted-foreground">Too many requests. Please try again in a moment.</p>
      </div>
    );
  }
  return <div>Something went wrong. Please try again.</div>;
}
```

---

## 14. Internationalization Considerations

### 14.1 Translatable Strings

All user-facing text on the profile page must support translation:

```json
{
  "profile.followers": "Followers",
  "profile.following": "Following",
  "profile.posts": "Posts",
  "profile.follow": "Follow",
  "profile.following_button": "Following",
  "profile.unfollow": "Unfollow",
  "profile.subscribe": "Subscribe",
  "profile.message": "Message",
  "profile.edit_profile": "Edit Profile",
  "profile.member_since": "Member since {{date}}",
  "profile.mutual_badge": "Mutual — follows you back",
  "profile.no_posts": "No posts yet.",
  "profile.load_more": "Load more",
  "profile.tab.posts": "Posts",
  "profile.tab.videos": "Videos",
  "profile.tab.about": "About",
  "profile.about.bio": "Bio",
  "profile.about.title": "Title",
  "profile.about.location": "Location",
  "profile.not_found.title": "Profile not found",
  "profile.not_found.body": "This profile doesn't exist or has been removed.",
  "profile.not_found.cta": "Discover creators",
  "profile.locked.price": "${{price}} to unlock",
  "profile.seo.title": "{{name}} - Profile",
  "profile.seo.description": "{{description}} | {{count}} followers"
}
```

### 14.2 Number Formatting

Follower/following/post counts should use locale-aware formatting:

```typescript
// Use Intl.NumberFormat for locale-aware formatting
const formatCount = (count: number): string => {
  if (count >= 1_000_000) {
    return `${(count / 1_000_000).toFixed(1)}M`;
  }
  if (count >= 10_000) {
    return `${(count / 1_000).toFixed(1)}K`;
  }
  return count.toLocaleString();
};
```

### 14.3 Date Formatting

"Member since" uses locale-aware date formatting:

```typescript
const memberSince = profile.created_at
  ? new Intl.DateTimeFormat(locale, { month: "long", year: "numeric" }).format(new Date(profile.created_at))
  : null;
```

### 14.4 RTL Layout Support

For RTL languages:
- Profile header: avatar moves to the right, text aligns right.
- Post grid: remains LTR (grid layout is direction-agnostic).
- Stats bar: numbers maintain LTR rendering (standard for Arabic/Hebrew numeric display).
- Action buttons: order reverses (Follow on the right in RTL).

Tailwind `rtl:` variant handles most cases automatically when `dir="rtl"` is set on the root element.

---

## Appendix A: URL Sharing Preview

When a profile URL (`/u/alice_creator`) is shared on social media, the link preview should show:

```
┌─────────────────────────────────────┐
│  [Avatar Image]                      │
│                                      │
│  Alice Creator - Profile             │
│  Content creator & photographer.     │
│  12,345 followers                    │
│                                      │
│  platformname.com                    │
└─────────────────────────────────────┘
```

This requires the `og:title`, `og:description`, and `og:image` meta tags to be set correctly. Client-side Helmet provides this for modern crawlers.

## Appendix B: Future Enhancements

- **Server-side rendering**: For full SEO crawler support, implement SSR for the `/u/:identifier` route using a prerender service (e.g., Puppeteer-based or a dedicated SSR framework).
- **Profile customization**: Allow creators to choose a banner color, pin posts, and add social links.
- **Media tab**: Separate tab for all images and videos (not just video posts).
- **Highlights/Stories**: Ephemeral content displayed at the top of the profile.
- **Verification badge**: Display a verification checkmark for verified creators.

## Appendix C: Component Wireframe — Mobile View

```
┌────────────────────────┐
│ ████████████████████████│ <- Cover (full width)
│                         │
│   ┌──────┐              │
│   │Avatar│  Display Name│
│   │ 60px │  @username   │
│   └──────┘  Location    │
│                         │
│   Bio text wraps to     │
│   full width on mobile  │
│                         │
│   234     56      12    │
│   Follow  Follow  Posts │
│   ers     ing           │
│                         │
│ [  Follow  ] [Subscribe]│
│ [       Message        ]│
│                         │
├─────────────────────────┤
│[Posts] [Videos] [About] │
├─────────────────────────┤
│ ┌─────────────────────┐ │
│ │     Post Card 1     │ │
│ │   (full width)      │ │
│ └─────────────────────┘ │
│ ┌─────────────────────┐ │
│ │     Post Card 2     │ │
│ │   (full width)      │ │
│ └─────────────────────┘ │
│                         │
│    [  Load more  ]      │
└─────────────────────────┘
```

## Appendix D: Related Tickets

- **SOC-001**: Follow system (provides follow button, counts, and status)
- **SOC-002**: Feed fan-out (post grid shows same content that fans out to followers)
- **SOC-003**: User search/discovery (discovery links to profile pages)
- **SOC-004**: Notification expansion (profile interactions generate notifications)

---

## Codebase References

### Backend — Routers

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `GET /profiles/{identifier}` | `app/routers/profile.py` | 58 | **Verified** — authenticated profile lookup |
| `_resolve_profile_identifier_to_user_sub()` | `app/routers/profile.py` | 185 | **Verified** |
| `GET /profile/public/{identifier}` | `app/routers/profile.py` | 295 | **Verified** — public profile endpoint (no auth required) |
| `GET /profile/public/{identifier}/posts` | `app/routers/profile.py` | 388 | **Verified** — paginated public posts for profile |
| `profile.py` total | `app/routers/profile.py` | 691 lines | **Verified** |
| `GET /api/creators/{creator_id}/plans` | `app/routers/subscription_server.py` | 746 | **Verified** — public endpoint, no auth |
| `POST_AUTHOR#{user_id}` (GSI2) | `app/routers/newsfeed.py` | 3248 | **Verified** — author post index |
| GSI2 query for author filter | `app/routers/newsfeed.py` | 4254 | **Verified** |
| `social_router` (`/ui/social/*`) | `app/routers/social.py` | 292 lines | **Exists** — follow/unfollow/counts/status endpoints |
| `social_router` registration | `app/main.py` | 71, 393 | **Verified** |

### Backend — Services

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `PROFILE_FIELDS` tuple | `app/services/profile.py` | 16 | **Verified** |
| `PROFILE_FIELD_VISIBILITY` | `app/services/profile.py` | 39+ | **Verified** — classifies fields as public/member/private |
| `DiscoverabilityState` enum | `app/services/profile_discoverability.py` | 10 | **Verified** |
| `social.py` (follow service) | `app/services/social.py` | 399 lines | **Exists** — `get_follow_counts()` at line 189, `get_follow_status()` at line 206 |

### DynamoDB (`scripts/local-ddb-init.py`)

| Reference | Line | Status |
|-----------|------|--------|
| `profiles` table | 61 | **Verified** — PK = `user_sub` |
| `app_single_table` (follow data, posts) | 222 | **Verified** |
| GSI2 (post author index) | 228 | **Verified** |
| GSI5 (followers reverse index) | 231 | **Verified** |

### Frontend

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `PublicUserProfilePage.tsx` | `frontend/src/pages/profile/PublicUserProfilePage.tsx` | **340 lines** | **Exists** (ticket says ~224 lines — **INCORRECT**, actual is 340) |
| Route `/u/:identifier` | `frontend/src/App.tsx` | 50, 124 | **Verified** — lazy import at line 50, route at line 124 (behind `showCanonicalProfileRoute` flag) |

### Corrections

1. **`PublicUserProfilePage.tsx` line count**: Ticket says ~224 lines, actual is 340 lines.
2. **Profile endpoint line numbers**: Need to verify against ticket's specific claims. `GET /ui/profiles/{identifier}` is at line 58 (not 50-51 as ticket may claim). `_resolve_profile_identifier_to_user_sub` is at line 185 (not 177).
3. **Public profile already partially exists**: `PublicUserProfilePage.tsx` (340 lines) is already implemented with profile display. The ticket's scope may overlap with existing functionality. The remaining work is likely: adding follow button, follower/following counts, follower list tabs, post grid/video tabs, subscription integration, and SEO meta tags.

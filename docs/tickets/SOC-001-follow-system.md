# SOC-001: Complete Follow/Unfollow System with Follower Lists, Counts, and Mutual Detection

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-26  
**Priority**: High  
**Estimated effort**: 5-7 days

---

## 1. Overview & Motivation

### The Gap

The platform has a rudimentary follow/unfollow mechanism embedded directly in the newsfeed router (`app/routers/newsfeed.py`, lines 2657-2688). Two endpoints exist:

- `POST /social/unfollow` — writes a `FOLLOWING#{target_id}` record with `state: "unfollowed"`
- `POST /social/refollow` — writes a `FOLLOWING#{target_id}` record with `state: "following"`

These endpoints store follow relationships in the `app_single_table` DynamoDB table using `PK=USER#{user_id}`, `SK=FOLLOWING#{target_id}`. However, the system is missing critical social graph functionality:

1. **No follower list endpoint** — A user cannot see who follows them. Only the forward relationship (`USER#{follower} -> FOLLOWING#{followed}`) is stored; there is no reverse index.
2. **No following list endpoint** — While the data exists under `USER#{user_id}` with SK prefix `FOLLOWING#`, there is no paginated API to list all users a person follows.
3. **No follower/following counts** — The profile (`app/services/profile.py`) has no `follower_count` or `following_count` fields. Counts would require a full table scan of follow records.
4. **No mutual follower detection** — No API to determine if two users follow each other, or to list mutual followers between the current user and a target.
5. **No block-prevents-follow enforcement** — Blocked users can still follow each other (no integration with any block system).
6. **No follow-back / follow-request infrastructure** — For future private accounts, there is no `pending` state in the follow workflow.

### Why This Is Needed

Social features (feed fan-out in SOC-002, discovery in SOC-003, notifications in SOC-004, and public profiles in SOC-005) all depend on a robust follow system. Without follower lists, there is no way to fan out posts. Without counts, profiles lack key social proof metrics. Without mutual detection, suggested-users algorithms cannot prioritize mutual connections.

### Architecture After This Change

```
                          app_single_table
                          +----------------------------------------------+
  Forward Follow Index    | PK=USER#{follower}  SK=FOLLOWING#{followed}  |
  (who am I following?)   |   state, created_at, Entity=Following       |
                          |   GSI5PK=FOLLOWERS#{followed}               |
  Reverse Follower Index  |   GSI5SK={created_at}#{follower}            |
  (who follows me?)       +----------------------------------------------+

  Atomic Counters         +----------------------------------------------+
  (profiles table)        | PK=user_sub                                  |
                          |   follower_count: N  (atomic increment)     |
                          |   following_count: N  (atomic increment)    |
                          +----------------------------------------------+

  API Endpoints:
  +----------------------------------+
  | POST   /social/follow            |  Follow a user
  | POST   /social/unfollow          |  Unfollow a user
  | GET    /social/{user_id}/followers|  Paginated follower list
  | GET    /social/{user_id}/following|  Paginated following list
  | GET    /social/{user_id}/counts  |  Follower + following counts
  | GET    /social/mutual/{user_id}  |  Mutual followers with target
  | GET    /social/status/{user_id}  |  Am I following this user? Are they following me?
  +----------------------------------+

  Frontend:
  +----------------------------------+
  | FollowButton component           |  Toggle follow/unfollow
  | FollowersList page tab           |  Paginated follower grid
  | FollowingList page tab           |  Paginated following grid
  | Profile follower/following counts|  Displayed on profile cards
  +----------------------------------+
```

---

## 2. Current State Analysis

### 2.1 Existing Follow Endpoints (`app/routers/newsfeed.py`, lines 2657-2688)

The current implementation is minimal:

```python
# Line 2659-2672
@router.post("/social/unfollow")
def unfollow(req: UnfollowRequest, user_id: UserIdDep):
    target = req.target_user_id
    item = {
        "pk": pk_user(user_id),           # USER#{user_id}
        "sk": f"FOLLOWING#{target}",
        "Entity": "Following",
        "user_id": user_id,
        "target_user_id": target,
        "state": "unfollowed",
        "updated_at": now_iso(),
    }
    ddb_put_item(item)
    return {"ok": True}

# Line 2675-2688
@router.post("/social/refollow")
def refollow(req: UnfollowRequest, user_id: UserIdDep):
    # ... identical structure, state="following"
```

**Problems**:
- Uses `ddb_put_item` (unconditional overwrite) — no idempotency tracking or count adjustment.
- No reverse index (GSI) for querying "who follows user X".
- No follower/following count maintained anywhere.
- `UnfollowRequest` model (line 1395) has only `target_user_id: str`.
- The `is_following()` helper (line 2131) does a point read: `ddb_get_item({"pk": pk_user(viewer_id), "sk": f"FOLLOWING#{target_id}"})` — this is used by `can_view_post()` (line 2146) for visibility gating.

### 2.2 DynamoDB Key Structure (`app_single_table`)

The `app_single_table` (line 217 of `scripts/local-ddb-init.py`) uses `pk`/`sk` as its primary key with five GSIs:

| Index | Partition Key | Sort Key | Current Usage |
|-------|--------------|----------|---------------|
| GSI1 | GSI1PK | GSI1SK | Feed refs (`FEED#{user_id}`) |
| GSI2 | GSI2PK | GSI2SK | Post author index (`POST_AUTHOR#{user_id}`) |
| GSI3 | GSI3PK | GSI3SK | Notifications (`NOTIF#{user_id}`) |
| GSI4 | GSI4PK | GSI4SK | Drafts index |
| GSI_SCHEDULE_DUE | GSI_SCHEDULE_PK | GSI_SCHEDULE_SK | Scheduled posts |

**Available slot**: GSI5 is not yet used. We will use it for the reverse follower index.

### 2.3 Profile Service (`app/services/profile.py`)

The `PROFILE_FIELDS` tuple (line 16) contains display fields like `display_name`, `profile_photo_url`, etc. There are no `follower_count` or `following_count` fields. The profile is stored in the `profiles` table (line 61 of `local-ddb-init.py`) with `user_sub` as the primary key.

The `PROFILE_FIELD_VISIBILITY` dictionary (line 39) classifies each field as `public`, `member`, or `private`. The `filter_profile_by_audience()` function filters which fields are returned based on the requester's relationship to the profile owner. The new count fields (`follower_count`, `following_count`) should be classified as `public` visibility since they are social proof metrics visible to everyone.

### 2.4 Frontend Follow/Unfollow (`frontend/src/api/endpoints/newsfeed.ts`, lines 66-70)

```typescript
export const follow = (userId: string) =>
  api.post<{ ok: boolean }>("/social/refollow", { target_user_id: userId });

export const unfollow = (userId: string) =>
  api.post<{ ok: boolean }>("/social/unfollow", { target_user_id: userId });
```

These are called from feed components but there is no dedicated FollowButton component, no follower list UI, and no counts displayed on profiles.

### 2.5 Public User Profile Page (`frontend/src/pages/profile/PublicUserProfilePage.tsx`)

The existing `PublicUserProfilePage` (route `/u/:identifier`) displays profile data but has no follow button, no follower/following counts, and no follower/following list tabs. It currently shows "Add to Contacts", "Message", and "View Profile" actions.

### 2.6 Tables Infrastructure (`app/core/tables.py`)

The `Tables` dataclass (line 9) holds typed references to all DDB table resources. Currently includes `profile`, `account_state`, `alerts`, `alert_prefs`, and ~60 other tables. The `app_single_table` is accessed via the raw `ddb.Table(APP_TABLE)` pattern in the newsfeed router rather than through this centralized dataclass. The follow system will continue to use the raw table reference pattern for consistency with existing newsfeed code.

---

## 3. Technical Design

### 3.1 DynamoDB Schema Changes

#### 3.1.1 Follow Record (Enhanced)

**Table**: `app_single_table`

| Attribute | Type | Value |
|-----------|------|-------|
| pk | S | `USER#{follower_user_id}` |
| sk | S | `FOLLOWING#{followed_user_id}` |
| Entity | S | `Following` |
| user_id | S | follower's user_sub |
| target_user_id | S | followed user's user_sub |
| state | S | `following` or `unfollowed` |
| created_at | S | ISO 8601 timestamp (when first followed) |
| updated_at | S | ISO 8601 timestamp (last state change) |
| GSI5PK | S | `FOLLOWERS#{followed_user_id}` |
| GSI5SK | S | `{created_at}#{follower_user_id}` |

The GSI5 reverse index enables querying "all followers of user X" sorted by follow date.

**GSI5 projection**: `KEYS_ONLY` plus `user_id`, `target_user_id`, `state` (projected attributes). Items with `state=unfollowed` are excluded from GSI5 by removing the GSI5PK/GSI5SK attributes on unfollow.

#### 3.1.2 Follower/Following Counts

**Table**: `profiles`

Add two numeric attributes to the profile record:

| Attribute | Type | Description |
|-----------|------|-------------|
| follower_count | N | Number of users following this user |
| following_count | N | Number of users this user follows |

Counts are maintained via atomic `ADD` operations on follow/unfollow, providing eventual consistency without requiring scans.

#### 3.1.3 GSI5 Definition

Add to `scripts/local-ddb-init.py` in the `app_single_table` GSI list:

```python
{"index_name": "GSI5", "partition_key": "GSI5PK", "sort_key": "GSI5SK"},
```

#### 3.1.4 DynamoDB Access Pattern Summary

```
+------------------------------------------------------------------+
| Access Pattern               | Table/Index | Key Condition        |
+------------------------------------------------------------------+
| Am I following user X?       | Main table  | PK=USER#{me}         |
|                              |             | SK=FOLLOWING#{X}     |
+------------------------------------------------------------------+
| Who follows user X?          | GSI5        | GSI5PK=FOLLOWERS#{X} |
|   (paginated, newest first)  |             | ScanIndexForward=F   |
+------------------------------------------------------------------+
| Who am I following?          | Main table  | PK=USER#{me}         |
|   (paginated)                |             | SK begins_with       |
|                              |             |   FOLLOWING#         |
+------------------------------------------------------------------+
| Follower count for user X    | profiles    | PK=user_sub          |
|   (O(1) read)               |             | follower_count attr  |
+------------------------------------------------------------------+
| Following count for user X   | profiles    | PK=user_sub          |
|   (O(1) read)               |             | following_count attr |
+------------------------------------------------------------------+
| Mutual followers of me & X   | GSI5 x2    | Intersection of      |
|   (computed in memory)       |             | FOLLOWERS#{X} and    |
|                              |             | my following list    |
+------------------------------------------------------------------+
```

### 3.2 API Endpoints

#### 3.2.1 `POST /ui/social/follow`

**Auth**: `Depends(require_ui_session)`

**Request**:
```python
class FollowRequest(BaseModel):
    target_user_id: str = Field(..., min_length=1, max_length=128)
```

**Response**:
```python
class FollowResponse(BaseModel):
    ok: bool
    status: Literal["followed", "already_following"]
    follower_count: int
    following_count: int
```

**Logic**:
1. Validate `target_user_id` is not the same as the authenticated user (self-follow prevention).
2. Check for block relationship — if the target has blocked the requester, return 403 `blocked`.
3. Read existing follow record at `PK=USER#{user_id}, SK=FOLLOWING#{target}`.
4. If `state == "following"` already, return `already_following` with current counts.
5. Write follow record with `state="following"`, setting GSI5PK/GSI5SK attributes.
6. Atomic increment: `profiles.update_item(Key=target, ADD follower_count 1)` and `profiles.update_item(Key=user, ADD following_count 1)`.
7. Emit `new_follower` alert to the target user (SOC-004 integration point).
8. Return updated counts.

**Error responses**:
- 400: Self-follow attempt
- 403: Target has blocked requester
- 404: Target user not found

**Data flow diagram**:
```
Client                       Backend                           DynamoDB
  |                            |                                  |
  |  POST /social/follow       |                                  |
  |  {target_user_id: "bob"}   |                                  |
  |--------------------------->|                                  |
  |                            |  1. Validate self-follow         |
  |                            |  2. Check block record           |
  |                            |  get_item(USER#{bob},            |
  |                            |     BLOCKED#{alice})             |
  |                            |--------------------------------->|
  |                            |  <-- null (not blocked)          |
  |                            |<---------------------------------|
  |                            |  3. Read existing follow         |
  |                            |  get_item(USER#{alice},          |
  |                            |     FOLLOWING#{bob})             |
  |                            |--------------------------------->|
  |                            |  <-- {state: "unfollowed"}       |
  |                            |<---------------------------------|
  |                            |  4. Write follow record          |
  |                            |  put_item(USER#{alice},          |
  |                            |     FOLLOWING#{bob},             |
  |                            |     state="following",           |
  |                            |     GSI5PK=FOLLOWERS#{bob},      |
  |                            |     GSI5SK=2026-05-26T...#alice) |
  |                            |--------------------------------->|
  |                            |  5. Increment counters           |
  |                            |  update_item(bob, ADD            |
  |                            |     follower_count 1)            |
  |                            |  update_item(alice, ADD          |
  |                            |     following_count 1)           |
  |                            |--------------------------------->|
  |                            |  6. Emit new_follower alert      |
  |  <-- 200 {ok, "followed",  |                                  |
  |       follower_count: 42,   |                                  |
  |       following_count: 17}  |                                  |
  |<---------------------------|                                  |
```

#### 3.2.2 `POST /ui/social/unfollow`

**Auth**: `Depends(require_ui_session)`

**Request**: Same `FollowRequest` model.

**Response**:
```python
class UnfollowResponse(BaseModel):
    ok: bool
    status: Literal["unfollowed", "not_following"]
```

**Logic**:
1. Read existing follow record.
2. If `state != "following"`, return `not_following`.
3. Update record: set `state="unfollowed"`, remove GSI5PK/GSI5SK attributes (removes from reverse index).
4. Atomic decrement: `ADD follower_count -1` on target, `ADD following_count -1` on user.
5. Guard against negative counts: use `ConditionExpression` to ensure count >= 0, or clamp at 0.

#### 3.2.3 `GET /ui/social/{user_id}/followers`

**Auth**: `Depends(require_ui_session)`

**Query parameters**:
```python
cursor: Optional[str] = Query(default=None)
limit: int = Query(default=20, ge=1, le=100)
```

**Response**:
```python
class FollowUser(BaseModel):
    user_id: str
    display_name: Optional[str] = None
    profile_photo_url: Optional[str] = None
    is_following: bool  # Does the viewer follow this person?
    is_mutual: bool     # Does this person also follow the viewer?

class FollowListResponse(BaseModel):
    items: List[FollowUser]
    next_cursor: Optional[str] = None
    total_count: int
```

**Logic**:
1. Query GSI5 with `GSI5PK = FOLLOWERS#{user_id}`, `ScanIndexForward=False` (newest first), `Limit=limit`.
2. For each follower, batch-fetch profile data (display_name, profile_photo_url).
3. For each follower, check if the viewer follows them (`is_following`) and if they follow the viewer (`is_mutual`). Batch these checks using `batch_get_item` on the follow records.
4. Encode `LastEvaluatedKey` as cursor for pagination.
5. Return `total_count` from the profile's `follower_count` field (O(1) read).

#### 3.2.4 `GET /ui/social/{user_id}/following`

Same structure as followers, but queries the primary table directly:
- `PK = USER#{user_id}`, `SK begins_with FOLLOWING#`, filter `state = "following"`.
- Returns `total_count` from `following_count` on the user's profile.

#### 3.2.5 `GET /ui/social/{user_id}/counts`

**Auth**: Optional (public endpoint for profile display).

**Response**:
```python
class FollowCountsResponse(BaseModel):
    follower_count: int
    following_count: int
```

**Logic**: Single `get_item` on profiles table, return the two count fields.

#### 3.2.6 `GET /ui/social/status/{target_user_id}`

**Auth**: `Depends(require_ui_session)`

**Response**:
```python
class FollowStatusResponse(BaseModel):
    is_following: bool      # Am I following target?
    is_followed_by: bool    # Does target follow me?
    is_mutual: bool         # Both directions?
```

**Logic**: Two `get_item` calls in parallel:
1. `PK=USER#{viewer}, SK=FOLLOWING#{target}` — check `state=="following"`.
2. `PK=USER#{target}, SK=FOLLOWING#{viewer}` — check `state=="following"`.

#### 3.2.7 `GET /ui/social/mutual/{target_user_id}`

**Auth**: `Depends(require_ui_session)`

**Query parameters**: `cursor`, `limit` (same as followers).

**Response**: Same `FollowListResponse`.

**Logic**:
1. Get viewer's following list (all `FOLLOWING#*` items where `state=following`).
2. For each, check if they also follow the target (via GSI5 query on `FOLLOWERS#{target}`).
3. This is expensive for large following lists. Optimization: query both GSI5 for `FOLLOWERS#{target}` and `FOLLOWING#*` for viewer, then intersect in memory.
4. Paginate the intersection result using a client-side cursor (offset-based since the intersection is computed in memory).
5. For large sets (>1000), return a capped result with `has_more=true`.

### 3.3 Service Layer (`app/services/social.py`)

New file with full implementations:

```python
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
tbl = ddb.Table(APP_TABLE)

FOLLOW_RATE_LIMIT_PER_MINUTE = 30
UNFOLLOW_RATE_LIMIT_PER_MINUTE = 60


def pk_user(user_id: str) -> str:
    return f"USER#{user_id}"


def follow_user(follower_id: str, followed_id: str) -> Dict[str, Any]:
    """Create or reactivate a follow relationship.

    Returns:
        {"ok": True, "status": "followed"|"already_following",
         "follower_count": int, "following_count": int}
    Raises:
        ValueError: self-follow, blocked, or user not found
    """
    if follower_id == followed_id:
        raise ValueError("self_follow")

    # Check block relationship
    if _is_blocked(followed_id, follower_id):
        raise ValueError("blocked")

    # Check target user exists
    target_profile = T.profile.get_item(Key={"user_sub": followed_id}).get("Item")
    if not target_profile:
        raise ValueError("user_not_found")

    # Read existing follow record
    existing = tbl.get_item(
        Key={"pk": pk_user(follower_id), "sk": f"FOLLOWING#{followed_id}"}
    ).get("Item")

    if existing and existing.get("state") == "following":
        # Already following — return counts without modification
        counts = get_follow_counts(followed_id)
        return {
            "ok": True,
            "status": "already_following",
            "follower_count": counts["follower_count"],
            "following_count": counts["following_count"],
        }

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    created_at = existing.get("created_at", now) if existing else now

    item = {
        "pk": pk_user(follower_id),
        "sk": f"FOLLOWING#{followed_id}",
        "Entity": "Following",
        "user_id": follower_id,
        "target_user_id": followed_id,
        "state": "following",
        "created_at": created_at,
        "updated_at": now,
        "GSI5PK": f"FOLLOWERS#{followed_id}",
        "GSI5SK": f"{created_at}#{follower_id}",
    }
    tbl.put_item(Item=item)

    # Increment counts atomically
    _increment_counts(follower_id, followed_id)

    counts = get_follow_counts(followed_id)
    return {
        "ok": True,
        "status": "followed",
        "follower_count": counts["follower_count"],
        "following_count": counts["following_count"],
    }


def unfollow_user(follower_id: str, followed_id: str) -> Dict[str, Any]:
    """Deactivate a follow relationship.

    Returns:
        {"ok": True, "status": "unfollowed"|"not_following"}
    """
    existing = tbl.get_item(
        Key={"pk": pk_user(follower_id), "sk": f"FOLLOWING#{followed_id}"}
    ).get("Item")

    if not existing or existing.get("state") != "following":
        return {"ok": True, "status": "not_following"}

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Update: set state to unfollowed, remove GSI5 attributes
    tbl.update_item(
        Key={"pk": pk_user(follower_id), "sk": f"FOLLOWING#{followed_id}"},
        UpdateExpression=(
            "SET #state = :unfollowed, updated_at = :now "
            "REMOVE GSI5PK, GSI5SK"
        ),
        ExpressionAttributeNames={"#state": "state"},
        ExpressionAttributeValues={
            ":unfollowed": "unfollowed",
            ":now": now,
        },
    )

    # Decrement counts atomically
    _decrement_counts(follower_id, followed_id)

    return {"ok": True, "status": "unfollowed"}


def get_followers(
    user_id: str, *, limit: int = 20, cursor: Optional[str] = None
) -> Tuple[List[Dict], Optional[str]]:
    """Query GSI5 for FOLLOWERS#{user_id} with pagination."""
    eks = decode_cursor(cursor)
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI5",
        "KeyConditionExpression": Key("GSI5PK").eq(f"FOLLOWERS#{user_id}"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if eks:
        kwargs["ExclusiveStartKey"] = eks

    resp = tbl.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))

    # Filter to only state=following (defensive — unfollowed items should
    # have had GSI5PK removed, but filter as a safety net)
    followers = [
        it for it in items
        if it.get("state", "following") == "following"
    ]
    return followers, next_cursor


def get_following(
    user_id: str, *, limit: int = 20, cursor: Optional[str] = None
) -> Tuple[List[Dict], Optional[str]]:
    """Query PK=USER#{user_id}, SK begins_with FOLLOWING#, filter state=following."""
    eks = decode_cursor(cursor)
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            Key("pk").eq(pk_user(user_id))
            & Key("sk").begins_with("FOLLOWING#")
        ),
        "FilterExpression": Attr("state").eq("following"),
        "Limit": limit,
    }
    if eks:
        kwargs["ExclusiveStartKey"] = eks

    resp = tbl.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return items, next_cursor


def get_follow_counts(user_id: str) -> Dict[str, int]:
    """Read follower_count and following_count from profiles table."""
    item = T.profile.get_item(Key={"user_sub": user_id}).get("Item") or {}
    return {
        "follower_count": int(item.get("follower_count", 0)),
        "following_count": int(item.get("following_count", 0)),
    }


def get_follow_status(viewer_id: str, target_id: str) -> Dict[str, bool]:
    """Check bidirectional follow status."""
    # Forward: does viewer follow target?
    fwd = tbl.get_item(
        Key={"pk": pk_user(viewer_id), "sk": f"FOLLOWING#{target_id}"}
    ).get("Item")
    is_following = bool(fwd and fwd.get("state") == "following")

    # Reverse: does target follow viewer?
    rev = tbl.get_item(
        Key={"pk": pk_user(target_id), "sk": f"FOLLOWING#{viewer_id}"}
    ).get("Item")
    is_followed_by = bool(rev and rev.get("state") == "following")

    return {
        "is_following": is_following,
        "is_followed_by": is_followed_by,
        "is_mutual": is_following and is_followed_by,
    }


def get_mutual_followers(
    viewer_id: str,
    target_id: str,
    *,
    limit: int = 20,
    cursor: Optional[str] = None,
) -> Tuple[List[Dict], Optional[str]]:
    """Compute intersection of viewer's following and target's followers.

    Strategy: fetch viewer's full following set (capped at 2000),
    then check each against target's followers via batch_get_item.
    """
    # Get all users the viewer follows
    viewer_following: Set[str] = set()
    last_key = None
    while len(viewer_following) < 2000:
        kw: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("pk").eq(pk_user(viewer_id))
                & Key("sk").begins_with("FOLLOWING#")
            ),
            "FilterExpression": Attr("state").eq("following"),
            "Limit": 500,
        }
        if last_key:
            kw["ExclusiveStartKey"] = last_key
        r = tbl.query(**kw)
        for it in r.get("Items", []):
            tid = it.get("target_user_id")
            if tid:
                viewer_following.add(tid)
        last_key = r.get("LastEvaluatedKey")
        if not last_key:
            break

    # Get target's followers
    target_follower_ids: Set[str] = set()
    last_key = None
    while len(target_follower_ids) < 2000:
        kw2: Dict[str, Any] = {
            "IndexName": "GSI5",
            "KeyConditionExpression": Key("GSI5PK").eq(f"FOLLOWERS#{target_id}"),
            "Limit": 500,
        }
        if last_key:
            kw2["ExclusiveStartKey"] = last_key
        r2 = tbl.query(**kw2)
        for it in r2.get("Items", []):
            uid = it.get("user_id")
            if uid:
                target_follower_ids.add(uid)
        last_key = r2.get("LastEvaluatedKey")
        if not last_key:
            break

    # Intersection
    mutual_ids = sorted(viewer_following & target_follower_ids)

    # Paginate via offset cursor
    offset = 0
    if cursor:
        try:
            offset = int(cursor)
        except (ValueError, TypeError):
            offset = 0
    page = mutual_ids[offset : offset + limit]
    next_cursor_val = None
    if offset + limit < len(mutual_ids):
        next_cursor_val = str(offset + limit)

    # Enrich with profile data
    results = []
    for uid in page:
        results.append({"user_id": uid})

    return results, next_cursor_val


def _increment_counts(follower_id: str, followed_id: str) -> None:
    """Atomic ADD +1 to following_count and follower_count."""
    try:
        T.profile.update_item(
            Key={"user_sub": followed_id},
            UpdateExpression="ADD follower_count :one",
            ExpressionAttributeValues={":one": 1},
        )
    except ClientError:
        logger.exception("Failed to increment follower_count for %s", followed_id)

    try:
        T.profile.update_item(
            Key={"user_sub": follower_id},
            UpdateExpression="ADD following_count :one",
            ExpressionAttributeValues={":one": 1},
        )
    except ClientError:
        logger.exception("Failed to increment following_count for %s", follower_id)


def _decrement_counts(follower_id: str, followed_id: str) -> None:
    """Atomic ADD -1 to following_count and follower_count, clamped at 0."""
    for user_sub, field in [
        (followed_id, "follower_count"),
        (follower_id, "following_count"),
    ]:
        try:
            T.profile.update_item(
                Key={"user_sub": user_sub},
                UpdateExpression=f"ADD {field} :neg_one",
                ConditionExpression=Attr(field).gt(0),
                ExpressionAttributeValues={":neg_one": -1},
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                # Count is already 0 — clamp
                T.profile.update_item(
                    Key={"user_sub": user_sub},
                    UpdateExpression=f"SET {field} = :zero",
                    ExpressionAttributeValues={":zero": 0},
                )
            else:
                logger.exception("Failed to decrement %s for %s", field, user_sub)


def _is_blocked(blocker_id: str, blocked_id: str) -> bool:
    """Check if blocker has blocked blocked_id. Returns False until block system is implemented."""
    item = tbl.get_item(
        Key={"pk": pk_user(blocker_id), "sk": f"BLOCKED#{blocked_id}"}
    ).get("Item")
    return bool(item and item.get("state") == "blocked")


def reconcile_follow_counts(user_id: str) -> Dict[str, int]:
    """Recompute follower_count and following_count from actual follow records.

    Used by the periodic reconciliation job to correct drift.
    """
    # Count following (forward)
    following_count = 0
    last_key = None
    while True:
        kw: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("pk").eq(pk_user(user_id))
                & Key("sk").begins_with("FOLLOWING#")
            ),
            "FilterExpression": Attr("state").eq("following"),
            "Select": "COUNT",
            "Limit": 1000,
        }
        if last_key:
            kw["ExclusiveStartKey"] = last_key
        r = tbl.query(**kw)
        following_count += r.get("Count", 0)
        last_key = r.get("LastEvaluatedKey")
        if not last_key:
            break

    # Count followers (reverse via GSI5)
    follower_count = 0
    last_key = None
    while True:
        kw2: Dict[str, Any] = {
            "IndexName": "GSI5",
            "KeyConditionExpression": Key("GSI5PK").eq(f"FOLLOWERS#{user_id}"),
            "Select": "COUNT",
            "Limit": 1000,
        }
        if last_key:
            kw2["ExclusiveStartKey"] = last_key
        r2 = tbl.query(**kw2)
        follower_count += r2.get("Count", 0)
        last_key = r2.get("LastEvaluatedKey")
        if not last_key:
            break

    # Update profile with reconciled counts
    T.profile.update_item(
        Key={"user_sub": user_id},
        UpdateExpression="SET follower_count = :fc, following_count = :fgc",
        ExpressionAttributeValues={":fc": follower_count, ":fgc": following_count},
    )
    return {"follower_count": follower_count, "following_count": following_count}
```

### 3.4 Complete Pydantic Model Definitions

All models to be added to `app/models.py`:

```python
from pydantic import BaseModel, Field, field_validator
from typing import List, Literal, Optional


class FollowRequest(BaseModel):
    """Request body for POST /social/follow and POST /social/unfollow."""
    target_user_id: str = Field(..., min_length=1, max_length=128, description="The user_sub of the user to follow/unfollow")

    @field_validator("target_user_id")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        return v.strip()


class FollowResponse(BaseModel):
    """Response body for POST /social/follow."""
    ok: bool
    status: Literal["followed", "already_following"]
    follower_count: int = Field(ge=0, description="Updated follower count of the followed user")
    following_count: int = Field(ge=0, description="Updated following count of the requester")


class UnfollowResponse(BaseModel):
    """Response body for POST /social/unfollow."""
    ok: bool
    status: Literal["unfollowed", "not_following"]


class FollowUser(BaseModel):
    """A user in a follower/following list."""
    user_id: str
    display_name: Optional[str] = None
    profile_photo_url: Optional[str] = None
    is_following: bool = False
    is_mutual: bool = False


class FollowListResponse(BaseModel):
    """Paginated list of followers or following."""
    items: List[FollowUser]
    next_cursor: Optional[str] = None
    total_count: int = Field(ge=0)


class FollowCountsResponse(BaseModel):
    """Follower and following counts for a user."""
    follower_count: int = Field(ge=0)
    following_count: int = Field(ge=0)


class FollowStatusResponse(BaseModel):
    """Bidirectional follow status between viewer and target."""
    is_following: bool
    is_followed_by: bool
    is_mutual: bool
```

### 3.5 Count Consistency Strategy

Atomic counters provide low-latency count reads but can drift if a follow/unfollow write succeeds but the counter update fails (e.g., network partition). Mitigation:

1. **Write follow record first**, then update counts. If count update fails, the follow is still recorded — counts are eventually consistent.
2. **Reconciliation job**: A periodic background task (daily) scans all follow records and recomputes counts. Implementation: query all `FOLLOWING#*` items, group by target, compare to stored `follower_count`. If discrepancy > threshold, overwrite.
3. **Counter clamp**: `_decrement_counts` uses `ConditionExpression: follower_count > :zero` to prevent negative values. If the condition fails, set to 0.

### 3.6 Block Integration

The block check in `follow_user()` queries for a block record. The block system does not yet exist as a standalone feature, so this is a placeholder:

```python
def _is_blocked(blocker_id: str, blocked_id: str) -> bool:
    """Check if blocker has blocked blocked_id. Returns False until block system is implemented."""
    item = ddb_get_item({"pk": pk_user(blocker_id), "sk": f"BLOCKED#{blocked_id}"})
    return bool(item and item.get("state") == "blocked")
```

When a user blocks another, an additional step should remove any existing follow relationship in both directions and decrement counts accordingly.

### 3.7 Rate Limiting

Follow/unfollow actions are rate-limited to prevent spam:
- **Per-user**: 30 follows per minute, 60 unfollows per minute.
- Implementation: Same sliding-window DDB counter pattern used elsewhere (`_enforce_signaling_rate_limit` in messaging.py).

```python
def _enforce_follow_rate_limit(user_id: str, action: str) -> None:
    """Enforce rate limits on follow/unfollow actions.

    Uses sliding-window counter in app_single_table:
    PK=RATE#{user_id}, SK=FOLLOW_RATE#{minute_bucket}
    """
    limit = FOLLOW_RATE_LIMIT_PER_MINUTE if action == "follow" else UNFOLLOW_RATE_LIMIT_PER_MINUTE
    minute_bucket = int(time.time()) // 60
    key = {"pk": f"RATE#{user_id}", "sk": f"FOLLOW_RATE#{minute_bucket}"}

    try:
        resp = tbl.update_item(
            Key=key,
            UpdateExpression="ADD #count :one SET #ttl = :ttl",
            ExpressionAttributeNames={"#count": "count", "#ttl": "ttl"},
            ExpressionAttributeValues={
                ":one": 1,
                ":ttl": int(time.time()) + 120,  # 2-minute TTL
            },
            ReturnValues="UPDATED_NEW",
        )
        current_count = int(resp["Attributes"].get("count", 0))
        if current_count > limit:
            raise ValueError("rate_limited")
    except ClientError:
        logger.exception("Rate limit check failed for %s", user_id)
        # Fail open on rate limit check errors
```

---

## 4. Implementation Plan

### Step 1: Add GSI5 to DynamoDB Init Script

**File**: `scripts/local-ddb-init.py`

Add to the `app_single_table` GSI list (after line 225):

```python
{"index_name": "GSI5", "partition_key": "GSI5PK", "sort_key": "GSI5SK"},
```

**Line-by-line**: Insert a single line in the `gsi` list of the `app_single_table` `TableDef`. This goes between the existing `GSI4` definition and the closing bracket of the `gsi` list. No `attr_types` needed because GSI5SK is a string.

### Step 2: Create Social Service Module

**File**: `app/services/social.py` (new file, ~350 lines)

Functions: `follow_user`, `unfollow_user`, `get_followers`, `get_following`, `get_follow_counts`, `get_follow_status`, `get_mutual_followers`, `_increment_counts`, `_decrement_counts`, `_is_blocked`, `reconcile_follow_counts`, `_enforce_follow_rate_limit`.

Each function is fully specified in section 3.3 above with complete implementation.

### Step 3: Create Social Router

**File**: `app/routers/social.py` (new file, ~250 lines)

Endpoints:
- `POST /ui/social/follow` — calls `social.follow_user()`, catches `ValueError("self_follow")` -> 400, `ValueError("blocked")` -> 403, `ValueError("user_not_found")` -> 404
- `POST /ui/social/unfollow` — calls `social.unfollow_user()`
- `GET /ui/social/{user_id}/followers` — calls `social.get_followers()`, enriches with profile data
- `GET /ui/social/{user_id}/following` — calls `social.get_following()`, enriches with profile data
- `GET /ui/social/{user_id}/counts` — calls `social.get_follow_counts()`
- `GET /ui/social/status/{target_user_id}` — calls `social.get_follow_status()`
- `GET /ui/social/mutual/{target_user_id}` — calls `social.get_mutual_followers()`

**Router definition**:
```python
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Dict, Optional
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/social", tags=["social"])
```

### Step 4: Register Router in Main App

**File**: `app/main.py`

Add import at the top (around line 105, after existing router imports):
```python
from app.routers.social import router as social_router
```

Add `app.include_router(social_router)` in the router registration section (around line 235).

### Step 5: Add Pydantic Models

**File**: `app/models.py` (or inline in router)

Models: `FollowRequest`, `FollowResponse`, `UnfollowResponse`, `FollowUser`, `FollowListResponse`, `FollowCountsResponse`, `FollowStatusResponse`. Full definitions in section 3.4.

### Step 6: Migrate Existing Follow Endpoints

**File**: `app/routers/newsfeed.py`

Replace the existing `POST /social/unfollow` and `POST /social/refollow` endpoints (lines 2659-2688) with thin wrappers that delegate to `app/services/social.py`. Maintain backward compatibility for the frontend's existing `follow()` and `unfollow()` calls.

**Specific changes**:
- Lines 2659-2672 (`unfollow`): Replace body with `return social.unfollow_user(user_id, req.target_user_id)`
- Lines 2675-2688 (`refollow`): Replace body with `return social.follow_user(user_id, req.target_user_id)`
- Add import at top: `from app.services import social`

### Step 7: Update `is_following()` Helper

**File**: `app/routers/newsfeed.py`, line 2131

Refactor to call `app/services/social.get_follow_status()` instead of doing a direct DDB read. This ensures all follow checks go through a single code path.

**Before**:
```python
def is_following(viewer_id: str, target_id: str) -> bool:
    it = ddb_get_item({"pk": pk_user(viewer_id), "sk": f"FOLLOWING#{target_id}"})
    return bool(it and it.get("state") == "following")
```

**After**:
```python
def is_following(viewer_id: str, target_id: str) -> bool:
    from app.services.social import get_follow_status
    status = get_follow_status(viewer_id, target_id)
    return status["is_following"]
```

### Step 8: Add Profile Count Fields

**File**: `app/services/profile.py`

Add `follower_count` and `following_count` to profile read functions. These fields are stored in the `profiles` DDB table but are not part of `PROFILE_FIELDS` (they are system-managed, not user-editable).

**Specific changes**:
- After line 32 (end of `PROFILE_FIELDS`): Do NOT add to this tuple — these are not user-editable profile fields
- In the profile read function: explicitly include `follower_count` and `following_count` in the returned dict if present in the DDB item
- In `PROFILE_FIELD_VISIBILITY` (line 39): Not applicable — count fields bypass the visibility system (always public)

### Step 9: Frontend — API Endpoints

**File**: `frontend/src/api/endpoints/social.ts` (new file)

```typescript
import api from "../client";

export interface FollowUser {
  user_id: string;
  display_name?: string;
  profile_photo_url?: string;
  is_following: boolean;
  is_mutual: boolean;
}

export interface FollowListResponse {
  items: FollowUser[];
  next_cursor?: string;
  total_count: number;
}

export interface FollowCounts {
  follower_count: number;
  following_count: number;
}

export interface FollowStatus {
  is_following: boolean;
  is_followed_by: boolean;
  is_mutual: boolean;
}

export const followUser = (userId: string) =>
  api.post<{ ok: boolean; status: string; follower_count: number; following_count: number }>(
    "/social/follow", { target_user_id: userId }
  );

export const unfollowUser = (userId: string) =>
  api.post<{ ok: boolean; status: string }>("/social/unfollow", { target_user_id: userId });

export const getFollowers = (userId: string, cursor?: string, limit = 20) =>
  api.get<FollowListResponse>(`/social/${userId}/followers`, { params: { cursor, limit } });

export const getFollowing = (userId: string, cursor?: string, limit = 20) =>
  api.get<FollowListResponse>(`/social/${userId}/following`, { params: { cursor, limit } });

export const getFollowCounts = (userId: string) =>
  api.get<FollowCounts>(`/social/${userId}/counts`);

export const getFollowStatus = (userId: string) =>
  api.get<FollowStatus>(`/social/status/${userId}`);
```

### Step 10: Frontend — FollowButton Component

**File**: `frontend/src/components/shared/FollowButton.tsx` (new file)

A reusable button component that:
- Queries follow status on mount via `useQuery(["follow-status", targetUserId])`.
- Shows "Follow" (primary) or "Following" (outline) based on state.
- On hover when following, shows "Unfollow" (destructive variant).
- Calls `followUser`/`unfollowUser` mutations with optimistic updates.
- Invalidates `["follow-status"]`, `["follow-counts"]`, and `["followers"]` query keys on success.

```typescript
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { followUser, unfollowUser, getFollowStatus } from "@/api/endpoints/social";
import { cn } from "@/lib/utils";

interface FollowButtonProps {
  targetUserId: string;
  isFollowing?: boolean;
  className?: string;
  size?: "sm" | "default" | "lg";
}

export function FollowButton({ targetUserId, isFollowing: initialFollowing, className, size = "default" }: FollowButtonProps) {
  const [isHovered, setIsHovered] = useState(false);
  const queryClient = useQueryClient();

  const { data: status } = useQuery({
    queryKey: ["follow-status", targetUserId],
    queryFn: () => getFollowStatus(targetUserId).then(r => r.data),
    initialData: initialFollowing !== undefined ? { is_following: initialFollowing, is_followed_by: false, is_mutual: false } : undefined,
  });

  const following = status?.is_following ?? false;

  const followMut = useMutation({
    mutationFn: () => followUser(targetUserId),
    onMutate: async () => {
      await queryClient.cancelQueries({ queryKey: ["follow-status", targetUserId] });
      queryClient.setQueryData(["follow-status", targetUserId], (old: any) => ({
        ...old,
        is_following: true,
        is_mutual: old?.is_followed_by ?? false,
      }));
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ["follow-status", targetUserId] });
      queryClient.invalidateQueries({ queryKey: ["follow-counts", targetUserId] });
      queryClient.invalidateQueries({ queryKey: ["followers"] });
    },
  });

  const unfollowMut = useMutation({
    mutationFn: () => unfollowUser(targetUserId),
    onMutate: async () => {
      await queryClient.cancelQueries({ queryKey: ["follow-status", targetUserId] });
      queryClient.setQueryData(["follow-status", targetUserId], (old: any) => ({
        ...old,
        is_following: false,
        is_mutual: false,
      }));
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ["follow-status", targetUserId] });
      queryClient.invalidateQueries({ queryKey: ["follow-counts", targetUserId] });
      queryClient.invalidateQueries({ queryKey: ["followers"] });
    },
  });

  const handleClick = () => {
    if (following) {
      unfollowMut.mutate();
    } else {
      followMut.mutate();
    }
  };

  const label = following ? (isHovered ? "Unfollow" : "Following") : "Follow";
  const variant = following ? (isHovered ? "destructive" : "outline") : "default";

  return (
    <Button
      variant={variant}
      size={size}
      className={cn("min-w-[100px]", className)}
      onClick={handleClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      disabled={followMut.isPending || unfollowMut.isPending}
      aria-pressed={following}
      aria-label={following ? `Unfollow user` : `Follow user`}
    >
      {label}
    </Button>
  );
}
```

### Step 11: Frontend — Follower/Following Lists

**File**: `frontend/src/pages/profile/FollowersTab.tsx` (new file)
**File**: `frontend/src/pages/profile/FollowingTab.tsx` (new file)

Both use `useInfiniteQuery` for paginated lists. Each entry shows: avatar, display name, follow button, mutual badge.

### Step 12: Update PublicUserProfilePage

**File**: `frontend/src/pages/profile/PublicUserProfilePage.tsx`

Add:
- Follower/following count display (e.g., "1,234 followers . 567 following").
- FollowButton component.
- Tabs: "Posts", "Followers", "Following" (lazy-loaded).

### Summary of Files Modified/Created

| File | Change Type | Estimated Lines |
|------|-------------|-----------------|
| `scripts/local-ddb-init.py` | Add GSI5 | ~2 |
| `app/services/social.py` | New file | ~350 |
| `app/routers/social.py` | New file | ~250 |
| `app/main.py` | Register router | ~3 |
| `app/routers/newsfeed.py` | Refactor follow endpoints | ~30 |
| `app/services/profile.py` | Add count fields | ~20 |
| `frontend/src/api/endpoints/social.ts` | New file | ~60 |
| `frontend/src/components/shared/FollowButton.tsx` | New file | ~80 |
| `frontend/src/pages/profile/FollowersTab.tsx` | New file | ~120 |
| `frontend/src/pages/profile/FollowingTab.tsx` | New file | ~120 |
| `frontend/src/pages/profile/PublicUserProfilePage.tsx` | Add counts/button/tabs | ~60 |
| **Total** | | **~1095** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_social.py`)

New file, ~400 lines. Tests the service layer using moto-mocked DynamoDB.

**Test function signatures and assertions**:

```python
import pytest
from moto import mock_dynamodb
from app.services.social import (
    follow_user, unfollow_user, get_followers, get_following,
    get_follow_counts, get_follow_status, get_mutual_followers,
    reconcile_follow_counts,
)

@pytest.fixture
def social_tables():
    """Create app_single_table with GSI5 and profiles table."""
    ...

def test_follow_user_creates_record(social_tables):
    """Follow creates a record with state='following' and GSI5 attributes."""
    result = follow_user("alice", "bob")
    assert result["ok"] is True
    assert result["status"] == "followed"
    assert result["follower_count"] >= 1
    # Verify DDB item directly
    item = tbl.get_item(Key={"pk": "USER#alice", "sk": "FOLLOWING#bob"}).get("Item")
    assert item is not None
    assert item["state"] == "following"
    assert item["GSI5PK"] == "FOLLOWERS#bob"
    assert "GSI5SK" in item
    assert item["Entity"] == "Following"
    assert item["created_at"] is not None

def test_follow_idempotency(social_tables):
    """Following the same user twice returns 'already_following', counts not doubled."""
    follow_user("alice", "bob")
    result = follow_user("alice", "bob")
    assert result["status"] == "already_following"
    counts = get_follow_counts("bob")
    assert counts["follower_count"] == 1  # Not 2

def test_unfollow_user(social_tables):
    """Unfollow sets state='unfollowed' and removes GSI5 attributes."""
    follow_user("alice", "bob")
    result = unfollow_user("alice", "bob")
    assert result["status"] == "unfollowed"
    item = tbl.get_item(Key={"pk": "USER#alice", "sk": "FOLLOWING#bob"}).get("Item")
    assert item["state"] == "unfollowed"
    assert "GSI5PK" not in item
    assert "GSI5SK" not in item

def test_unfollow_when_not_following(social_tables):
    """Unfollow a user you don't follow returns 'not_following'."""
    result = unfollow_user("alice", "bob")
    assert result["status"] == "not_following"

def test_self_follow_prevention(social_tables):
    """Following yourself raises ValueError('self_follow')."""
    with pytest.raises(ValueError, match="self_follow"):
        follow_user("alice", "alice")

def test_follower_list_pagination(social_tables):
    """Create 30 followers, verify page 1 (20 items) + page 2 (10 items)."""
    for i in range(30):
        follow_user(f"follower_{i}", "target")
    page1, cursor1 = get_followers("target", limit=20)
    assert len(page1) == 20
    assert cursor1 is not None
    page2, cursor2 = get_followers("target", limit=20, cursor=cursor1)
    assert len(page2) == 10
    assert cursor2 is None

def test_following_list_pagination(social_tables):
    """Same pattern for the forward following list."""
    for i in range(30):
        follow_user("source", f"target_{i}")
    page1, cursor1 = get_following("source", limit=20)
    assert len(page1) == 20

def test_follower_list_excludes_unfollowed(social_tables):
    """After unfollowing, the user no longer appears in the follower list."""
    follow_user("alice", "bob")
    unfollow_user("alice", "bob")
    followers, _ = get_followers("bob")
    follower_ids = [f.get("user_id") for f in followers]
    assert "alice" not in follower_ids

def test_follow_counts_accuracy(social_tables):
    """Follow 5 users, verify following_count=5. Have 3 follow target, verify follower_count=3."""
    for i in range(5):
        follow_user("alice", f"target_{i}")
    assert get_follow_counts("alice")["following_count"] == 5  # wrong key, testing alice not targets
    for i in range(3):
        follow_user(f"follower_{i}", "bob")
    assert get_follow_counts("bob")["follower_count"] == 3

def test_count_clamp_at_zero(social_tables):
    """Unfollow when count is already 0 does not go negative."""
    # Manually set count to 0 then unfollow
    T.profile.put_item(Item={"user_sub": "bob", "follower_count": 0})
    T.profile.put_item(Item={"user_sub": "alice", "following_count": 0})
    # Force an unfollow (write a fake follow record first)
    tbl.put_item(Item={"pk": "USER#alice", "sk": "FOLLOWING#bob", "state": "following"})
    unfollow_user("alice", "bob")
    assert get_follow_counts("bob")["follower_count"] == 0
    assert get_follow_counts("alice")["following_count"] == 0

def test_follow_status_all_permutations(social_tables):
    """Verify is_following, is_followed_by, is_mutual for all states."""
    # Neither follows
    status = get_follow_status("alice", "bob")
    assert not status["is_following"]
    assert not status["is_followed_by"]
    assert not status["is_mutual"]
    # Alice follows Bob
    follow_user("alice", "bob")
    status = get_follow_status("alice", "bob")
    assert status["is_following"]
    assert not status["is_followed_by"]
    assert not status["is_mutual"]
    # Bob follows Alice (mutual)
    follow_user("bob", "alice")
    status = get_follow_status("alice", "bob")
    assert status["is_following"]
    assert status["is_followed_by"]
    assert status["is_mutual"]

def test_mutual_followers(social_tables):
    """A follows B, C follows B, A follows C, C follows A. Mutual(A, B) should include C."""
    follow_user("alice", "bob")
    follow_user("charlie", "bob")
    follow_user("alice", "charlie")
    follow_user("charlie", "alice")
    mutuals, _ = get_mutual_followers("alice", "bob")
    mutual_ids = [m["user_id"] for m in mutuals]
    assert "charlie" in mutual_ids

def test_block_prevents_follow(social_tables):
    """When target has blocked requester, follow raises ValueError('blocked')."""
    tbl.put_item(Item={"pk": "USER#bob", "sk": "BLOCKED#alice", "state": "blocked"})
    with pytest.raises(ValueError, match="blocked"):
        follow_user("alice", "bob")

def test_count_reconciliation(social_tables):
    """Manually corrupt count, run reconciliation, verify corrected."""
    follow_user("follower_1", "target")
    follow_user("follower_2", "target")
    T.profile.update_item(
        Key={"user_sub": "target"},
        UpdateExpression="SET follower_count = :bad",
        ExpressionAttributeValues={":bad": 999},
    )
    result = reconcile_follow_counts("target")
    assert result["follower_count"] == 2

def test_large_follower_list(social_tables):
    """Create 200 followers, verify pagination handles all pages."""
    for i in range(200):
        follow_user(f"f_{i}", "popular")
    all_followers = []
    cursor = None
    while True:
        page, cursor = get_followers("popular", limit=50, cursor=cursor)
        all_followers.extend(page)
        if not cursor:
            break
    assert len(all_followers) == 200
```

### 5.2 E2E Tests (`frontend/e2e/social-follow.spec.ts`)

New file, ~500 lines. Tests full API round-trips and UI interactions.

**Section 90: Follow/Unfollow API (8 tests)**:

1. `Alice follows Bob` — POST /social/follow, verify 200, status="followed".
2. `Alice follows Bob again (idempotent)` — Verify status="already_following".
3. `Alice unfollows Bob` — POST /social/unfollow, verify 200, status="unfollowed".
4. `Alice unfollows Bob when not following` — Verify status="not_following".
5. `Self-follow returns 400` — Alice tries to follow herself.
6. `Follow status reflects bidirectional state` — Alice follows Bob, check status: is_following=true, is_followed_by=false. Bob follows Alice, check: is_mutual=true.
7. `Follower count increments on follow` — Check counts endpoint after follow.
8. `Follower count decrements on unfollow` — Check counts after unfollow.

**Section 91: Follower/Following Lists API (6 tests)**:

1. `Get followers returns follower with profile data` — Follow, then query followers list.
2. `Get following returns followed user` — Query following list.
3. `Followers list excludes unfollowed users` — Unfollow, verify removed from list.
4. `Pagination with cursor` — Seed multiple follows, verify cursor-based pagination.
5. `Mutual followers computed correctly` — Seed mutual relationships, verify mutual endpoint.
6. `Follow counts endpoint returns correct values` — Verify against actual list lengths.

**Section 92: Follow Button UI (5 tests)**:

1. `Follow button shows "Follow" for non-followed user` — Navigate to profile, verify button text.
2. `Click Follow changes button to "Following"` — Click, verify optimistic update.
3. `Hover on "Following" shows "Unfollow"` — Hover interaction.
4. `Click Unfollow reverts to "Follow"` — Click, verify state change.
5. `Follower count updates on follow/unfollow` — Verify count display changes.

**Section 93: Followers/Following Tabs UI (5 tests)**:

1. `Followers tab shows list of followers` — Navigate to followers tab, verify entries.
2. `Following tab shows list of followed users` — Navigate to following tab.
3. `Follow button in list toggles state` — Click follow on a user in the list.
4. `Mutual badge shown for mutual followers` — Verify "Mutual" badge on mutual follows.
5. `Infinite scroll loads more followers` — Scroll to bottom, verify more loaded.

### 5.3 Edge Cases

1. **Race condition on counts**: Two users follow the same target simultaneously. Atomic `ADD` operations in DynamoDB are serializable per item, so counts will be correct.
2. **Orphaned GSI5 records**: If the unfollow write to remove GSI5PK/GSI5SK fails but the state change succeeds, the user would appear in the followers list with `state=unfollowed`. Mitigate by filtering `state=following` in follower list queries.
3. **Deleted accounts**: If a user is deleted, their follow records remain as orphans. The follower list should skip entries where the profile lookup returns 404.
4. **Large mutual computation**: For users with >10K followers, the mutual computation is expensive. Cap at 1000 results and return a `truncated: true` flag.
5. **GSI propagation delay**: DynamoDB GSI updates are eventually consistent. A follow may not appear in the follower list for up to a few hundred milliseconds. Use `ConsistentRead=True` on the primary table for the following list (which queries the main table), but GSI5 queries for follower lists remain eventually consistent.

### 5.4 Performance Considerations

| Operation | DDB Reads | DDB Writes | Expected Latency |
|-----------|-----------|------------|-------------------|
| Follow | 2 (exist check + block check) | 3 (follow record + 2 count updates) | ~25ms |
| Unfollow | 1 (exist check) | 3 (follow record + 2 count updates) | ~20ms |
| Follower list (page) | 1 GSI query + N profile batch reads | 0 | ~30ms |
| Follow counts | 1 get_item | 0 | ~5ms |
| Follow status | 2 get_item | 0 | ~10ms |

---

## 6. Security Considerations

### 6.1 Authentication & Authorization

- All follow endpoints require `Depends(require_ui_session)` — no anonymous follow/unfollow.
- The follower/following list endpoints for a given `{user_id}` are accessible to any authenticated user, not just the profile owner. This is intentional — follower lists are public social data.
- The counts endpoint is optionally authenticated (public for profile display on unauthenticated public profile pages per SOC-005).

### 6.2 Input Validation

- `target_user_id` is validated via Pydantic `Field(..., min_length=1, max_length=128)`.
- The `@field_validator` strips whitespace to prevent `" bob "` from being treated as a different user than `"bob"`.
- Path parameters for `{user_id}` in GET endpoints should be validated against injection patterns (no `#`, no `{`, no control characters).

### 6.3 Rate Limiting

- Follow: 30/minute per user. Prevents mass-follow spam bots that follow thousands of accounts to get follow-back.
- Unfollow: 60/minute per user. Higher limit because mass-unfollow is less abusive.
- Both limits use the same sliding-window DDB counter pattern as `_enforce_signaling_rate_limit` in `app/routers/messaging.py`.

### 6.4 Abuse Vectors

- **Follow/unfollow cycling**: A user follows and unfollows repeatedly to generate notification spam. Mitigation: the `new_follower` alert is batched (SOC-004), so rapid follow/unfollow cycles produce a single batched notification. Additionally, rate limiting caps the frequency.
- **Bot follow farms**: Automated accounts following many users to inflate counts. Mitigation: rate limiting + future CAPTCHA on follow action if abuse detected.
- **Count manipulation**: No direct API to set counts — they are only modified by atomic ADD operations triggered by actual follow/unfollow actions. The reconciliation job corrects any drift.

### 6.5 Data Privacy (PII Handling)

- Follower/following lists expose `user_id`, `display_name`, and `profile_photo_url` — all classified as `public` visibility in `PROFILE_FIELD_VISIBILITY`.
- Email addresses are NOT exposed in follow lists (even though the messaging UserSearch table indexes emails).
- Users with `discoverability_status = "hidden"` should not appear in follower lists. Add a filter in the list enrichment step.

### 6.6 Spam Prevention

- New accounts (created within last 24 hours) have a reduced follow rate limit of 10/minute.
- Accounts with `discoverability_status = "deactivated"` cannot follow other users.

---

## 7. Migration & Rollback Plan

### 7.1 DDB Table Creation

GSI5 must be added to the `app_single_table`. In the local dev environment, this requires modifying `scripts/local-ddb-init.py` and re-running the init script. In production, GSI creation is an online operation — add GSI5 via the AWS Console or CloudFormation and wait for backfill to complete (no downtime).

```python
# Production GSI5 creation command (AWS CLI):
aws dynamodb update-table \
  --table-name app_single_table \
  --attribute-definitions \
    AttributeName=GSI5PK,AttributeType=S \
    AttributeName=GSI5SK,AttributeType=S \
  --global-secondary-index-updates \
    '[{"Create":{"IndexName":"GSI5","KeySchema":[{"AttributeName":"GSI5PK","KeyType":"HASH"},{"AttributeName":"GSI5SK","KeyType":"RANGE"}],"Projection":{"ProjectionType":"ALL"}}}]'
```

### 7.2 Data Backfill for Existing Users

Existing follow records lack GSI5PK/GSI5SK attributes. A one-time migration script:

```python
# scripts/migrate_follow_records.py

def backfill_gsi5_attributes():
    """Scan all FOLLOWING# records and add GSI5PK/GSI5SK."""
    last_key = None
    updated = 0
    while True:
        kwargs = {
            "FilterExpression": Attr("Entity").eq("Following") & Attr("state").eq("following"),
            "Limit": 100,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = tbl.scan(**kwargs)
        for item in resp.get("Items", []):
            target = item.get("target_user_id")
            follower = item.get("user_id")
            created_at = item.get("created_at") or item.get("updated_at") or "2026-01-01T00:00:00Z"
            if target and follower and "GSI5PK" not in item:
                tbl.update_item(
                    Key={"pk": item["pk"], "sk": item["sk"]},
                    UpdateExpression="SET GSI5PK = :gpk, GSI5SK = :gsk",
                    ExpressionAttributeValues={
                        ":gpk": f"FOLLOWERS#{target}",
                        ":gsk": f"{created_at}#{follower}",
                    },
                )
                updated += 1
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        time.sleep(0.1)  # Throttle
    return updated


def backfill_follow_counts():
    """Compute and set follower_count and following_count on all profiles."""
    # ... scan profiles table, for each user run reconcile_follow_counts()
```

### 7.3 Feature Flag Rollout

```
SOCIAL_FOLLOW_SYSTEM_ENABLED=true   # Kill switch for all new endpoints
SOCIAL_FOLLOW_COUNTS_ENABLED=true   # Kill switch for count updates (fallback to count=0)
```

If `SOCIAL_FOLLOW_SYSTEM_ENABLED=false`, the new router returns 503 for all endpoints and the old `/social/refollow` + `/social/unfollow` continue to work as before.

### 7.4 Rollback Steps

1. Set `SOCIAL_FOLLOW_SYSTEM_ENABLED=false` in environment.
2. Deploy previous version of `app/routers/newsfeed.py` to restore original follow endpoints.
3. GSI5 data remains in DDB but is harmless (not queried).
4. Count fields on profiles remain but are not displayed (frontend rolled back).

### 7.5 Zero-Downtime Deployment

1. Deploy backend with new social router + feature flag OFF.
2. Run GSI5 creation (online, no downtime).
3. Run backfill script for existing follow records.
4. Run count reconciliation for all users.
5. Enable feature flag (`SOCIAL_FOLLOW_SYSTEM_ENABLED=true`).
6. Deploy frontend with FollowButton, follower lists, and counts.

---

## 8. Operational Runbook

### 8.1 Metrics to Add

Add to `app/metrics.py`:

```python
record_social_follow_total        # Counter: total follow operations (by status: followed, already_following)
record_social_unfollow_total      # Counter: total unfollow operations (by status: unfollowed, not_following)
record_social_follow_latency      # Histogram: follow operation latency
record_social_followers_query     # Counter: follower list queries
record_social_rate_limited        # Counter: rate limit rejections
record_social_count_reconciled    # Counter: count reconciliation corrections
```

### 8.2 Alerting Thresholds

| Metric | Threshold | Action |
|--------|-----------|--------|
| `social_follow_latency_p99` | > 500ms | Investigate DDB throttling or GSI backfill lag |
| `social_rate_limited` | > 100/min | Possible bot farm — escalate to abuse team |
| `social_count_reconciled` | > 50 corrections/day | Investigate count drift root cause |
| `social_follow_error_rate` | > 1% | Check DDB health, GSI status |

### 8.3 Common Debugging Scenarios

**Follower count wrong**: Run `reconcile_follow_counts(user_id)` for the affected user. If recurring, check whether the count update in `_increment_counts` is failing silently.

**User not appearing in follower list**: Check whether the follow record has `GSI5PK` and `GSI5SK` attributes. If missing, the record predates the migration — run the backfill script for that user.

**Follow returning 500**: Check logs for `ClientError` on the `update_item` call. Common cause: the profiles table item doesn't exist for the target user (no `user_sub` key). Ensure profile creation happens before follow.

### 8.4 Log Patterns

```
INFO  social.follow_user follower=alice followed=bob status=followed follower_count=42
INFO  social.unfollow_user follower=alice followed=bob status=unfollowed
WARN  social._decrement_counts ConditionalCheckFailedException field=follower_count user=bob (clamped to 0)
ERROR social._increment_counts ClientError user=bob (profile item missing?)
```

### 8.5 Health Checks

Add to `GET /internal/health`:
```python
# Check GSI5 exists and is ACTIVE
gsi5_status = tbl.meta.client.describe_table(TableName=APP_TABLE)["Table"]["GlobalSecondaryIndexes"]
gsi5 = next((g for g in gsi5_status if g["IndexName"] == "GSI5"), None)
assert gsi5 and gsi5["IndexStatus"] == "ACTIVE"
```

---

## 9. Performance & Capacity Planning

### 9.1 Expected Throughput

| Scenario | Follows/day | Writes/day | Reads/day |
|----------|------------|------------|-----------|
| 1K users, 5 follows/day each | 5,000 | 15,000 (3 writes per follow) | ~50,000 |
| 10K users, 10 follows/day each | 100,000 | 300,000 | ~1,000,000 |
| 100K users, 10 follows/day each | 1,000,000 | 3,000,000 | ~10,000,000 |

### 9.2 DDB Capacity Units

At on-demand pricing ($1.25/M WCU, $0.25/M RCU):
- 100K users scenario: 3M WCU/day = $3.75/day = $112.50/month
- 100K users scenario: 10M RCU/day = $2.50/day = $75/month

### 9.3 Hot Partition Analysis

**Popular user with 1M followers**: The `FOLLOWERS#{user_id}` GSI5 partition holds 1M items. DDB partitions support up to 10GB and 3000 RCU. At 200 bytes per follow record, 1M records = 200MB — well within partition limits.

**Hot key on counts update**: When a popular user gets 1000 new followers in a minute, the profiles table item for that user receives 1000 atomic ADD operations. DDB supports 1000 WCU per partition per second, so this is at the edge. For users with extreme follow rates, consider buffering count updates (increment a DDB counter once per second with accumulated delta).

### 9.4 Caching Strategy

- **Follow counts**: Cache in the frontend via React Query with `staleTime: 30_000` (30 seconds). Counts are social proof metrics that don't need real-time accuracy.
- **Follow status**: Cache with `staleTime: 60_000` (1 minute). The FollowButton does optimistic updates on click, so the cached status is only used for initial render.
- **Follower list**: Not cached server-side (paginated queries are cheap). Frontend uses React Query infinite query caching.

### 9.5 Latency Budgets

| Operation | Target P50 | Target P99 | Budget Breakdown |
|-----------|-----------|-----------|------------------|
| Follow | 15ms | 50ms | 5ms auth + 5ms block check + 5ms write + 5ms count update |
| Unfollow | 10ms | 40ms | 5ms auth + 5ms read + 5ms update + 5ms count update |
| Follower list | 20ms | 60ms | 5ms auth + 10ms GSI query + 5ms profile batch |
| Follow status | 8ms | 25ms | 5ms auth + 3ms parallel get_items |

---

## 10. Dependency Analysis

### 10.1 Tickets This Blocks

| Ticket | Dependency | Detail |
|--------|-----------|--------|
| SOC-002 | Follower list | Fan-out needs `get_followers()` to know who to write FEEDREF items for |
| SOC-003 | Follower counts | Discovery ranking uses follower_count for search relevance scoring |
| SOC-004 | Follow event | `new_follower` alert emitted from `follow_user()` |
| SOC-005 | Counts + FollowButton | Public profile displays follower/following counts and Follow button |

### 10.2 Tickets This Is Blocked By

None. SOC-001 is the foundation ticket with no upstream dependencies.

### 10.3 Integration Points

- **`app/services/social.py::follow_user()`** is the primary integration point. SOC-002 calls `get_followers()`, SOC-004 calls `emit_social_alert()` from within `follow_user()`, SOC-005 calls `get_follow_counts()` and `get_follow_status()`.
- **`app/routers/newsfeed.py::is_following()`** (line 2131) must be refactored to delegate to `social.get_follow_status()` — this is the integration point between the existing feed visibility system and the new follow system.

### 10.4 API Contracts

The following API contracts are committed and must not change once SOC-002/003/004/005 depend on them:

| Function | Signature | Return Type |
|----------|-----------|-------------|
| `follow_user` | `(follower_id: str, followed_id: str)` | `Dict[str, Any]` with `ok`, `status`, `follower_count`, `following_count` |
| `get_followers` | `(user_id: str, *, limit: int, cursor: Optional[str])` | `Tuple[List[Dict], Optional[str]]` |
| `get_follow_counts` | `(user_id: str)` | `Dict[str, int]` with `follower_count`, `following_count` |
| `get_follow_status` | `(viewer_id: str, target_id: str)` | `Dict[str, bool]` with `is_following`, `is_followed_by`, `is_mutual` |

---

## 11. Acceptance Criteria

1. **Follow**: A user can follow another user. The follow record is created with `state=following` and GSI5 attributes are set. The target's `follower_count` increments by 1. The follower's `following_count` increments by 1. Response includes updated counts.

2. **Idempotent follow**: Following the same user twice returns `already_following` without modifying counts.

3. **Unfollow**: A user can unfollow another user. The follow record's state changes to `unfollowed` and GSI5 attributes are removed. Counts decrement. Counts never go below 0.

4. **Self-follow prevention**: Attempting to follow yourself returns HTTP 400.

5. **Block enforcement**: If the target has blocked the requester, follow returns HTTP 403.

6. **Follower list**: `GET /social/{user_id}/followers` returns a paginated list of followers with profile data (display_name, photo_url), the viewer's follow status for each, and mutual flag.

7. **Following list**: `GET /social/{user_id}/following` returns a paginated list of users the target follows.

8. **Follow counts**: `GET /social/{user_id}/counts` returns `follower_count` and `following_count` in O(1) time.

9. **Follow status**: `GET /social/status/{target_user_id}` returns `is_following`, `is_followed_by`, and `is_mutual`.

10. **FollowButton component**: The frontend FollowButton shows "Follow"/"Following"/"Unfollow" states with optimistic updates and proper ARIA labels.

11. **Rate limiting**: Follow actions are rate-limited to 30/minute per user.

12. **Count reconciliation**: A background job can recompute counts from actual follow records.

---

## 12. Error Handling Matrix

| Error Condition | HTTP Status | Error Code | User Message | Recovery |
|----------------|-------------|------------|--------------|----------|
| Self-follow attempt | 400 | `self_follow` | "You cannot follow yourself" | N/A |
| Target has blocked requester | 403 | `blocked` | "Unable to follow this user" | User must be unblocked |
| Target user not found | 404 | `user_not_found` | "User not found" | Verify user_id |
| Rate limit exceeded | 429 | `rate_limited` | "Too many follow actions. Try again in a minute." | Wait 60 seconds |
| Not authenticated | 401 | `unauthorized` | "Please log in" | Re-authenticate |
| Invalid target_user_id format | 422 | `validation_error` | "Invalid user ID format" | Fix input |
| DDB write failure | 500 | `internal_error` | "Something went wrong. Please try again." | Retry |
| GSI5 not yet active | 503 | `service_unavailable` | "Feature temporarily unavailable" | Wait for GSI backfill |
| Count update failed (non-fatal) | 200 (partial) | N/A | N/A (follow succeeds, count stale) | Reconciliation job |

---

## 13. Frontend Component Specifications

### 13.1 FollowButton Props

```typescript
interface FollowButtonProps {
  targetUserId: string;               // Required: user_sub of the target
  isFollowing?: boolean;              // Optional: initial state (avoids extra query)
  className?: string;                 // Tailwind classes
  size?: "sm" | "default" | "lg";    // shadcn Button size
  onFollowChange?: (isFollowing: boolean) => void; // Callback after state change
}
```

### 13.2 React Query Key Structures

```typescript
// Follow status for a specific user
["follow-status", targetUserId: string]        // -> FollowStatus

// Follow counts for a specific user
["follow-counts", userId: string]              // -> FollowCounts

// Paginated follower list
["followers", userId: string]                   // -> InfiniteData<FollowListResponse>

// Paginated following list
["following", userId: string]                   // -> InfiniteData<FollowListResponse>

// Mutual followers
["mutual-followers", targetUserId: string]      // -> InfiniteData<FollowListResponse>
```

### 13.3 Responsive Design Breakpoints

| Breakpoint | FollowButton | Follower List | Count Display |
|-----------|-------------|--------------|---------------|
| `< 640px` (mobile) | Full width, `size="lg"` | Single column, 48px avatars | Stacked: "1.2K followers" |
| `640-1024px` (tablet) | `size="default"`, inline | Two columns | Inline: "1,234 followers . 567 following" |
| `> 1024px` (desktop) | `size="default"`, inline | Three columns | Inline with separator dots |

### 13.4 Accessibility (ARIA)

- FollowButton: `aria-pressed={isFollowing}` indicates toggle state.
- FollowButton: `aria-label="Follow {displayName}"` / `aria-label="Unfollow {displayName}"`.
- Follower list: `role="list"` on container, `role="listitem"` on each entry.
- Mutual badge: `aria-label="Mutual follower"` on the badge element.
- Count links: `aria-label="1,234 followers, view list"` on the clickable count.
- Keyboard navigation: Enter/Space toggles follow state. Tab moves between list items.

### 13.5 Loading / Error / Empty States

- **Loading**: FollowButton shows a `Loader2` spinner icon during mutation. Follower list shows skeleton cards (3 placeholder entries).
- **Error**: FollowButton shows a toast via `useToast()` with the error message. Follower list shows "Failed to load followers. Tap to retry."
- **Empty**: Follower list shows "No followers yet" with a subtle illustration. Following list shows "Not following anyone yet."

---

## 14. Internationalization Considerations

### 14.1 Translatable Strings

| Key | Default (English) | Notes |
|-----|-------------------|-------|
| `follow.button.follow` | "Follow" | Button label |
| `follow.button.following` | "Following" | Button label (active state) |
| `follow.button.unfollow` | "Unfollow" | Button label (hover on active) |
| `follow.count.followers` | "{count} Followers" | Pluralized |
| `follow.count.following` | "{count} Following" | |
| `follow.list.no_followers` | "No followers yet" | Empty state |
| `follow.list.no_following` | "Not following anyone yet" | Empty state |
| `follow.error.self_follow` | "You cannot follow yourself" | Error toast |
| `follow.error.blocked` | "Unable to follow this user" | Error toast |
| `follow.error.rate_limited` | "Too many follow actions. Try again in a minute." | Error toast |
| `follow.badge.mutual` | "Mutual" | Badge on mutual followers |

### 14.2 Number Formatting

Follower counts use `toLocaleString()` for locale-aware number formatting:
- English: "1,234"
- German: "1.234"
- Japanese: "1,234"

For large counts, use compact notation: `Intl.NumberFormat(locale, { notation: "compact" })`:
- English: "1.2K", "45.6M"
- Chinese: "1.2万", "4560万"

### 14.3 RTL Support

- FollowButton text is inherently LTR but the button layout in the profile header should respect `dir="rtl"` (action buttons right-aligned become left-aligned).
- Follower list entries: avatar on the right in RTL, follow button on the left.
- Count display: numbers remain LTR even in RTL layouts (handled by Unicode bidirectional algorithm).

---

## Appendix A: Migration Plan for Existing Follow Records

Existing follow records (from the current `refollow`/`unfollow` endpoints) lack GSI5PK/GSI5SK attributes. A one-time migration script must:

1. Scan all items with `SK begins_with FOLLOWING#` and `state=following`.
2. For each, add `GSI5PK=FOLLOWERS#{target_user_id}` and `GSI5SK={created_at}#{user_id}`.
3. Compute and set `follower_count` and `following_count` on each affected profile.

## Appendix B: Social Graph Partition Key Distribution

```
app_single_table partition distribution for follow data:

  PK=USER#alice     [ FOLLOWING#bob, FOLLOWING#charlie, ... ]     ← Forward edges
  PK=USER#bob       [ FOLLOWING#alice, FOLLOWING#dave, ... ]

GSI5 partition distribution (reverse index):

  GSI5PK=FOLLOWERS#alice   [ 2026-05-20T...#bob, 2026-05-21T...#dave ]   ← Reverse edges
  GSI5PK=FOLLOWERS#bob     [ 2026-05-19T...#alice, 2026-05-22T...#charlie ]

Key insight: Each follow record appears in BOTH the forward (main table PK)
and reverse (GSI5 PK) partitions. The GSI5 projection is automatic —
DynamoDB replicates items with GSI5PK/GSI5SK attributes into the GSI.

For a user with 1M followers, the FOLLOWERS#{user_id} partition in GSI5
contains 1M items (~200 bytes each = ~200MB). This is well within
DynamoDB's 10GB partition limit but may require multiple physical partitions
(DDB handles this automatically with adaptive capacity).
```

## Appendix C: State Machine Diagram

```
Follow Relationship States:

  +----------+    follow_user()    +-----------+
  |          |-------------------->|           |
  |  (none)  |                     | following |
  |          |<-        --------->|           |
  +----------+  \      /          +-----------+
                 \    /                 |
     first        \  / refollow        | unfollow_user()
     follow        \/                  |
                                       v
                               +------------+
                               |            |
                               | unfollowed |
                               |            |
                               +------------+
                                    |
                                    | follow_user() (re-follow)
                                    v
                               +-----------+
                               |           |
                               | following |
                               |           |
                               +-----------+

GSI5 Attribute Lifecycle:

  State: following   -> GSI5PK = FOLLOWERS#{target}, GSI5SK = {ts}#{follower}
  State: unfollowed  -> GSI5PK REMOVED, GSI5SK REMOVED
  
Count Side Effects:

  (none) -> following:   follower_count(target) +1, following_count(follower) +1
  following -> unfollowed: follower_count(target) -1, following_count(follower) -1
  unfollowed -> following: follower_count(target) +1, following_count(follower) +1
```

## Appendix D: Related Tickets

- **SOC-002**: Feed fan-out (depends on follower list from SOC-001)
- **SOC-003**: User search and discovery (uses follower counts for ranking)
- **SOC-004**: Notification expansion (emits `new_follower` alerts)
- **SOC-005**: Public profile page (displays counts, follow button)

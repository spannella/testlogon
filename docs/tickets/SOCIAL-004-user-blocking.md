# SOCIAL-004: User Blocking

**Ticket**: SOCIAL-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: P0 — Core User Experience
**Estimated effort**: 10-14 days

---

## 1. Executive Summary

The platform has partial blocking infrastructure but no user-facing way to block someone. The private function `_is_blocked()` in `app/services/social.py:393-398` checks for a `BLOCKED#{blocked_id}` sort key under `USER#{blocker_id}` in the `app_single_table`, and the follow endpoint in `app/routers/social.py:108-118` returns 403 when the target has blocked the requester. However, there are no public endpoints to create or remove a block, no endpoint to list blocked users, no messaging filter for blocked users, no prevention of DM creation with blocked users, and no frontend UI for blocking.

User blocking is a safety feature required by virtually every social platform. Without it, users have no way to protect themselves from harassment, unwanted messages, or uncomfortable interactions. The absence of blocking is a trust and safety liability.

This feature exposes the existing blocking infrastructure through public endpoints, extends enforcement to messaging (preventing DM creation and filtering messages), adds a block/unblock button on user profiles, and provides a blocked users management page in settings.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | I want to block a user who is harassing me. | "Block" button on profile; user is immediately blocked. |
| User | I want blocked users to not be able to message me. | DM creation from blocked user returns error; existing messages hidden. |
| User | I want to see a list of users I have blocked. | Settings page shows blocked users list with "Unblock" button. |
| User | I want to unblock a user I previously blocked. | "Unblock" button restores normal interaction. |
| User | I want blocking to be mutual — blocked user cannot see my content. | Blocked user's feed excludes my posts; my profile hidden from them. |
| Admin | I want to see block relationships for moderation. | Admin endpoint to query block records. |

### 2.2 Pain Points

1. **No self-service safety tool**: Users cannot protect themselves from unwanted interactions. The only option is to report a user and wait for moderation action.
2. **Harassment vector via DMs**: A user can send unlimited messages to anyone. There is no way to stop a specific user from contacting you.
3. **Infrastructure exists but is inaccessible**: `_is_blocked()` (social.py:393-398) works correctly but there is no way to create the DDB items it reads, making it dead code from the user's perspective.
4. **Following block works, but nothing else**: The `follow_user()` function (social.py:40-41) checks `_is_blocked()` and raises `ValueError("blocked")`, which the router (social.py:112-113) converts to 403. But messaging, feed, discovery, and contacts do not check blocking.

### 2.3 What Exists Today

The blocking infrastructure in `app/services/social.py:393-398`:

```python
def _is_blocked(blocker_id: str, blocked_id: str) -> bool:
    """Check if blocker has blocked blocked_id."""
    item = tbl.get_item(
        Key={"pk": pk_user(blocker_id), "sk": f"BLOCKED#{blocked_id}"}
    ).get("Item")
    return bool(item and item.get("state") == "blocked")
```

This function reads from the `app_single_table` (social.py:19-20, uses `APP_TABLE` env var). The DDB item it expects:
- `pk=USER#{blocker_id}`, `sk=BLOCKED#{blocked_id}`, with `state="blocked"`

The `follow_user()` function calls it (social.py:40-41):
```python
if _is_blocked(followed_id, follower_id):
    raise ValueError("blocked")
```

The router converts this to HTTP 403 (social.py:112-113):
```python
if msg == "blocked":
    raise HTTPException(status_code=403, detail="Unable to follow this user")
```

---

## 3. Current State Analysis

### 3.1 Social Router Endpoints

`app/routers/social.py:1-200` defines these endpoints:
- `POST /ui/social/follow` (line 103-118)
- `POST /ui/social/unfollow` (line 122-126)
- `GET /ui/social/{user_id}/followers` (line 129-144)
- `GET /ui/social/{user_id}/following` (line 147-162)
- `GET /ui/social/{user_id}/counts` (line 165-171)
- `GET /ui/social/status/{target_user_id}` (line 174-181)
- `GET /ui/social/mutual/{target_user_id}` (line 184-200)

There are NO block/unblock/blocked-list endpoints. The router is 200 lines total.

### 3.2 Social Service Functions

`app/services/social.py:1-398` provides:
- `follow_user()` (line 31-98)
- `unfollow_user()` (line 101-134)
- `get_followers()` (line 141-163)
- `get_following()` (line 166-185)
- `get_follow_counts()` (line 188-194)
- `is_following()` (line 197-202)
- `get_follow_status()` (line 205-221)
- `get_mutual_followers()` (line 224-287)
- `reconcile_follow_counts()` (line 294-338)
- `_increment_counts()` (line 345-363)
- `_decrement_counts()` (line 366-390)
- `_is_blocked()` (line 393-398) — private, read-only

No `block_user()`, `unblock_user()`, or `get_blocked_users()` function exists.

### 3.3 Messaging DM Creation

`app/routers/messaging.py:5798-5825` defines `find_or_create_dm()`:
- At line 5802: checks `user_id == target_sub` (self-DM)
- At line 5805: calls `_find_existing_dm(user_id, target_sub)`
- No call to `_is_blocked()` or any block check

This means a blocked user can create a DM with their blocker — a critical gap.

### 3.4 DDB Table

The `app_single_table` (`scripts/local-ddb-init.py:216-227`) has PK/SK and GSIs GSI1-GSI5 + GSI_SCHEDULE_DUE. Block entities will use the main PK/SK. For listing blocked users, GSI5 can be repurposed (it's used for followers: `GSI5PK=FOLLOWERS#{user_id}`), or we can use a direct table query with `sk begins_with BLOCKED#`.

### 3.5 Frontend Profile Page

`frontend/src/pages/profile/PublicUserProfilePage.tsx` shows user profiles with a follow/unfollow button and a "Message" button. There is no "Block" option anywhere.

---

## 4. Technical Architecture

### 4.1 System Diagram

```
Profile Page / Settings                Backend API                     DynamoDB (app_single_table)
  |                                       |                                |
  |-- POST /ui/social/block ------------>|-- put_item ------------------>| pk=USER#{blocker_id}
  |     { target_user_id }               |                                | sk=BLOCKED#{blocked_id}
  |                                       |-- put_item (reverse index) -->| pk=USER#{blocked_id}
  |                                       |                                | sk=BLOCKEDBY#{blocker_id}
  |                                       |-- unfollow (if following) --->|
  |                                       |                                |
  |-- POST /ui/social/unblock ---------->|-- delete_item ----------------->|
  |                                       |-- delete_item (reverse) ------>|
  |                                       |                                |
  |-- GET /ui/social/blocked ----------->|-- query pk=USER#{uid},         |
  |                                       |   sk begins_with BLOCKED# --->|
  |                                       |                                |
Messaging (DM creation)                  |                                |
  |-- POST /conversations/dm/find-or-create -->|                          |
  |                                       |-- _is_blocked(target, user) ->| (existing check)
  |                                       |-- _is_blocked(user, target) ->| (new: bidirectional)
  |                                       |   if blocked: 403             |
  |                                       |                                |
Feed (existing query)                    |                                |
  |-- GET /feed ----------------------->|                                |
  |                                       |-- filter out blocked users' posts
```

### 4.2 Data Flow -- Block a User

1. User clicks "Block" on a profile or context menu
2. Frontend calls `POST /ui/social/block` with `{ target_user_id: "bob@test.local" }`
3. Backend validates: not self-block, target exists
4. Backend writes block entity: `pk=USER#{blocker}, sk=BLOCKED#{blocked}, state=blocked`
5. Backend writes reverse index: `pk=USER#{blocked}, sk=BLOCKEDBY#{blocker}` (for "am I blocked by?" lookups)
6. Backend auto-unfollows in both directions (if following)
7. Backend returns `{ ok: true, status: "blocked" }`
8. Frontend removes follow button, shows "Blocked" state

### 4.3 Data Flow -- Enforcement Points

Blocking must be enforced at these points:

| Enforcement Point | File | Action |
|-------------------|------|--------|
| Follow | `app/services/social.py:40-41` | Already implemented: ValueError("blocked") |
| DM creation | `app/routers/messaging.py:5798-5825` | NEW: check `_is_blocked()` bidirectionally before creating DM |
| Message send | `app/routers/messaging.py` (send_text_message) | NEW: check block before allowing message in existing DM |
| Feed query | `app/routers/newsfeed.py` | NEW: filter out posts from blocked users |
| Discovery search | `app/services/discovery.py:99` | NEW: filter blocked users from results |
| Contact search | messaging contacts search | NEW: filter blocked users |
| Profile view | Profile endpoints | NEW: return 403 or limited profile for blocked users |

---

## 5. Data Model Deep Dive

### 5.1 Block Entity (Forward)

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `USER#{blocker_id}` | `"USER#alice@test.local"` |
| `sk` | S | `BLOCKED#{blocked_id}` | `"BLOCKED#bob@test.local"` |
| `Entity` | S | `"Block"` | `"Block"` |
| `blocker_id` | S | User who initiated block | `"alice@test.local"` |
| `blocked_id` | S | User who is blocked | `"bob@test.local"` |
| `state` | S | `"blocked"` | `"blocked"` |
| `created_at` | S | ISO timestamp | `"2026-05-27T10:00:00Z"` |
| `reason` | S | Optional reason (for audit) | `"harassment"` |

This is the same entity that `_is_blocked()` (social.py:393-398) already reads. The function checks `state == "blocked"`.

### 5.2 Block Entity (Reverse Index)

For efficient "is user X blocked BY anyone?" lookups:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `USER#{blocked_id}` | `"USER#bob@test.local"` |
| `sk` | S | `BLOCKEDBY#{blocker_id}` | `"BLOCKEDBY#alice@test.local"` |
| `Entity` | S | `"BlockedBy"` | `"BlockedBy"` |
| `blocker_id` | S | Who blocked | `"alice@test.local"` |
| `blocked_id` | S | Who is blocked | `"bob@test.local"` |
| `state` | S | `"blocked"` | `"blocked"` |
| `created_at` | S | Same as forward entity | `"2026-05-27T10:00:00Z"` |

### 5.3 Access Patterns

| Access Pattern | Key Condition | Index |
|---------------|---------------|-------|
| Check if A blocked B | `pk=USER#{A}, sk=BLOCKED#{B}` | Table (existing: `_is_blocked()`) |
| Check if A is blocked by B | `pk=USER#{A}, sk=BLOCKEDBY#{B}` | Table |
| List all users A has blocked | `pk=USER#{A}, sk begins_with BLOCKED#` | Table |
| List all users who blocked A | `pk=USER#{A}, sk begins_with BLOCKEDBY#` | Table |
| Bidirectional check | Two get_item calls (or one for each direction) | Table |

---

## 6. API Contract Design

### 6.1 Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/social/block` | `require_ui_session` | Block a user |
| POST | `/ui/social/unblock` | `require_ui_session` | Unblock a user |
| GET | `/ui/social/blocked` | `require_ui_session` | List blocked users |
| GET | `/ui/social/block-status/{target_user_id}` | `require_ui_session` | Check block status |

### 6.2 POST `/ui/social/block`

**Request:**
```json
{
  "target_user_id": "bob@test.local",
  "reason": "harassment"
}
```
`reason` is optional, stored for audit purposes.

**Response (200):**
```json
{
  "ok": true,
  "status": "blocked",
  "target_user_id": "bob@test.local"
}
```

**Side Effects:**
1. If blocker follows target: auto-unfollow (calls `unfollow_user()`)
2. If target follows blocker: auto-unfollow (calls `unfollow_user()`)
3. Both follow count adjustments happen atomically

**Error Codes:**
| Status | Condition |
|--------|-----------|
| 400 | Cannot block yourself |
| 404 | Target user not found |
| 409 | Already blocked |
| 429 | Rate limited |

### 6.3 POST `/ui/social/unblock`

**Request:**
```json
{
  "target_user_id": "bob@test.local"
}
```

**Response (200):**
```json
{
  "ok": true,
  "status": "unblocked",
  "target_user_id": "bob@test.local"
}
```

**Side Effects:** Deletes both forward and reverse block entities. Does NOT auto-re-follow.

### 6.4 GET `/ui/social/blocked`

**Query parameters:**
- `limit` (int, default 20, max 100)
- `cursor` (string, optional)

**Response (200):**
```json
{
  "blocked_users": [
    {
      "user_id": "bob@test.local",
      "display_name": "Bob",
      "profile_photo_url": "...",
      "blocked_at": "2026-05-27T10:00:00Z"
    }
  ],
  "next_cursor": null,
  "total_count": 1
}
```

### 6.5 GET `/ui/social/block-status/{target_user_id}`

**Response (200):**
```json
{
  "is_blocked_by_me": true,
  "is_blocking_me": false
}
```

### 6.6 Existing Endpoint Changes

The `GET /ui/social/status/{target_user_id}` response (social.py:174-181) should be extended:

```json
{
  "is_following": false,
  "is_followed_by": false,
  "is_mutual": false,
  "is_blocked_by_me": true,
  "is_blocking_me": false
}
```

---

## 7. Frontend Component Design

### 7.1 New Files

| File | Purpose |
|------|---------|
| `frontend/src/pages/settings/BlockedUsersPage.tsx` | Blocked users list with unblock buttons |
| `frontend/src/components/shared/BlockButton.tsx` | Block/unblock button for profiles |
| `frontend/src/api/endpoints/blocking.ts` | API client for block endpoints |

### 7.2 BlockButton Component

```tsx
interface BlockButtonProps {
  targetUserId: string;
  isBlocked: boolean;
  onBlockChange?: (blocked: boolean) => void;
}
```

- Renders "Block" (with `Ban` icon) or "Unblock" button
- Confirmation dialog before blocking: "Block this user? They won't be able to message you or see your content."
- Uses `useMutation` with optimistic update
- Invalidates `["social", "status"]` and `["social", "blocked"]` queries

### 7.3 Profile Page Integration

Add `BlockButton` to `PublicUserProfilePage.tsx` in the action button area (alongside Follow and Message buttons):

```tsx
<BlockButton
  targetUserId={userId}
  isBlocked={blockStatus?.is_blocked_by_me ?? false}
/>
```

Add a dropdown menu (three-dot `MoreHorizontal` icon) with "Block" option for cleaner UI:

```tsx
<DropdownMenu>
  <DropdownMenuTrigger asChild>
    <Button variant="ghost" size="icon"><MoreHorizontal /></Button>
  </DropdownMenuTrigger>
  <DropdownMenuContent>
    <DropdownMenuItem onClick={() => setBlockDialogOpen(true)}>
      <Ban className="mr-2 h-4 w-4" />
      {isBlocked ? "Unblock" : "Block"}
    </DropdownMenuItem>
  </DropdownMenuContent>
</DropdownMenu>
```

### 7.4 Blocked Users Page

Accessible from Settings page. Route: `/settings/blocked`.

```
BlockedUsersPage
  |-- Header ("Blocked Users")
  |-- Description text
  |-- Blocked user list
  |     |-- BlockedUserCard[]
  |           |-- Avatar
  |           |-- Display Name
  |           |-- Blocked date
  |           |-- "Unblock" button
  |-- EmptyState ("You haven't blocked anyone")
  |-- Pagination
```

### 7.5 Route and Navigation

Add to `App.tsx` (near other settings routes around line 130):
```tsx
<Route path="settings/blocked" element={<BlockedUsersPage />} />
```

Add to Settings page navigation or Sidebar Account group (after Privacy, around line 127 in Sidebar.tsx):
```tsx
{ label: "Blocked Users", i18nKey: "nav.blockedUsers", path: "/settings/blocked", icon: <Ban className="h-5 w-5" /> },
```

### 7.6 API Client

```typescript
// frontend/src/api/endpoints/blocking.ts
export const blockUser = (body: { target_user_id: string; reason?: string }) =>
  api.post("/ui/social/block", body);

export const unblockUser = (body: { target_user_id: string }) =>
  api.post("/ui/social/unblock", body);

export const getBlockedUsers = (params?: { limit?: number; cursor?: string }) =>
  api.get<BlockedUsersResponse>("/ui/social/blocked", params);

export const getBlockStatus = (targetUserId: string) =>
  api.get<BlockStatusResponse>(`/ui/social/block-status/${targetUserId}`);
```

---

## 7.7 Pydantic Request/Response Models

### Request Models

```python
class BlockUserIn(BaseModel):
    target_user_id: str = Field(..., min_length=1, max_length=256)
    reason: Optional[str] = Field(default=None, max_length=500)

class UnblockUserIn(BaseModel):
    target_user_id: str = Field(..., min_length=1, max_length=256)
```

### Response Models

```python
class BlockActionOut(BaseModel):
    ok: bool = True
    status: str  # "blocked" or "unblocked"
    target_user_id: str

class BlockedUserItem(BaseModel):
    user_id: str
    display_name: Optional[str] = None
    profile_photo_url: Optional[str] = None
    blocked_at: str

class BlockedUsersListOut(BaseModel):
    blocked_users: List[BlockedUserItem]
    next_cursor: Optional[str] = None
    total_count: int

class BlockStatusOut(BaseModel):
    is_blocked_by_me: bool
    is_blocking_me: bool
```

### TypeScript Interfaces

```typescript
export interface BlockedUser {
  user_id: string;
  display_name?: string;
  profile_photo_url?: string;
  blocked_at: string;
}

export interface BlockedUsersResponse {
  blocked_users: BlockedUser[];
  next_cursor?: string;
  total_count: number;
}

export interface BlockStatusResponse {
  is_blocked_by_me: boolean;
  is_blocking_me: boolean;
}

export interface BlockActionResponse {
  ok: boolean;
  status: "blocked" | "unblocked";
  target_user_id: string;
}
```

---

## 7.8 Service Implementation

### `app/services/blocking.py`

```python
from app.core.tables import T
from app.core.time import now_iso
from app.services.social import _is_blocked, unfollow_user, is_following

tbl = T.app_single

def pk_user(uid: str) -> str:
    return f"USER#{uid}"


def block_user(blocker_id: str, blocked_id: str, reason: str | None = None) -> dict:
    """Create forward + reverse block entities; auto-unfollow both directions."""
    if blocker_id == blocked_id:
        raise ValueError("self_block")
    if _is_blocked(blocker_id, blocked_id):
        raise ValueError("already_blocked")

    now = now_iso()

    # Forward entity
    tbl.put_item(Item={
        "pk": pk_user(blocker_id), "sk": f"BLOCKED#{blocked_id}",
        "Entity": "Block", "blocker_id": blocker_id, "blocked_id": blocked_id,
        "state": "blocked", "created_at": now, "reason": reason or "",
    })
    # Reverse entity
    tbl.put_item(Item={
        "pk": pk_user(blocked_id), "sk": f"BLOCKEDBY#{blocker_id}",
        "Entity": "BlockedBy", "blocker_id": blocker_id, "blocked_id": blocked_id,
        "state": "blocked", "created_at": now,
    })

    # Auto-unfollow both directions
    if is_following(blocker_id, blocked_id):
        unfollow_user(blocker_id, blocked_id)
    if is_following(blocked_id, blocker_id):
        unfollow_user(blocked_id, blocker_id)

    return {"ok": True, "status": "blocked", "target_user_id": blocked_id}


def unblock_user(blocker_id: str, blocked_id: str) -> dict:
    """Remove forward + reverse block entities."""
    tbl.delete_item(Key={"pk": pk_user(blocker_id), "sk": f"BLOCKED#{blocked_id}"})
    tbl.delete_item(Key={"pk": pk_user(blocked_id), "sk": f"BLOCKEDBY#{blocker_id}"})
    return {"ok": True, "status": "unblocked", "target_user_id": blocked_id}


def get_blocked_users(user_id: str, limit: int = 20, cursor=None) -> tuple:
    """List users blocked by user_id with enriched profiles."""
    kwargs = {
        "KeyConditionExpression": "pk = :pk AND begins_with(sk, :prefix)",
        "ExpressionAttributeValues": {":pk": pk_user(user_id), ":prefix": "BLOCKED#"},
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = cursor
    resp = tbl.query(**kwargs)
    items = resp.get("Items", [])
    # Enrich with profile data
    enriched = []
    for item in items:
        profile = _get_profile_summary(item["blocked_id"])
        enriched.append({
            "user_id": item["blocked_id"],
            "display_name": profile.get("display_name"),
            "profile_photo_url": profile.get("profile_photo_url"),
            "blocked_at": item["created_at"],
        })
    return enriched, resp.get("LastEvaluatedKey"), len(enriched)
```

---

## 8. Security & Privacy

### 8.1 Authorization

- All block endpoints use `require_ui_session` (cookie auth + CSRF enforcement for POST endpoints).
- Users can only block/unblock on their own behalf (session user_sub).
- Block status is private: only the blocker can see their blocked list.
- The blocked user is NOT notified when they are blocked (standard privacy practice).
- Admin users cannot block on behalf of other users (no impersonation bypass for safety actions).

### 8.2 Block Enforcement Matrix

| Feature | Check | Behavior when blocked |
|---------|-------|----------------------|
| Follow | `_is_blocked()` both directions | 403 "Unable to follow" (existing) |
| DM creation | `is_any_block()` | 403 "Cannot message this user" (new) |
| Message send | `is_any_block()` | 403 "Cannot send message" (new) |
| Feed | Filter by blocked set | Blocked user's posts hidden (new) |
| Discovery search | Filter by blocked set | Blocked user not in results (new) |
| Profile view | `_is_blocked()` reverse check | Limited profile or 404 (new) |
| Contact list | Filter by blocked set | Blocked user hidden from contacts (new) |
| Notifications | Filter by blocked set | No alerts from blocked users (new) |
| Group chat | Message filter | Blocked user's messages hidden in-memory (new) |

### 8.3 Bidirectional Enforcement

When Alice blocks Bob:
- Alice cannot see Bob's content (enforced by filtering Bob out of Alice's feed/search)
- Bob cannot see Alice's content (enforced by checking if Alice has blocked Bob)
- Neither can message the other
- Neither can follow the other

This bidirectional enforcement requires checking BOTH `_is_blocked(alice, bob)` AND `_is_blocked(bob, alice)` at most enforcement points. The helper function `is_any_block(user_a, user_b)` encapsulates this:

```python
def is_any_block(user_a: str, user_b: str) -> bool:
    """Check if there is a block in either direction between two users."""
    return _is_blocked(user_a, user_b) or _is_blocked(user_b, user_a)
```

For hot paths (feed, search), the optimization is to load the blocked set once per request:

```python
def get_blocked_set(user_id: str) -> Set[str]:
    """Load all user IDs that user_id has blocked."""
    items = tbl.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={":pk": pk_user(user_id), ":prefix": "BLOCKED#"},
    ).get("Items", [])
    return {item["blocked_id"] for item in items}

def get_blocked_by_set(user_id: str) -> Set[str]:
    """Load all user IDs that have blocked user_id."""
    items = tbl.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={":pk": pk_user(user_id), ":prefix": "BLOCKEDBY#"},
    ).get("Items", [])
    return {item["blocker_id"] for item in items}
```

### 8.4 Abuse Prevention

- Rate limit: 30 block/unblock operations per hour per user. Uses the existing rate limiter pattern in `app/services/rate_limiter.py`.
- No block-loop detection needed (blocking is not mutual -- Alice blocking Bob does not block Alice from Bob's perspective unless Bob also blocks Alice).
- Rapid block/unblock cycling (block then unblock within seconds, repeated) could be used to disrupt DM threading. Mitigated by rate limit.

### 8.5 curl Examples

```bash
# Block a user
curl -s -b cookies.txt \
  -H "x-csrf-token: $CSRF" \
  -H "Content-Type: application/json" \
  -d '{"target_user_id":"bob@test.local","reason":"spam"}' \
  "http://localhost:8000/ui/social/block" | jq .

# Unblock a user
curl -s -b cookies.txt \
  -H "x-csrf-token: $CSRF" \
  -H "Content-Type: application/json" \
  -d '{"target_user_id":"bob@test.local"}' \
  "http://localhost:8000/ui/social/unblock" | jq .

# List blocked users
curl -s -b cookies.txt \
  "http://localhost:8000/ui/social/blocked?limit=20" | jq .

# Check block status
curl -s -b cookies.txt \
  "http://localhost:8000/ui/social/block-status/bob@test.local" | jq .
```

---

## 9. Performance & Scalability

### 9.1 DynamoDB Read/Write Estimates

| Operation | WCU | RCU | Latency |
|-----------|-----|-----|---------|
| `_is_blocked(A, B)` | 0 | 0.5 RCU (get_item) | ~5ms |
| `is_any_block(A, B)` | 0 | 1 RCU (2 get_items) | ~5ms (parallel) |
| Block user | 2 WCU (forward + reverse) + 0-4 WCU (unfollows) | 0-2 RCU (follow checks) | ~20ms |
| Unblock user | 2 WCU (delete forward + reverse) | 0 | ~10ms |
| List blocked (page of 20) | 0 | 1 RCU (query) + 10 RCU (20 profile lookups, ~0.5 each) | ~50ms |
| Feed filter (load blocked set) | 0 | 1-2 RCU | ~10ms |
| Block status check | 0 | 1 RCU (2 get_items) | ~5ms |

### 9.2 Feed Filtering Optimization

Checking `is_any_block()` for every post in a feed query would add N*2 DDB reads per page (expensive). Instead:

1. **On feed query**: Fetch the user's complete blocked set once (query `pk=USER#{uid}, sk begins_with BLOCKED#` -- typically <100 items) plus blocked-by set
2. **In-memory filter**: Check each post's `author_id` against `blocked_set | blocked_by_set`
3. **Request-scoped cache**: Both sets cached for the duration of the request (no thread-local needed; pass as function parameter)

This adds 2 queries per feed request instead of 2N queries.

### 9.3 DM Creation Check

The `find_or_create_dm()` endpoint (messaging.py:5798-5825) will add 2 `get_item` calls (bidirectional block check). This adds ~10ms to DM creation, which is negligible given DM creation is an infrequent action.

### 9.4 Blocked Set Size

Most users block <10 people. Power users might block up to 500. The query to load the blocked set returns all items in the `BLOCKED#` SK range under the user's PK. At ~200 bytes per item, 500 blocks = ~100KB, well within a single DDB query page (1MB limit).

---

## 10. Migration & Rollback

### 10.1 Feature Flag

`USER_BLOCKING_ENABLED` (default `true`). When false:
- Block/unblock endpoints return 404
- Block enforcement in messaging disabled
- Feed filtering disabled
- BlockButton hidden
- Existing `_is_blocked()` in follow path remains active (grandfathered)

### 10.2 Rollback

- Set `USER_BLOCKING_ENABLED=false`. All new enforcement points disabled.
- The existing `_is_blocked()` check in follow remains active (pre-existing behavior).
- Block entities remain in DDB but are not acted upon (except for follow blocking which existed before).
- To fully remove: scan and delete items with SK starting with `BLOCKED#` or `BLOCKEDBY#`.

---

## 11. Testing Strategy

### 11.1 Unit Tests (pytest)

**File:** `tests/test_blocking.py`

| # | Test | Assertion |
|---|------|-----------|
| 1 | block_user creates forward entity | `pk=USER#{A}, sk=BLOCKED#{B}` exists with `state=blocked` |
| 2 | block_user creates reverse entity | `pk=USER#{B}, sk=BLOCKEDBY#{A}` exists |
| 3 | block_user auto-unfollows both directions | After block, `is_following(A,B)` and `is_following(B,A)` both False |
| 4 | unblock_user removes forward entity | `get_item` returns None |
| 5 | unblock_user removes reverse entity | Reverse item also deleted |
| 6 | Self-block raises ValueError("self_block") | ValueError with correct message |
| 7 | Duplicate block raises ValueError("already_blocked") | ValueError on second call |
| 8 | is_any_block(A,B) returns True after A blocks B | True |
| 9 | is_any_block(B,A) returns True after A blocks B | True (bidirectional check) |
| 10 | is_any_block returns False when no block | False |
| 11 | get_blocked_users returns enriched list | List includes display_name, blocked_at |
| 12 | get_blocked_users paginates | With 25 blocks, limit=10 returns 10 + cursor |
| 13 | get_block_status returns correct booleans | is_blocked_by_me=True, is_blocking_me=False |
| 14 | get_blocked_set returns set of blocked IDs | Set contains all blocked user IDs |
| 15 | get_blocked_by_set returns set of blocker IDs | Set contains all users who blocked this user |

```python
class TestBlockUser:
    def test_creates_forward_entity(self):
        block_user("alice", "bob")
        item = tbl.get_item(Key={"pk": "USER#alice", "sk": "BLOCKED#bob"}).get("Item")
        assert item is not None
        assert item["state"] == "blocked"

    def test_creates_reverse_entity(self):
        block_user("alice", "bob")
        item = tbl.get_item(Key={"pk": "USER#bob", "sk": "BLOCKEDBY#alice"}).get("Item")
        assert item is not None

    def test_auto_unfollows(self):
        follow_user("alice", "bob")
        follow_user("bob", "alice")
        block_user("alice", "bob")
        assert not is_following("alice", "bob")
        assert not is_following("bob", "alice")

    def test_self_block(self):
        with pytest.raises(ValueError, match="self_block"):
            block_user("alice", "alice")

    def test_duplicate_block(self):
        block_user("alice", "bob")
        with pytest.raises(ValueError, match="already_blocked"):
            block_user("alice", "bob")


class TestUnblockUser:
    def test_removes_both_entities(self):
        block_user("alice", "bob")
        unblock_user("alice", "bob")
        assert not _is_blocked("alice", "bob")
        fwd = tbl.get_item(Key={"pk": "USER#alice", "sk": "BLOCKED#bob"}).get("Item")
        rev = tbl.get_item(Key={"pk": "USER#bob", "sk": "BLOCKEDBY#alice"}).get("Item")
        assert fwd is None
        assert rev is None


class TestIsAnyBlock:
    def test_forward(self):
        block_user("alice", "bob")
        assert is_any_block("alice", "bob") is True
        assert is_any_block("bob", "alice") is True  # bidirectional

    def test_no_block(self):
        assert is_any_block("alice", "carol") is False
```

### 11.2 E2E Tests

**Test File:** `frontend/e2e/user-blocking.spec.ts`

**Section 1: Block/Unblock API (7 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Alice blocks Bob | 200; `{ ok: true, status: "blocked", target_user_id: "e2e_bob@test.local" }` |
| 2 | Duplicate block returns 409 | 409; "Already blocked" detail |
| 3 | Alice cannot block herself | 400; "Cannot block yourself" |
| 4 | Block status shows is_blocked_by_me=true | `GET /block-status/e2e_bob@test.local` -> `is_blocked_by_me: true` |
| 5 | Block status for non-blocked user | `GET /block-status/e2e_charlie@test.local` -> both false |
| 6 | Alice unblocks Bob | 200; `{ status: "unblocked" }` |
| 7 | Block auto-unfollows both directions | Before block: both follow each other. After block: GET /status -> `is_following: false, is_followed_by: false` |

**Section 2: Blocked Users List API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 8 | Blocked list contains blocked user | Alice blocks Bob; `GET /blocked` -> list includes Bob with display_name |
| 9 | Blocked list empty after unblock | After unblock, `GET /blocked` -> `blocked_users: []` |
| 10 | Blocked list pagination | Block 3 users; `limit=2` returns 2 + cursor; next page returns 1 |

**Section 3: Messaging Enforcement (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 11 | DM creation fails when blocked | Alice blocks Bob; Bob tries find-or-create DM with Alice; 403 |
| 12 | Message send fails when blocked | Alice blocks Bob; Bob sends message to existing DM; 403 |
| 13 | Blocker also cannot message blocked user | Alice tries to send to Bob after blocking; 403 (bidirectional) |
| 14 | After unblock, DM creation works | Unblock; Bob creates DM with Alice; 200 |
| 15 | After unblock, message send works | Unblock; Bob sends message; 200 |

**Section 4: Feed Enforcement (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 16 | Blocked user's posts hidden from blocker's feed | Alice blocks Bob; create Bob post; Alice GET /feed -> Bob's post absent |
| 17 | Unblock restores posts in feed | Unblock; Alice GET /feed -> Bob's post visible |
| 18 | Blocked user cannot see blocker's posts | After Alice blocks Bob; create Alice post; Bob GET /feed -> Alice's post absent |

**Section 5: Blocked Users UI (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 19 | Blocked users page loads | Navigate to `/settings/blocked`; heading "Blocked Users" visible |
| 20 | Blocked user appears in list with unblock button | After block; Bob's display_name visible; "Unblock" button visible |
| 21 | Unblock from list works | Click "Unblock"; confirmation dialog; confirm; Bob removed from list |
| 22 | Empty state when no blocks | "You haven't blocked anyone" message visible |

**Section 6: Follow Status Extended (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 23 | Follow status includes block fields | GET /status/bob; response has `is_blocked_by_me` and `is_blocking_me` keys |
| 24 | Follow blocked user returns 403 | Alice blocks Bob; Bob tries to follow Alice; 403 "Unable to follow" |
| 25 | Blocked user's profile shows limited info | GET /discover/profile/bob after block; response omits sensitive fields or returns 404 |

---

## 12. Open Questions & Risks

### 12.1 Unresolved Decisions

1. **Mute vs. Block**: Should there be a separate "Mute" action (hide content without preventing contact)? Recommendation: Phase 2. Block is the priority; mute is a softer action.
2. **Block from message context**: Should users be able to block someone from within a DM conversation? Recommendation: yes, add a context menu option in MessageBubble.
3. **Existing DMs after block**: Should existing DMs remain visible or be hidden? Recommendation: keep DM visible but disable sending. Show "You have blocked this user" banner.
4. **Group chat with blocked user**: If Alice and Bob are in a group chat and Alice blocks Bob, should Alice leave the group or should Bob's messages be hidden? Recommendation: hide Bob's messages from Alice in the group; do not force-leave.

### 12.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Feed filter performance for users with many blocks | Low | Medium | Cache blocked set per request; set is typically <100 |
| DM creation race condition (block between check and create) | Very Low | Low | Eventual consistency acceptable; message may slip through |
| Blocked user still receives push notifications | Medium | Medium | Filter blocked users in push delivery path (alerts.py) |
| Block enforcement gaps in new features | Medium | Medium | Add `is_any_block()` to the feature checklist for all new social endpoints |

---

## 13. Files to Create

| File | Purpose |
|------|---------|
| `app/services/blocking.py` | Block/unblock/list/check functions |
| `frontend/src/pages/settings/BlockedUsersPage.tsx` | Blocked users management page |
| `frontend/src/components/shared/BlockButton.tsx` | Block/unblock button with confirmation dialog |
| `frontend/src/api/endpoints/blocking.ts` | API client |
| `frontend/e2e/user-blocking.spec.ts` | E2E tests |

## 14. Files to Modify

| File | Change |
|------|--------|
| `app/routers/social.py` | Add block/unblock/blocked/block-status endpoints; extend follow-status response |
| `app/services/social.py` | Make `_is_blocked()` public; add `is_any_block()` helper; import blocking service |
| `app/routers/messaging.py` | Add block check in `find_or_create_dm()` (line 5798-5825); add block check in message send |
| `app/main.py` | No change needed (social router already registered at line 365) |
| `app/core/settings.py` | Add `user_blocking_enabled: bool` setting |
| `frontend/src/api/types.ts` | Add `BlockedUser`, `BlockStatusResponse` interfaces |
| `frontend/src/App.tsx` | Add `/settings/blocked` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Blocked Users" link to Account group (after Privacy, line 127) |
| `frontend/src/pages/profile/PublicUserProfilePage.tsx` | Add BlockButton / block option in dropdown menu |

---

## 15. Dependencies

- **Social service (existing)**: `app/services/social.py` — `_is_blocked()` (line 393-398) already reads block entities; `follow_user()` (line 40-41) already checks blocks.
- **Messaging router (existing)**: `app/routers/messaging.py:5798-5825` — `find_or_create_dm()` needs block check added.
- **app_single_table (existing)**: Block entities use PK/SK on the same table as follows (`scripts/local-ddb-init.py:216-227`).

---

## 16. Acceptance Criteria

1. Users can block another user via `POST /ui/social/block`.
2. Users can unblock via `POST /ui/social/unblock`.
3. Blocking auto-unfollows in both directions.
4. Blocked users cannot create DMs with the blocker (403).
5. Blocked users cannot send messages to the blocker in existing DMs (403).
6. Blocked users' posts are filtered from the blocker's feed.
7. The blocker's posts are filtered from the blocked user's feed.
8. Blocked users are filtered from discovery/search results.
9. `GET /ui/social/blocked` returns the user's blocked list with profile info.
10. `/settings/blocked` page shows blocked users with "Unblock" buttons.
11. Follow status endpoint includes `is_blocked_by_me` and `is_blocking_me` fields.
12. The blocked user is NOT notified about being blocked.

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| `_is_blocked()` function | `app/services/social.py` | 393-398 | VERIFIED |
| `_is_blocked()` checks state=="blocked" | `app/services/social.py` | 398 | VERIFIED |
| `_is_blocked()` reads from app_single_table | `app/services/social.py` | 19-20, 395-397 | VERIFIED |
| follow_user calls _is_blocked | `app/services/social.py` | 40-41 | VERIFIED |
| Router returns 403 on blocked follow | `app/routers/social.py` | 112-113 | VERIFIED |
| Social router has no block endpoints | `app/routers/social.py` | 1-200 | VERIFIED: all 200 lines reviewed |
| Social service has no block/unblock functions | `app/services/social.py` | 1-398 | VERIFIED |
| find_or_create_dm has no block check | `app/routers/messaging.py` | 5798-5825 | VERIFIED: no _is_blocked call |
| Social router registered in main.py | `app/main.py` | 69, 365 | VERIFIED |
| app_single_table schema | `scripts/local-ddb-init.py` | 216-227 | VERIFIED |
| DDB key pattern: USER#{id} + BLOCKED#{id} | `app/services/social.py` | 396 | VERIFIED |
| DDB key pattern: USER#{id} + FOLLOWING#{id} | `app/services/social.py` | 51, 69 | VERIFIED |
| GSI5 used for followers | `app/services/social.py` | 77, 148 | VERIFIED |

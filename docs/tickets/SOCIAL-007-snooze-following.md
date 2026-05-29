# SOCIAL-007: Snooze Following

**Ticket**: SOCIAL-007
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 4-5 days

---

## 1. Overview & Motivation

### 1.1 Purpose

SOCIAL-007 adds the ability to temporarily mute a followed user's content for a configurable number of days without unfollowing. When snoozed, the followed user's posts are filtered from the snoozee's feed and notifications are suppressed. Snooze auto-expires when the `snoozed_until` timestamp passes. Users can manage snoozed follows and unsnooze early.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Follower | As a follower, I want to snooze someone I follow for a set period without unfollowing. | Click "Snooze" on profile; choose duration; their posts disappear from my feed. |
| Follower | As a follower, I want to choose snooze duration: 1 day, 3 days, 7 days, 30 days, or custom. | Duration picker with preset options + custom input. |
| Follower | As a follower, I want to see who I've snoozed and for how long. | "Snoozed" list shows all snoozed users with expiry dates. |
| Follower | As a follower, I want to unsnooze someone early. | "Unsnooze" button on profile or in snoozed list; immediate effect. |
| Follower | As a follower, I want snooze to auto-expire so I don't have to remember to unsnooze. | After `snoozed_until` passes, posts reappear automatically. |
| Followed user | As a followed user, I want my content to remain visible to non-snoozed followers. | Snooze is per-follower; other followers unaffected. |

### 1.3 Why This Is Needed Now

Users often want a break from someone's content without the social friction of unfollowing. Common scenarios: a creator posting too frequently about a topic, someone on vacation sharing excessively, a brand partner running a campaign the user has seen enough of. Snooze is a standard feature in Facebook, Instagram, and Twitter/X. Without it, users either unfollow (losing the relationship) or endure unwanted content (degrading feed quality).

---

## 2. Architecture Diagram

```
 User (Alice)                        Backend                           DynamoDB
 ────────────                        ───────                           ────────
      │                                  │                                │
      │  POST /social/following/         │                                │
      │       {bob_id}/snooze            │                                │
      │  Body: { days: 7 }              │                                │
      │─────────────────────────────────►│                                │
      │                                  │  1. Validate follow exists     │
      │                                  │─────────────────────────────►│
      │                                  │  ◄── follow record found       │
      │                                  │                                │
      │                                  │  2. Compute snoozed_until      │
      │                                  │     = now_ts() + (7 * 86400)   │
      │                                  │                                │
      │                                  │  3. Update follow record       │
      │                                  │─────────────────────────────►│
      │                                  │  UpdateItem: SET snoozed_until │
      │                                  │                                │
      │◄─────────────────────────────────│  4. Return 200                 │
      │  { ok: true, snoozed_until }    │                                │

 ═══════════════ Feed Filtering ════════════════════════════════════════════

 User (Alice)                        Backend (GET /feed)               DynamoDB
      │                                  │                                │
      │  GET /feed                       │                                │
      │─────────────────────────────────►│                                │
      │                                  │  1. Get Alice's followings     │
      │                                  │─────────────────────────────►│
      │                                  │  ◄── following records          │
      │                                  │                                │
      │                                  │  2. Filter snoozed:            │
      │                                  │     Bob: snoozed_until         │
      │                                  │       = 1749100000 (future)    │
      │                                  │       → SNOOZED (exclude)      │
      │                                  │     Carol: snoozed_until       │
      │                                  │       = null                   │
      │                                  │       → ACTIVE (include)       │
      │                                  │     Dave: snoozed_until        │
      │                                  │       = 1748000000 (past)      │
      │                                  │       → EXPIRED (include)      │
      │                                  │                                │
      │                                  │  3. Query posts from           │
      │                                  │     non-snoozed followings     │
      │                                  │─────────────────────────────►│
      │                                  │  ◄── posts (excluding Bob)     │
      │                                  │                                │
      │◄─────────────────────────────────│  4. Return filtered posts      │
      │  { posts: [...] }               │                                │

 ═══════════════ Notification Suppression ══════════════════════════════════

 Bob posts new content                Backend                           DynamoDB
      │                                  │                                │
      │  POST /posts                     │                                │
      │─────────────────────────────────►│                                │
      │                                  │  1. Create post                │
      │                                  │  2. Fan out notifications      │
      │                                  │     For each follower:         │
      │                                  │       is_snoozed(follower, Bob)?│
      │                                  │       Alice: YES → skip        │
      │                                  │       Carol: NO → notify       │
      │                                  │                                │
```

---

## 3. Current State Analysis

### 3.1 Following System

<!-- NOTE: The follow system is NOT in profile.py or social_alerts.py. The correct locations are:
  - Service: app/services/social.py — follow_user (line 31), unfollow_user (line 102), get_follow_status (line 206)
  - Router: app/routers/social.py — POST /ui/social/follow (line 139), POST /ui/social/unfollow (line 158)
  - DDB keys: pk=USER#{user_id}, sk=FOLLOWING#{followed_id} (NOT pk=FOLLOW#{follower}, sk=USER#{...} as shown in section 4)
  - GSI5PK=FOLLOWERS#{followed_id} for reverse lookups
-->

The following system is implemented in `app/services/social.py` (see `follow_user` at line 31, `unfollow_user` at line 102) and `app/routers/social.py` (see line 139, 158):
- Follow: `POST /ui/social/follow` (see `app/routers/social.py:139`)
- Unfollow: `POST /ui/social/unfollow` (see `app/routers/social.py:158`)
- Following list: `GET /ui/social/{user_id}/following`
- Followers list: `GET /ui/social/{user_id}/followers`

Following records are stored in `app_single_table` with `pk=USER#{user_id}`, `sk=FOLLOWING#{followed_id}`, plus GSI5 for reverse follower lookups (`GSI5PK=FOLLOWERS#{followed_id}`).

### 3.2 Feed Filtering

`GET /feed` queries posts from followed users via GSI. Currently there is no per-follow filtering. Adding a `snoozed_until` field to the follow record enables filtering at feed query time.

### 3.3 Notifications

Follow-triggered notifications (new post alerts) are generated by `app/services/social_alerts.py`. Snooze should suppress these notifications for the snoozed follow.

### 3.4 Gaps

1. **No `snoozed_until` field on follow records** -- no snooze state.
2. **No snooze endpoint** -- no API to set or clear snooze.
3. **No feed filtering by snooze** -- `GET /feed` doesn't check snooze status.
4. **No notification suppression** -- alerts sent regardless of snooze.
5. **No snooze UI** -- no snooze button on profiles or following list.
6. **No snoozed users management page** -- no way to see or manage snoozed follows.

---

## 4. DynamoDB Access Patterns

### 4.1 Follow Record with Snooze Field

<!-- NOTE: The actual DDB key pattern for follows is PK=USER#{user_id}, SK=FOLLOWING#{followed_id} (see app/services/social.py:52,70). The table is app_single_table, not a separate "social" table. -->

| # | Operation | Table | Key / Index | Condition | Frequency |
|---|-----------|-------|-------------|-----------|-----------|
| 1 | Verify follow exists | app_single_table | PK=`USER#{follower}`, SK=`FOLLOWING#{following}` | None | Per snooze/unsnooze |
| 2 | Set snooze | app_single_table | PK=`USER#{follower}`, SK=`FOLLOWING#{following}` | `attribute_exists(pk)` | Per snooze |
| 3 | Clear snooze | app_single_table | PK=`USER#{follower}`, SK=`FOLLOWING#{following}` | `attribute_exists(pk)` | Per unsnooze |
| 4 | List followings | app_single_table | PK=`USER#{follower}`, SK begins_with `FOLLOWING#` | None | Per feed request |
| 5 | Filter snoozed | In-memory | N/A | `snoozed_until > now_ts()` | Per feed request |
| 6 | List snoozed only | app_single_table + filter | PK=`USER#{follower}`, SK begins_with `FOLLOWING#` | `snoozed_until > :now` | Per management page |

### 4.2 Example DynamoDB Items

**Follow Record (no snooze):**

```json
{
  "pk": "USER#alice@test.local",
  "sk": "FOLLOWING#bob@test.local",
  "follower_sub": "alice@test.local",
  "following_sub": "bob@test.local",
  "followed_at": 1747000000,
  "following_name": "Bob Smith",
  "following_avatar_url": "/mock/s3/avatars/bob.jpg"
}
```

**Follow Record (snoozed for 7 days):**

```json
{
  "pk": "USER#alice@test.local",
  "sk": "FOLLOWING#bob@test.local",
  "follower_sub": "alice@test.local",
  "following_sub": "bob@test.local",
  "followed_at": 1747000000,
  "following_name": "Bob Smith",
  "following_avatar_url": "/mock/s3/avatars/bob.jpg",
  "snoozed_until": 1749129600
}
```

**Follow Record (snooze expired):**

```json
{
  "pk": "USER#alice@test.local",
  "sk": "FOLLOWING#carol@test.local",
  "follower_sub": "alice@test.local",
  "following_sub": "carol@test.local",
  "followed_at": 1746500000,
  "following_name": "Carol Jones",
  "following_avatar_url": "/mock/s3/avatars/carol.jpg",
  "snoozed_until": 1748000000
}
```

---

## 5. Technical Design

### 5.1 Data Model Extension

Add `snoozed_until` field to the follow record:

| Field | Type | Description |
|-------|------|-------------|
| `snoozed_until` | Number (optional) | Unix timestamp when snooze expires. Null = not snoozed. |

This field is checked at feed query time and at notification dispatch time. When `snoozed_until` is set and is in the future, the follow is considered snoozed.

### 5.2 Backend Service

**File**: `app/services/social_alerts.py` (extend existing)

```python
def snooze_following(follower_sub: str, following_sub: str, days: int) -> dict:
    """Snooze a following for N days."""
    # 1. Validate not self-snooze
    if follower_sub == following_sub:
        raise HTTPException(status_code=400, detail="Cannot snooze yourself")

    # 2. Verify the follow relationship exists
    follow = _get_follow(follower_sub, following_sub)
    if not follow:
        raise HTTPException(status_code=404, detail="Not following this user")

    # 3. Calculate snoozed_until
    snoozed_until = now_ts() + (days * 86400)

    # 4. Update follow record with snoozed_until
    _update_follow(follower_sub, following_sub, snoozed_until=snoozed_until)

    return {"ok": True, "snoozed_until": snoozed_until}

def unsnooze_following(follower_sub: str, following_sub: str) -> dict:
    """Remove snooze from a following."""
    _update_follow(follower_sub, following_sub, snoozed_until=None)
    return {"ok": True}

def list_snoozed_followings(follower_sub: str) -> list[dict]:
    """List all snoozed followings for a user."""
    followings = _list_followings(follower_sub)
    now = now_ts()
    snoozed = [
        f for f in followings
        if f.get("snoozed_until") and f["snoozed_until"] > now
    ]
    return snoozed

def is_snoozed(follower_sub: str, following_sub: str) -> bool:
    """Check if a following is currently snoozed."""
    follow = _get_follow(follower_sub, following_sub)
    if not follow:
        return False
    snoozed_until = follow.get("snoozed_until")
    return snoozed_until is not None and snoozed_until > now_ts()
```

### 5.3 Feed Filtering

In the `GET /feed` endpoint, after fetching posts:

```python
# Get snoozed user IDs
snoozed_followings = list_snoozed_followings(user_sub)
snoozed_user_ids = {f["following_sub"] for f in snoozed_followings}

# Filter out posts from snoozed users
posts = [p for p in posts if p.get("user_id") not in snoozed_user_ids]
```

**Auto-unsnooze check**: The check is done at query time. If `snoozed_until` has passed, the follow is not considered snoozed -- no explicit cleanup needed. A periodic cleanup job can remove stale `snoozed_until` values for cleanliness, but it's not required for correctness.

### 5.4 Notification Suppression

In the notification dispatch function (when generating "new post" alerts):

```python
def _should_notify_follower(follower_sub: str, poster_sub: str) -> bool:
    """Check if a follower should receive a notification from this poster."""
    if is_snoozed(follower_sub, poster_sub):
        return False
    return True
```

### 5.5 Backend Router

**File**: `app/routers/profile.py` (extend existing)

```python
class SnoozeFollowingIn(BaseModel):
    days: int = Field(..., ge=1, le=90, description="Number of days to snooze")

@router.post("/ui/social/following/{user_id}/snooze", status_code=200)
def snooze_following_endpoint(user_id: str, body: SnoozeFollowingIn, ctx=Depends(require_ui_session)):
    """Snooze a followed user for N days."""
    return snooze_following(ctx["user_sub"], user_id, body.days)

@router.delete("/ui/social/following/{user_id}/snooze", status_code=200)
def unsnooze_following_endpoint(user_id: str, ctx=Depends(require_ui_session)):
    """Remove snooze from a followed user."""
    return unsnooze_following(ctx["user_sub"], user_id)

@router.get("/ui/social/following/snoozed", status_code=200)
def list_snoozed_endpoint(ctx=Depends(require_ui_session)):
    """List all snoozed followings."""
    return list_snoozed_followings(ctx["user_sub"])
```

---

## 6. API Request/Response Examples

### 6.1 Snooze a Following

```bash
curl -X POST http://localhost:8000/ui/social/following/bob@test.local/snooze \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=alice_session; ui_csrf=csrf_val" \
  -H "x-csrf-token: csrf_val" \
  -d '{"days": 7}'
```

**Response (200):**
```json
{
  "ok": true,
  "snoozed_until": 1749129600
}
```

### 6.2 Unsnooze a Following

```bash
curl -X DELETE http://localhost:8000/ui/social/following/bob@test.local/snooze \
  -H "Cookie: ui_session=alice_session; ui_csrf=csrf_val" \
  -H "x-csrf-token: csrf_val"
```

**Response (200):**
```json
{
  "ok": true
}
```

### 6.3 List Snoozed Followings

```bash
curl http://localhost:8000/ui/social/following/snoozed \
  -H "Cookie: ui_session=alice_session"
```

**Response (200):**
```json
{
  "snoozed": [
    {
      "following_sub": "bob@test.local",
      "following_name": "Bob Smith",
      "following_avatar_url": "/mock/s3/avatars/bob.jpg",
      "followed_at": 1747000000,
      "snoozed_until": 1749129600,
      "snooze_remaining_hours": 142
    }
  ],
  "total": 1
}
```

### 6.4 Snooze with Invalid Duration

```bash
curl -X POST http://localhost:8000/ui/social/following/bob@test.local/snooze \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=alice_session; ui_csrf=csrf_val" \
  -H "x-csrf-token: csrf_val" \
  -d '{"days": 0}'
```

**Response (422):**
```json
{
  "detail": [
    {
      "loc": ["body", "days"],
      "msg": "ensure this value is greater than or equal to 1",
      "type": "value_error.number.not_ge"
    }
  ]
}
```

### 6.5 Snooze Unfollowed User

```bash
curl -X POST http://localhost:8000/ui/social/following/unknown@test.local/snooze \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=alice_session; ui_csrf=csrf_val" \
  -H "x-csrf-token: csrf_val" \
  -d '{"days": 7}'
```

**Response (404):**
```json
{
  "detail": "Not following this user"
}
```

### 6.6 Snooze Self

```bash
curl -X POST http://localhost:8000/ui/social/following/alice@test.local/snooze \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=alice_session; ui_csrf=csrf_val" \
  -H "x-csrf-token: csrf_val" \
  -d '{"days": 7}'
```

**Response (400):**
```json
{
  "detail": "Cannot snooze yourself"
}
```

---

## 7. Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | Detail | Recovery |
|---|----------|-------------|------------|--------|----------|
| 1 | Not following the target user | 404 | `not_found` | "Not following this user" | Follow the user first |
| 2 | Days below minimum (0) | 422 | `validation_error` | "ensure this value is >= 1" | Use days >= 1 |
| 3 | Days above maximum (91+) | 422 | `validation_error` | "ensure this value is <= 90" | Use days <= 90 |
| 4 | Unsnooze when not snoozed | 200 | N/A | No-op (idempotent) | No action needed |
| 5 | Snooze when already snoozed | 200 | N/A | Updates snoozed_until (replaces) | Intentional behavior |
| 6 | Missing CSRF token | 403 | `csrf_error` | "CSRF token missing" | Include x-csrf-token |
| 7 | Unauthenticated request | 401 | `unauthorized` | "Authentication required" | Log in first |
| 8 | Snooze self | 400 | `invalid_request` | "Cannot snooze yourself" | Don't pass own ID |
| 9 | Days as non-integer | 422 | `validation_error` | "value is not a valid integer" | Pass integer value |
| 10 | Missing days field | 422 | `validation_error` | "field required" | Include days in body |
| 11 | Concurrent snooze/unfollow race | 200/404 | N/A | If unfollow wins, snooze gets 404 | Re-follow and try again |

---

## 8. Pydantic Model Definitions

```python
# --- In app/models.py ---

from pydantic import BaseModel, Field
from typing import Optional, List

class SnoozeFollowingIn(BaseModel):
    """Request body for POST /social/following/{user_id}/snooze."""
    days: int = Field(..., ge=1, le=90, description="Number of days to snooze (1-90)")

    class Config:
        json_schema_extra = {
            "example": {"days": 7}
        }


class SnoozeFollowingOut(BaseModel):
    """Response for snooze endpoint."""
    ok: bool = True
    snoozed_until: int  # Unix timestamp

    class Config:
        json_schema_extra = {
            "example": {"ok": True, "snoozed_until": 1749129600}
        }


class UnsnoozeFollowingOut(BaseModel):
    """Response for unsnooze endpoint."""
    ok: bool = True


class SnoozedFollowingOut(BaseModel):
    """A single snoozed following in the list."""
    following_sub: str
    following_name: Optional[str] = None
    following_avatar_url: Optional[str] = None
    followed_at: int = 0
    snoozed_until: int = 0
    snooze_remaining_hours: Optional[int] = None  # Computed from snoozed_until - now

    class Config:
        json_schema_extra = {
            "example": {
                "following_sub": "bob@test.local",
                "following_name": "Bob Smith",
                "following_avatar_url": "/mock/s3/avatars/bob.jpg",
                "followed_at": 1747000000,
                "snoozed_until": 1749129600,
                "snooze_remaining_hours": 142
            }
        }


class SnoozedFollowingListOut(BaseModel):
    """Response for GET /social/following/snoozed."""
    snoozed: List[SnoozedFollowingOut] = Field(default_factory=list)
    total: int = 0


class FollowingOut(BaseModel):
    """Extended following record with snooze state."""
    following_sub: str
    following_name: Optional[str] = None
    following_avatar_url: Optional[str] = None
    followed_at: int = 0
    snoozed_until: Optional[int] = None
    is_snoozed: bool = False  # Computed: snoozed_until > now_ts()
```

---

## 9. Frontend Component Tree

```
ProfilePage (for followed user)
├── ProfileHeader
│   ├── Avatar
│   ├── Display Name
│   ├── FollowButton
│   └── MoreOptionsDropdown
│       ├── MenuItem: "Snooze" → opens SnoozeDurationPicker
│       └── MenuItem: "Unfollow"
├── SnoozeBadge (if snoozed)
│   ├── BellOff icon
│   ├── Text: "Snoozed until Jun 5"
│   └── Button: "Unsnooze"
└── Content tabs (Videos, Posts, etc.)

FollowingListPage
├── Tab: "All" / "Snoozed"
└── FollowingList
    └── For each following:
        ├── Avatar + Name
        ├── FollowedSinceDate
        ├── SnoozeBadge (if snoozed)
        │   ├── BellOff icon + "Snoozed until {date}"
        │   └── Button: "Unsnooze"
        └── MoreOptionsDropdown
            ├── MenuItem: "Snooze" → SnoozeDurationPicker
            └── MenuItem: "Unfollow"

SnoozeDurationPicker (shared dialog)
├── Title: "Snooze {user_name}"
├── PresetButtons
│   ├── Button: "1 day"
│   ├── Button: "3 days"
│   ├── Button: "7 days"
│   └── Button: "30 days"
├── CustomInput
│   ├── NumberInput (1-90)
│   └── Label: "days"
├── Button: "Snooze" (primary)
└── Button: "Cancel" (ghost)
```

### 9.1 Props Interfaces

```typescript
interface SnoozeDurationPickerProps {
  userId: string;
  userName: string;
  open: boolean;
  onClose: () => void;
  onSnooze: (days: number) => void;
}

interface SnoozeBadgeProps {
  snoozedUntil: number;  // Unix timestamp
  onUnsnooze: () => void;
}

interface FollowingListItemProps {
  following: Following;
  onSnooze: (userId: string) => void;
  onUnsnooze: (userId: string) => void;
  onUnfollow: (userId: string) => void;
}
```

### 9.2 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface Following {
  // ... existing fields ...
  snoozed_until?: number | null;
}

export interface SnoozedFollowing {
  following_sub: string;
  following_name?: string;
  following_avatar_url?: string;
  followed_at: number;
  snoozed_until: number;
  snooze_remaining_hours?: number;
}

export interface SnoozedFollowingList {
  snoozed: SnoozedFollowing[];
  total: number;
}
```

### 9.3 Frontend API

**File**: `frontend/src/api/endpoints/social.ts`

```typescript
export const snoozeFollowing = (userId: string, days: number) =>
  api.post(`/ui/social/following/${userId}/snooze`, { days });

export const unsnoozeFollowing = (userId: string) =>
  api.delete(`/ui/social/following/${userId}/snooze`);

export const listSnoozedFollowings = () =>
  api.get<SnoozedFollowingList>("/ui/social/following/snoozed");
```

### 9.4 State Management

```typescript
// React Query keys
const SNOOZE_KEYS = {
  snoozed: ["social", "snoozed"] as const,
  following: ["social", "following"] as const,
};

const useSnoozeMutation = () => useMutation({
  mutationFn: ({ userId, days }: { userId: string; days: number }) =>
    snoozeFollowing(userId, days),
  onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: SNOOZE_KEYS.snoozed });
    queryClient.invalidateQueries({ queryKey: SNOOZE_KEYS.following });
    queryClient.invalidateQueries({ queryKey: ["feed"] });
    toast.success("User snoozed");
  },
});

const useUnsnoozeMutation = () => useMutation({
  mutationFn: (userId: string) => unsnoozeFollowing(userId),
  onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: SNOOZE_KEYS.snoozed });
    queryClient.invalidateQueries({ queryKey: SNOOZE_KEYS.following });
    queryClient.invalidateQueries({ queryKey: ["feed"] });
    toast.success("User unsnoozed");
  },
});
```

---

## 10. Observability & Monitoring

### 10.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `social_snooze_total` | Counter | `action` (snooze/unsnooze) | Total snooze/unsnooze operations |
| `social_snooze_duration_days` | Histogram | None | Distribution of chosen snooze durations |
| `social_feed_posts_filtered_total` | Counter | `reason` (snoozed) | Posts filtered from feed due to snooze |
| `social_notifications_suppressed_total` | Counter | `type` (new_post, etc.) | Notifications not sent due to snooze |

### 10.2 Log Events

| Event | Level | Fields | Trigger |
|-------|-------|--------|---------|
| `social.snooze_set` | INFO | `follower`, `following`, `days`, `snoozed_until` | User snoozes a following |
| `social.snooze_cleared` | INFO | `follower`, `following` | User unsnoozes |
| `social.snooze_auto_expired` | DEBUG | `follower`, `following` | Snooze naturally expired at query time |
| `social.notification_suppressed` | DEBUG | `follower`, `poster`, `alert_type` | Notification suppressed by snooze |

### 10.3 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High snooze rate | >30% of feed requests filter 5+ users | Info | Check for content quality issues |
| Snooze service errors | >1% error rate on snooze endpoints | Warning | Check DDB connectivity |

---

## 11. Rollout Plan

### Phase 1: Backend (Days 1-2)

- **Feature flag**: `SOCIAL_SNOOZE_ENABLED=false`
- Add `snoozed_until` field support to follow records
- Implement snooze/unsnooze/list service functions
- Add router endpoints
- Modify feed query to filter snoozed users
- Add notification suppression check
- Unit tests for snooze logic and feed filtering

### Phase 2: Frontend (Days 3-4)

- Add frontend types and API client
- Build SnoozeDurationPicker shared component
- Integrate snooze into profile page and following list
- Add snooze badge component
- **Feature flag**: `SOCIAL_SNOOZE_ENABLED=true`

### Phase 3: Testing & Polish (Day 5)

- Write E2E tests
- Verify auto-expiry behavior
- Test notification suppression
- Monitor snooze adoption metrics

### Rollback Procedure

1. Set `SOCIAL_SNOOZE_ENABLED=false` (hides UI components, disables endpoints)
2. Existing `snoozed_until` values remain in DDB but are ignored (feed filtering skipped)
3. No data migration needed for rollback
4. Re-enable by setting flag back to `true`

---

## 12. Performance Considerations

### 12.1 Latency Targets

| Operation | P50 Target | P99 Target | Notes |
|-----------|-----------|-----------|-------|
| Snooze/unsnooze | <100ms | <300ms | Single DDB UpdateItem |
| Feed with snooze filter | <250ms | <600ms | One extra in-memory filter step |
| List snoozed | <150ms | <400ms | Query + in-memory filter |
| is_snoozed check | <50ms | <150ms | Single DDB GetItem |

### 12.2 Caching Strategy

- **Snoozed user set**: Computed once per feed request, not cached across requests (followings change infrequently; per-request cost is acceptable)
- **Notification suppression**: `is_snoozed()` result cached per notification dispatch batch (multiple followers notified for one post)
- No persistent cache needed given DDB latency characteristics

### 12.3 Scalability

| Concern | Mitigation |
|---------|-----------|
| Extra query for snoozed followings per feed request | Single DDB query for all followings; in-memory filter for snoozed; results cached per request |
| Many snoozed followings | Cap at 90-day max; most users snooze few people; set intersection is O(n) but n is small |
| Notification suppression | `is_snoozed()` is a single DDB GetItem; acceptable latency for notification dispatch |
| Stale snoozed_until values | No cleanup needed; check-based expiry is zero-cost; optional periodic cleanup for DDB hygiene |

### 12.4 Query Cost Analysis

| Operation | DDB Reads | DDB Writes | Notes |
|-----------|-----------|------------|-------|
| Snooze a following | 1 (verify exists) | 1 (UpdateItem) | Single round-trip |
| Unsnooze a following | 0 | 1 (UpdateItem) | Idempotent, no read needed |
| List snoozed | 1 (query followings) | 0 | Filter in memory |
| Feed with snooze filter | 1 (query followings) + N (query posts) | 0 | N = number of non-snoozed followings |
| is_snoozed check | 1 (GetItem) | 0 | Per notification |
| Bulk notification dispatch (100 followers) | 100 (GetItem per follower) | 0 | Consider batch: get all followings for poster, filter in memory |

---

## 13. E2E Test Plan

### 13.1 Test File

`frontend/e2e/snooze-following.spec.ts` -- 24 tests across 6 sections.

### 13.2 Test Setup

```typescript
const TS = Date.now();

test.beforeAll(async ({ browser }) => {
  // Set up Alice and Bob sessions
  // Ensure Alice follows Bob
  // Bob creates a post (to verify feed filtering)
});
```

### 13.3 Section 323: Snooze API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 323.1 | Snooze a followed user for 7 days | POST `/social/following/{bob_id}/snooze` with `days=7`; 200; `snoozed_until` set to ~7 days from now |
| 323.2 | Snoozed user's posts filtered from feed | GET `/feed`; Bob's post NOT in results |
| 323.3 | Unsnooze a user | DELETE `/social/following/{bob_id}/snooze`; 200 |
| 323.4 | After unsnooze, posts reappear in feed | GET `/feed`; Bob's post IS in results |
| 323.5 | Cannot snooze unfollowed user | POST snooze for unfollowed user; 404 |

### 13.4 Section 324: Snoozed List & Management API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 324.1 | List snoozed followings | Snooze Bob; GET `/social/following/snoozed`; Bob in results with `snoozed_until` |
| 324.2 | Snoozed list empty after unsnooze | Unsnooze Bob; GET snoozed; empty array |
| 324.3 | Snooze duration options validated | POST with `days=0`; 422; POST with `days=91`; 422 |
| 324.4 | Re-snooze extends duration | Snooze for 3 days; snooze again for 7 days; `snoozed_until` updated to 7 days from now |

### 13.5 Section 325: Snooze UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 325.1 | Snooze button visible on followed user's profile | Navigate to Bob's profile; snooze option visible |
| 325.2 | Snooze indicator shown on snoozed user | After snoozing; badge showing "Snoozed until..." visible |
| 325.3 | Unsnooze button works | Click "Unsnooze"; badge disappears |

### 13.6 Section 325a: Notification Suppression (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 325a.1 | Snoozed user's new post does not generate notification | Snooze Bob; Bob creates post; Alice has no new_post notification for Bob |
| 325a.2 | Unsnoozed user's new post generates notification | Unsnooze Bob; Bob creates post; Alice receives notification |
| 325a.3 | Snooze does not suppress non-post notifications | Snooze Bob; Bob sends DM to Alice; Alice still receives DM notification |
| 325a.4 | Expired snooze generates notifications again | Snooze for 1 day; advance time past expiry; Bob posts; Alice receives notification |

### 13.7 Section 325b: Edge Cases (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 325b.1 | Snooze self returns 400 | POST snooze for own user ID; 400 |
| 325b.2 | Unfollow clears snooze implicitly | Snooze Bob; unfollow Bob; re-follow Bob; Bob not in snoozed list |
| 325b.3 | Multiple users can be snoozed simultaneously | Snooze Bob and Carol; both in snoozed list; both filtered from feed |
| 325b.4 | Snooze duration presets: 1, 3, 7, 30 days | Snooze with each preset; verify snoozed_until matches expected timestamp |

### 13.8 Section 325c: Auto-Expiry (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 325c.1 | Expired snooze not in snoozed list | Set snoozed_until in past via DDB; GET snoozed; user not in list |
| 325c.2 | Expired snooze allows posts in feed | Set snoozed_until in past; GET feed; user's posts appear |
| 325c.3 | is_snoozed returns false for expired | Set snoozed_until in past; internal check returns false |
| 325c.4 | Snooze with max duration (90 days) | POST with days=90; verify snoozed_until is ~90 days from now |

---

## 14. Security Considerations

- Users can only snooze their own followings (enforced by `ctx["user_sub"]` from session)
- Snoozed state is private (the snoozed user cannot see they've been snoozed)
- Snooze doesn't affect the follow relationship -- the followed user still sees follower count
- Auto-expiry is check-based (no background jobs needed)
- CSRF protection on POST/DELETE snooze endpoints (require x-csrf-token header)
- Cannot snooze yourself (server-side validation)

---

## 15. Implementation Plan

### 15.1 Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/components/shared/SnoozeDurationPicker.tsx` | Duration selection dialog (~100 lines) |
| `frontend/e2e/snooze-following.spec.ts` | E2E tests (~400 lines) |

### 15.2 Files to Modify

| File | Changes |
|------|---------|
| `app/services/social.py` | Add snooze/unsnooze functions, is_snoozed check (follow system lives here, not social_alerts.py) |
| `app/routers/social.py` | Add snooze/unsnooze/list-snoozed endpoints (follow endpoints are here at lines 139, 158, not in profile.py) |
| `app/routers/newsfeed.py` | Filter snoozed users' posts from feed |
| `app/models.py` | Add snooze Pydantic models |
| `frontend/src/api/types.ts` | Add snoozed fields to Following type |
| `frontend/src/api/endpoints/social.ts` | Add snooze API functions |
| `frontend/src/pages/settings/ProfilePage.tsx` | Add snooze button and indicator |
| `frontend/src/pages/settings/FollowingList.tsx` | Show snooze badges and unsnooze buttons |

### 15.3 Step-by-Step Order

1. Add `snoozed_until` field support to follow records
2. Implement snooze/unsnooze service functions
3. Add router endpoints
4. Modify feed query to filter snoozed users
5. Add notification suppression check
6. Add frontend types and API
7. Build SnoozeDurationPicker component
8. Integrate snooze into profile page and following list
9. Write E2E tests

---

## 16. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| Following system | Existing | Available — `app/services/social.py:31` (follow_user), `app/routers/social.py:139` (POST /follow) |
| Feed query | Existing | Available — `app/routers/newsfeed.py` (GET /feed) |
| Notification system | Existing | Available — `app/services/social_alerts.py` |

---

## Codebase References

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| Follow system in social_alerts.py / profile.py | `app/services/social.py`, `app/routers/social.py` | 31, 102 (service), 139, 158 (router) | **WRONG LOCATION** — follow system is in social.py, NOT in profile.py or social_alerts.py |
| Follow records use PK=FOLLOW#{follower}, SK=USER#{following} | `app/services/social.py` | 52, 70 | **WRONG KEY PATTERN** — actual keys are PK=`USER#{user_id}`, SK=`FOLLOWING#{followed_id}` |
| GSI5 for follower reverse lookups | `app/services/social.py` | 77, 148 | VERIFIED: `GSI5PK=FOLLOWERS#{followed_id}` |
| app_single_table used for follows | `app/services/social.py` | 19-20 | VERIFIED |
| social_alerts.py exists | `app/services/social_alerts.py` | — | VERIFIED (but does NOT contain follow system logic) |
| Snooze/snoozed_until not implemented | `app/services/social.py` | — | VERIFIED: no snooze-related code exists anywhere |
| Feed fan-out system | `app/services/newsfeed_fanout.py` | — | VERIFIED |
| now_ts() utility | `app/core/time.py` | — | VERIFIED |

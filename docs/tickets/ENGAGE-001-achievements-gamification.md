# ENGAGE-001: Achievements & Gamification System

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-28  
**Priority**: Medium  
**Estimated effort**: 12-16 days

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The platform has robust creator tools (broadcast, VOD, newsfeed, messaging, subscriptions) and monetization features (tips, locked content, pay-per-view) but **no gamification layer** to drive habitual engagement. Creators lack visible milestones to celebrate their growth, and viewers have no reward system that encourages continued participation beyond content consumption itself.

Competitor platforms use achievement systems extensively: Twitch has channel-point badges and streamer milestones; YouTube has creator awards and subscriber counters; Patreon highlights subscriber milestones. Without a gamification layer, the platform misses opportunities to:

1. **Increase creator retention** -- visible progress toward goals (posting streaks, subscriber milestones, earnings targets) provides motivational feedback loops.
2. **Increase viewer stickiness** -- badges and leaderboard positions give viewers status within the community.
3. **Surface social proof** -- achievement badges on profiles and in chat messages signal a user's engagement level to others.
4. **Drive specific behaviors** -- achievements can steer users toward underutilized features (e.g., "First Calendar Share", "First Encrypted Message").

### 1.2 How It Works

1. **Achievement definitions** are stored as configuration records in DynamoDB, each specifying a category, threshold(s), icon, and rarity tier.
2. A **progress tracker** evaluates user actions against achievement criteria. Some achievements are event-driven (unlock on first occurrence), others are cumulative (tip count reaches N).
3. When a threshold is met, an **achievement unlock** record is written and a notification is dispatched through the existing alert system.
4. Unlocked achievements appear as **badges on user profiles** and optionally as **flair in chat messages** (both broadcast chat and DM messaging).
5. A **leaderboard** aggregates achievement points per user within configurable time windows (weekly, monthly, all-time).

### 1.3 Design Principles

- **Non-intrusive**: Achievements are additive. Users who ignore them lose nothing. No feature is gated behind an achievement.
- **Auditable**: Every unlock is timestamped and attributed to a specific triggering event.
- **Extensible**: New achievement types can be added by inserting a definition row -- no code deployment required for simple threshold achievements.
- **Performance**: Progress checks are amortized. Counters are maintained via atomic DynamoDB increments (same pattern as tip goal progress), not computed by scanning history.

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to see my posting streak so I know if I'll lose my "Consistent Creator" badge. | Profile shows current streak count; badge appears when streak >= 7 days. |
| Creator | As a creator, I want to celebrate reaching 100 subscribers. | "Century Club" badge unlocks automatically; notification appears in alert stream. |
| Viewer | As a viewer, I want a badge for tipping 50 times so others can see I'm a generous supporter. | "Generous Tipper" badge appears on profile after 50 tips. |
| Viewer | As a viewer, I want to see my position on the weekly engagement leaderboard. | Leaderboard page shows rank based on achievement points earned this week. |
| Any user | As a user, I want badges to show next to my name in chat. | Broadcast chat and DM messages display up to 3 selected badge icons. |
| Creator | As a creator, I want to know how close I am to the next milestone so I can stay motivated. | Progress tracker page shows bar charts for each metric with current/threshold values. |
| Admin | As an admin, I want to create new achievement definitions without deploying code. | Admin UI allows inserting/editing achievement definition rows via DDB. |
| Any user | As a user, I want to receive a celebratory notification when I unlock an achievement. | SSE-delivered toast with confetti animation and badge icon. |

---

## 2. Current State Analysis

### 2.1 Alert System (`app/routers/alerts.py`, `app/services/alerts.py`) <!-- VERIFIED: app/services/alerts.py exists -->

The alert system already supports structured event dispatch, SSE delivery, and per-type preferences. The `ALERT_EVENT_TYPES` list in `app/services/alerts.py` (line 133) defines supported alert types: <!-- CORRECTED: was line 46, actually line 133 -->

```python
ALERT_EVENT_TYPES: List[str] = [
    "login_success","login_failure","mfa_success","mfa_failure","challenge_created","challenge_revoked",
    "challenge_failed","api_key_created","api_key_revoked","api_key_ip_rules_updated","session_revoked",
    "totp_device_added","totp_device_removed","rate_limited","access_denied","security_event",
    "device_new","device_location_mismatch","device_trust","device_revoke",
    "calendar_event_created","calendar_event_updated","calendar_event_deleted",
    "ticket_created","ticket_assigned","ticket_replied","ticket_status_changed","ticket_reopened",
    # Social notifications (SOC-004)
    "new_follower","post_liked","post_reaction","post_comment",
    "comment_reply","mention","subscription_started","post_shared",
    "post_tip","message_tip",
    "cart.abandoned",
]
```

Achievement unlock notifications will be added as a new event type (`achievement_unlocked`) to this list. The existing SSE infrastructure in `app/services/alerts.py` provides real-time delivery via `sse_publish_alert()` (see `app/services/alerts.py:173`): <!-- CORRECTED: sse_publish_alert is at line 173, not 84 -->

```python
def sse_publish_alert(user_sub: str, alert_obj: Dict[str, Any]) -> None:
    s = _SSE_SUBSCRIBERS.get(user_sub)
    if not s:
        return
    dead = []
    for q in list(s):
        try:
            q.put_nowait(alert_obj)
        except Exception:
            dead.append(q)
    for q in dead:
        sse_unsubscribe(user_sub, q)
```

The `audit_event` function (see `app/services/alerts.py:695`) handles writing alert rows and dispatching to channels. The unread count sentinel in `app/services/notification_unread.py` (line 26) uses atomic DynamoDB increments: <!-- CORRECTED: audit_event is at line 695, not 570. increment_unread_count at line 26 is correct. -->

```python
def increment_unread_count(user_sub: str, delta: int = 1) -> int:
    resp = T.alerts.update_item(
        Key={"user_sub": user_sub, "alert_id": _SENTINEL_SK},
        UpdateExpression="SET #c = if_not_exists(#c, :zero) + :delta, updated_at = :now",
        ...
    )
```

Achievement unlock alerts will use the same increment mechanism.

### 2.2 Tip Goal Tracking (`app/services/broadcast_tip_goals.py`) <!-- VERIFIED: app/services/broadcast_tip_goals.py exists -->

The tip goal system provides a proven pattern for **goal creation, progress tracking, and SSE event dispatch** that the achievement system can mirror. Key patterns from `broadcast_tip_goals.py`:

**Goal creation with max-per-entity limit** (line 20): <!-- VERIFIED: app/services/broadcast_tip_goals.py:20 -->
```python
def create_goal(*, session_id: str, label: str, target_cents: int, sort_order: int = 0, actor: str) -> Dict[str, Any]:
    existing = list_goals(session_id)
    max_goals = S.broadcast_max_goals_per_session
    if len(existing) >= max_goals:
        raise HTTPException(status_code=409, detail={"code": "MAX_GOALS_REACHED", ...})
```

**Atomic progress advance with overflow spillover** (line 98): <!-- VERIFIED: app/services/broadcast_tip_goals.py:98 -->
```python
def advance_goal_progress(session_id: str, tip_amount_cents: int) -> List[Dict[str, Any]]:
    remaining = tip_amount_cents
    for goal in goals:
        if remaining <= 0 or goal.get("reached"):
            continue
        capacity = max(0, target - current)
        applied = min(remaining, capacity)
        remaining -= applied
        # Atomic update
        T.broadcast_tip_goals.update_item(
            Key={"session_id": session_id, "goal_id": goal["goal_id"]},
            UpdateExpression="SET " + ", ".join(update_parts),
            ExpressionAttributeValues=expr_vals,
        )
```

**SSE event dispatch on milestone** (line 164): <!-- VERIFIED: app/services/broadcast_tip_goals.py:164 -->
```python
broadcast_sse_publish(session_id, {"_type": "goal:progress", **goal_out, "tip_applied_cents": applied})
if reached_now:
    broadcast_sse_publish(session_id, {"_type": "goal:reached", **goal_out})
```

The achievement system will use the same atomic-increment + threshold-check + SSE-publish pattern for cumulative achievements.

### 2.3 Profile System (`frontend/src/pages/settings/ProfilePage.tsx`) <!-- VERIFIED: frontend/src/pages/settings/ProfilePage.tsx exists -->

The profile page currently displays tabs for Profile, Posts, Addresses, and Activity:

```tsx
export default function ProfilePage() {
  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 sm:p-6">
        <Tabs defaultValue="profile">
          <TabsList>
            <TabsTrigger value="profile">Profile</TabsTrigger>
            {profilePostsEnabled ? <TabsTrigger value="posts">Posts</TabsTrigger> : null}
            <TabsTrigger value="addresses">Addresses</TabsTrigger>
            <TabsTrigger value="activity">Activity</TabsTrigger>
          </TabsList>
```

Achievement badges will be added to the Profile tab (`frontend/src/pages/settings/Profile.tsx`), which uses React Query to fetch and display user data: <!-- VERIFIED: frontend/src/pages/settings/Profile.tsx:59-62 -->

```tsx
const profileQuery = useQuery({
    queryKey: ["profile"],
    queryFn: getProfile,
});
```

A new "Achievements" tab will be added alongside the existing tabs, and a badge showcase section will be added to the Profile component itself.

### 2.4 Social Alert Emission (`app/services/social_alerts.py`) <!-- VERIFIED: app/services/social_alerts.py exists -->

The social alert system provides batching and per-type preference checks. `SOCIAL_ALERT_TYPES` (line 32) lists supported social notifications: <!-- VERIFIED: app/services/social_alerts.py:32 -->

```python
SOCIAL_ALERT_TYPES: List[str] = [
    "new_follower", "post_liked", "post_reaction", "post_comment",
    "comment_reply", "mention", "subscription_started", "post_shared",
    "post_tip", "message_tip",
]
```

The `_is_alert_type_enabled` helper (line 64) checks per-user opt-out preferences before emitting: <!-- VERIFIED: app/services/social_alerts.py:64 -->

```python
def _is_alert_type_enabled(user_sub: str, alert_type: str) -> bool:
    prefs = get_alert_prefs(user_sub)
    type_prefs: Dict[str, Any] = prefs.get("type_preferences", {})
    type_pref: Dict[str, Any] = type_prefs.get(alert_type, {})
    return type_pref.get("enabled", True)
```

Achievement unlock notifications will integrate with this system, allowing users to disable achievement alerts while keeping other social notifications active.

### 2.5 Broadcast Chat Message Output (`app/services/broadcast_chat_store.py`) <!-- VERIFIED: app/services/broadcast_chat_store.py exists -->

Chat messages already carry sender metadata via `_chat_msg_out()` (line 344): <!-- VERIFIED: app/services/broadcast_chat_store.py:344 -->

```python
def _chat_msg_out(item: Dict[str, Any], viewer_user_id: Optional[str] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "message_id": item["message_id"],
        "session_id": item["session_id"],
        "sender_id": sender_id,
        "sender_display_name": item.get("sender_display_name", ""),
        "text": item.get("text", ""),
        "kind": item.get("kind", "text"),
        ...
    }
```

Badge flair will be added as a `sender_badges` field to this output, populated by looking up the sender's selected display badges.

### 2.6 DM Messaging Output (`app/routers/messaging.py`) <!-- VERIFIED: app/routers/messaging.py exists, _message_out_from_item at line 3766 -->

The DM messaging system serializes messages via `_message_out_from_item()` (line 3766). This function already includes sender metadata fields. The `sender_badges` field will be injected here as well, following the same pattern as broadcast chat. The badges are resolved by a lightweight cache lookup (see section 3.6) to avoid per-message DDB queries.

### 2.7 Newsfeed Post Actions (`app/routers/newsfeed.py`)

The newsfeed router handles post creation, commenting, tipping, and reactions. Each of these actions is a potential achievement trigger. The post creation endpoint (see `app/routers/newsfeed.py:3013`) writes the post item and feed reference: <!-- CORRECTED: was "line ~1400", then corrected to 2975, actually line 3013. Signature is `def create_post(req: CreatePostRequest, user_id: UserIdDep)`, not `async def create_post(...ctx: dict = Depends(require_ui_session))` -->

```python
@router.post("/posts", status_code=200)
def create_post(req: CreatePostRequest, user_id: UserIdDep):  # NOTE: not async, uses UserIdDep not Depends(require_ui_session)
    user_id = ctx["user_sub"]
    post_id = f"p_{uuid4().hex}"
    # ... post creation logic ...
    ddb_put_item(post_item)
    _write_feed_ref_for_published_post(user_id=user_id, post_id=post_id, created_at=created_at)
    # Achievement hook point:
    # advance_achievement_progress(user_id, "post_count", delta=1)
    # update_achievement_streak(user_id, "posting_streak")
```

---

## 3. Technical Design

### 3.1 DynamoDB Schema

**Table: `achievements`**

Stores achievement definition records. These are admin-managed configuration data.

| Field | Type | Key | Description |
|-------|------|-----|-------------|
| `achievement_id` | S | PK | Unique ID, e.g. `ach_posting_streak_7` |
| `category` | S | | `creator` or `viewer` |
| `subcategory` | S | | e.g. `posting`, `tipping`, `watching`, `earnings` |
| `label` | S | | Human-readable name, e.g. "Week Warrior" |
| `description` | S | | Description of how to earn it |
| `icon_url` | S | | URL to badge icon asset (must be same-origin) |
| `rarity` | S | | `common`, `uncommon`, `rare`, `epic`, `legendary` |
| `threshold` | N | | Numeric target (e.g., 7 for a 7-day streak) |
| `points` | N | | Achievement points awarded on unlock |
| `metric_key` | S | | Counter key to track, e.g. `posting_streak`, `tip_count` |
| `active` | BOOL | | Whether this achievement is currently earnable |
| `sort_order` | N | | Display ordering within category |
| `created_at` | N | | Unix timestamp |
| `updated_at` | N | | Unix timestamp of last modification |
| `GSI1PK` | S | GSI | `METRIC#{metric_key}` for listing definitions by metric |
| `GSI1SK` | S | GSI | `{threshold}` for ordering by threshold within metric |

DynamoDB table definition for `scripts/local-ddb-init.py`:

```python
TableDef(
    "achievements",
    "achievement_id",
    gsi=[
        {"index_name": "ByMetric", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
    attr_types={"GSI1SK": "N"},
),
```

**Table: `user_achievements`**

Stores per-user unlock records. One row per (user, achievement) pair.

| Field | Type | Key | Description |
|-------|------|-----|-------------|
| `user_sub` | S | PK | User who earned the achievement |
| `achievement_id` | S | SK | Which achievement was earned |
| `unlocked_at` | N | | Unix timestamp of unlock |
| `trigger_event` | S | | Event that triggered the unlock, e.g. `posting_streak:7` |
| `points` | N | | Points earned (denormalized from definition) |
| `displayed` | BOOL | | Whether user has this badge in their display set |
| `label` | S | | Denormalized label for fast reads |
| `icon_url` | S | | Denormalized icon URL for fast reads |
| `rarity` | S | | Denormalized rarity for fast reads |
| `GSI1PK` | S | GSI | `LEADERBOARD#{period}` for leaderboard queries |
| `GSI1SK` | S | GSI | `{points_total_padded}#{user_sub}` for leaderboard ranking |
| `GSI2PK` | S | GSI | `DISPLAY#{user_sub}` for fetching displayed badges |
| `GSI2SK` | S | GSI | `{sort_order}` for badge display ordering |

DynamoDB table definition:

```python
TableDef(
    "user_achievements",
    "user_sub",
    "achievement_id",
    gsi=[
        {"index_name": "ByLeaderboard", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
        {"index_name": "ByDisplay", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
    ],
    attr_types={"GSI1SK": "S", "GSI2SK": "N"},
),
```

**Table: `user_achievement_progress`**

Tracks per-user metric counters.

| Field | Type | Key | Description |
|-------|------|-----|-------------|
| `user_sub` | S | PK | User being tracked |
| `metric_key` | S | SK | Counter key, e.g. `posting_streak`, `tip_count` |
| `current_value` | N | | Current counter value |
| `last_updated_at` | N | | Last time this counter was incremented |
| `last_updated_date` | S | | ISO date string of last update (for streak calculations) |
| `streak_anchor_date` | S | | For streak metrics: the date the current streak started |
| `highest_value` | N | | All-time high for this metric (for "personal best" display) |

DynamoDB table definition:

```python
TableDef(
    "user_achievement_progress",
    "user_sub",
    "metric_key",
),
```

**Table: `achievement_leaderboard`**

Denormalized leaderboard records for fast ranking queries.

| Field | Type | Key | Description |
|-------|------|-----|-------------|
| `period_key` | S | PK | `weekly#2026-W22`, `monthly#2026-05`, or `alltime` |
| `user_sub` | S | SK | User ID |
| `total_points` | N | | Points accumulated in this period |
| `achievement_count` | N | | Number of achievements unlocked in this period |
| `display_name` | S | | Denormalized for display |
| `display_badges` | L | | List of badge {achievement_id, icon_url, rarity} |
| `updated_at` | N | | Last update timestamp |
| `GSI1PK` | S | GSI | Same as `period_key` |
| `GSI1SK` | N | GSI | `total_points` (numeric for descending sort) |

DynamoDB table definition:

```python
TableDef(
    "achievement_leaderboard",
    "period_key",
    "user_sub",
    gsi=[
        {"index_name": "ByPoints", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
    attr_types={"GSI1SK": "N"},
),
```

### 3.2 Achievement Categories

**Creator Achievements:**

| Achievement | Metric Key | Thresholds | Rarity | Points |
|------------|-----------|------------|--------|--------|
| First Post | `post_count` | 1 | Common | 10 |
| Regular Poster (10 posts) | `post_count` | 10 | Common | 25 |
| Prolific Creator (100 posts) | `post_count` | 100 | Uncommon | 100 |
| Content Machine (500 posts) | `post_count` | 500 | Rare | 250 |
| Content Legend (1000 posts) | `post_count` | 1000 | Epic | 500 |
| Week Warrior (7-day streak) | `posting_streak` | 7 | Uncommon | 50 |
| Month Marathon (30-day streak) | `posting_streak` | 30 | Rare | 200 |
| Year of Dedication (365-day streak) | `posting_streak` | 365 | Legendary | 1000 |
| Century Club (100 subscribers) | `subscriber_count` | 100 | Uncommon | 100 |
| Thousand Strong | `subscriber_count` | 1000 | Rare | 300 |
| Ten Thousand Club | `subscriber_count` | 10000 | Epic | 750 |
| First $100 Earned | `earnings_cents` | 10000 | Uncommon | 75 |
| $1K Milestone | `earnings_cents` | 100000 | Rare | 200 |
| $10K Milestone | `earnings_cents` | 1000000 | Epic | 500 |
| Live Legend (100 broadcasts) | `broadcast_count` | 100 | Epic | 300 |
| First Broadcast | `broadcast_count` | 1 | Common | 10 |
| Event Organizer (10 calendar events) | `calendar_event_count` | 10 | Uncommon | 50 |
| First Encrypted Message | `encrypted_message_count` | 1 | Common | 15 |
| First Calendar Share | `calendar_share_count` | 1 | Common | 10 |

**Viewer Achievements:**

| Achievement | Metric Key | Thresholds | Rarity | Points |
|------------|-----------|------------|--------|--------|
| First Tip | `tip_count` | 1 | Common | 10 |
| Generous Tipper (50 tips) | `tip_count` | 50 | Uncommon | 100 |
| Whale (500 tips) | `tip_count` | 500 | Epic | 500 |
| Big Spender ($100 tipped) | `tip_total_cents` | 10000 | Uncommon | 100 |
| Patron ($1000 tipped) | `tip_total_cents` | 100000 | Rare | 300 |
| Comment Streak (7 days) | `comment_streak` | 7 | Uncommon | 50 |
| Comment Streak (30 days) | `comment_streak` | 30 | Rare | 200 |
| Binge Watcher (10 hours) | `watch_minutes` | 600 | Uncommon | 75 |
| Marathon Viewer (100 hours) | `watch_minutes` | 6000 | Rare | 200 |
| First Unlock | `unlock_count` | 1 | Common | 10 |
| Collector (50 unlocks) | `unlock_count` | 50 | Uncommon | 100 |
| Social Butterfly (follow 50) | `follow_count` | 50 | Uncommon | 75 |
| Community Builder (follow 200) | `follow_count` | 200 | Rare | 200 |
| First Reaction | `reaction_count` | 1 | Common | 5 |
| Reaction King (1000 reactions) | `reaction_count` | 1000 | Rare | 150 |
| Clip Creator (first clip) | `clip_count` | 1 | Common | 10 |
| Clip Master (50 clips) | `clip_count` | 50 | Uncommon | 100 |

### 3.3 Progress Tracking Engine

The progress tracker follows the tip-goal atomic increment pattern:

```python
# app/services/achievement_progress.py

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import sse_publish_alert
from app.services.social_alerts import _is_alert_type_enabled

logger = logging.getLogger(__name__)

# Feature flag check
def _achievements_enabled() -> bool:
    return getattr(S, "achievements_enabled", False)


def advance_progress(user_sub: str, metric_key: str, delta: int = 1) -> List[Dict[str, Any]]:
    """Atomically increment a user's progress counter and check for unlocks.

    Returns list of newly unlocked achievements (may be empty).
    Side effects: writes unlock rows, updates leaderboard, emits SSE alerts.
    """
    if not _achievements_enabled():
        return []

    # Atomic increment
    resp = T.user_achievement_progress.update_item(
        Key={"user_sub": user_sub, "metric_key": metric_key},
        UpdateExpression=(
            "SET current_value = if_not_exists(current_value, :zero) + :delta, "
            "last_updated_at = :now, "
            "last_updated_date = :today, "
            "highest_value = if_not_exists(highest_value, :zero)"
        ),
        ExpressionAttributeValues={
            ":delta": delta,
            ":zero": 0,
            ":now": now_ts(),
            ":today": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        },
        ReturnValues="ALL_NEW",
    )
    attrs = resp["Attributes"]
    new_value = int(attrs["current_value"])

    # Update highest_value if new_value exceeds it
    highest = int(attrs.get("highest_value", 0))
    if new_value > highest:
        T.user_achievement_progress.update_item(
            Key={"user_sub": user_sub, "metric_key": metric_key},
            UpdateExpression="SET highest_value = :hv",
            ConditionExpression="highest_value < :hv OR attribute_not_exists(highest_value)",
            ExpressionAttributeValues={":hv": new_value},
        )

    # Check thresholds
    definitions = _list_achievements_for_metric(metric_key)
    already_unlocked = _get_user_achievement_ids(user_sub)
    newly_unlocked = []

    for defn in definitions:
        ach_id = defn["achievement_id"]
        if ach_id in already_unlocked:
            continue
        threshold = int(defn["threshold"])
        if new_value >= threshold:
            unlock = _unlock_achievement(
                user_sub, defn,
                trigger_event=f"{metric_key}:{new_value}",
            )
            newly_unlocked.append(unlock)

    return newly_unlocked


def update_streak(user_sub: str, metric_key: str) -> int:
    """Update a daily streak counter. Returns the new streak value.

    A streak increments when the user performs the action on a new calendar day (UTC).
    If they skip a day, the streak resets to 1. Same-day duplicate calls are idempotent.

    After updating the streak, also calls advance_progress to check for
    streak-based achievements.
    """
    if not _achievements_enabled():
        return 0

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Read current progress
    resp = T.user_achievement_progress.get_item(
        Key={"user_sub": user_sub, "metric_key": metric_key},
    )
    progress = resp.get("Item")

    if progress is None:
        # First ever action -- start streak at 1
        T.user_achievement_progress.put_item(Item={
            "user_sub": user_sub,
            "metric_key": metric_key,
            "current_value": 1,
            "last_updated_at": now_ts(),
            "last_updated_date": today,
            "streak_anchor_date": today,
            "highest_value": 1,
        })
        _check_streak_unlocks(user_sub, metric_key, 1)
        return 1

    last_date = progress.get("last_updated_date", "")
    if last_date == today:
        return int(progress["current_value"])  # Already counted today

    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    if last_date == yesterday:
        # Streak continues
        new_value = int(progress["current_value"]) + 1
        anchor = progress.get("streak_anchor_date", today)
    else:
        # Streak broken, reset
        new_value = 1
        anchor = today

    # Update atomically
    highest = max(new_value, int(progress.get("highest_value", 0)))
    T.user_achievement_progress.update_item(
        Key={"user_sub": user_sub, "metric_key": metric_key},
        UpdateExpression=(
            "SET current_value = :val, "
            "last_updated_at = :now, "
            "last_updated_date = :today, "
            "streak_anchor_date = :anchor, "
            "highest_value = :highest"
        ),
        ExpressionAttributeValues={
            ":val": new_value,
            ":now": now_ts(),
            ":today": today,
            ":anchor": anchor,
            ":highest": highest,
        },
    )

    _check_streak_unlocks(user_sub, metric_key, new_value)
    return new_value


def _check_streak_unlocks(user_sub: str, metric_key: str, streak_value: int) -> None:
    """Check if any streak-based achievements should unlock."""
    definitions = _list_achievements_for_metric(metric_key)
    already_unlocked = _get_user_achievement_ids(user_sub)

    for defn in definitions:
        ach_id = defn["achievement_id"]
        if ach_id in already_unlocked:
            continue
        if streak_value >= int(defn["threshold"]):
            _unlock_achievement(
                user_sub, defn,
                trigger_event=f"{metric_key}:{streak_value}",
            )


def get_progress(user_sub: str, metric_key: str) -> Optional[Dict[str, Any]]:
    """Get a single progress record."""
    resp = T.user_achievement_progress.get_item(
        Key={"user_sub": user_sub, "metric_key": metric_key},
    )
    item = resp.get("Item")
    if not item:
        return None
    return _progress_out(item)


def list_all_progress(user_sub: str) -> List[Dict[str, Any]]:
    """List all progress counters for a user."""
    resp = T.user_achievement_progress.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub),
    )
    return [_progress_out(item) for item in resp.get("Items", [])]


def _progress_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "metric_key": item["metric_key"],
        "current_value": int(item.get("current_value", 0)),
        "last_updated_at": int(item.get("last_updated_at", 0)),
        "last_updated_date": item.get("last_updated_date", ""),
        "streak_anchor_date": item.get("streak_anchor_date"),
        "highest_value": int(item.get("highest_value", 0)),
    }
```

### 3.4 Achievement Unlock Logic

```python
# Continued in app/services/achievement_progress.py

def _unlock_achievement(
    user_sub: str,
    defn: Dict[str, Any],
    trigger_event: str,
) -> Dict[str, Any]:
    """Write an unlock record and emit notifications.

    Uses ConditionExpression to ensure idempotency -- two concurrent threads
    triggering the same achievement will not produce duplicate unlocks.
    """
    ach_id = defn["achievement_id"]
    ts = now_ts()
    points = int(defn.get("points", 0))

    unlock_item = {
        "user_sub": user_sub,
        "achievement_id": ach_id,
        "unlocked_at": ts,
        "trigger_event": trigger_event,
        "points": points,
        "displayed": False,
        "label": defn.get("label", ""),
        "icon_url": defn.get("icon_url", ""),
        "rarity": defn.get("rarity", "common"),
    }

    try:
        T.user_achievements.put_item(
            Item=unlock_item,
            ConditionExpression="attribute_not_exists(achievement_id)",
        )
    except T.user_achievements.meta.client.exceptions.ConditionalCheckFailedException:
        # Already unlocked (concurrent race condition). Return existing.
        existing = T.user_achievements.get_item(
            Key={"user_sub": user_sub, "achievement_id": ach_id},
        ).get("Item", {})
        return _unlock_out(existing)

    # Update leaderboard
    _update_leaderboard(user_sub, points)

    # Emit alert notification
    _emit_achievement_alert(user_sub, defn, trigger_event, ts)

    logger.info(
        "Achievement unlocked: user=%s achievement=%s trigger=%s",
        user_sub, ach_id, trigger_event,
    )

    return _unlock_out(unlock_item)


def _emit_achievement_alert(
    user_sub: str,
    defn: Dict[str, Any],
    trigger_event: str,
    ts: int,
) -> None:
    """Emit an achievement unlock alert via SSE and persist to alerts table."""
    if not _is_alert_type_enabled(user_sub, "achievement_unlocked"):
        return

    alert_obj = {
        "alert_id": f"ach_{uuid4().hex[:12]}",
        "event_type": "achievement_unlocked",
        "user_sub": user_sub,
        "created_at": ts,
        "data": {
            "achievement_id": defn["achievement_id"],
            "label": defn.get("label", ""),
            "description": defn.get("description", ""),
            "icon_url": defn.get("icon_url", ""),
            "rarity": defn.get("rarity", "common"),
            "points": int(defn.get("points", 0)),
            "trigger_event": trigger_event,
        },
    }

    # Persist to alerts table <!-- CORRECTED: write_alert actual signature is write_alert(user_sub, *, event, outcome, title, details) at line 355, not 266. Must use keyword args. -->
    from app.services.alerts import write_alert
    write_alert(user_sub, event="achievement_unlocked", outcome="success", title=defn.get("label", ""), details=alert_obj.get("data", {}))

    # SSE push
    sse_publish_alert(user_sub, alert_obj)


def _update_leaderboard(user_sub: str, points: int) -> None:
    """Update all leaderboard periods (weekly, monthly, alltime) with new points."""
    now = datetime.now(timezone.utc)
    week = now.strftime("%Y-W%W")
    month = now.strftime("%Y-%m")

    for period_key in [f"weekly#{week}", f"monthly#{month}", "alltime"]:
        T.achievement_leaderboard.update_item(
            Key={"period_key": period_key, "user_sub": user_sub},
            UpdateExpression=(
                "SET total_points = if_not_exists(total_points, :zero) + :pts, "
                "achievement_count = if_not_exists(achievement_count, :zero) + :one, "
                "updated_at = :now, "
                "GSI1PK = :pk, "
                "GSI1SK = if_not_exists(GSI1SK, :zero) + :pts"
            ),
            ExpressionAttributeValues={
                ":pts": points,
                ":one": 1,
                ":zero": 0,
                ":now": now_ts(),
                ":pk": period_key,
            },
        )
```

### 3.5 Badge Display Logic

```python
# app/services/achievement_badges.py

from __future__ import annotations
from typing import Any, Dict, List
from boto3.dynamodb.conditions import Key
from fastapi import HTTPException
from app.core.tables import T
from app.core.time import now_ts

MAX_DISPLAY_BADGES = 3


def set_display_badges(user_sub: str, achievement_ids: List[str]) -> List[Dict[str, Any]]:
    """Set which badges the user displays (max 3).

    Validates all achievement_ids are unlocked by the user.
    Clears previous display selections and sets new ones.
    """
    if len(achievement_ids) > MAX_DISPLAY_BADGES:
        raise HTTPException(400, f"maximum {MAX_DISPLAY_BADGES} display badges")

    # Validate all achievements are unlocked
    for ach_id in achievement_ids:
        resp = T.user_achievements.get_item(
            Key={"user_sub": user_sub, "achievement_id": ach_id},
        )
        if not resp.get("Item"):
            raise HTTPException(400, f"achievement {ach_id} not unlocked")

    # Clear all current display flags
    current = _get_all_user_achievements(user_sub)
    for ach in current:
        if ach.get("displayed"):
            T.user_achievements.update_item(
                Key={"user_sub": user_sub, "achievement_id": ach["achievement_id"]},
                UpdateExpression="SET displayed = :f",
                ExpressionAttributeValues={":f": False},
            )

    # Set new display flags
    results = []
    for i, ach_id in enumerate(achievement_ids):
        T.user_achievements.update_item(
            Key={"user_sub": user_sub, "achievement_id": ach_id},
            UpdateExpression="SET displayed = :t, GSI2PK = :dpk, GSI2SK = :dsk",
            ExpressionAttributeValues={
                ":t": True,
                ":dpk": f"DISPLAY#{user_sub}",
                ":dsk": i,
            },
        )
        item = T.user_achievements.get_item(
            Key={"user_sub": user_sub, "achievement_id": ach_id},
        ).get("Item", {})
        results.append(_unlock_out(item))

    # Update badge cache
    _invalidate_badge_cache(user_sub)

    return results


def get_display_badges(user_sub: str) -> List[Dict[str, Any]]:
    """Get badges the user has chosen to display (max 3)."""
    resp = T.user_achievements.query(
        IndexName="ByDisplay",
        KeyConditionExpression=Key("GSI2PK").eq(f"DISPLAY#{user_sub}"),
        ScanIndexForward=True,
    )
    return [_badge_summary(item) for item in resp.get("Items", [])]


def _badge_summary(item: Dict[str, Any]) -> Dict[str, Any]:
    """Minimal badge representation for inline display."""
    return {
        "achievement_id": item.get("achievement_id", ""),
        "label": item.get("label", ""),
        "icon_url": item.get("icon_url", ""),
        "rarity": item.get("rarity", "common"),
    }
```

### 3.6 Badge Flair Cache

To avoid per-message DDB queries when rendering chat messages with badge flair, the system maintains an in-memory TTL cache of display badges per user:

```python
# app/services/achievement_badge_cache.py

from __future__ import annotations
import threading
import time
from typing import Any, Dict, List, Optional

_BADGE_CACHE: Dict[str, Dict[str, Any]] = {}  # user_sub -> {badges: [...], expires_at: int}
_BADGE_CACHE_LOCK = threading.Lock()
_BADGE_CACHE_TTL = 300  # 5 minutes

def get_cached_badges(user_sub: str) -> List[Dict[str, Any]]:
    """Get display badges from cache, falling back to DDB on miss."""
    with _BADGE_CACHE_LOCK:
        entry = _BADGE_CACHE.get(user_sub)
        if entry and entry["expires_at"] > int(time.time()):
            return entry["badges"]

    # Cache miss -- fetch from DDB
    from app.services.achievement_badges import get_display_badges
    badges = get_display_badges(user_sub)

    with _BADGE_CACHE_LOCK:
        _BADGE_CACHE[user_sub] = {
            "badges": badges,
            "expires_at": int(time.time()) + _BADGE_CACHE_TTL,
        }

    return badges


def _invalidate_badge_cache(user_sub: str) -> None:
    """Invalidate cache when user changes their display badges."""
    with _BADGE_CACHE_LOCK:
        _BADGE_CACHE.pop(user_sub, None)
```

### 3.7 Integration Points <!-- CORRECTED: create_post at newsfeed.py:3013 (not 2975), transition_session_status at broadcast_store.py:336 (not 326), _message_out_from_item at messaging.py:3766 (correct) -->

Achievement progress must be advanced at the point of action. Key integration points with existing code:

| Action | File | Function | Integration Code |
|--------|------|----------|-----------------|
| New post created | `app/routers/newsfeed.py` | `create_post` | `advance_progress(user_id, "post_count"); update_streak(user_id, "posting_streak")` |
| Tip sent | `app/routers/messaging.py` | `/messages/{id}/tip` handler | `advance_progress(tipper_sub, "tip_count"); advance_progress(tipper_sub, "tip_total_cents", delta=amount)` |
| Broadcast started | `app/routers/broadcast.py` | `transition_session_status("live")` | `advance_progress(creator_sub, "broadcast_count")` |
| Subscription started | `app/services/subscription_access.py` | subscription record created | `advance_progress(creator_sub, "subscriber_count")` |
| Comment posted | `app/routers/newsfeed.py` | comment create handler | `advance_progress(user_id, "comment_count"); update_streak(user_id, "comment_streak")` |
| Follow action | `app/routers/newsfeed.py` | follow handler | `advance_progress(follower_sub, "follow_count")` |
| Content unlocked | `app/routers/newsfeed.py` | unlock handler | `advance_progress(user_id, "unlock_count")` |
| Reaction sent | `app/routers/newsfeed.py` | react handler | `advance_progress(user_id, "reaction_count")` |
| Encrypted message | `app/routers/messaging.py` | message with encryption | `advance_progress(user_id, "encrypted_message_count")` |
| Calendar share | `app/routers/messaging.py` | calendar-share handler | `advance_progress(user_id, "calendar_share_count")` |
| Clip created | `app/routers/broadcast.py` | clip creation handler | `advance_progress(user_id, "clip_count")` |

**Integration pattern** (example for post creation):

```python
# In app/routers/newsfeed.py, at the end of create_post:
try:
    from app.services.achievement_progress import advance_progress, update_streak
    advance_progress(user_id, "post_count", delta=1)
    update_streak(user_id, "posting_streak")
except Exception:
    logger.warning("Achievement progress update failed", exc_info=True)
    # Non-critical -- never fail the main action
```

### 3.8 Achievement Definition Management

```python
# app/services/achievement_definitions.py

from __future__ import annotations
from typing import Any, Dict, List, Optional
from boto3.dynamodb.conditions import Key
from fastapi import HTTPException
from app.core.tables import T
from app.core.time import now_ts

def create_definition(
    *,
    achievement_id: str,
    category: str,
    subcategory: str,
    label: str,
    description: str,
    icon_url: str,
    rarity: str,
    threshold: int,
    points: int,
    metric_key: str,
    sort_order: int = 0,
) -> Dict[str, Any]:
    """Create a new achievement definition (admin only)."""
    # Validate rarity
    valid_rarities = {"common", "uncommon", "rare", "epic", "legendary"}
    if rarity not in valid_rarities:
        raise HTTPException(400, f"rarity must be one of {valid_rarities}")

    # Validate category
    if category not in ("creator", "viewer", "general"):
        raise HTTPException(400, "category must be creator, viewer, or general")

    # Validate icon URL is same-origin
    if icon_url and not icon_url.startswith("/"):
        raise HTTPException(400, "icon_url must be a relative path (same-origin)")

    ts = now_ts()
    item = {
        "achievement_id": achievement_id,
        "category": category,
        "subcategory": subcategory,
        "label": label,
        "description": description,
        "icon_url": icon_url,
        "rarity": rarity,
        "threshold": threshold,
        "points": points,
        "metric_key": metric_key,
        "active": True,
        "sort_order": sort_order,
        "created_at": ts,
        "updated_at": ts,
        "GSI1PK": f"METRIC#{metric_key}",
        "GSI1SK": threshold,
    }

    # Prevent duplicates
    try:
        T.achievements.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(achievement_id)",
        )
    except T.achievements.meta.client.exceptions.ConditionalCheckFailedException:
        raise HTTPException(409, f"achievement {achievement_id} already exists")

    return _definition_out(item)


def update_definition(
    achievement_id: str,
    **updates: Any,
) -> Dict[str, Any]:
    """Update fields on an existing achievement definition."""
    allowed_fields = {
        "label", "description", "icon_url", "rarity", "threshold",
        "points", "active", "sort_order", "subcategory",
    }
    filtered = {k: v for k, v in updates.items() if k in allowed_fields and v is not None}
    if not filtered:
        raise HTTPException(400, "no valid fields to update")

    parts = []
    vals: Dict[str, Any] = {":now": now_ts()}
    names: Dict[str, str] = {}
    for k, v in filtered.items():
        placeholder = f":v_{k}"
        name_placeholder = f"#n_{k}"
        parts.append(f"{name_placeholder} = {placeholder}")
        vals[placeholder] = v
        names[name_placeholder] = k

    parts.append("updated_at = :now")

    # If threshold changed, update GSI1SK too
    if "threshold" in filtered:
        parts.append("GSI1SK = :v_threshold")

    T.achievements.update_item(
        Key={"achievement_id": achievement_id},
        UpdateExpression="SET " + ", ".join(parts),
        ExpressionAttributeValues=vals,
        ExpressionAttributeNames=names,
        ConditionExpression="attribute_exists(achievement_id)",
    )

    return get_definition(achievement_id)


def get_definition(achievement_id: str) -> Dict[str, Any]:
    resp = T.achievements.get_item(Key={"achievement_id": achievement_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, "achievement not found")
    return _definition_out(item)


def list_definitions(active_only: bool = True) -> List[Dict[str, Any]]:
    """List all achievement definitions, optionally filtered to active only."""
    resp = T.achievements.scan()
    items = resp.get("Items", [])
    if active_only:
        items = [i for i in items if i.get("active", True)]
    items.sort(key=lambda i: (i.get("category", ""), int(i.get("sort_order", 0))))
    return [_definition_out(i) for i in items]


def _list_achievements_for_metric(metric_key: str) -> List[Dict[str, Any]]:
    """List active achievement definitions for a given metric key."""
    resp = T.achievements.query(
        IndexName="ByMetric",
        KeyConditionExpression=Key("GSI1PK").eq(f"METRIC#{metric_key}"),
        ScanIndexForward=True,
    )
    return [
        _definition_out(item)
        for item in resp.get("Items", [])
        if item.get("active", True)
    ]


def _definition_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "achievement_id": item.get("achievement_id", ""),
        "category": item.get("category", ""),
        "subcategory": item.get("subcategory", ""),
        "label": item.get("label", ""),
        "description": item.get("description", ""),
        "icon_url": item.get("icon_url", ""),
        "rarity": item.get("rarity", "common"),
        "threshold": int(item.get("threshold", 0)),
        "points": int(item.get("points", 0)),
        "metric_key": item.get("metric_key", ""),
        "active": bool(item.get("active", True)),
        "sort_order": int(item.get("sort_order", 0)),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }
```

### 3.9 Leaderboard Queries

```python
# app/services/achievement_leaderboard.py

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.core.cursor import encode_cursor, decode_cursor


def get_leaderboard(
    period: str = "weekly",
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Get ranked leaderboard for a time period.

    period: "weekly", "monthly", or "alltime"
    Returns (entries, next_cursor).
    """
    period_key = _resolve_period_key(period)

    kwargs = {
        "IndexName": "ByPoints",
        "KeyConditionExpression": Key("GSI1PK").eq(period_key),
        "ScanIndexForward": False,  # highest points first
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.achievement_leaderboard.query(**kwargs)
    items = resp.get("Items", [])

    # Compute ranks
    entries = []
    for i, item in enumerate(items):
        entries.append({
            "rank": i + 1,  # Relative rank within this page
            "user_sub": item.get("user_sub", ""),
            "display_name": item.get("display_name", ""),
            "total_points": int(item.get("total_points", 0)),
            "achievement_count": int(item.get("achievement_count", 0)),
            "display_badges": item.get("display_badges", []),
        })

    next_cursor = None
    last_key = resp.get("LastEvaluatedKey")
    if last_key:
        next_cursor = encode_cursor(last_key)

    return entries, next_cursor


def get_my_rank(user_sub: str, period: str = "weekly") -> Dict[str, Any]:
    """Get the current user's rank and points for a period."""
    period_key = _resolve_period_key(period)

    # Get user's entry
    resp = T.achievement_leaderboard.get_item(
        Key={"period_key": period_key, "user_sub": user_sub},
    )
    entry = resp.get("Item")
    if not entry:
        return {
            "rank": None,
            "user_sub": user_sub,
            "total_points": 0,
            "achievement_count": 0,
            "period": period,
        }

    user_points = int(entry.get("total_points", 0))

    # Count users with more points (for approximate rank)
    # This is a scan -- acceptable for leaderboards since the period partition is bounded
    count_resp = T.achievement_leaderboard.query(
        IndexName="ByPoints",
        KeyConditionExpression=(
            Key("GSI1PK").eq(period_key) &
            Key("GSI1SK").gt(user_points)
        ),
        Select="COUNT",
    )
    rank = count_resp.get("Count", 0) + 1

    return {
        "rank": rank,
        "user_sub": user_sub,
        "total_points": user_points,
        "achievement_count": int(entry.get("achievement_count", 0)),
        "display_badges": entry.get("display_badges", []),
        "period": period,
    }


def _resolve_period_key(period: str) -> str:
    now = datetime.now(timezone.utc)
    if period == "weekly":
        return f"weekly#{now.strftime('%Y-W%W')}"
    elif period == "monthly":
        return f"monthly#{now.strftime('%Y-%m')}"
    elif period == "alltime":
        return "alltime"
    else:
        return f"weekly#{now.strftime('%Y-W%W')}"
```

---

## 4. API Endpoints

### 4.1 Achievement Definitions (Admin)

```
GET  /ui/achievements/definitions
POST /ui/achievements/definitions
PUT  /ui/achievements/definitions/{achievement_id}
```

**POST /ui/achievements/definitions** -- Create a new achievement definition.

Auth: `Depends(require_root_session)`

Request body (Pydantic model):
```python
class CreateAchievementDefinitionIn(BaseModel):
    achievement_id: str = Field(..., min_length=4, max_length=64, pattern=r"^ach_[a-z0-9_]+$")
    category: Literal["creator", "viewer", "general"]
    subcategory: str = Field(..., min_length=1, max_length=32)
    label: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., min_length=1, max_length=500)
    icon_url: str = Field(..., min_length=1, max_length=256)
    rarity: Literal["common", "uncommon", "rare", "epic", "legendary"]
    threshold: int = Field(..., ge=1)
    points: int = Field(..., ge=1, le=10000)
    metric_key: str = Field(..., min_length=1, max_length=64)
    sort_order: int = Field(default=0, ge=0)
```

Response (201):
```json
{
  "achievement_id": "ach_posting_streak_7",
  "category": "creator",
  "subcategory": "posting",
  "label": "Week Warrior",
  "description": "Post every day for 7 consecutive days",
  "icon_url": "/assets/badges/week-warrior.svg",
  "rarity": "uncommon",
  "threshold": 7,
  "points": 50,
  "metric_key": "posting_streak",
  "active": true,
  "sort_order": 0,
  "created_at": 1748400000,
  "updated_at": 1748400000
}
```

Error responses:
- 400: Invalid rarity, category, or icon_url not same-origin
- 403: Not root user
- 409: Achievement ID already exists

**PUT /ui/achievements/definitions/{achievement_id}** -- Update an existing definition.

Auth: `Depends(require_root_session)`

Request body:
```python
class UpdateAchievementDefinitionIn(BaseModel):
    label: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, min_length=1, max_length=500)
    icon_url: Optional[str] = Field(default=None, min_length=1, max_length=256)
    rarity: Optional[Literal["common", "uncommon", "rare", "epic", "legendary"]] = None
    threshold: Optional[int] = Field(default=None, ge=1)
    points: Optional[int] = Field(default=None, ge=1, le=10000)
    active: Optional[bool] = None
    sort_order: Optional[int] = Field(default=None, ge=0)
    subcategory: Optional[str] = Field(default=None, min_length=1, max_length=32)
```

Response (200): Updated definition object (same shape as POST response).

**GET /ui/achievements/definitions** -- List all definitions.

Auth: `Depends(require_root_session)` (admin view shows inactive too)

Query params:
- `active_only`: bool (default `true`)

Response (200):
```json
{
  "definitions": [
    { "achievement_id": "ach_first_post", "label": "First Post", ... },
    { "achievement_id": "ach_posting_streak_7", "label": "Week Warrior", ... }
  ]
}
```

### 4.2 User Achievements

```
GET  /ui/achievements                         — List user's unlocked achievements
GET  /ui/achievements/progress                — Get all progress counters
GET  /ui/achievements/progress/{metric_key}   — Get progress for a specific metric
GET  /ui/users/{user_sub}/achievements        — Public: view another user's badges
POST /ui/achievements/display                 — Set which badges to display (max 3)
```

**GET /ui/achievements** -- List the authenticated user's unlocked achievements.

Auth: `Depends(require_ui_session)` (see `app/services/sessions.py:283`)

Query params:
- `displayed`: Optional[bool] -- filter to only displayed badges
- `category`: Optional[str] -- filter by category

Response (200):
```json
{
  "achievements": [
    {
      "achievement_id": "ach_posting_streak_7",
      "label": "Week Warrior",
      "description": "Post every day for 7 consecutive days",
      "icon_url": "/assets/badges/week-warrior.svg",
      "rarity": "uncommon",
      "points": 50,
      "unlocked_at": 1748400000,
      "trigger_event": "posting_streak:7",
      "displayed": true
    }
  ],
  "total_points": 150,
  "achievement_count": 5
}
```

**GET /ui/achievements/progress** -- Get all progress counters for the authenticated user.

Auth: `Depends(require_ui_session)`

Response (200):
```json
{
  "progress": [
    {
      "metric_key": "post_count",
      "current_value": 42,
      "last_updated_at": 1748400000,
      "last_updated_date": "2026-05-28",
      "highest_value": 42,
      "next_threshold": 100,
      "next_achievement": {
        "achievement_id": "ach_prolific_creator",
        "label": "Prolific Creator",
        "rarity": "uncommon",
        "points": 100
      }
    },
    {
      "metric_key": "posting_streak",
      "current_value": 5,
      "last_updated_at": 1748400000,
      "last_updated_date": "2026-05-28",
      "streak_anchor_date": "2026-05-23",
      "highest_value": 12,
      "next_threshold": 7,
      "next_achievement": {
        "achievement_id": "ach_posting_streak_7",
        "label": "Week Warrior",
        "rarity": "uncommon",
        "points": 50
      }
    }
  ]
}
```

**GET /ui/achievements/progress/{metric_key}** -- Get progress for a specific metric.

Auth: `Depends(require_ui_session)`

Response (200): Single progress object with `next_threshold` and `next_achievement`.

**GET /ui/users/{user_sub}/achievements** -- Public endpoint to view another user's displayed badges.

Auth: `Depends(require_ui_session)` (any authenticated user)

Response (200):
```json
{
  "user_sub": "user_abc123",
  "display_badges": [
    {"achievement_id": "ach_month_marathon", "icon_url": "/assets/badges/month-marathon.svg", "rarity": "rare", "label": "Month Marathon"}
  ],
  "total_points": 450,
  "achievement_count": 12
}
```

**POST /ui/achievements/display** -- Set which badges to display (max 3).

Auth: `Depends(require_ui_session)`

Request body:
```python
class SetDisplayBadgesIn(BaseModel):
    achievement_ids: List[str] = Field(..., min_length=0, max_length=3)
```

Response (200):
```json
{
  "ok": true,
  "display_badges": [
    {"achievement_id": "ach_month_marathon", "icon_url": "...", "rarity": "rare", "label": "Month Marathon"},
    {"achievement_id": "ach_whale", "icon_url": "...", "rarity": "epic", "label": "Whale"}
  ]
}
```

Error responses:
- 400: More than 3 badges, or badge not unlocked

### 4.3 Leaderboards

```
GET  /ui/leaderboards?period=weekly|monthly|alltime&limit=50&cursor=...
GET  /ui/leaderboards/me?period=weekly        — Current user's rank
```

**GET /ui/leaderboards** -- Get ranked leaderboard.

Auth: `Depends(require_ui_session)`

Query params:
- `period`: `weekly` | `monthly` | `alltime` (default `weekly`)
- `limit`: int (default 50, max 100)
- `cursor`: Optional[str] for pagination

Response (200):
```json
{
  "period": "weekly",
  "period_label": "Week 22, 2026",
  "entries": [
    {
      "rank": 1,
      "user_sub": "user_abc123",
      "display_name": "TopCreator",
      "total_points": 1250,
      "achievement_count": 23,
      "display_badges": [
        {"achievement_id": "ach_month_marathon", "icon_url": "...", "rarity": "rare"}
      ]
    }
  ],
  "next_cursor": "eyJwayI6Li4u"
}
```

**GET /ui/leaderboards/me** -- Current user's rank.

Auth: `Depends(require_ui_session)`

Query params:
- `period`: `weekly` | `monthly` | `alltime`

Response (200):
```json
{
  "rank": 42,
  "user_sub": "e2e_alice@test.local",
  "total_points": 150,
  "achievement_count": 5,
  "display_badges": [],
  "period": "weekly"
}
```

### 4.4 Response Shapes

**Achievement unlock (SSE alert payload):**
```json
{
  "alert_id": "ach_abc123def456",
  "event_type": "achievement_unlocked",
  "user_sub": "e2e_alice@test.local",
  "created_at": 1748400000,
  "data": {
    "achievement_id": "ach_posting_streak_7",
    "label": "Week Warrior",
    "description": "Post every day for 7 consecutive days",
    "icon_url": "/assets/badges/week-warrior.svg",
    "rarity": "uncommon",
    "points": 50,
    "trigger_event": "posting_streak:7"
  }
}
```

**Leaderboard entry:**
```json
{
  "rank": 1,
  "user_sub": "user_abc123",
  "display_name": "TopCreator",
  "total_points": 1250,
  "achievement_count": 23,
  "display_badges": [
    {"achievement_id": "ach_month_marathon", "icon_url": "...", "rarity": "rare"}
  ]
}
```

---

## 5. Frontend Components

### 5.1 New Pages and Components

| Component | Path | Description |
|-----------|------|-------------|
| `AchievementsPage` | `pages/achievements/AchievementsPage.tsx` | Full page with tabs: My Badges, Progress, Leaderboard |
| `BadgeGrid` | `pages/achievements/BadgeGrid.tsx` | Grid of badge cards (earned = full color, unearned = grayscale) |
| `ProgressTracker` | `pages/achievements/ProgressTracker.tsx` | Progress bars for each metric toward next threshold |
| `LeaderboardTable` | `pages/achievements/LeaderboardTable.tsx` | Ranked table with avatar, name, points, top badges |
| `BadgeShowcase` | `components/shared/BadgeShowcase.tsx` | Inline badge display for profiles and chat (1-3 badges) |
| `AchievementUnlockToast` | `components/shared/AchievementUnlockToast.tsx` | Animated toast with confetti when achievement unlocks |
| `BadgeDetailDialog` | `pages/achievements/BadgeDetailDialog.tsx` | Dialog showing full badge details, rarity, unlock date |
| `AchievementAdminPage` | `pages/admin/AchievementAdminPage.tsx` | Admin page for CRUD on achievement definitions |

### 5.2 API Endpoints (`frontend/src/api/endpoints/achievements.ts`)

```typescript
import { api } from "@/api/client";  // NOTE: codebase uses named `api` export, not default `client` import

// Types
export interface AchievementDefinition {
  achievement_id: string;
  category: "creator" | "viewer" | "general";
  subcategory: string;
  label: string;
  description: string;
  icon_url: string;
  rarity: "common" | "uncommon" | "rare" | "epic" | "legendary";
  threshold: number;
  points: number;
  metric_key: string;
  active: boolean;
  sort_order: number;
  created_at: number;
  updated_at: number;
}

export interface UserAchievement {
  achievement_id: string;
  label: string;
  description: string;
  icon_url: string;
  rarity: string;
  points: number;
  unlocked_at: number;
  trigger_event: string;
  displayed: boolean;
}

export interface AchievementProgress {
  metric_key: string;
  current_value: number;
  last_updated_at: number;
  last_updated_date: string;
  highest_value: number;
  streak_anchor_date?: string;
  next_threshold?: number;
  next_achievement?: {
    achievement_id: string;
    label: string;
    rarity: string;
    points: number;
  };
}

export interface LeaderboardEntry {
  rank: number;
  user_sub: string;
  display_name: string;
  total_points: number;
  achievement_count: number;
  display_badges: BadgeSummary[];
}

export interface BadgeSummary {
  achievement_id: string;
  label: string;
  icon_url: string;
  rarity: string;
}

// API calls
export const getMyAchievements = async (params?: { displayed?: boolean; category?: string }) =>
  api.get<{ achievements: UserAchievement[]; total_points: number; achievement_count: number }>(
    "/ui/achievements", { params }
  ).then(r => r.data);

export const getAchievementProgress = async () =>
  api.get<{ progress: AchievementProgress[] }>("/ui/achievements/progress").then(r => r.data);

export const getProgressForMetric = async (metricKey: string) =>
  api.get<AchievementProgress>(`/ui/achievements/progress/${metricKey}`).then(r => r.data);

export const getUserAchievements = async (userSub: string) =>
  api.get<{ user_sub: string; display_badges: BadgeSummary[]; total_points: number }>(
    `/ui/users/${userSub}/achievements`
  ).then(r => r.data);

export const setDisplayBadges = async (achievementIds: string[]) =>
  api.post("/ui/achievements/display", { achievement_ids: achievementIds }).then(r => r.data);

export const getLeaderboard = async (params: { period: string; limit?: number; cursor?: string }) =>
  api.get<{ entries: LeaderboardEntry[]; next_cursor?: string; period: string }>(
    "/ui/leaderboards", { params }
  ).then(r => r.data);

export const getMyRank = async (period: string) =>
  api.get<LeaderboardEntry & { period: string }>("/ui/leaderboards/me", { params: { period } }).then(r => r.data);
```

### 5.3 AchievementsPage Component

```tsx
// frontend/src/pages/achievements/AchievementsPage.tsx
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/PageHeader";
import { Trophy } from "lucide-react";
import { BadgeGrid } from "./BadgeGrid";
import { ProgressTracker } from "./ProgressTracker";
import { LeaderboardTable } from "./LeaderboardTable";

export default function AchievementsPage() {
  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Achievements"
        description="Track your milestones and earn badges"
        icon={<Trophy className="h-6 w-6" />}
      />

      <Tabs defaultValue="badges">
        <TabsList>
          <TabsTrigger value="badges">My Badges</TabsTrigger>
          <TabsTrigger value="progress">Progress</TabsTrigger>
          <TabsTrigger value="leaderboard">Leaderboard</TabsTrigger>
        </TabsList>
        <TabsContent value="badges">
          <BadgeGrid />
        </TabsContent>
        <TabsContent value="progress">
          <ProgressTracker />
        </TabsContent>
        <TabsContent value="leaderboard">
          <LeaderboardTable />
        </TabsContent>
      </Tabs>
    </div>
  );
}
```

### 5.4 BadgeGrid Component

```tsx
// frontend/src/pages/achievements/BadgeGrid.tsx
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getMyAchievements, setDisplayBadges, getAchievementProgress } from "@/api/endpoints/achievements";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { Star, Check } from "lucide-react";
import { toast } from "sonner";

const RARITY_COLORS: Record<string, string> = {
  common: "bg-gray-100 text-gray-700 border-gray-300",
  uncommon: "bg-green-100 text-green-700 border-green-400",
  rare: "bg-blue-100 text-blue-700 border-blue-400",
  epic: "bg-purple-100 text-purple-700 border-purple-400",
  legendary: "bg-amber-100 text-amber-700 border-amber-400",
};

export function BadgeGrid() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["achievements", "mine"],
    queryFn: () => getMyAchievements(),
  });

  const displayMut = useMutation({
    mutationFn: (ids: string[]) => setDisplayBadges(ids),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["achievements"] });
      toast.success("Display badges updated");
    },
  });

  if (isLoading) return <div className="text-muted-foreground">Loading badges...</div>;

  const achievements = data?.achievements ?? [];
  const displayed = achievements.filter(a => a.displayed);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {data?.achievement_count ?? 0} badges earned / {data?.total_points ?? 0} total points
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-4">
        {achievements.map((ach) => (
          <Card
            key={ach.achievement_id}
            className={cn(
              "cursor-pointer transition-all hover:shadow-md",
              ach.displayed && "ring-2 ring-primary"
            )}
          >
            <CardContent className="flex flex-col items-center p-4 text-center">
              <img
                src={ach.icon_url}
                alt={ach.label}
                className="h-12 w-12 mb-2"
              />
              <span className="text-sm font-medium">{ach.label}</span>
              <Badge className={cn("mt-1 text-xs", RARITY_COLORS[ach.rarity])}>
                {ach.rarity}
              </Badge>
              <span className="text-xs text-muted-foreground mt-1">
                +{ach.points} pts
              </span>
              {ach.displayed && (
                <Check className="h-4 w-4 text-primary mt-1" />
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
```

### 5.5 ProgressTracker Component

```tsx
// frontend/src/pages/achievements/ProgressTracker.tsx
import { useQuery } from "@tanstack/react-query";
import { getAchievementProgress } from "@/api/endpoints/achievements";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";

export function ProgressTracker() {
  const { data, isLoading } = useQuery({
    queryKey: ["achievements", "progress"],
    queryFn: getAchievementProgress,
  });

  if (isLoading) return <div className="text-muted-foreground">Loading progress...</div>;

  const progress = data?.progress ?? [];

  return (
    <div className="space-y-4">
      {progress.map((p) => {
        const pct = p.next_threshold
          ? Math.min(100, (p.current_value / p.next_threshold) * 100)
          : 100;
        return (
          <Card key={p.metric_key}>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center justify-between">
                <span>{formatMetricKey(p.metric_key)}</span>
                {p.next_achievement && (
                  <span className="text-xs text-muted-foreground">
                    Next: {p.next_achievement.label}
                  </span>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Progress value={pct} className="h-3" />
              <div className="flex justify-between mt-1 text-xs text-muted-foreground">
                <span>{p.current_value}</span>
                <span>{p.next_threshold ?? "Complete"}</span>
              </div>
              {p.streak_anchor_date && (
                <div className="text-xs text-muted-foreground mt-1">
                  Streak started: {p.streak_anchor_date} / Best: {p.highest_value}
                </div>
              )}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

function formatMetricKey(key: string): string {
  return key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
```

### 5.6 Profile Integration

The `Profile.tsx` component will render a `BadgeShowcase` below the avatar. The showcase pulls from `GET /ui/achievements?displayed=true`:

```tsx
// In Profile.tsx, below the avatar section:
const badgesQuery = useQuery({
    queryKey: ["achievements", "displayed"],
    queryFn: () => getMyAchievements({ displayed: true }),
});

// Render below avatar
<BadgeShowcase badges={badgesQuery.data?.achievements ?? []} maxDisplay={3} />
```

### 5.7 BadgeShowcase Component

```tsx
// frontend/src/components/shared/BadgeShowcase.tsx
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

interface BadgeShowcaseProps {
  badges: Array<{ achievement_id: string; label: string; icon_url: string; rarity: string }>;
  maxDisplay?: number;
  size?: "sm" | "md";
}

export function BadgeShowcase({ badges, maxDisplay = 3, size = "md" }: BadgeShowcaseProps) {
  const displayed = badges.slice(0, maxDisplay);
  if (displayed.length === 0) return null;

  const sizeClass = size === "sm" ? "h-4 w-4" : "h-5 w-5";

  return (
    <div className="flex items-center gap-0.5">
      {displayed.map((badge) => (
        <Tooltip key={badge.achievement_id}>
          <TooltipTrigger asChild>
            <img
              src={badge.icon_url}
              alt={badge.label}
              className={`${sizeClass} inline-block`}
            />
          </TooltipTrigger>
          <TooltipContent>
            <span className="text-xs">{badge.label}</span>
          </TooltipContent>
        </Tooltip>
      ))}
    </div>
  );
}
```

### 5.8 Chat Badge Flair

In broadcast chat (`_chat_msg_out`) and DM messaging, the sender's display badges are resolved and attached:

```tsx
// In ChatMessage component (broadcast chat)
{message.sender_badges?.map(badge => (
    <img key={badge.achievement_id} src={badge.icon_url} alt={badge.label}
         className="inline-block h-4 w-4 ml-0.5" title={badge.label} />
))}
```

```tsx
// In MessageBubble component (DM messaging)
<div className="flex items-center gap-1">
  <span className="font-semibold text-sm">{message.sender_display_name}</span>
  <BadgeShowcase badges={message.sender_badges ?? []} maxDisplay={3} size="sm" />
</div>
```

### 5.9 AchievementUnlockToast Component

```tsx
// frontend/src/components/shared/AchievementUnlockToast.tsx
import { toast } from "sonner";
import { Trophy } from "lucide-react";

interface AchievementAlertData {
  achievement_id: string;
  label: string;
  description: string;
  icon_url: string;
  rarity: string;
  points: number;
}

export function showAchievementUnlockToast(data: AchievementAlertData) {
  toast.custom(() => (
    <div className="flex items-center gap-3 bg-background border rounded-lg p-4 shadow-lg">
      <div className="relative">
        <img src={data.icon_url} alt={data.label} className="h-10 w-10" />
        <Trophy className="absolute -top-1 -right-1 h-4 w-4 text-yellow-500" />
      </div>
      <div>
        <div className="font-semibold text-sm">Achievement Unlocked!</div>
        <div className="text-sm">{data.label}</div>
        <div className="text-xs text-muted-foreground">{data.description}</div>
        <div className="text-xs text-primary">+{data.points} points</div>
      </div>
    </div>
  ), { duration: 5000 });
}
```

The SSE handler in the alert stream listener calls this function:

```tsx
// In useAlertStream hook
case "achievement_unlocked":
  showAchievementUnlockToast(event.data);
  queryClient.invalidateQueries({ queryKey: ["achievements"] });
  break;
```

### 5.10 Sidebar Navigation

Add "Achievements" with a `Trophy` icon to the sidebar in `Sidebar.tsx` under the Social group.

```tsx
// In Sidebar.tsx, Social group
{ to: "/achievements", label: "Achievements", icon: Trophy },
```

### 5.11 Route Registration

```tsx
// In App.tsx
const AchievementsPage = lazy(() => import("./pages/achievements/AchievementsPage"));

// Inside Routes
<Route path="/achievements" element={<AchievementsPage />} />
```

---

## 6. E2E Test Plan

### Section 80: Achievement Definitions API (Admin)

| # | Test | Assertion |
|---|------|-----------|
| 80.1 | Root creates a new achievement definition | 201, returns achievement_id, label, threshold, points |
| 80.2 | List achievement definitions returns all active | 200, array includes created definition |
| 80.3 | Update achievement definition (change threshold) | 200, threshold updated to new value |
| 80.4 | Non-admin cannot create definitions | 403 |
| 80.5 | Deactivate an achievement definition | 200, active=false |
| 80.6 | Duplicate achievement_id returns 409 | 409, "already exists" |
| 80.7 | Invalid rarity value rejected | 400 |
| 80.8 | External icon_url rejected | 400, "must be a relative path" |

### Section 81: Achievement Progress & Unlock API

| # | Test | Assertion |
|---|------|-----------|
| 81.1 | Alice creates a post; posting progress increments | GET progress shows `post_count: 1` |
| 81.2 | After threshold met, achievement appears in user list | GET achievements includes the unlocked badge |
| 81.3 | Achievement unlock creates alert notification | GET alerts includes `achievement_unlocked` event |
| 81.4 | Duplicate unlock is idempotent | Second post does not create second unlock record |
| 81.5 | Streak increments on consecutive days (mocked date) | posting_streak counter advances to 2 |
| 81.6 | Streak resets after gap day | posting_streak counter resets to 1 |
| 81.7 | Same-day duplicate posting streak call is idempotent | Counter stays at current value |
| 81.8 | Multiple achievements unlock from single action | Tip count crossing 1 and 10 both unlock |
| 81.9 | Progress highest_value tracks all-time high | After streak reset, highest_value still shows previous peak |
| 81.10 | Disabled achievement does not unlock | Deactivated achievement_id skipped even when threshold met |

### Section 82: Badge Display API

| # | Test | Assertion |
|---|------|-----------|
| 82.1 | Alice sets 2 badges as displayed | POST display returns ok, 2 badges in response |
| 82.2 | Public profile shows displayed badges | GET /users/{sub}/achievements returns only displayed badges |
| 82.3 | Setting more than 3 displayed badges fails | 400, "maximum 3 display badges" |
| 82.4 | Setting badge not unlocked fails | 400, "not unlocked" |
| 82.5 | Clearing all displayed badges (empty array) | POST with [] returns ok, 0 badges |
| 82.6 | Updating display badges replaces previous selection | Previous selection cleared |

### Section 83: Leaderboard API

| # | Test | Assertion |
|---|------|-----------|
| 83.1 | Weekly leaderboard returns ranked list | 200, sorted by total_points descending |
| 83.2 | "My rank" endpoint returns current user position | 200, includes rank and total_points |
| 83.3 | Leaderboard pagination with cursor | Next page returns different users |
| 83.4 | Monthly leaderboard uses correct period key | 200, period="monthly" |
| 83.5 | Alltime leaderboard accumulates across periods | Points from previous weeks still counted |
| 83.6 | User with no achievements gets rank=null | 200, rank=null, total_points=0 |

### Section 84: Achievements UI

| # | Test | Assertion |
|---|------|-----------|
| 84.1 | Achievements page loads with badge grid | Badge cards visible |
| 84.2 | Earned badge shows full color; unearned is grayscale | CSS class check |
| 84.3 | Progress tab shows progress bars | Bar width proportional to progress/threshold |
| 84.4 | Leaderboard tab shows ranked table | Table rows ordered by rank |
| 84.5 | Clicking badge card opens detail dialog | Dialog shows label, description, rarity, unlock date |
| 84.6 | Display badge toggle updates profile | After toggling, profile shows updated badges |
| 84.7 | Achievement points summary shown at top | "X badges earned / Y total points" text visible |
| 84.8 | Sidebar shows "Achievements" link | Trophy icon + "Achievements" text in sidebar |

### Section 84b: Badge Flair in Chat

| # | Test | Assertion |
|---|------|-----------|
| 84b.1 | Display badges appear next to sender name in broadcast chat | img elements with badge icon_url visible |
| 84b.2 | Display badges appear next to sender name in DM messages | BadgeShowcase renders in MessageBubble |
| 84b.3 | User with no display badges shows no flair | No img elements in sender line |

---

## 7. Edge Cases

1. **Streak timezone handling**: Streaks are evaluated in UTC. A user posting at 23:59 UTC and 00:01 UTC has posted on two consecutive calendar days even though only 2 minutes elapsed. This is documented behavior. Users near timezone boundaries may perceive inconsistency, but UTC normalization prevents gaming by timezone-hopping.

2. **Retroactive unlocks**: When a new achievement definition is added, existing users who already meet the threshold do not automatically unlock it. A backfill script must be run separately:
   ```python
   # scripts/backfill_achievements.py
   def backfill_for_metric(metric_key: str):
       """Scan all progress records for a metric and unlock eligible users."""
       resp = T.user_achievement_progress.scan(
           FilterExpression=Attr("metric_key").eq(metric_key),
       )
       for item in resp.get("Items", []):
           advance_progress(item["user_sub"], metric_key, delta=0)  # delta=0 re-checks thresholds
   ```

3. **Counter overflow**: Counters use DynamoDB Number type (up to 38 digits of precision). No practical overflow concern.

4. **Achievement definition deletion**: Soft-delete only (`active=false`). Already-unlocked badges remain visible. The badge icon URL must remain valid (served from static assets, not deleted).

5. **Race conditions on unlock**: Two concurrent tip events could both trigger `advance_progress`. The atomic DynamoDB increment ensures the counter is correct, but both threads may attempt to write the unlock row. Use `ConditionExpression: attribute_not_exists(achievement_id)` on the put to ensure idempotency. The losing thread catches `ConditionalCheckFailedException` and returns the existing unlock.

6. **Badge display after achievement revocation**: If an admin deactivates an achievement, users who already unlocked it keep the badge. The badge icon URL must remain valid (served from static assets, not deleted).

7. **Leaderboard period rollover**: Weekly leaderboards roll over at midnight UTC on Monday (ISO week boundary). The `_resolve_period_key` function uses `strftime("%Y-W%W")` which produces ISO week numbers. At rollover, all users start at 0 for the new period.

8. **Badge cache staleness**: The 5-minute badge cache TTL means a user who changes their display badges may not see the change reflected in other users' chat messages for up to 5 minutes. This is acceptable for a cosmetic feature.

9. **Achievement progress after account deletion**: If a user's account is closed, their achievement records should be cleaned up by the account closure process. However, leaderboard entries for past periods are not retroactively removed -- the user simply appears as "[Deleted User]".

10. **High-frequency metric updates**: For metrics like `reaction_count` that can advance rapidly (user reacting to many posts in quick succession), the per-action `advance_progress` call adds latency. Mitigation: the achievement check is fast (single GSI query for definitions, single get_item for existing unlocks), and the main action is never blocked on achievement failure (try/except wrapper).

---

## 8. Security Considerations

1. **Progress counter manipulation**: Only server-side code advances progress counters. No client-facing endpoint accepts arbitrary counter increments. The `advance_progress` function is called internally from action handlers, never from a direct API route.

2. **Admin-only definition management**: Achievement creation/update requires `require_root_session` auth dependency. Regular users and even ADMIN-role users cannot modify definitions.

3. **Leaderboard privacy**: Users can opt out of leaderboard visibility via a profile setting (`leaderboard_visible: false`). Opted-out users' entries are excluded from leaderboard queries. The opt-out is checked server-side in the leaderboard query filter.

4. **Rate limiting on progress writes**: Achievement progress advances are a side effect of existing rate-limited actions (posting, tipping, etc.), so no additional rate limiting is needed. The atomic DDB increment is O(1).

5. **Icon URL validation**: Achievement icon URLs must point to the platform's own CDN or S3 bucket (must start with `/`). External URLs are rejected to prevent XSS via malicious SVGs. The validation is in `create_definition`:
   ```python
   if icon_url and not icon_url.startswith("/"):
       raise HTTPException(400, "icon_url must be a relative path (same-origin)")
   ```

6. **Public badge endpoint access control**: `GET /ui/users/{user_sub}/achievements` requires authentication but does not require ownership. This is intentional -- badges are public social signals. However, only `displayed=true` badges are returned, never the full unlock history.

7. **Leaderboard enumeration**: The leaderboard endpoint is paginated and rate-limited by the session auth rate limiter. It does not expose sensitive user data beyond display names and badge selections.

8. **SSE achievement alerts**: Achievement unlock SSE events are only sent to the user who earned the achievement, not broadcast to other users. This prevents information leakage about other users' progress.

---

## 9. Rollout Plan

1. **Phase 1** (days 1-5): Backend -- DDB tables, achievement definition service, progress tracker, unlock logic, leaderboard service, integration hooks at post/tip/broadcast/subscribe/follow/react/comment actions. Settings: `ACHIEVEMENTS_ENABLED` feature flag in `app/core/settings.py`.

2. **Phase 2** (days 6-9): Frontend -- AchievementsPage (tabs: badges, progress, leaderboard), BadgeGrid, ProgressTracker, LeaderboardTable, profile badge showcase. API endpoint wrappers. Route in App.tsx. Sidebar entry.

3. **Phase 3** (days 10-12): Chat flair integration in broadcast chat (`_chat_msg_out` adds `sender_badges`) and DM messaging (`_message_out_from_item` adds `sender_badges`). Badge cache service. Achievement unlock toast with SSE. Admin definition management page.

4. **Phase 4** (days 13-16): E2E tests (sections 80-84b), seed initial achievement definitions via script, backfill script for existing users, QA.

Feature flag: `ACHIEVEMENTS_ENABLED` (default `false`). All achievement progress writes and UI components are gated behind this flag. The feature flag is checked in `_achievements_enabled()` at the top of `advance_progress` and `update_streak`, and in the frontend via a feature flag check before rendering the Achievements sidebar link and page.

```python
# app/core/settings.py — already exists at line 1444:
achievements_enabled: bool = os.environ.get("ACHIEVEMENTS_ENABLED", "0") not in ("0", "false", "False")
# Also: achievements_table_name, user_achievements_table_name, user_achievement_progress_table_name,
#        achievement_leaderboard_table_name (lines 1445-1448)
```

---

## Codebase References

| Ref | File | Line(s) | Status |
|-----|------|---------|--------|
| `ALERT_EVENT_TYPES` | `app/services/alerts.py` | 133 | VERIFIED (ticket said 46) |
| `sse_publish_alert` | `app/services/alerts.py` | 173 | VERIFIED (ticket said 84) |
| `audit_event` | `app/services/alerts.py` | 695 | VERIFIED (ticket said 570) |
| `write_alert` | `app/services/alerts.py` | 355 | VERIFIED (ticket said 266) |
| `increment_unread_count` | `app/services/notification_unread.py` | 26 | VERIFIED |
| `broadcast_tip_goals.py` | `app/services/broadcast_tip_goals.py` | exists | VERIFIED |
| `create_goal` | `app/services/broadcast_tip_goals.py` | 20 | VERIFIED |
| `advance_goal_progress` | `app/services/broadcast_tip_goals.py` | 98 | VERIFIED |
| SSE event dispatch | `app/services/broadcast_tip_goals.py` | 164 | VERIFIED |
| ProfilePage | `frontend/src/pages/settings/ProfilePage.tsx` | exists | VERIFIED |
| Profile `profileQuery` | `frontend/src/pages/settings/Profile.tsx` | 59 | VERIFIED |
| `SOCIAL_ALERT_TYPES` | `app/services/social_alerts.py` | 32 | VERIFIED |
| `_is_alert_type_enabled` | `app/services/social_alerts.py` | 64 | VERIFIED |
| `_chat_msg_out` | `app/services/broadcast_chat_store.py` | 344 | VERIFIED |
| `_message_out_from_item` | `app/routers/messaging.py` | 3766 | VERIFIED |
| `create_post` | `app/routers/newsfeed.py` | 3013 | VERIFIED (ticket said 2975; signature uses `UserIdDep`, not `Depends(require_ui_session)`) |
| `transition_session_status` | `app/services/broadcast_store.py` | 336 | VERIFIED (ticket said 326) |
| `require_ui_session` | `app/services/sessions.py` | 283 | VERIFIED (NOT in app/auth/deps.py) |
| Achievement settings | `app/core/settings.py` | 1444-1448 | VERIFIED: `achievements_enabled` + 4 table names |
| Achievement table handles | `app/core/tables.py` | 115-118, 239-242 | VERIFIED: achievements, user_achievements, user_achievement_progress, achievement_leaderboard |
| Achievement DDB tables | `scripts/local-ddb-init.py` | 1012-1039 | VERIFIED: 4 tables with GSIs |
| Achievement router registration | `app/main.py` | 159, 450 | VERIFIED |
| Backend service: progress | `app/services/achievement_progress.py` | exists (11960 bytes) | VERIFIED |
| Backend service: badges | `app/services/achievement_badges.py` | exists (2957 bytes) | VERIFIED |
| Backend service: badge cache | `app/services/achievement_badge_cache.py` | exists (1102 bytes) | VERIFIED |
| Backend router | `app/routers/achievements.py` | exists (12940 bytes) | VERIFIED |
| Frontend API | `frontend/src/api/endpoints/achievements.ts` | 1 (`import { api } from "@/api/client"`) | VERIFIED |
| AchievementsPage | `frontend/src/pages/achievements/AchievementsPage.tsx` | exists | VERIFIED |
| BadgeGrid | `frontend/src/pages/achievements/BadgeGrid.tsx` | exists | VERIFIED |
| ProgressTracker | `frontend/src/pages/achievements/ProgressTracker.tsx` | exists | VERIFIED |
| LeaderboardTable | `frontend/src/pages/achievements/LeaderboardTable.tsx` | exists | VERIFIED |
| Route registration | `frontend/src/App.tsx` | 81, 190 | VERIFIED |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_achievements.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_engage_001_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_engage_001_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_engage_001_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_engage_001_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_engage_001_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_engage_001_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_engage_001_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_engage_001_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/achievements.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 15

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `ACHIEVEMENTS_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `ACHIEVEMENTS_ENABLED` must be enabled for tests to run
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
- [ ] Feature flag `ACHIEVEMENTS_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite

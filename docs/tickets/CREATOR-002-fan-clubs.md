# CREATOR-002: Fan Clubs / Membership Tiers

**Ticket**: CREATOR-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-28

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The current subscription system (`app/routers/subscription_server.py`) provides a single-tier subscription model: a creator defines plans with pricing, and subscribers gain access. However, this model lacks several features that top-tier creator platforms provide:

- **Named membership tiers**: Creators cannot offer multiple distinct levels of access (e.g., "Bronze", "Silver", "Gold") with progressively richer benefits.
- **Custom badges**: Subscribers have no visual identity in chat or messaging that reflects their tier.
- **Exclusive chat rooms**: There is no mechanism for tier-specific communication channels.
- **Early access gating**: Content cannot be released to higher tiers first and lower tiers later.
- **Custom benefit definitions**: Creators cannot define arbitrary perks (monthly shoutouts, exclusive polls, custom emojis) per tier.

These limitations push creators to use off-platform tools (Discord, Patreon) for community building, fragmenting their audience.

### 1.2 Goals

1. **Named Tiers with Custom Benefits**: Creators define up to 6 tiers with names, colors, badges, and benefit lists.
2. **Tier-Specific Badges**: Member badges appear in broadcast chat, DM messages, and newsfeed comments.
3. **Exclusive Chat Channels**: Each tier unlocks access to a dedicated chat channel (plus all lower-tier channels).
4. **Early Access Content**: Posts and VOD can be released to specific tiers first, with a configurable delay before wider release.
5. **Benefit Management Dashboard**: Creators manage tiers, benefits, and members from a dedicated UI.

### 1.3 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | I want to create named tiers (e.g., "Supporter", "VIP", "Ultra") with different prices. | POST creates a tier linked to a subscription plan with custom name, color, badge, and benefits list. |
| Creator | I want to assign a custom badge to each tier. | Badge renders as a colored icon/emoji in broadcast chat and messages. |
| Creator | I want to create a chat room exclusive to "VIP" tier and above. | POST creates a chat channel with `min_tier_level` access control. |
| Subscriber | I want my badge to appear when I send broadcast chat messages. | Badge renders next to display name in `BroadcastChatMessageOut`. |
| Subscriber | I want to see which exclusive channels I can access based on my tier. | GET returns channels list filtered by user's tier level. |
| Subscriber | I want early access to new content before lower-tier members. | Content with `early_access_tier` is visible to qualifying subscribers immediately; others see it after a configurable delay. |
| Admin | I want to see tier distribution analytics for a creator. | GET endpoint returns member counts per tier. |
| Creator | I want to see a member list for each tier with subscriber details. | GET endpoint returns paginated member list with join date, total spent, and badge info. |
| Creator | I want to upload a custom badge image (PNG/SVG) for a tier. | PUT uploads a badge image to S3 under a tier-specific path; validates size and format. |
| Subscriber | I want to upgrade from one tier to another without losing my subscription continuity. | PATCH on subscription record changes plan_id and tier; billing prorates automatically. |
| Creator | I want to set up a "welcome message" that is automatically sent to new tier members. | Tier configuration includes `welcome_message` field; system sends it as a DM upon subscription. |

---

## 2. Current State Analysis

### 2.1 Subscription Plan System

The subscription server (`app/routers/subscription_server.py`) stores plans in the `T.subscriptions` table using a composite key pattern (lines 106-119):
<!-- VERIFIED: app/routers/subscription_server.py:106 pk_plan, :110 pk_creator, :114 pk_subscriber, :118 pk_subscription -->

```python
def pk_plan(plan_id: str) -> str:
    return f"PLAN#{plan_id}"

def pk_creator(creator_id: str) -> str:
    return f"CREATOR#{creator_id}"

def pk_subscriber(subscriber_id: str) -> str:
    return f"SUBSCRIBER#{subscriber_id}"

def pk_subscription(subscription_id: str) -> str:
    return f"SUB#{subscription_id}"
```

Plans are created with `PlanCreateIn` (line 289-298):
<!-- VERIFIED: app/routers/subscription_server.py:289 PlanCreateIn -->

```python
class PlanCreateIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    description: Optional[str] = Field(default=None, max_length=1000)
    price_cents: conint(gt=0)
    currency: str = Field(default="usd", min_length=3, max_length=10)
    interval: Literal["month", "year"] = "month"
    annual_price_cents: Optional[conint(gt=0)] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    asset_paths: List[str] = Field(default_factory=list)
```

Plans support `metadata` as a freeform dict, but there is no structured tier system. Each plan is independent -- there is no concept of tier ordering or progressive access.

The plan creation endpoint (`POST /api/plans`) writes the plan record to DynamoDB under `pk=PLAN#{plan_id}` with `sk=META`. The plan includes `creator_id`, `name`, `price_cents`, `currency`, and `interval`. The tier system adds `tier_id` as a foreign key linking a plan to a specific tier configuration.

### 2.2 Subscription Access Control

The access control service (`app/services/subscription_access.py`, lines 55-69) checks subscription status as a boolean (has/doesn't have active subscription):
<!-- CORRECTED: was "lines 55-77", actually has_active_subscription is lines 55-69 -->

```python
def has_active_subscription(subscriber_id: str, creator_id: str) -> bool:
    try:
        resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(_pk_subscriber(subscriber_id)) & Key("sk").begins_with("SUB#"),
        )
    except Exception:
        return False
    items: List[Dict[str, Any]] = resp.get("Items", [])
    for item in items:
        if item.get("creator_id") != creator_id:
            continue
        status = (item.get("status") or "").lower()
        if status in {"active", "past_due", "trialing"}:
            return True
    return False
```

This returns a simple boolean. The fan club system needs a function like `get_subscriber_tier_level(subscriber_id, creator_id) -> Optional[int]` that returns the tier level (1-6) or None.

The `can_access_creator` function (lines 72-77) is the main access gate:
<!-- VERIFIED: app/services/subscription_access.py:72 can_access_creator -->

```python
def can_access_creator(subscriber_id: str, creator_id: str) -> bool:
    if subscriber_id == creator_id:
        return True
    if not creator_requires_subscription(creator_id):
        return True
    return has_active_subscription(subscriber_id, creator_id)
```

This will be augmented with `can_access_tier(subscriber_id, creator_id, min_tier_level)` for tier-gated content.

### 2.3 Subscription Settings

The subscription access service (`app/services/subscription_access.py`, lines 20-31) manages per-creator subscription settings:
<!-- CORRECTED: was "lines 20-48", actually get_subscription_settings is lines 20-31 -->

```python
def get_subscription_settings(creator_id: str) -> Dict[str, Any]:
    try:
        item = T.subscriptions.get_item(Key={"pk": _pk_creator(creator_id), "sk": "SETTINGS"}).get("Item")
    except Exception:
        item = None
    if not item:
        return {"require_subscription": False, "disable_auto_renew": False, "updated_at": 0}
    return {
        "require_subscription": bool(item.get("require_subscription", False)),
        "disable_auto_renew": bool(item.get("disable_auto_renew", False)),
        "updated_at": int(item.get("updated_at") or 0),
    }
```

The fan club system will extend this with tier configuration stored under the same creator partition.

### 2.4 Broadcast Chat Display Names and Badges

The broadcast chat store (`app/services/broadcast_chat_store.py`, line 136-150) sends messages with `sender_id` and `sender_display_name`:
<!-- VERIFIED: app/services/broadcast_chat_store.py:136 send_chat_message -->

```python
def send_chat_message(
    session_id: str,
    user_id: str,
    display_name: str,
    text: str,
    *,
    skip_rate_limit: bool = False,
    reply_to_message_id: Optional[str] = None,
    expires_in_seconds: Optional[int] = None,
    lock_price_cents: Optional[int] = None,
    lock_description: Optional[str] = None,
) -> Dict[str, Any]:
```

The `BroadcastChatMessageOut` model (`app/routers/broadcast.py`, line 1233-1263) includes `sender_display_name` but no badge fields:
<!-- CORRECTED: was "line 1233-1262", actually ends at line 1263 -->

```python
class BroadcastChatMessageOut(BaseModel):
    message_id: str
    session_id: str
    sender_id: str
    sender_display_name: str
    text: Optional[str] = None
    kind: str = "text"
    ...
```

New fields `sender_badge_emoji`, `sender_badge_color`, and `sender_tier_name` will be added.

The chat message SSE event (`broadcast_sse_publish`) currently includes `sender_display_name`. Badge data will be included in the SSE payload so clients can render badges in real-time without additional API calls:

```python
broadcast_sse_publish(session_id, {
    "_type": "chat:message",
    "message_id": msg_id,
    "sender_id": user_id,
    "sender_display_name": display_name,
    "sender_badge": badge_data,  # NEW: {tier_name, badge_emoji, badge_color}
    "text": text,
    "created_at": ts,
})
```

### 2.5 Broadcast Chat Mute System

The chat store's mute system (`app/services/broadcast_chat_store.py`, lines 77-131) uses a separate `broadcast_chat_mutes` table
<!-- VERIFIED: app/services/broadcast_chat_store.py:77 get_mute_status --> with `session_user` as PK. The exclusive chat channel system will follow a similar per-session access pattern but with tier-based access instead of mute-based restriction.

The mute enforcement pattern:

```python
def get_mute_status(session_id: str, user_id: str) -> Optional[int]:
    key = f"{session_id}#{user_id}"
    resp = T.broadcast_chat_mutes.get_item(Key={"session_user": key})
    item = resp.get("Item")
    if not item:
        return None
    muted_until = int(item.get("muted_until", 0) or 0)
    if muted_until > now_ts():
        return muted_until
    return None
```

This pattern -- checking a record before allowing a chat action -- is reusable for tier-based channel access: instead of checking a mute record, check the subscriber's tier level against the channel's `min_tier_level`.

### 2.6 Profile Identity Resolution

The subscription server (`app/routers/subscription_server.py`, line 147-150) resolves profile identity for display:
<!-- VERIFIED: app/routers/subscription_server.py:147 attach_creator_profile -->

```python
def attach_creator_profile(plan: Dict[str, Any]) -> Dict[str, Any]:
    enriched = plan.copy()
    enriched["creator_profile"] = get_profile_identity(plan["creator_id"])
    return enriched
```

Badge information will be resolved similarly from the tier configuration when enriching chat messages and post comments.

### 2.7 Subscription Lifecycle Events

The subscription server handles lifecycle transitions (activate, cancel, renew) in `app/routers/subscription_server.py`. These events are where tier-related side effects are triggered:

- **On subscribe**: Increment `member_count` on the tier, send welcome DM if configured, add to exclusive channels
- **On cancel**: Decrement `member_count`, remove from exclusive channels (after grace period)
- **On upgrade/downgrade**: Update tier association, adjust channel access, update badge

The subscription cycle order emission (`emit_subscription_cycle_order_and_reconcile`, lines 56-80) handles billing reconciliation. Tier changes during a billing cycle use prorated amounts calculated by `_apply_discount` patterns (lines 182-195).
<!-- CORRECTED: was "lines 182-197", actually _apply_discount is lines 182-195 -->

---

## 3. Technical Design

### 3.1 Tier Data Model

Tiers are stored in the `T.subscriptions` table under the creator's partition, using the existing single-table pattern:

```python
# Tier record in subscriptions table
{
    "pk": "CREATOR#{creator_id}",
    "sk": "TIER#{tier_id}",
    "tier_id": "tier_abc123",
    "creator_id": "user_alice",
    "plan_id": "plan_xyz",           # links to existing subscription plan
    "name": "VIP",
    "level": 2,                      # 1-6, higher = more access
    "color": "#FFD700",              # hex color for badge
    "badge_emoji": "crown",          # emoji identifier or custom upload path
    "badge_image_url": null,         # optional custom badge image
    "description": "VIP members get early access and exclusive chat",
    "benefits": [
        {"type": "early_access", "delay_hours": 0},
        {"type": "exclusive_chat", "channel_id": "chan_vip"},
        {"type": "custom_emoji", "emoji_pack_id": "pack_vip"},
        {"type": "badge", "display": true},
        {"type": "text", "label": "Monthly shoutout on stream"},
    ],
    "welcome_message": "Welcome to VIP! You now have access to exclusive content and chat.",
    "member_count": 0,               # denormalized count
    "sort_order": 2,
    "active": true,
    "created_at": 1748390400,
    "updated_at": 1748390400,
}
```

#### 3.1.1 Tier Benefits Schema

Each benefit in the `benefits` list is a typed object:

```python
# Benefit type definitions
BENEFIT_TYPES = {
    "early_access": {
        "description": "See content before lower tiers",
        "fields": {"delay_hours": int},  # 0 = instant, > 0 = delayed for non-qualifying tiers
    },
    "exclusive_chat": {
        "description": "Access to exclusive chat channel",
        "fields": {"channel_id": str},
    },
    "custom_emoji": {
        "description": "Use custom emojis in chat",
        "fields": {"emoji_pack_id": str},
    },
    "badge": {
        "description": "Display badge in chat and comments",
        "fields": {"display": bool},
    },
    "text": {
        "description": "Free-text benefit description",
        "fields": {"label": str},
    },
    "discount": {
        "description": "Discount on shop items",
        "fields": {"percent_off": int, "applies_to": list},
    },
    "priority_dm": {
        "description": "Priority DM responses from creator",
        "fields": {},
    },
}
```

### 3.2 Exclusive Chat Channels

Tier-exclusive chat channels are stored as records in a new `fan_club_channels` table:

```python
{
    "channel_id": "chan_vip_alice",
    "creator_id": "user_alice",
    "name": "VIP Lounge",
    "description": "Private chat for VIP members",
    "min_tier_level": 2,             # members at tier level >= 2 can access
    "message_count": 0,
    "last_message_at": 0,
    "last_message_preview": null,    # truncated last message for channel list
    "pinned_message_id": null,       # optional pinned message
    "slowmode_seconds": 0,           # 0 = no slowmode, > 0 = minimum seconds between messages
    "max_message_length": 500,       # character limit per message
    "created_at": 1748390400,
    "updated_at": 1748390400,
}
```

Channel messages follow the same pattern as broadcast chat (`app/services/broadcast_chat_store.py`) but with tier-based access enforcement instead of session-based.

#### 3.2.1 Channel Message Data Model

```python
# fan_club_messages table
{
    "channel_id": "chan_vip_alice",
    "sort_key": "1748395000#msg_abc123",  # "{timestamp}#{message_id}" for chronological ordering
    "message_id": "msg_abc123",
    "sender_id": "user_bob",
    "sender_display_name": "Bob",
    "sender_badge": {
        "tier_name": "VIP",
        "tier_level": 2,
        "badge_emoji": "crown",
        "badge_color": "#FFD700",
    },
    "text": "Hello VIP lounge!",
    "kind": "text",            # text | image | reaction | system
    "reply_to_message_id": null,
    "reactions": {},           # {emoji: {user_id: True}}
    "deleted": false,
    "deleted_by": null,
    "deleted_at": null,
    "created_at": 1748395000,
}
```

### 3.3 Badge Resolution Pipeline

When a chat message or comment is rendered, the system resolves the sender's badge:

```python
# app/services/fan_club_badges.py

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# In-memory cache: {f"{user_id}#{creator_id}": (badge_data, expires_at)}
_BADGE_CACHE: Dict[str, tuple] = {}
_BADGE_CACHE_TTL_SECONDS = 60


def resolve_member_badge(user_id: str, creator_id: str) -> Optional[Dict[str, Any]]:
    """Resolve the highest-tier badge for a user within a creator's fan club.

    Returns None if user has no active subscription or creator has no tiers.
    Uses a 60-second in-memory cache to avoid repeated DDB queries during chat.
    """
    cache_key = f"{user_id}#{creator_id}"
    now = now_ts()

    # Check cache
    cached = _BADGE_CACHE.get(cache_key)
    if cached and cached[1] > now:
        return cached[0]

    # 1. Find user's active subscription to this creator
    sub = _get_active_subscription(user_id, creator_id)
    if not sub:
        _BADGE_CACHE[cache_key] = (None, now + _BADGE_CACHE_TTL_SECONDS)
        return None

    # 2. Look up the tier linked to this plan
    tier = _get_tier_by_plan(creator_id, sub["plan_id"])
    if not tier or not tier.get("active"):
        _BADGE_CACHE[cache_key] = (None, now + _BADGE_CACHE_TTL_SECONDS)
        return None

    badge = {
        "tier_name": tier["name"],
        "tier_level": int(tier["level"]),
        "badge_emoji": tier.get("badge_emoji"),
        "badge_color": tier.get("color"),
        "badge_image_url": tier.get("badge_image_url"),
    }
    _BADGE_CACHE[cache_key] = (badge, now + _BADGE_CACHE_TTL_SECONDS)
    return badge


def _get_active_subscription(user_id: str, creator_id: str) -> Optional[Dict[str, Any]]:
    """Get the user's active subscription to a creator."""
    try:
        resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(f"SUBSCRIBER#{user_id}")
            & Key("sk").begins_with("SUB#"),
        )
    except Exception:
        return None

    for item in resp.get("Items", []):
        if item.get("creator_id") != creator_id:
            continue
        status = (item.get("status") or "").lower()
        if status in {"active", "past_due", "trialing"}:
            return item
    return None


def _get_tier_by_plan(creator_id: str, plan_id: str) -> Optional[Dict[str, Any]]:
    """Find the tier linked to a specific plan for a creator."""
    try:
        resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(f"CREATOR#{creator_id}")
            & Key("sk").begins_with("TIER#"),
        )
    except Exception:
        return None

    for item in resp.get("Items", []):
        if item.get("plan_id") == plan_id:
            return item
    return None


def get_subscriber_tier_level(subscriber_id: str, creator_id: str) -> Optional[int]:
    """Get the tier level for a subscriber, or None if not subscribed or no tier system.

    This is the primary function for access control checks.
    """
    badge = resolve_member_badge(subscriber_id, creator_id)
    if badge:
        return badge["tier_level"]
    return None


def get_creator_tiers(creator_id: str) -> List[Dict[str, Any]]:
    """List all tiers for a creator, sorted by level."""
    try:
        resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(f"CREATOR#{creator_id}")
            & Key("sk").begins_with("TIER#"),
        )
    except Exception:
        return []

    tiers = [item for item in resp.get("Items", []) if item.get("active", True)]
    tiers.sort(key=lambda t: int(t.get("level", 0)))
    return tiers


def invalidate_badge_cache(user_id: str, creator_id: str) -> None:
    """Clear the cached badge for a user-creator pair (call on subscription change)."""
    cache_key = f"{user_id}#{creator_id}"
    _BADGE_CACHE.pop(cache_key, None)
```

### 3.4 Early Access Content Gating

Posts and VOD content support a new `early_access_config` field:

```python
{
    "early_access_tier_level": 3,     # only tier >= 3 sees it immediately
    "general_release_at": 1748563200, # Unix timestamp when all subscribers can see it
    "general_release_delay_hours": 48,# alternative: auto-compute from publish time
}
```

The content visibility check:

```python
# app/services/fan_club_access.py

from app.core.time import now_ts
from app.services.fan_club_badges import get_subscriber_tier_level
from app.services.subscription_access import can_access_creator


def can_view_content(user_id: str, creator_id: str, content: Dict[str, Any]) -> bool:
    """Check if user can view content considering early access.

    Access decision tree:
    1. Creator can always see their own content
    2. If no early_access_tier_level, use standard subscription check
    3. If past general_release_at, use standard subscription check
    4. Before general release: require tier level >= early_access_tier_level

    Returns True if user can view, False otherwise.
    """
    # Creator always sees own content
    if user_id == creator_id:
        return True

    early_access = content.get("early_access_tier_level")
    if not early_access:
        return can_access_creator(user_id, creator_id)  # existing check

    general_release = content.get("general_release_at", 0)
    if now_ts() >= general_release:
        return can_access_creator(user_id, creator_id)  # past general release

    # Before general release: check tier level
    tier_level = get_subscriber_tier_level(user_id, creator_id)
    return tier_level is not None and tier_level >= early_access


def compute_general_release_at(publish_at: int, delay_hours: int) -> int:
    """Compute the general release timestamp from publish time + delay."""
    return publish_at + (delay_hours * 3600)


def get_early_access_status(
    user_id: str,
    creator_id: str,
    content: Dict[str, Any],
) -> Dict[str, Any]:
    """Get detailed early access status for a content item.

    Returns a dict with:
    - can_view: bool
    - is_early_access: bool
    - user_tier_level: Optional[int]
    - required_tier_level: Optional[int]
    - general_release_at: Optional[int]
    - time_until_release_seconds: Optional[int]
    """
    early_access = content.get("early_access_tier_level")
    if not early_access:
        return {"can_view": can_access_creator(user_id, creator_id), "is_early_access": False}

    general_release = content.get("general_release_at", 0)
    now = now_ts()
    tier_level = get_subscriber_tier_level(user_id, creator_id)
    can_view = (
        user_id == creator_id
        or now >= general_release
        or (tier_level is not None and tier_level >= early_access)
    )

    return {
        "can_view": can_view,
        "is_early_access": True,
        "user_tier_level": tier_level,
        "required_tier_level": early_access,
        "general_release_at": general_release,
        "time_until_release_seconds": max(0, general_release - now) if now < general_release else 0,
    }
```

### 3.5 Tier Upgrade/Downgrade Flow

```
Subscriber                   Backend                     Billing
    |                           |                            |
    |  POST /subscribe          |                            |
    |  {plan_id: "plan_gold"}   |                            |
    |-------------------------->|                            |
    |                           | resolve tier for plan_gold |
    |                           | check existing subscription|
    |                           |                            |
    |                           | [UPGRADE path]             |
    |                           | calculate proration        |
    |                           |--------------------------->|
    |                           |    charge/credit proration |
    |                           |<---------------------------|
    |                           |                            |
    |                           | update subscription record |
    |                           | (plan_id = plan_gold,      |
    |                           |  tier_id = tier_gold)      |
    |                           |                            |
    |                           | decrement old tier count   |
    |                           | increment new tier count   |
    |                           | invalidate badge cache     |
    |                           | update channel access      |
    |                           | send welcome message       |
    |                           |                            |
    |  200 {subscription}       |                            |
    |<--------------------------|                            |
```

### 3.6 Channel Access Enforcement

```python
# app/services/fan_club_channels.py

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.fan_club_badges import get_subscriber_tier_level, resolve_member_badge

logger = logging.getLogger(__name__)


def enforce_channel_access(channel: Dict[str, Any], user_id: str, creator_id: str) -> None:
    """Validate that a user has the required tier level for a channel.

    The creator always has access to their own channels.

    Raises HTTPException 403 if access is denied.
    """
    # Creator always has access
    if user_id == creator_id:
        return

    min_level = int(channel.get("min_tier_level", 1))
    user_level = get_subscriber_tier_level(user_id, creator_id)

    if user_level is None:
        raise HTTPException(
            status_code=403,
            detail="You need an active subscription to access this channel.",
        )

    if user_level < min_level:
        raise HTTPException(
            status_code=403,
            detail=f"Your membership tier does not include access to this channel. Required: level {min_level}+, your level: {user_level}.",
        )


def create_channel(
    *,
    creator_id: str,
    name: str,
    description: Optional[str] = None,
    min_tier_level: int = 1,
    slowmode_seconds: int = 0,
    max_message_length: int = 500,
) -> Dict[str, Any]:
    """Create a new exclusive chat channel."""
    channel_id = f"chan_{uuid.uuid4().hex[:12]}"
    now = now_ts()

    item = {
        "channel_id": channel_id,
        "creator_id": creator_id,
        "name": name,
        "description": description,
        "min_tier_level": min_tier_level,
        "message_count": 0,
        "last_message_at": 0,
        "last_message_preview": None,
        "pinned_message_id": None,
        "slowmode_seconds": slowmode_seconds,
        "max_message_length": max_message_length,
        "created_at": now,
        "updated_at": now,
    }
    T.fan_club_channels.put_item(Item=item)
    return item


def send_channel_message(
    *,
    channel_id: str,
    sender_id: str,
    sender_display_name: str,
    text: str,
    creator_id: str,
    kind: str = "text",
    reply_to_message_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Send a message to an exclusive chat channel.

    Validates tier access, enforces rate limits, resolves badge,
    writes message, and publishes SSE event.
    """
    # Get channel
    channel = get_channel(channel_id)
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")

    # Enforce access
    enforce_channel_access(channel, sender_id, creator_id)

    # Enforce slowmode
    slowmode = int(channel.get("slowmode_seconds", 0))
    if slowmode > 0 and sender_id != creator_id:
        _enforce_slowmode(channel_id, sender_id, slowmode)

    # Enforce message length
    max_len = int(channel.get("max_message_length", 500))
    if len(text) > max_len:
        raise HTTPException(status_code=400, detail=f"Message too long. Maximum {max_len} characters.")

    # Resolve badge
    badge = resolve_member_badge(sender_id, creator_id)

    # Write message
    msg_id = f"msg_{uuid.uuid4().hex[:12]}"
    now = now_ts()
    sort_key = f"{now}#{msg_id}"

    message_item = {
        "channel_id": channel_id,
        "sort_key": sort_key,
        "message_id": msg_id,
        "sender_id": sender_id,
        "sender_display_name": sender_display_name,
        "sender_badge": badge,
        "text": text,
        "kind": kind,
        "reply_to_message_id": reply_to_message_id,
        "reactions": {},
        "deleted": False,
        "created_at": now,
    }
    T.fan_club_messages.put_item(Item=message_item)

    # Update channel metadata
    _update_channel_last_message(channel_id, now, text[:100])

    return message_item


def get_channel(channel_id: str) -> Optional[Dict[str, Any]]:
    """Get a channel by ID."""
    resp = T.fan_club_channels.get_item(Key={"channel_id": channel_id})
    return resp.get("Item")


def list_channels_for_user(creator_id: str, user_id: str) -> List[Dict[str, Any]]:
    """List channels accessible to a user based on their tier level.

    Returns all channels where user's tier >= channel's min_tier_level.
    Creator sees all channels regardless of tier.
    """
    # Get all channels for this creator
    resp = T.fan_club_channels.query(
        IndexName="ByCreator",
        KeyConditionExpression=Key("creator_id").eq(creator_id),
    )
    all_channels = resp.get("Items", [])

    if user_id == creator_id:
        return sorted(all_channels, key=lambda c: int(c.get("min_tier_level", 1)))

    user_level = get_subscriber_tier_level(user_id, creator_id)
    if user_level is None:
        return []

    accessible = [c for c in all_channels if int(c.get("min_tier_level", 1)) <= user_level]
    return sorted(accessible, key=lambda c: int(c.get("min_tier_level", 1)))


def get_channel_messages(
    channel_id: str,
    *,
    limit: int = 50,
    before_sort_key: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Get paginated message history for a channel (newest first)."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("channel_id").eq(channel_id),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if before_sort_key:
        kwargs["ExclusiveStartKey"] = {"channel_id": channel_id, "sort_key": before_sort_key}

    resp = T.fan_club_messages.query(**kwargs)
    items = resp.get("Items", [])
    return [item for item in items if not item.get("deleted")]


def _update_channel_last_message(channel_id: str, timestamp: int, preview: str) -> None:
    """Update channel's last_message_at and preview."""
    try:
        T.fan_club_channels.update_item(
            Key={"channel_id": channel_id},
            UpdateExpression="SET last_message_at = :ts, last_message_preview = :preview, message_count = message_count + :one, updated_at = :ts",
            ExpressionAttributeValues={":ts": timestamp, ":preview": preview, ":one": 1},
        )
    except Exception:
        logger.warning("Failed to update channel last message", extra={"channel_id": channel_id})


def _enforce_slowmode(channel_id: str, user_id: str, slowmode_seconds: int) -> None:
    """Enforce slowmode rate limit for a channel."""
    # Use in-memory rate limiting (same pattern as broadcast_chat_store.py)
    import time
    key = f"{channel_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    limit_ms = slowmode_seconds * 1000

    # Simple in-memory check (production would use Redis or DDB)
    from app.services.broadcast_chat_store import _CHAT_RATE_LOCK, _CHAT_RATE_BUCKETS
    with _CHAT_RATE_LOCK:
        last = _CHAT_RATE_BUCKETS.get(f"fanclub#{key}", 0)
        if now_ms - last < limit_ms:
            raise HTTPException(
                status_code=429,
                detail=f"Slowmode active. Please wait {slowmode_seconds} seconds between messages.",
            )
        _CHAT_RATE_BUCKETS[f"fanclub#{key}"] = now_ms
```

### 3.7 Tier Member Count Maintenance

Member counts are denormalized on tier records for fast display. They are maintained via atomic increments on subscription events:

```python
def increment_tier_member_count(creator_id: str, tier_id: str, delta: int = 1) -> None:
    """Atomically increment or decrement the member count on a tier."""
    try:
        T.subscriptions.update_item(
            Key={"pk": f"CREATOR#{creator_id}", "sk": f"TIER#{tier_id}"},
            UpdateExpression="SET member_count = if_not_exists(member_count, :zero) + :delta, updated_at = :now",
            ExpressionAttributeValues={":delta": delta, ":zero": 0, ":now": now_ts()},
        )
    except Exception:
        logger.warning("Failed to update tier member count", extra={"tier_id": tier_id, "delta": delta})
```

A nightly reconciliation job can recount actual subscribers per tier and fix any drift from failed atomic updates.

---

## 4. API Endpoints

### 4.1 Tier Management (Creator)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/fan-club/tiers` | `require_ui_session` | Create a new tier |
| GET | `/ui/fan-club/tiers` | `require_ui_session` | List creator's tiers |
| GET | `/ui/fan-club/tiers/{tier_id}` | `require_ui_session` | Get tier detail |
| PATCH | `/ui/fan-club/tiers/{tier_id}` | `require_ui_session` | Update tier (name, color, benefits, active) |
| DELETE | `/ui/fan-club/tiers/{tier_id}` | `require_ui_session` | Archive a tier (soft delete) |
| PATCH | `/ui/fan-club/tiers/reorder` | `require_ui_session` | Reorder tiers |
| GET | `/ui/fan-club/tiers/{tier_id}/members` | `require_ui_session` | Paginated member list for a tier |
| PUT | `/ui/fan-club/tiers/{tier_id}/badge-image` | `require_ui_session` | Upload custom badge image |

### 4.2 Exclusive Chat Channels

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/fan-club/channels` | `require_ui_session` | Create an exclusive chat channel |
| GET | `/ui/fan-club/channels` | `require_ui_session` | List channels accessible to the user |
| GET | `/ui/fan-club/channels/{channel_id}` | `require_ui_session` | Get channel detail |
| PATCH | `/ui/fan-club/channels/{channel_id}` | `require_ui_session` | Update channel settings |
| DELETE | `/ui/fan-club/channels/{channel_id}` | `require_ui_session` | Delete a channel (creator only) |
| POST | `/ui/fan-club/channels/{channel_id}/messages` | `require_ui_session` | Send a message |
| GET | `/ui/fan-club/channels/{channel_id}/messages` | `require_ui_session` | Get message history |
| DELETE | `/ui/fan-club/channels/{channel_id}/messages/{message_id}` | `require_ui_session` | Delete a message (creator/admin) |
| POST | `/ui/fan-club/channels/{channel_id}/messages/{message_id}/react` | `require_ui_session` | Add reaction |
| DELETE | `/ui/fan-club/channels/{channel_id}/messages/{message_id}/react/{emoji}` | `require_ui_session` | Remove reaction |
| PUT | `/ui/fan-club/channels/{channel_id}/pin/{message_id}` | `require_ui_session` | Pin a message |

### 4.3 Public Tier Listing

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/creators/{creator_id}/tiers` | None | List active tiers for a creator (public, for display on creator profile) |

### 4.4 Member Badge Resolution

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/fan-club/badge/{creator_id}` | `require_ui_session` | Get caller's badge for a specific creator |
| GET | `/ui/fan-club/my-badges` | `require_ui_session` | Get all badges for the caller across all creators |

### 4.5 Tier Analytics (Creator)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/fan-club/analytics` | `require_ui_session` | Tier distribution, revenue by tier, churn by tier |

### 4.6 Request/Response Models

```python
# app/models.py additions

class TierBenefit(BaseModel):
    type: str = Field(..., description="Benefit type: early_access, exclusive_chat, custom_emoji, badge, text, discount, priority_dm")
    label: Optional[str] = Field(default=None, max_length=200, description="Display label for text benefits")
    delay_hours: Optional[int] = Field(default=None, ge=0, le=720, description="Early access delay for non-qualifying tiers")
    channel_id: Optional[str] = Field(default=None, description="Channel ID for exclusive_chat benefit")
    emoji_pack_id: Optional[str] = Field(default=None, description="Emoji pack ID for custom_emoji benefit")
    display: Optional[bool] = Field(default=None, description="Whether badge is displayed (for badge benefit)")
    percent_off: Optional[int] = Field(default=None, ge=1, le=100, description="Discount percentage for discount benefit")
    applies_to: Optional[List[str]] = Field(default=None, description="What the discount applies to")


class TierCreateIn(BaseModel):
    plan_id: str = Field(..., min_length=1, max_length=128, description="Linked subscription plan ID")
    name: str = Field(..., min_length=1, max_length=50, description="Tier display name")
    level: int = Field(..., ge=1, le=6, description="Tier level (1=lowest, 6=highest)")
    color: str = Field(..., pattern=r"^#[0-9a-fA-F]{6}$", description="Hex color for badge")
    badge_emoji: Optional[str] = Field(default=None, max_length=32, description="Emoji for the badge")
    description: Optional[str] = Field(default=None, max_length=500, description="Tier description")
    benefits: List[TierBenefit] = Field(default_factory=list, max_length=20, description="List of tier benefits")
    welcome_message: Optional[str] = Field(default=None, max_length=1000, description="Auto-DM on subscription")
    sort_order: int = Field(default=0, ge=0, le=10, description="Display order")


class TierUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=50)
    color: Optional[str] = Field(default=None, pattern=r"^#[0-9a-fA-F]{6}$")
    badge_emoji: Optional[str] = Field(default=None, max_length=32)
    description: Optional[str] = Field(default=None, max_length=500)
    benefits: Optional[List[TierBenefit]] = Field(default=None, max_length=20)
    welcome_message: Optional[str] = Field(default=None, max_length=1000)
    sort_order: Optional[int] = Field(default=None, ge=0, le=10)
    active: Optional[bool] = None


class TierOut(BaseModel):
    tier_id: str
    creator_id: str
    plan_id: str
    name: str
    level: int
    color: str
    badge_emoji: Optional[str] = None
    badge_image_url: Optional[str] = None
    description: Optional[str] = None
    benefits: List[Dict[str, Any]] = Field(default_factory=list)
    welcome_message: Optional[str] = None
    member_count: int = 0
    sort_order: int = 0
    active: bool = True
    plan_price_cents: Optional[int] = None
    plan_currency: Optional[str] = None
    plan_interval: Optional[str] = None
    created_at: int
    updated_at: int


class TierReorderIn(BaseModel):
    tier_ids: List[str] = Field(..., min_length=1, max_length=6, description="Tier IDs in desired order")


class ChannelCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Channel display name")
    description: Optional[str] = Field(default=None, max_length=500, description="Channel description")
    min_tier_level: int = Field(..., ge=1, le=6, description="Minimum tier level for access")
    slowmode_seconds: int = Field(default=0, ge=0, le=3600, description="Seconds between messages (0=off)")
    max_message_length: int = Field(default=500, ge=1, le=2000, description="Maximum message length")


class ChannelOut(BaseModel):
    channel_id: str
    creator_id: str
    name: str
    description: Optional[str] = None
    min_tier_level: int
    message_count: int = 0
    last_message_at: int = 0
    last_message_preview: Optional[str] = None
    pinned_message_id: Optional[str] = None
    slowmode_seconds: int = 0
    max_message_length: int = 500
    created_at: int
    updated_at: int


class ChannelMessageIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=2000)
    reply_to_message_id: Optional[str] = None


class ChannelMessageOut(BaseModel):
    message_id: str
    channel_id: str
    sender_id: str
    sender_display_name: str
    sender_badge: Optional[Dict[str, Any]] = None
    text: str
    kind: str = "text"
    reply_to_message_id: Optional[str] = None
    reactions: Dict[str, Any] = Field(default_factory=dict)
    created_at: int
    deleted: bool = False


class MemberBadgeOut(BaseModel):
    tier_name: str
    tier_level: int
    badge_emoji: Optional[str] = None
    badge_color: Optional[str] = None
    badge_image_url: Optional[str] = None


class TierMemberOut(BaseModel):
    user_id: str
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    subscribed_at: int
    tier_name: str
    tier_level: int
    total_spent_cents: int = 0


class TierAnalyticsOut(BaseModel):
    total_members: int = 0
    tiers: List[Dict[str, Any]] = Field(default_factory=list)  # [{tier_id, name, level, member_count, revenue_cents}]
    churn_rate_30d: float = 0.0
    upgrade_rate_30d: float = 0.0
    avg_lifetime_days: float = 0.0
```

---

## 5. Frontend Components

### 5.1 New Pages and Components

| Component | Path | Purpose |
|-----------|------|---------|
| `FanClubPage` | `frontend/src/pages/fan-club/FanClubPage.tsx` | Creator management dashboard for tiers and channels |
| `TierEditor` | `frontend/src/pages/fan-club/TierEditor.tsx` | Create/edit tier with color picker, emoji selector, benefits list |
| `TierCard` | `frontend/src/pages/fan-club/TierCard.tsx` | Display card for a single tier (used in creator dashboard and public profile) |
| `ExclusiveChatView` | `frontend/src/pages/fan-club/ExclusiveChatView.tsx` | Chat interface for exclusive channels (reuses ConversationView patterns) |
| `MemberBadge` | `frontend/src/components/shared/MemberBadge.tsx` | Inline badge component: colored emoji/icon that renders in chat and comments |
| `TierSelector` | `frontend/src/components/shared/TierSelector.tsx` | Dropdown for selecting early access tier when creating posts |
| `ChannelList` | `frontend/src/pages/fan-club/ChannelList.tsx` | List of exclusive channels with access indicators |
| `TierMemberList` | `frontend/src/pages/fan-club/TierMemberList.tsx` | Paginated member list with search |
| `TierAnalyticsPanel` | `frontend/src/pages/fan-club/TierAnalyticsPanel.tsx` | Tier distribution charts and churn metrics |
| `BadgeImageUploader` | `frontend/src/pages/fan-club/BadgeImageUploader.tsx` | Upload/preview custom badge images |

### 5.2 Frontend API Types and Endpoints

```typescript
// frontend/src/api/types.ts additions

export interface TierBenefit {
  type: string;
  label?: string;
  delay_hours?: number;
  channel_id?: string;
  emoji_pack_id?: string;
  display?: boolean;
  percent_off?: number;
  applies_to?: string[];
}

export interface TierCreateIn {
  plan_id: string;
  name: string;
  level: number;
  color: string;
  badge_emoji?: string;
  description?: string;
  benefits: TierBenefit[];
  welcome_message?: string;
  sort_order?: number;
}

export interface TierOut {
  tier_id: string;
  creator_id: string;
  plan_id: string;
  name: string;
  level: number;
  color: string;
  badge_emoji?: string;
  badge_image_url?: string;
  description?: string;
  benefits: TierBenefit[];
  welcome_message?: string;
  member_count: number;
  sort_order: number;
  active: boolean;
  plan_price_cents?: number;
  plan_currency?: string;
  plan_interval?: string;
  created_at: number;
  updated_at: number;
}

export interface ChannelOut {
  channel_id: string;
  creator_id: string;
  name: string;
  description?: string;
  min_tier_level: number;
  message_count: number;
  last_message_at: number;
  last_message_preview?: string;
  slowmode_seconds: number;
  created_at: number;
}

export interface ChannelMessageOut {
  message_id: string;
  channel_id: string;
  sender_id: string;
  sender_display_name: string;
  sender_badge?: MemberBadgeData;
  text: string;
  kind: string;
  reply_to_message_id?: string;
  reactions: Record<string, Record<string, boolean>>;
  created_at: number;
  deleted: boolean;
}

export interface MemberBadgeData {
  tier_name: string;
  tier_level: number;
  badge_emoji?: string;
  badge_color?: string;
  badge_image_url?: string;
}
```

```typescript
// frontend/src/api/endpoints/fan-club.ts

import api from "../client";
import type { TierCreateIn, TierOut, ChannelOut, ChannelMessageOut, MemberBadgeData } from "../types";

export async function createTier(data: TierCreateIn): Promise<TierOut> {
  const res = await api.post("/ui/fan-club/tiers", data);
  return res.data;
}

export async function listTiers(): Promise<TierOut[]> {
  const res = await api.get("/ui/fan-club/tiers");
  return res.data;
}

export async function updateTier(tierId: string, data: Partial<TierCreateIn>): Promise<TierOut> {
  const res = await api.patch(`/ui/fan-club/tiers/${tierId}`, data);
  return res.data;
}

export async function deleteTier(tierId: string): Promise<void> {
  await api.delete(`/ui/fan-club/tiers/${tierId}`);
}

export async function listChannels(creatorId?: string): Promise<ChannelOut[]> {
  const params = creatorId ? { creator_id: creatorId } : {};
  const res = await api.get("/ui/fan-club/channels", { params });
  return res.data;
}

export async function sendChannelMessage(channelId: string, text: string): Promise<ChannelMessageOut> {
  const res = await api.post(`/ui/fan-club/channels/${channelId}/messages`, { text });
  return res.data;
}

export async function getChannelMessages(channelId: string, params?: { before?: string; limit?: number }): Promise<ChannelMessageOut[]> {
  const res = await api.get(`/ui/fan-club/channels/${channelId}/messages`, { params });
  return res.data;
}

export async function getMyBadge(creatorId: string): Promise<MemberBadgeData | null> {
  const res = await api.get(`/ui/fan-club/badge/${creatorId}`);
  return res.data;
}

export async function getPublicTiers(creatorId: string): Promise<TierOut[]> {
  const res = await api.get(`/api/creators/${creatorId}/tiers`);
  return res.data;
}
```

### 5.3 Integration Points

- **BroadcastChatMessageOut rendering**: Add `MemberBadge` next to `sender_display_name` in broadcast chat
- **MessageBubble.tsx**: Show `MemberBadge` for DM messages when sender has a tier in the recipient's fan club
- **CommentRow.tsx** (`CommentsThread`): Show `MemberBadge` next to commenter name on newsfeed posts
- **CreatePost.tsx**: Add `TierSelector` for early access gating
- **Sidebar.tsx / AppShell.tsx**: Add "Fan Club" nav item
- **MobileNav.tsx**: Add "Fan Club" to `MORE_LINKS`
- **Creator profile page**: Show tier cards for potential subscribers
- **PostCard.tsx**: Show early access indicator ("Early access for VIP+") when content has `early_access_tier_level`

### 5.4 Badge Rendering

```tsx
// frontend/src/components/shared/MemberBadge.tsx

import { cn } from "@/lib/utils";
import type { MemberBadgeData } from "@/api/types";

interface MemberBadgeProps {
  badge: MemberBadgeData | null;
  size?: "xs" | "sm" | "md";
  showName?: boolean;
}

export function MemberBadge({ badge, size = "sm", showName = true }: MemberBadgeProps) {
  if (!badge) return null;

  const sizeClasses = {
    xs: "px-1 py-0 text-[10px]",
    sm: "px-1.5 py-0.5 text-xs",
    md: "px-2 py-1 text-sm",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center gap-0.5 rounded-full font-medium",
        sizeClasses[size],
      )}
      style={{
        backgroundColor: badge.badge_color ? `${badge.badge_color}20` : undefined,
        color: badge.badge_color || undefined,
      }}
      title={badge.tier_name}
    >
      {badge.badge_image_url ? (
        <img src={badge.badge_image_url} alt="" className="h-3 w-3 rounded-full" />
      ) : badge.badge_emoji ? (
        <span>{badge.badge_emoji}</span>
      ) : null}
      {showName && <span>{badge.tier_name}</span>}
    </span>
  );
}
```

### 5.5 Route

```tsx
// App.tsx
{ path: "/fan-club", element: <FanClubPage /> }
```

---

## 6. DynamoDB Table Definitions

### 6.1 Existing Table Extension (subscriptions)

Tiers are stored in the existing `subscriptions` table under `CREATOR#{creator_id}` / `TIER#{tier_id}` keys. No new table needed for tier metadata.

Access patterns on the subscriptions table for tiers:
| Pattern | Key Condition |
|---------|---------------|
| List creator's tiers | `pk = CREATOR#{creator_id}, sk begins_with TIER#` |
| Get specific tier | `pk = CREATOR#{creator_id}, sk = TIER#{tier_id}` |
| Find tier by plan | `pk = CREATOR#{creator_id}, sk begins_with TIER#` + filter `plan_id = X` |

### 6.2 New Table: fan_club_channels

```python
# scripts/local-ddb-init.py
TableDef(
    name="fan_club_channels",
    pk="channel_id",
    gsis=[
        GsiDef(name="ByCreator", pk="creator_id", sk="created_at"),
    ],
    attr_types={"created_at": "N"},
),
```

Table handle registration:
```python
# app/core/tables.py
fan_club_channels = ddb.Table(S.fan_club_channels_table or "fan_club_channels")
```

### 6.3 New Table: fan_club_messages

```python
# scripts/local-ddb-init.py
TableDef(
    name="fan_club_messages",
    pk="channel_id",
    sk="sort_key",  # "{timestamp}#{message_id}" for chronological ordering
    gsis=[],
),
```

Table handle registration:
```python
# app/core/tables.py
fan_club_messages = ddb.Table(S.fan_club_messages_table or "fan_club_messages")
```

### 6.4 Capacity Estimates

- **Tiers**: ~6 items per creator, very low volume. Stored in existing subscriptions table.
- **Channels**: ~3-5 per creator, very low volume.
- **Messages**: High volume for active channels. Estimated 100-1000 messages/day for popular channels. On-demand billing recommended.
- **Badge cache**: In-memory, no DDB cost. Cache hit rate expected >95% during chat sessions.

---

## 7. E2E Test Plan

### 7.1 Test File

`frontend/e2e/fan-club.spec.ts`

### 7.2 Test Sections

| Section | Title | Tests |
|---------|-------|-------|
| 1 | Tier CRUD API | 7 tests: create tier, list tiers, get tier, update tier, reorder tiers, archive tier, public tier listing |
| 2 | Badge Resolution API | 4 tests: resolve badge for subscriber, no badge for non-subscriber, badge includes emoji and color, badge appears in broadcast chat message |
| 3 | Exclusive Chat Channels API | 6 tests: create channel, list channels (filtered by tier), send message, get history, delete message, non-member gets 403 |
| 4 | Early Access Content API | 4 tests: create post with early access, high-tier sees immediately, low-tier sees 403, post becomes visible after delay |
| 5 | Fan Club Page UI | 5 tests: page loads with tiers tab, create tier dialog, tier card renders with badge, channel list renders, exclusive chat opens |
| 6 | Badge Display Integration | 4 tests: badge in broadcast chat, badge in DM message, badge in newsfeed comment, no badge for non-member |
| 7 | Tier Upgrade/Downgrade API | 4 tests: upgrade changes badge, downgrade loses channel access, member count updates, badge cache invalidated |
| 8 | Channel Features API | 4 tests: slowmode enforcement, message length limit, pin message, reactions |

**Estimated total**: ~38 tests

### 7.3 Test Users

- Alice: creator with fan club tiers configured
- Bob: subscribed to Alice's "VIP" tier (level 2)
- Charlie: subscribed to Alice's "Basic" tier (level 1)
- Root: admin for audit endpoints

### 7.4 Test Data Setup

```typescript
const TS = Date.now();
let tierId1: string; // Basic, level 1
let tierId2: string; // VIP, level 2
let channelId: string;

test.beforeAll(async ({ browser }) => {
  // 1. Create subscription plans for Alice
  // (using subscription server API)
  const alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");

  // Create Basic plan
  const basicPlanResp = await alicePage.request.post("/api/plans", {
    headers: { "x-user-id": sessions.alice.user_sub },
    data: {
      name: `Basic ${TS}`,
      price_cents: 499,
      currency: "usd",
      interval: "month",
    },
  });
  const basicPlan = await basicPlanResp.json();

  // Create VIP plan
  const vipPlanResp = await alicePage.request.post("/api/plans", {
    headers: { "x-user-id": sessions.alice.user_sub },
    data: {
      name: `VIP ${TS}`,
      price_cents: 999,
      currency: "usd",
      interval: "month",
    },
  });
  const vipPlan = await vipPlanResp.json();

  // Create tiers
  const tier1Resp = await alicePage.request.post("/ui/fan-club/tiers", {
    headers: { "x-csrf-token": sessions.alice.csrf_token },
    data: {
      plan_id: basicPlan.plan_id,
      name: "Basic",
      level: 1,
      color: "#3B82F6",
      badge_emoji: "star",
      description: "Basic tier",
      benefits: [{ type: "badge", display: true }],
    },
  });
  tierId1 = (await tier1Resp.json()).tier_id;

  const tier2Resp = await alicePage.request.post("/ui/fan-club/tiers", {
    headers: { "x-csrf-token": sessions.alice.csrf_token },
    data: {
      plan_id: vipPlan.plan_id,
      name: "VIP",
      level: 2,
      color: "#FFD700",
      badge_emoji: "crown",
      description: "VIP tier",
      benefits: [
        { type: "badge", display: true },
        { type: "early_access", delay_hours: 0 },
      ],
    },
  });
  tierId2 = (await tier2Resp.json()).tier_id;

  // Create exclusive channel
  const chanResp = await alicePage.request.post("/ui/fan-club/channels", {
    headers: { "x-csrf-token": sessions.alice.csrf_token },
    data: {
      name: `VIP Lounge ${TS}`,
      description: "For VIP members",
      min_tier_level: 2,
    },
  });
  channelId = (await chanResp.json()).channel_id;

  // Subscribe Bob to VIP plan, Charlie to Basic plan
  // (direct DDB writes for test setup)
  // ...

  await alicePage.close();
});
```

### 7.5 Example Test Cases

```typescript
test("3.6 — Non-member gets 403 on channel message", async ({ browser }) => {
  // Charlie is Basic (level 1), channel requires level 2
  const page = await browser.newPage();
  await injectAuth(page, "charlie");

  const resp = await page.request.post(`/ui/fan-club/channels/${channelId}/messages`, {
    headers: { "x-csrf-token": sessions.charlie.csrf_token },
    data: { text: "I should not be able to send this" },
  });
  expect(resp.status()).toBe(403);
  const body = await resp.json();
  expect(body.detail).toContain("membership tier");

  await page.close();
});

test("4.1 — High-tier sees early access content", async ({ browser }) => {
  // Alice creates post with early_access_tier_level=2
  const alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");

  const postResp = await alicePage.request.post("/posts", {
    headers: { "x-csrf-token": sessions.alice.csrf_token },
    data: {
      body: `Early access post ${TS}`,
      early_access_tier_level: 2,
      general_release_delay_hours: 48,
    },
  });
  expect(postResp.status()).toBe(201);
  const post = await postResp.json();

  // Bob (VIP, level 2) can see it
  const bobPage = await browser.newPage();
  await injectAuth(bobPage, "bob");
  const bobResp = await bobPage.request.get(`/posts/${post.post_id}`);
  expect(bobResp.status()).toBe(200);

  // Charlie (Basic, level 1) gets 403 or filtered out
  const charliePage = await browser.newPage();
  await injectAuth(charliePage, "charlie");
  const charlieResp = await charliePage.request.get(`/posts/${post.post_id}`);
  expect(charlieResp.status()).toBe(403);

  await Promise.all([alicePage.close(), bobPage.close(), charliePage.close()]);
});
```

---

## 8. Edge Cases

| Case | Behavior |
|------|----------|
| Creator has no tiers defined | Fan club features are disabled. No badges, no exclusive channels. Subscriptions work as before. |
| Plan linked to tier is archived | Tier becomes inactive. Existing members retain access until subscription expires. |
| User upgrades tier | Higher tier unlocks immediately. Badge updates on next message. All lower-tier channels remain accessible. |
| User downgrades tier | Lower-tier channels that require higher level become inaccessible. Badge updates. Existing messages in higher-tier channels remain visible (read-only). |
| Tier level conflict | Two tiers cannot share the same `level` for the same creator. 409 on create/update. |
| Badge image upload | Custom badge images are stored in S3 under `uploads/badges/{creator_id}/{tier_id}.*`. Max size 256KB, PNG/SVG only. |
| Channel with no eligible members | Channel exists but is empty. Creator can still post messages. |
| Tier deletion with active members | Soft delete only. Members retain current badge until subscription renewal. At renewal, they must pick a different plan/tier. |
| Early access content with no tiers | `early_access_tier_level` is ignored if creator has no tiers. Content is visible to all subscribers. |
| Concurrent tier updates | DynamoDB conditional update on `updated_at` prevents lost writes. 409 on conflict. |
| Badge emoji not found | Frontend renders a colored dot fallback if `badge_emoji` is an unrecognized value. |
| Channel message while subscription lapses mid-session | Message send fails with 403. Frontend shows "Your subscription has expired" toast. |
| Large badge image | Server validates <= 256KB before S3 upload. Returns 413 for oversized images. |
| Tier with 0 benefits | Allowed. Tier acts as a named subscription level with badge only. |
| Welcome message with special characters | Message is sanitized (HTML entities escaped) before sending as DM. Markdown is allowed. |
| Creator views own channel | Creator always has access regardless of tier (they don't subscribe to themselves). |

---

## 9. Security Considerations

### 9.1 Channel Access Enforcement

Every message send and history fetch to an exclusive channel validates the sender's tier level:

```python
def _enforce_channel_access(channel: Dict, user_id: str, creator_id: str) -> None:
    min_level = channel.get("min_tier_level", 1)
    user_level = get_subscriber_tier_level(user_id, creator_id)
    if user_level is None or user_level < min_level:
        raise HTTPException(
            status_code=403,
            detail="Your membership tier does not include access to this channel.",
        )
```

The creator always has access to their own channels regardless of tier.

### 9.2 Badge Spoofing Prevention

- Badges are resolved server-side from the subscription table, never from client-provided data
- The `sender_badge` field in `ChannelMessageOut` and `BroadcastChatMessageOut` is populated by the backend
- Frontend receives badge data as read-only; no client input influences badge display
- Badge cache is invalidated on subscription changes to prevent stale tier display

### 9.3 Rate Limiting

- Exclusive channel messages: same rate limit as broadcast chat (1 message per 2 seconds, `app/services/broadcast_chat_store.py` line 25-43), plus configurable per-channel slowmode
- Tier CRUD: 10 operations per minute per creator
- Badge resolution: cached for 60 seconds per user-creator pair to avoid repeated DDB queries during chat
- Channel creation: max 10 channels per creator
- Badge image upload: max 1 per minute per tier

### 9.4 Data Privacy

- Member lists for exclusive channels are only visible to the creator
- Other subscribers cannot see who else is in a channel (no member list endpoint for non-creators)
- Badge display in public contexts (broadcast chat) is opt-in per tier configuration (`display: true/false`)
- Channel message history is only accessible to users who currently meet the tier requirement (no "read after downgrade")

### 9.5 Badge Image Security

- Badge images are validated server-side: PNG or SVG only, max 256KB
- SVG files are sanitized to remove script tags and event handlers (prevents XSS)
- Images are served from S3 with `Content-Type` headers forced to `image/png` or `image/svg+xml`
- Filenames are randomized (`{tier_id}_{uuid}.{ext}`) to prevent enumeration

### 9.6 Early Access Content Security

- Early access checks are performed server-side on every content fetch, not just on initial load
- Shared URLs to early access content respect the tier gate (no "unlisted link" bypass)
- The `general_release_at` timestamp is computed server-side to prevent client-side clock manipulation

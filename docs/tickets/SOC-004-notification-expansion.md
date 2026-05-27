# SOC-004: Notification System Expansion — Social Alert Types, Batching, Unread Badge, and Real-Time SSE

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-26  
**Priority**: Medium  
**Estimated effort**: 7-10 days

---

## 1. Overview & Motivation

### The Gap

The existing alert system (`app/services/alerts.py`, `app/routers/alerts.py`) provides a solid foundation for security and administrative notifications, but it lacks social notification types entirely. The current `ALERT_EVENT_TYPES` list (line 46 of `alerts.py`) contains only:

```python
ALERT_EVENT_TYPES: List[str] = [
    "login_success","login_failure","mfa_success","mfa_failure","challenge_created","challenge_revoked",
    "challenge_failed","api_key_created","api_key_revoked","api_key_ip_rules_updated","session_revoked",
    "totp_device_added","totp_device_removed","rate_limited","access_denied","security_event",
    "device_new","device_location_mismatch","device_trust","device_revoke",
    "calendar_event_created","calendar_event_updated","calendar_event_deleted",
    "ticket_created","ticket_assigned","ticket_replied","ticket_status_changed","ticket_reopened",
]
```

There are no social event types (follower, reaction, comment, mention, etc.). Additionally:

1. **No notification batching** — Each alert is stored and displayed individually. A popular post receiving 50 reactions generates 50 separate alert entries. The user sees 50 identical "Someone reacted to your post" notifications.
2. **No unread count badge** — The frontend header (`frontend/src/components/layout/Header.tsx`) has a bell icon with notification dropdown (line 244+), but there is no real-time unread count badge.
3. **No real-time SSE for social notifications** — The alert SSE endpoint (`alerts_stream`, line 382-383 of `app/routers/alerts.py`) exists but only streams alerts published via the in-process `_SSE_SUBSCRIBERS` pubsub. Social events (post reactions, comments) do not trigger SSE publishes.
4. **No per-type notification preferences** — The existing preference system (`get_alert_prefs`/`set_alert_prefs`) manages channel preferences (email on/off, SMS on/off, toast on/off), but there is no per-alert-type toggle to silence specific notification categories.

### Why This Is Needed

Social notifications are the primary engagement driver for social platforms. They:
- Tell creators when someone interacts with their content.
- Drive return visits (notification badges prompt users to open the app).
- Enable real-time engagement (someone comments on your post, you see it instantly).
- Are expected by users — a social feed without notifications feels broken.

### Architecture After This Change

```
Notification Flow
                                                                            
  Social Event (e.g., "Bob liked your post")                               
       │                                                                    
       ▼                                                                    
  ┌──────────────────────┐                                                 
  │ emit_social_alert()  │  New function in alerts service                 
  │                      │  Handles: dedup, batching, preference check     
  └──────────┬───────────┘                                                 
             │                                                              
     ┌───────┼────────────────────┐                                        
     │       │                    │                                        
     ▼       ▼                    ▼                                        
  ┌──────┐ ┌──────┐         ┌──────────┐                                  
  │ DDB  │ │ SSE  │         │ Push /   │                                  
  │write │ │publish│         │ Email    │                                  
  └──────┘ └──────┘         └──────────┘                                  
     │       │                    │                                        
     │       │                    │                                        
     ▼       ▼                    ▼                                        
  ┌──────────────────────────────────────────────┐                        
  │              Frontend                         │                        
  │                                               │                        
  │  ┌────────────┐  ┌──────────────────────────┐ │                        
  │  │ Bell Badge │  │ Notification Center Page │ │                        
  │  │ (unread #) │  │ Grouped + paginated list │ │                        
  │  └────────────┘  └──────────────────────────┘ │                        
  └───────────────────────────────────────────────┘                        
                                                                            
Batching Example:                                                           
  "Alice and 3 others liked your post"                                     
  ┌──────────────────────────────────────┐                                 
  │ batch_key: reaction:{post_id}        │                                 
  │ actors: [alice, bob, charlie, dave]  │                                 
  │ count: 4                             │                                 
  │ latest_at: 2026-05-26T14:30:00Z     │                                 
  └──────────────────────────────────────┘                                 
```

### Detailed Data Flow Diagram — `emit_social_alert()` Call Path

```
                          ┌───────────────────────────┐
                          │  Caller (router handler)   │
                          │  e.g. reaction_create()    │
                          └────────────┬──────────────┘
                                       │
                                       ▼
                          ┌───────────────────────────┐
                          │  emit_social_alert()       │
                          │  - recipient_user_id       │
                          │  - alert_type              │
                          │  - actor_user_id           │
                          │  - actor_display_name      │
                          │  - batch_key (optional)    │
                          │  - title                   │
                          │  - details dict            │
                          └────────────┬──────────────┘
                                       │
                          ┌────────────┼────────────┐
                          │ Check 1    │ Check 2    │
                          │ self?      │ pref?      │
                          ▼            ▼            │
                    ┌──────────┐ ┌──────────────┐   │
                    │ Same user│ │ _is_alert_   │   │
                    │ => None  │ │ type_enabled │   │
                    └──────────┘ │ (DDB read)   │   │
                                 └──────┬───────┘   │
                                        │           │
                          ┌─────────────┼───────────┘
                          │ false       │ true
                          ▼             ▼
                    ┌──────────┐ ┌──────────────────────────┐
                    │ => None  │ │ batch_key provided?       │
                    └──────────┘ └───────┬──────────────────┘
                                         │
                               ┌─────────┼────────────┐
                               │ yes     │            │ no
                               ▼         │            ▼
                    ┌──────────────────┐  │  ┌─────────────────────┐
                    │ _batch_alert()   │  │  │ write_alert()       │
                    │ DDB update_item  │  │  │ DDB put_item        │
                    │ atomic append    │  │  │ + sse_publish_alert │
                    │ + sse_publish    │  │  │ + email/push        │
                    └──────────────────┘  │  └─────────────────────┘
                               │         │            │
                               ▼         │            ▼
                    ┌──────────────────┐  │  ┌─────────────────────┐
                    │ _get_alert_      │  │  │ send_push_for_alert │
                    │ channels()       │  │  │ send_alert_email    │
                    │ email/push/sms   │  │  └─────────────────────┘
                    └──────────────────┘  │
                                         │
                          return alert_obj
```

### Sequence Diagram — Reaction to Post

```
User Bob         Backend            DDB (alerts)    DDB (alert_prefs)    SSE Queue (Alice)
  │                │                     │                │                    │
  │  POST /posts/  │                     │                │                    │
  │  {id}/reactions│                     │                │                    │
  │ ──────────────>│                     │                │                    │
  │                │ write reaction      │                │                    │
  │                │ to newsfeed table   │                │                    │
  │                │                     │                │                    │
  │                │ emit_social_alert   │                │                    │
  │                │ (post_reaction)     │                │                    │
  │                │                     │                │                    │
  │                │ self-check: ok      │                │                    │
  │                │ (Bob != Alice)      │                │                    │
  │                │                     │                │                    │
  │                │ ─── get_alert_prefs ────────────────>│                    │
  │                │ <── {type_prefs...} ─────────────────│                    │
  │                │                     │                │                    │
  │                │ _is_alert_type_     │                │                    │
  │                │ enabled() => true   │                │                    │
  │                │                     │                │                    │
  │                │ batch_key =         │                │                    │
  │                │ "reaction:{post_id}"│                │                    │
  │                │                     │                │                    │
  │                │ ── update_item ────>│                │                    │
  │                │   (atomic append    │                │                    │
  │                │    actor, inc count) │                │                    │
  │                │ <── ALL_NEW ────────│                │                    │
  │                │                     │                │                    │
  │                │ trim actors to 10   │                │                    │
  │                │ (if > 10)           │                │                    │
  │                │                     │                │                    │
  │                │ format batch title  │                │                    │
  │                │ "Bob reacted to     │                │                    │
  │                │  your post"         │                │                    │
  │                │                     │                │                    │
  │                │ ── sse_publish_alert ───────────────────────────────────>│
  │                │   {alert_type,      │                │                    │
  │                │    title, actors,   │                │                    │
  │                │    batch_key, ...}  │                │                    │
  │                │                     │                │                    │
  │                │ _get_alert_channels │                │                    │
  │                │ email=false for     │                │                    │
  │                │ post_reaction       │                │                    │
  │                │ => skip email       │                │                    │
  │                │                     │                │                    │
  │ <── 200 ok ────│                     │                │                    │
```

---

## 2. Current State Analysis

### 2.1 Alert Service (`app/services/alerts.py`, 680 lines)

**Core function**: `write_alert()` (line 261):
```python
def write_alert(user_sub: str, *, event: str, outcome: str, title: str, details: Dict[str, Any]) -> Optional[Dict[str, Any]]:
```

This writes an alert item to the `alerts` DDB table with `user_sub` as PK and a unique `alert_id` as SK. It also:
- Checks the `_NO_ALERT_EVENTS` set (line 29) — high-frequency events like `messaging_presence_heartbeat_processed` are silently dropped.
- Publishes to SSE via `sse_publish_alert()`.
- Optionally sends email/SMS based on preferences.
- Sends push notifications via `send_push_for_alert()`.

**Event-to-type mapping**: `event_to_type()` (line 92) maps raw event strings to alert types. Currently maps ~25 event types (security/admin events only).

### 2.2 Alert Preferences (`app/services/alerts.py`, lines 177-260)

```python
def get_alert_prefs(user_sub: str) -> Dict[str, Any]:
    it = T.alert_prefs.get_item(Key={"user_sub": user_sub}).get("Item")
    if not it:
        return {"email_enabled": True, "sms_enabled": False, "toast_enabled": True, ...}
```

Preferences are stored in the `alert_prefs` table. Current structure:
- `email_enabled: bool`
- `sms_enabled: bool`
- `toast_enabled: bool`
- `push_enabled: bool`
- `webhook_enabled: bool`
- `email_addresses: List[str]`
- `sms_numbers: List[str]`
- `webhook_urls: List[str]`

**Missing**: Per-alert-type preferences. There is no way to say "I want email for login_failure but not for post_liked".

### 2.3 Alert Router (`app/routers/alerts.py`)

Key endpoints:
- `GET /alerts/types` (line 90) — returns `ALERT_EVENT_TYPES` list.
- `GET /alerts` (line 95) — paginated alert list.
- `GET /alerts/search` (line 121) — text search across alerts.
- `POST /alerts/mark_read` (line 156) — mark alerts as read (note: underscore, not hyphen).
- `GET /alerts/stream` (line 382) — SSE endpoint for real-time alerts.
- Various preference endpoints for email, SMS, toast, push, webhook.

### 2.4 SSE Infrastructure (`app/services/alerts.py`, lines 59-91)

In-memory pubsub using `asyncio.Queue`:
- `sse_subscribe(user_sub)` — returns a queue for the user.
- `sse_unsubscribe(user_sub, q)` — removes the queue.
- `sse_publish_alert(user_sub, alert_obj)` — pushes to all subscriber queues.

This is single-process only. The `alerts_stream` endpoint (line 382-383) consumes from the queue and yields SSE events.

### 2.5 Frontend Header Bell (`frontend/src/components/layout/Header.tsx`, line 109+)

The header has a bell icon with a dropdown that shows recent notifications. There is a "shake animation when unread count increases" (line 111 comment), suggesting some unread count logic exists. However, the unread count is not populated from the backend — it relies on client-side tracking of alerts received via SSE during the current session.

### 2.6 Newsfeed Notification Hook Points

The newsfeed router (`app/routers/newsfeed.py`) has an internal notification system for the newsfeed (lines 2060-2080 area) that writes to `GSI3PK=NOTIF#{user_id}`. This is a separate notification mechanism from the alerts system — it is newsfeed-specific and not integrated with the alert preferences or SSE infrastructure.

---

## 3. Technical Design

### 3.1 New Social Alert Types

Add to `ALERT_EVENT_TYPES` in `app/services/alerts.py`:

```python
# Social notifications
"new_follower",           # Someone followed you
"post_liked",             # Someone liked your post (heart reaction)
"post_reaction",          # Someone reacted to your post (any emoji)
"post_comment",           # Someone commented on your post
"comment_reply",          # Someone replied to your comment
"mention",                # You were mentioned in a post or comment
"subscription_started",   # Someone subscribed to your content
"post_shared",            # Someone shared your post
"post_tip",               # Someone tipped your post
"message_tip",            # Someone tipped your message
```

### 3.2 Social Alert Emission Points

| Alert Type | Trigger Location | File |
|------------|-----------------|------|
| `new_follower` | `follow_user()` | `app/services/social.py` (SOC-001) |
| `post_liked` | `POST /posts/{id}/reactions` | `app/routers/newsfeed.py` |
| `post_reaction` | `POST /posts/{id}/reactions` | `app/routers/newsfeed.py` |
| `post_comment` | `POST /posts/{id}/comments` | `app/routers/newsfeed.py` |
| `comment_reply` | `POST /posts/{id}/comments` (with `parent_comment_id`) | `app/routers/newsfeed.py` |
| `mention` | Text parsing in post/comment create | `app/routers/newsfeed.py` |
| `subscription_started` | Subscription create | `app/routers/subscription_server.py` |
| `post_tip` | `POST /posts/{id}/tip` | `app/routers/newsfeed.py` |
| `message_tip` | `POST /messages/{id}/tip` | `app/routers/messaging.py` |

### 3.3 Notification Batching

#### 3.3.1 Batch Key Design

Similar notifications are grouped by a `batch_key` that combines the alert type and the target object:

```python
BATCH_KEY_PATTERNS = {
    "post_reaction": "reaction:{post_id}",
    "post_liked": "liked:{post_id}",
    "post_comment": "comment:{post_id}",
    "post_tip": "tip:{post_id}",
    "new_follower": "follower:{user_id}",
}
```

#### 3.3.2 Batch Record Schema

**Table**: `alerts`

| Attribute | Type | Value |
|-----------|------|-------|
| user_sub | S | Alert recipient |
| alert_id | S | `BATCH#{batch_key}` (e.g., `BATCH#reaction:post_abc123`) |
| alert_type | S | e.g., `post_reaction` |
| batch_key | S | e.g., `reaction:post_abc123` |
| actors | L | List of `{user_id, display_name, timestamp}` (most recent 10) |
| actor_count | N | Total number of actors (may exceed actors list length) |
| title | S | e.g., "Alice and 3 others reacted to your post" |
| details | M | Post metadata, latest reaction emoji, etc. |
| created_at | S | First event timestamp |
| updated_at | S | Latest event timestamp |
| read | BOOL | false |
| ttl | N | Expiry timestamp |

#### 3.3.3 Batch Write Logic — Full Implementation

```python
# app/services/social_alerts.py — Complete implementation

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set

from boto3.dynamodb.conditions import Key, Attr

from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import (
    ALERT_EVENT_TYPES,
    get_alert_prefs,
    set_alert_prefs,
    sse_publish_alert,
    write_alert,
)
from app.services.profile import get_profile_identity
from app.services.push import send_push_for_alert
from app.services.rate_limit import can_send_alert_channel

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  Constants                                                                    #
# --------------------------------------------------------------------------- #

SOCIAL_ALERT_TYPES: List[str] = [
    "new_follower",
    "post_liked",
    "post_reaction",
    "post_comment",
    "comment_reply",
    "mention",
    "subscription_started",
    "post_shared",
    "post_tip",
    "message_tip",
]

BATCH_KEY_PATTERNS: Dict[str, str] = {
    "post_reaction": "reaction:{post_id}",
    "post_liked":    "liked:{post_id}",
    "post_comment":  "comment:{post_id}",
    "post_tip":      "tip:{post_id}",
    "new_follower":  "follower:{user_id}",
}

_BATCH_ACTORS_MAX = 10          # Actors list trimmed to most recent N
_BATCH_SSE_ACTORS = 3           # Actor subset sent over SSE for display
_BATCH_TTL_SECONDS = 30 * 86400  # 30-day TTL on batch records

MENTION_REGEX = re.compile(r"@(\w+(?:\.\w+)*)")

# --------------------------------------------------------------------------- #
#  Preference helpers                                                           #
# --------------------------------------------------------------------------- #

def _is_alert_type_enabled(user_sub: str, alert_type: str) -> bool:
    """Check if a specific alert type is enabled for the user.

    Returns True when no explicit preference exists (opt-out model).
    Performs a single DDB get_item on the alert_prefs table.
    """
    prefs = get_alert_prefs(user_sub)
    type_prefs: Dict[str, Any] = prefs.get("type_preferences", {})
    type_pref: Dict[str, Any] = type_prefs.get(alert_type, {})
    return type_pref.get("enabled", True)


def _get_alert_channels(user_sub: str, alert_type: str) -> Dict[str, bool]:
    """Get which delivery channels are enabled for a specific alert type.

    Falls back to the global channel preferences when no per-type override
    exists.  This allows a user to say "email me for comments but not for
    reactions" while keeping a global email_enabled=True default.
    """
    prefs = get_alert_prefs(user_sub)
    type_prefs: Dict[str, Any] = prefs.get("type_preferences", {})
    type_pref: Dict[str, Any] = type_prefs.get(alert_type, {})
    return {
        "email": type_pref.get("email", prefs.get("email_enabled", True)),
        "push":  type_pref.get("push", prefs.get("push_enabled", True)),
        "in_app": type_pref.get("in_app", prefs.get("toast_enabled", True)),
        "sms":   type_pref.get("sms", prefs.get("sms_enabled", False)),
    }


def update_type_preference(
    user_sub: str,
    alert_type: str,
    *,
    enabled: Optional[bool] = None,
    email: Optional[bool] = None,
    push: Optional[bool] = None,
    in_app: Optional[bool] = None,
    sms: Optional[bool] = None,
) -> Dict[str, Any]:
    """Persist per-type notification preference.

    Performs a read-modify-write on the alert_prefs record.  The
    type_preferences map is stored as a nested DDB Map attribute.
    """
    prefs = get_alert_prefs(user_sub)
    type_prefs: Dict[str, Any] = prefs.get("type_preferences", {})
    pref = type_prefs.get(alert_type, {"enabled": True, "email": True, "push": True, "in_app": True, "sms": False})

    if enabled is not None:
        pref["enabled"] = enabled
    if email is not None:
        pref["email"] = email
    if push is not None:
        pref["push"] = push
    if in_app is not None:
        pref["in_app"] = in_app
    if sms is not None:
        pref["sms"] = sms

    type_prefs[alert_type] = pref
    prefs["type_preferences"] = type_prefs
    set_alert_prefs(user_sub, prefs)
    return pref


def get_all_type_preferences(user_sub: str) -> Dict[str, Dict[str, Any]]:
    """Return the full type_preferences map with defaults for missing types."""
    prefs = get_alert_prefs(user_sub)
    type_prefs: Dict[str, Any] = prefs.get("type_preferences", {})
    # Ensure every known social alert type has a preference entry
    defaults = {"enabled": True, "email": True, "push": True, "in_app": True, "sms": False}
    result: Dict[str, Dict[str, Any]] = {}
    all_types = ALERT_EVENT_TYPES + SOCIAL_ALERT_TYPES
    for at in all_types:
        result[at] = type_prefs.get(at, dict(defaults))
    return result


# --------------------------------------------------------------------------- #
#  Core alert emission                                                          #
# --------------------------------------------------------------------------- #

def emit_social_alert(
    *,
    recipient_user_id: str,
    alert_type: str,
    actor_user_id: str,
    actor_display_name: str,
    batch_key: Optional[str] = None,
    title: str,
    details: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Emit a social notification with optional batching.

    This is the single entry-point for all social notifications.  Every
    caller passes the recipient, actor, alert_type, and optional batch_key.
    The function handles:
      1. Self-notification suppression (don't alert user about own action).
      2. Per-type preference check (skip if user disabled this type).
      3. Batching (if batch_key provided, atomic upsert instead of new item).
      4. Channel routing (email, push, in-app, SMS based on prefs).
      5. SSE real-time publish.
    """
    # 1. Don't notify self
    if recipient_user_id == actor_user_id:
        return None

    # 2. Check per-type preference
    if not _is_alert_type_enabled(recipient_user_id, alert_type):
        return None

    # 3. If batch_key provided, try to batch
    if batch_key:
        alert_obj = _batch_alert(
            recipient_user_id=recipient_user_id,
            alert_type=alert_type,
            batch_key=batch_key,
            actor_user_id=actor_user_id,
            actor_display_name=actor_display_name,
            details=details,
        )
    else:
        # 4. Non-batched: write individual alert via existing write_alert
        alert_obj = write_alert(
            recipient_user_id,
            event=alert_type,
            outcome="success",
            title=title,
            details=details,
        )

    if not alert_obj:
        return None

    # 5. Route through enabled channels
    channels = _get_alert_channels(recipient_user_id, alert_type)
    _dispatch_to_channels(
        recipient_user_id=recipient_user_id,
        alert_type=alert_type,
        title=alert_obj.get("title", title),
        details=details,
        channels=channels,
    )

    return alert_obj


def _dispatch_to_channels(
    *,
    recipient_user_id: str,
    alert_type: str,
    title: str,
    details: Dict[str, Any],
    channels: Dict[str, bool],
) -> None:
    """Route the alert through the enabled delivery channels.

    Each channel is gated by rate-limit check (can_send_alert_channel)
    to avoid flooding users.
    """
    # NOTE: Actual function signatures differ from naive social-alert usage.
    # send_push_for_alert(user_sub, alert_type, title, body, alert_id)
    # send_alert_email(to_emails: List[str], subject, body_text)
    # send_alert_sms(to_numbers: List[str], body_text)
    # The caller must resolve email addresses / phone numbers from alert_prefs
    # before calling send_alert_email / send_alert_sms.
    if channels.get("push") and can_send_alert_channel(recipient_user_id, "push"):
        try:
            send_push_for_alert(
                recipient_user_id,
                alert_type,
                title,
                title,  # body — use title as body for social alerts
                alert_id or "",
            )
        except Exception:
            logger.warning("Push delivery failed", extra={"user": recipient_user_id, "type": alert_type})

    if channels.get("email") and can_send_alert_channel(recipient_user_id, "email"):
        try:
            from app.services.alerts import send_alert_email, get_alert_prefs as _get_prefs
            prefs = _get_prefs(recipient_user_id)
            to_emails = prefs.get("email_addresses") or []
            if to_emails:
                send_alert_email(to_emails, title, f"{title}\n\nDetails: {details}")
        except Exception:
            logger.warning("Email delivery failed", extra={"user": recipient_user_id, "type": alert_type})

    if channels.get("sms") and can_send_alert_channel(recipient_user_id, "sms"):
        try:
            from app.services.alerts import send_alert_sms, get_alert_prefs as _get_prefs2
            prefs = _get_prefs2(recipient_user_id)
            to_numbers = prefs.get("sms_numbers") or []
            if to_numbers:
                send_alert_sms(to_numbers, title)
        except Exception:
            logger.warning("SMS delivery failed", extra={"user": recipient_user_id, "type": alert_type})


# --------------------------------------------------------------------------- #
#  Batching                                                                     #
# --------------------------------------------------------------------------- #

def _batch_alert(
    *,
    recipient_user_id: str,
    alert_type: str,
    batch_key: str,
    actor_user_id: str,
    actor_display_name: str,
    details: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Add actor to existing batch or create new batch.

    Uses DynamoDB atomic update_item to:
      - Append actor to actors list (list_append)
      - Increment actor_count (ADD operation)
      - Update updated_at timestamp
      - Reset read to false (mark batch as unread)

    After update, trims actors list to _BATCH_ACTORS_MAX if it has grown
    beyond that limit.  The actor_count is always accurate because it
    uses atomic ADD, but the actors display list may temporarily contain
    up to _BATCH_ACTORS_MAX + 1 entries between the append and trim.
    """
    batch_id = f"BATCH#{batch_key}"
    now = now_ts()
    now_iso = str(now)  # Using integer timestamp for consistency with now_ts()
    actor_entry = {
        "user_id": actor_user_id,
        "display_name": actor_display_name,
        "timestamp": now_iso,
    }

    try:
        # Atomic update: append actor to list, increment count
        resp = T.alerts.update_item(
            Key={"user_sub": recipient_user_id, "alert_id": batch_id},
            UpdateExpression=(
                "SET actors = list_append(if_not_exists(actors, :empty_list), :new_actor), "
                "actor_count = if_not_exists(actor_count, :zero) + :one, "
                "updated_at = :now, "
                "#read = :false, "
                "alert_type = :alert_type, "
                "batch_key = :batch_key, "
                "details = :details, "
                "created_at = if_not_exists(created_at, :now), "
                "ttl = :ttl"
            ),
            ExpressionAttributeNames={"#read": "read"},
            ExpressionAttributeValues={
                ":new_actor": [actor_entry],
                ":empty_list": [],
                ":zero": 0,
                ":one": 1,
                ":now": now_iso,
                ":false": False,
                ":alert_type": alert_type,
                ":batch_key": batch_key,
                ":details": details,
                ":ttl": now + _BATCH_TTL_SECONDS,
            },
            ReturnValues="ALL_NEW",
        )
        item = resp.get("Attributes", {})

        # Trim actors list to most recent _BATCH_ACTORS_MAX
        actors = item.get("actors", [])
        if len(actors) > _BATCH_ACTORS_MAX:
            trimmed = actors[-_BATCH_ACTORS_MAX:]
            T.alerts.update_item(
                Key={"user_sub": recipient_user_id, "alert_id": batch_id},
                UpdateExpression="SET actors = :trimmed",
                ExpressionAttributeValues={":trimmed": trimmed},
            )
            actors = trimmed

        # Generate display title
        count = int(item.get("actor_count", 1))
        title = _format_batch_title(alert_type, actors[-1:], count, details)

        # Update title on the record
        T.alerts.update_item(
            Key={"user_sub": recipient_user_id, "alert_id": batch_id},
            UpdateExpression="SET title = :title",
            ExpressionAttributeValues={":title": title},
        )

        # Publish to SSE
        alert_obj = {
            "alert_id": batch_id,
            "alert_type": alert_type,
            "title": title,
            "batch_key": batch_key,
            "actor_count": count,
            "actors": actors[-_BATCH_SSE_ACTORS:],  # Last N for display
            "details": details,
            "read": False,
            "updated_at": now_iso,
        }
        sse_publish_alert(recipient_user_id, alert_obj)

        return alert_obj

    except Exception:
        logger.exception("Batch alert failed", extra={
            "recipient": recipient_user_id, "batch_key": batch_key,
        })
        return None


# --------------------------------------------------------------------------- #
#  Batch title formatting                                                       #
# --------------------------------------------------------------------------- #

def _format_batch_title(
    alert_type: str,
    recent_actors: List[Dict[str, Any]],
    total_count: int,
    details: Dict[str, Any],
) -> str:
    """Generate a human-readable title for a batched notification.

    Rules:
      - 0 actors: return empty string (should not happen).
      - 1 actor: "Alice reacted to your post"
      - 2 actors: "Alice and 1 other reacted to your post"
      - 3+ actors: "Alice and N others reacted to your post"

    The first_name is taken from the most recent actor in the batch,
    so the notification always references the latest person who
    interacted.
    """
    if total_count == 0:
        return ""

    first_name = recent_actors[0]["display_name"] if recent_actors else "Someone"
    others = total_count - 1

    templates_single = {
        "post_reaction":       "{name} reacted to your post",
        "post_liked":          "{name} liked your post",
        "post_comment":        "{name} commented on your post",
        "comment_reply":       "{name} replied to your comment",
        "new_follower":        "{name} followed you",
        "post_tip":            "{name} tipped your post",
        "message_tip":         "{name} tipped your message",
        "subscription_started": "{name} subscribed to your content",
        "post_shared":         "{name} shared your post",
        "mention":             "{name} mentioned you",
    }

    if others == 0:
        template = templates_single.get(alert_type, "{name} interacted with your content")
        return template.format(name=first_name)

    other_word = "other" if others == 1 else "others"
    templates_plural = {
        "post_reaction":       f"{{name}} and {others} {other_word} reacted to your post",
        "post_liked":          f"{{name}} and {others} {other_word} liked your post",
        "post_comment":        f"{{name}} and {others} {other_word} commented on your post",
        "comment_reply":       f"{{name}} and {others} {other_word} replied to your comment",
        "new_follower":        f"{{name}} and {others} {other_word} followed you",
        "post_tip":            f"{{name}} and {others} {other_word} tipped your post",
        "message_tip":         f"{{name}} and {others} {other_word} tipped your message",
        "subscription_started": f"{{name}} and {others} {other_word} subscribed to your content",
        "post_shared":         f"{{name}} and {others} {other_word} shared your post",
        "mention":             f"{{name}} and {others} {other_word} mentioned you",
    }

    template = templates_plural.get(alert_type, f"{{name}} and {others} {other_word} interacted with your content")
    return template.format(name=first_name)


# --------------------------------------------------------------------------- #
#  Unread count                                                                 #
# --------------------------------------------------------------------------- #

def get_unread_alert_count(user_sub: str, *, cap: int = 99) -> int:
    """Count unread alerts for a user, capped at `cap`.

    Uses a DDB query with FilterExpression on the `read` attribute.
    Note: FilterExpression does NOT reduce the amount of data read — DDB
    still reads up to 1MB per page.  We set Limit=1000 to bound cost,
    and loop with LastEvaluatedKey only up to `cap` results.
    """
    total = 0
    lek: Optional[Dict[str, Any]] = None

    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("user_sub").eq(user_sub),
            "FilterExpression": Attr("read").eq(False),
            "Select": "COUNT",
            "Limit": 500,
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek

        resp = T.alerts.query(**kwargs)
        total += resp.get("Count", 0)

        if total >= cap:
            return cap

        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break

    return min(total, cap)


def mark_all_alerts_read(user_sub: str) -> int:
    """Mark all unread alerts as read for the given user.

    Queries for unread alerts, then issues batch update_item calls.
    Returns the number of alerts marked read.

    Note: This scans up to 2000 alerts (4 pages of 500).  For users with
    extremely large alert histories, a background job should be used.
    """
    marked = 0
    lek: Optional[Dict[str, Any]] = None
    pages = 0

    while pages < 4:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("user_sub").eq(user_sub),
            "FilterExpression": Attr("read").eq(False),
            "ProjectionExpression": "user_sub, alert_id",
            "Limit": 500,
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek

        resp = T.alerts.query(**kwargs)
        items = resp.get("Items", [])

        for item in items:
            try:
                T.alerts.update_item(
                    Key={"user_sub": item["user_sub"], "alert_id": item["alert_id"]},
                    UpdateExpression="SET #read = :true",
                    ExpressionAttributeNames={"#read": "read"},
                    ExpressionAttributeValues={":true": True},
                )
                marked += 1
            except Exception:
                logger.warning("Failed to mark alert read", extra={
                    "user_sub": user_sub, "alert_id": item.get("alert_id"),
                })

        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        pages += 1

    return marked


# --------------------------------------------------------------------------- #
#  Mention detection                                                            #
# --------------------------------------------------------------------------- #

def extract_mentions(text: str) -> List[str]:
    """Extract @mentioned usernames from text.

    Supports formats:
      - @alice         -> "alice"
      - @bob.smith     -> "bob.smith"
      - @alice_creator -> "alice_creator"

    Deduplicates results.  Returns empty list for None/empty text.
    Case-insensitive matching (returns lowercase).
    """
    if not text:
        return []
    matches = MENTION_REGEX.findall(text.lower())
    return list(dict.fromkeys(matches))  # Deduplicate preserving order


def resolve_mentions_to_user_ids(mentions: List[str]) -> List[Dict[str, str]]:
    """Resolve @username strings to user_ids.

    Returns a list of dicts:
      [{"username": "alice", "user_id": "sub_abc", "display_name": "Alice"}]

    Unknown usernames are silently skipped.  This performs one DDB lookup
    per mention, so callers should limit the number of mentions parsed
    (e.g., max 20 per post).
    """
    resolved: List[Dict[str, str]] = []
    for username in mentions[:20]:  # Hard cap at 20 mentions per text
        user_sub = _resolve_username_to_user_sub(username)
        if user_sub:
            identity = get_profile_identity(user_sub)
            resolved.append({
                "username": username,
                "user_id": user_sub,
                "display_name": identity.get("display_name") or username,
            })
    return resolved


def _resolve_username_to_user_sub(username: str) -> Optional[str]:
    """Look up a user_sub by username/handle alias.

    Searches the profiles table for records with a matching alias field.
    This mirrors the alias resolution in app/routers/profile.py
    (_resolve_profile_identifier_to_user_sub).
    """
    try:
        resp = T.profile.scan(
            FilterExpression=Attr("alias").eq(username),
            ProjectionExpression="user_sub",
            Limit=1,
        )
        items = resp.get("Items", [])
        if items:
            return items[0]["user_sub"]
    except Exception:
        logger.warning("Username resolution failed", extra={"username": username})
    return None


def emit_mention_alerts(
    *,
    text: str,
    author_user_id: str,
    author_display_name: str,
    context_type: str,  # "post" or "comment"
    context_id: str,    # post_id or comment_id
    post_id: str,       # Always present for navigation
) -> int:
    """Parse mentions from text and emit alerts for each mentioned user.

    Returns the number of mention alerts emitted.
    """
    mentions = extract_mentions(text)
    if not mentions:
        return 0

    resolved = resolve_mentions_to_user_ids(mentions)
    count = 0
    for mention in resolved:
        emit_social_alert(
            recipient_user_id=mention["user_id"],
            alert_type="mention",
            actor_user_id=author_user_id,
            actor_display_name=author_display_name,
            title=f"{author_display_name} mentioned you in a {context_type}",
            details={
                "context_type": context_type,
                "context_id": context_id,
                "post_id": post_id,
                "text_preview": text[:100],
            },
        )
        count += 1
    return count
```

### 3.4 Per-Type Notification Preferences

#### 3.4.1 Preference Schema Extension

Add to the `alert_prefs` table record:

```python
{
    "user_sub": "...",
    # Existing channel preferences
    "email_enabled": True,
    "sms_enabled": False,
    "toast_enabled": True,
    "push_enabled": True,
    # New: per-type preferences (default all enabled)
    "type_preferences": {
        "new_follower": {"enabled": True, "email": True, "push": True, "in_app": True},
        "post_liked": {"enabled": True, "email": False, "push": True, "in_app": True},
        "post_reaction": {"enabled": True, "email": False, "push": True, "in_app": True},
        "post_comment": {"enabled": True, "email": True, "push": True, "in_app": True},
        "comment_reply": {"enabled": True, "email": True, "push": True, "in_app": True},
        "mention": {"enabled": True, "email": True, "push": True, "in_app": True},
        "subscription_started": {"enabled": True, "email": True, "push": True, "in_app": True},
        "post_tip": {"enabled": True, "email": True, "push": True, "in_app": True},
        "message_tip": {"enabled": True, "email": False, "push": True, "in_app": True},
    }
}
```

#### 3.4.2 Pydantic Models

```python
# In app/models.py — new models for social alerts

class AlertTypePreferenceUpdate(BaseModel):
    """Request body for POST /alerts/type-preferences."""
    alert_type: str = Field(..., min_length=1, max_length=64)
    enabled: Optional[bool] = None
    email: Optional[bool] = None
    push: Optional[bool] = None
    in_app: Optional[bool] = None
    sms: Optional[bool] = None

    @field_validator("alert_type")
    @classmethod
    def validate_alert_type(cls, v: str) -> str:
        # Accept both existing and new social alert types
        from app.services.alerts import ALERT_EVENT_TYPES
        from app.services.social_alerts import SOCIAL_ALERT_TYPES
        valid_types = set(ALERT_EVENT_TYPES) | set(SOCIAL_ALERT_TYPES)
        if v not in valid_types:
            raise ValueError(f"Unknown alert type: {v}")
        return v


class AlertTypePreference(BaseModel):
    """Single type preference entry."""
    enabled: bool = True
    email: bool = True
    push: bool = True
    in_app: bool = True
    sms: bool = False


class AlertTypePreferencesResponse(BaseModel):
    """Response for GET /alerts/type-preferences."""
    type_preferences: Dict[str, AlertTypePreference]


class UnreadCountResponse(BaseModel):
    """Response for GET /alerts/unread-count."""
    unread_count: int = Field(..., ge=0, le=99)


class MarkAllReadResponse(BaseModel):
    """Response for POST /alerts/mark-all-read."""
    marked_count: int
```

### 3.5 Unread Count System

#### 3.5.1 Backend: Unread Count Endpoint

```python
# In app/routers/alerts.py

@router.get("/alerts/unread-count")
async def get_unread_count(ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    count = get_unread_alert_count(user_sub, cap=99)
    return {"unread_count": count}
```

#### 3.5.2 Backend: Mark All Read Endpoint

```python
@router.post("/alerts/mark-all-read")
async def mark_all_read(ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    marked = mark_all_alerts_read(user_sub)
    return {"marked_count": marked}
```

#### 3.5.3 Backend: Type Preference Endpoints

```python
@router.get("/alerts/type-preferences")
async def get_type_preferences(ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    prefs = get_all_type_preferences(user_sub)
    return {"type_preferences": prefs}


@router.post("/alerts/type-preferences")
async def update_type_preferences(
    body: AlertTypePreferenceUpdate,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    user_sub = ctx["user_sub"]
    updated = update_type_preference(
        user_sub,
        body.alert_type,
        enabled=body.enabled,
        email=body.email,
        push=body.push,
        in_app=body.in_app,
        sms=body.sms,
    )
    return {"alert_type": body.alert_type, **updated}
```

#### 3.5.4 Backend: SSE Unread Count Push

When a new alert is published via SSE, include the updated unread count:

```python
def sse_publish_alert(user_sub: str, alert_obj: Dict[str, Any]) -> None:
    # ... existing publish logic ...
    # Add unread_count to the SSE payload
    alert_obj["_unread_count_delta"] = 1  # Increment hint for frontend
```

#### 3.5.5 Frontend: Unread Badge

```typescript
// frontend/src/hooks/useNotificationCount.ts (new file)

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import api from "@/api/client";

export function useNotificationCount() {
  const queryClient = useQueryClient();
  
  const { data } = useQuery({
    queryKey: ["alerts", "unread-count"],
    queryFn: () => api.get<{ unread_count: number }>("/alerts/unread-count").then(r => r.data),
    refetchInterval: 30_000, // Poll every 30s as fallback
    staleTime: 10_000,
  });
  
  // Listen for SSE alerts to increment count
  useEffect(() => {
    const handler = (e: Event) => {
      queryClient.setQueryData<{ unread_count: number }>(
        ["alerts", "unread-count"],
        (old) => ({ unread_count: Math.min((old?.unread_count ?? 0) + 1, 99) })
      );
    };
    window.addEventListener("alert:new", handler);
    return () => window.removeEventListener("alert:new", handler);
  }, [queryClient]);
  
  return data?.unread_count ?? 0;
}
```

### 3.6 Mention Detection

```python
MENTION_REGEX = re.compile(r"@(\w+(?:\.\w+)*)")  # Matches @username, @user.name

def extract_mentions(text: str) -> List[str]:
    """Extract @mentioned usernames from text."""
    if not text:
        return []
    return list(set(MENTION_REGEX.findall(text)))

def resolve_mentions_to_user_ids(mentions: List[str]) -> List[Dict[str, str]]:
    """Resolve @username strings to user_ids. Returns [{username, user_id, display_name}]."""
    resolved = []
    for username in mentions:
        # Look up in profiles table by username/handle
        # Uses the same alias resolution as profile.py
        user_sub = _resolve_username_to_user_sub(username)
        if user_sub:
            identity = get_profile_identity(user_sub)
            resolved.append({
                "username": username,
                "user_id": user_sub,
                "display_name": identity.get("display_name") or username,
            })
    return resolved
```

### 3.7 API Endpoints — New and Modified

#### 3.7.1 `GET /alerts/unread-count` (new)

Returns `{"unread_count": int}`.

#### 3.7.2 `GET /alerts/types` (modified)

Returns the expanded `ALERT_EVENT_TYPES` list including social types.

#### 3.7.3 `POST /alerts/type-preferences` (new)

**Request**:
```python
class AlertTypePreferenceUpdate(BaseModel):
    alert_type: str
    enabled: Optional[bool] = None
    email: Optional[bool] = None
    push: Optional[bool] = None
    in_app: Optional[bool] = None
    sms: Optional[bool] = None
```

**Response**: Updated preferences for the type.

#### 3.7.4 `GET /alerts/type-preferences` (new)

Returns the full `type_preferences` map.

#### 3.7.5 `POST /alerts/mark-all-read` (new)

Marks all unread alerts as read. Updates the `read` field on all items where `read=False`.

### 3.8 DDB Access Pattern Summary

| Access Pattern | Table | Key / Index | Operation | Frequency |
|---|---|---|---|---|
| Write batched alert | `alerts` | PK=`user_sub`, SK=`BATCH#{batch_key}` | `update_item` (upsert) | Per social event |
| Write individual alert | `alerts` | PK=`user_sub`, SK=`ALERT#{uuid}` | `put_item` | Per non-batchable event |
| Read unread count | `alerts` | PK=`user_sub`, Filter: `read=false` | `query` + Count | Per page load + poll |
| Mark all read | `alerts` | PK=`user_sub`, Filter: `read=false` | `query` + N `update_item` | On user action |
| Read type preferences | `alert_prefs` | PK=`user_sub` | `get_item` | Per emit + per settings page |
| Write type preferences | `alert_prefs` | PK=`user_sub` | `put_item` | On preference change |
| Resolve mention | `profiles` | Scan with `alias` filter | `scan` (limited) | Per mention in text |
| Trim batch actors | `alerts` | PK=`user_sub`, SK=`BATCH#{batch_key}` | `update_item` | When actors > 10 |

---

## 4. Implementation Plan

### Step 1: Expand Alert Event Types

**File**: `app/services/alerts.py`

Add social types to `ALERT_EVENT_TYPES` (line 46):
```python
ALERT_EVENT_TYPES.extend([
    "new_follower", "post_liked", "post_reaction", "post_comment",
    "comment_reply", "mention", "subscription_started", "post_shared",
    "post_tip", "message_tip",
])
```

Add the `emit_social_alert()` function and batch logic (~150 lines).

### Step 2: Add Per-Type Preferences

**File**: `app/services/alerts.py`

Add `_is_alert_type_enabled()`, `_get_alert_channels()`, and preference read/write functions for the `type_preferences` map (~80 lines).

### Step 3: Add Unread Count Endpoint

**File**: `app/routers/alerts.py`

Add `GET /alerts/unread-count` endpoint (~20 lines).

### Step 4: Add Type Preference Endpoints

**File**: `app/routers/alerts.py`

Add `GET /alerts/type-preferences` and `POST /alerts/type-preferences` (~40 lines).

### Step 5: Add Mark-All-Read Endpoint

**File**: `app/routers/alerts.py`

Add `POST /alerts/mark-all-read` (~30 lines).

### Step 6: Hook Social Alert Emission into Newsfeed

**File**: `app/routers/newsfeed.py`

Add `emit_social_alert()` calls in:
- Reaction create endpoint (after `PUT reactions` — emit `post_reaction` / `post_liked`).
- Comment create endpoint (after writing comment — emit `post_comment` or `comment_reply`).
- Post tip endpoint (after recording tip — emit `post_tip`).
- Post create (parse mentions, emit `mention` for each).

**Lines modified**: ~60 across 4 handlers.

**Detailed hook-in for reaction create**:

> **Note**: Newsfeed endpoints use `user_id: UserIdDep` (not `ctx["user_sub"]`).
> Replace `ctx["user_sub"]` with `user_id` in the code below.

```python
# In app/routers/newsfeed.py, after writing the reaction to DDB:
# (around line 3790 area in the reaction create handler)

# Determine if this is a "like" (heart) or general reaction
is_like = emoji == "❤️" or emoji == "heart"
alert_type = "post_liked" if is_like else "post_reaction"

# Only notify the post author, not the reactor
if post_author_id != ctx["user_sub"]:
    from app.services.social_alerts import emit_social_alert
    emit_social_alert(
        recipient_user_id=post_author_id,
        alert_type=alert_type,
        actor_user_id=ctx["user_sub"],
        actor_display_name=actor_name,
        batch_key=f"{'liked' if is_like else 'reaction'}:{post_id}",
        title=f"{actor_name} {'liked' if is_like else 'reacted to'} your post",
        details={
            "post_id": post_id,
            "emoji": emoji,
            "post_preview": post_body[:100] if post_body else "",
        },
    )
```

**Detailed hook-in for comment create**:
```python
# In app/routers/newsfeed.py, after writing the comment:

from app.services.social_alerts import emit_social_alert, emit_mention_alerts

# If this is a reply to another comment, notify the parent comment author
if parent_comment_id and parent_comment_author_id:
    emit_social_alert(
        recipient_user_id=parent_comment_author_id,
        alert_type="comment_reply",
        actor_user_id=ctx["user_sub"],
        actor_display_name=actor_name,
        batch_key=f"reply:{parent_comment_id}",
        title=f"{actor_name} replied to your comment",
        details={
            "post_id": post_id,
            "comment_id": comment_id,
            "parent_comment_id": parent_comment_id,
            "text_preview": comment_text[:100],
        },
    )

# Always notify the post author (unless the commenter IS the post author)
emit_social_alert(
    recipient_user_id=post_author_id,
    alert_type="post_comment",
    actor_user_id=ctx["user_sub"],
    actor_display_name=actor_name,
    batch_key=f"comment:{post_id}",
    title=f"{actor_name} commented on your post",
    details={
        "post_id": post_id,
        "comment_id": comment_id,
        "text_preview": comment_text[:100],
    },
)

# Parse and emit mention alerts
emit_mention_alerts(
    text=comment_text,
    author_user_id=ctx["user_sub"],
    author_display_name=actor_name,
    context_type="comment",
    context_id=comment_id,
    post_id=post_id,
)
```

### Step 7: Hook Social Alert Emission into Messaging

**File**: `app/routers/messaging.py`

Add `emit_social_alert()` call in the message tip endpoint (emit `message_tip`).

**Lines modified**: ~15.

```python
# In the message tip handler, after recording the tip:
from app.services.social_alerts import emit_social_alert

emit_social_alert(
    recipient_user_id=message_author_id,
    alert_type="message_tip",
    actor_user_id=ctx["user_sub"],
    actor_display_name=actor_name,
    title=f"{actor_name} tipped your message",
    details={
        "conversation_id": conversation_id,
        "message_id": message_id,
        "amount_cents": amount_cents,
        "currency": "usd",
    },
)
```

### Step 8: Hook Social Alert into Follow System

**File**: `app/services/social.py` (from SOC-001)

Add `emit_social_alert()` call in `follow_user()` (emit `new_follower`).

**Lines modified**: ~10.

```python
# In follow_user(), after writing the follow record:
from app.services.social_alerts import emit_social_alert

emit_social_alert(
    recipient_user_id=target_user_id,
    alert_type="new_follower",
    actor_user_id=follower_user_id,
    actor_display_name=follower_display_name,
    batch_key=f"follower:{target_user_id}",
    title=f"{follower_display_name} followed you",
    details={
        "follower_user_id": follower_user_id,
        "follower_display_name": follower_display_name,
    },
)
```

### Step 9: Add Mention Detection

**File**: `app/services/social_alerts.py` (included in the main file above)

Add `extract_mentions()`, `resolve_mentions_to_user_ids()`, and `emit_mention_alerts()` functions (~60 lines).

### Step 10: Frontend — Notification Count Hook

**File**: `frontend/src/hooks/useNotificationCount.ts` (new file, ~40 lines)

### Step 11: Frontend — Header Unread Badge

**File**: `frontend/src/components/layout/Header.tsx`

Modify the bell icon section to use `useNotificationCount()` and display a red badge with the count:

```tsx
const unreadCount = useNotificationCount();
// ...
<div className="relative">
  <Bell className="h-5 w-5" />
  {unreadCount > 0 && (
    <span className="absolute -top-1 -right-1 h-4 w-4 rounded-full bg-destructive text-[10px] text-destructive-foreground flex items-center justify-center">
      {unreadCount > 9 ? "9+" : unreadCount}
    </span>
  )}
</div>
```

**Lines modified**: ~20.

### Step 12: Frontend — Notification Center Page

**File**: `frontend/src/pages/alerts/NotificationCenter.tsx` (new or enhance existing alerts page)

Enhance the existing alerts page to:
- Show batched notifications with actor avatars and "and N others" text.
- Group by category (Social, Security, System).
- Show per-type toggle switches in a preferences panel.
- "Mark all as read" button.
- Real-time updates via SSE.

**Lines**: ~200 (enhancement to existing page).

### Step 13: Frontend — Notification Preferences UI

**File**: `frontend/src/pages/alerts/NotificationPreferences.tsx` (new or enhance existing)

Per-type preference toggles:

```
┌───────────────────────────────────────────────┐
│ Notification Preferences                       │
├───────────────────────────────────────────────┤
│ Social Notifications                           │
│                                                │
│   New Followers          [In-App ✓] [Email ✓] │
│   Post Reactions         [In-App ✓] [Email ✗] │
│   Comments               [In-App ✓] [Email ✓] │
│   Mentions               [In-App ✓] [Email ✓] │
│   Tips                   [In-App ✓] [Email ✓] │
│                                                │
│ Security Notifications                         │
│                                                │
│   Login Alerts           [In-App ✓] [Email ✓] │
│   Device Alerts          [In-App ✓] [Email ✓] │
│   API Key Changes        [In-App ✓] [Email ✓] │
└───────────────────────────────────────────────┘
```

**Lines**: ~150.

### Step 14: Frontend — API Endpoints

**File**: `frontend/src/api/endpoints/alerts.ts` (modify existing)

Add:
```typescript
export const getUnreadCount = () =>
  api.get<{ unread_count: number }>("/alerts/unread-count");

export const markAllRead = () =>
  api.post("/alerts/mark-all-read");

export const getTypePreferences = () =>
  api.get<Record<string, TypePreference>>("/alerts/type-preferences");

export const updateTypePreference = (alertType: string, prefs: Partial<TypePreference>) =>
  api.post("/alerts/type-preferences", { alert_type: alertType, ...prefs });
```

### Summary of Files Modified/Created

| File | Change Type | Estimated Lines |
|------|-------------|-----------------|
| `app/services/social_alerts.py` | New file: emission, batching, mentions, prefs | ~450 |
| `app/services/alerts.py` | Add social types to ALERT_EVENT_TYPES | ~10 |
| `app/routers/alerts.py` | Add unread/prefs/mark-all endpoints | ~100 |
| `app/routers/newsfeed.py` | Hook emission in reactions/comments/tips | ~60 |
| `app/routers/messaging.py` | Hook emission in message tips | ~15 |
| `app/services/social.py` | Hook emission on follow | ~10 |
| `app/models.py` | New Pydantic models | ~50 |
| `frontend/src/hooks/useNotificationCount.ts` | New file | ~40 |
| `frontend/src/components/layout/Header.tsx` | Add unread badge | ~20 |
| `frontend/src/pages/alerts/NotificationCenter.tsx` | Enhance | ~200 |
| `frontend/src/pages/alerts/NotificationPreferences.tsx` | New/enhance | ~150 |
| `frontend/src/api/endpoints/alerts.ts` | Add new endpoints | ~30 |
| **Total** | | **~1135** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_social_alerts.py`)

New file, ~500 lines.

**Test cases with full signatures and assertions**:

```python
# tests/test_social_alerts.py

import pytest
from unittest.mock import patch, MagicMock
from moto import mock_dynamodb
from app.services.social_alerts import (
    emit_social_alert,
    _batch_alert,
    _format_batch_title,
    _is_alert_type_enabled,
    _get_alert_channels,
    extract_mentions,
    resolve_mentions_to_user_ids,
    emit_mention_alerts,
    get_unread_alert_count,
    mark_all_alerts_read,
    update_type_preference,
    get_all_type_preferences,
)


@pytest.fixture
def alert_tables(ddb_resource):
    """Create alerts and alert_prefs tables for testing."""
    ddb_resource.create_table(
        TableName="alerts",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "alert_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "alert_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ddb_resource.create_table(
        TableName="alert_prefs",
        KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    yield


class TestEmitSocialAlert:
    def test_emit_new_follower_alert(self, alert_tables):
        """Follow user -> alert written to DDB with correct type and title."""
        result = emit_social_alert(
            recipient_user_id="alice",
            alert_type="new_follower",
            actor_user_id="bob",
            actor_display_name="Bob",
            batch_key="follower:alice",
            title="Bob followed you",
            details={"follower_user_id": "bob"},
        )
        assert result is not None
        assert result["alert_type"] == "new_follower"
        assert result["actor_count"] == 1
        assert "Bob" in result["title"]

    def test_emit_post_reaction_alert(self, alert_tables):
        """React to post -> alert for post author."""
        result = emit_social_alert(
            recipient_user_id="alice",
            alert_type="post_reaction",
            actor_user_id="bob",
            actor_display_name="Bob",
            batch_key="reaction:post_123",
            title="Bob reacted to your post",
            details={"post_id": "post_123", "emoji": "🔥"},
        )
        assert result is not None
        assert result["alert_type"] == "post_reaction"
        assert result["details"]["emoji"] == "🔥"

    def test_self_notification_suppressed(self, alert_tables):
        """Author reacts to own post -> no alert generated."""
        result = emit_social_alert(
            recipient_user_id="alice",
            alert_type="post_reaction",
            actor_user_id="alice",  # Same as recipient
            actor_display_name="Alice",
            batch_key="reaction:post_123",
            title="Alice reacted to your post",
            details={"post_id": "post_123"},
        )
        assert result is None

    def test_batching_two_reactions_same_post(self, alert_tables):
        """React from two users -> single batch entry with actor_count=2."""
        emit_social_alert(
            recipient_user_id="alice",
            alert_type="post_reaction",
            actor_user_id="bob",
            actor_display_name="Bob",
            batch_key="reaction:post_123",
            title="Bob reacted",
            details={"post_id": "post_123"},
        )
        result = emit_social_alert(
            recipient_user_id="alice",
            alert_type="post_reaction",
            actor_user_id="charlie",
            actor_display_name="Charlie",
            batch_key="reaction:post_123",
            title="Charlie reacted",
            details={"post_id": "post_123"},
        )
        assert result is not None
        assert result["actor_count"] == 2
        assert "1 other" in result["title"]

    def test_batch_title_formatting_three_actors(self, alert_tables):
        """3 actors -> 'Charlie and 2 others reacted to your post'."""
        for name in ["Alice_r", "Bob_r", "Charlie_r"]:
            emit_social_alert(
                recipient_user_id="target",
                alert_type="post_reaction",
                actor_user_id=name.lower(),
                actor_display_name=name,
                batch_key="reaction:post_456",
                title=f"{name} reacted",
                details={"post_id": "post_456"},
            )
        # The title should reference the most recent actor
        result = emit_social_alert(
            recipient_user_id="target",
            alert_type="post_reaction",
            actor_user_id="dave",
            actor_display_name="Dave",
            batch_key="reaction:post_456",
            title="Dave reacted",
            details={"post_id": "post_456"},
        )
        assert result["actor_count"] == 4
        assert "3 others" in result["title"]


class TestBatchActorsTrimming:
    def test_actors_list_capped_at_10(self, alert_tables):
        """15 reactions -> actors list length is 10, actor_count is 15."""
        for i in range(15):
            emit_social_alert(
                recipient_user_id="alice",
                alert_type="post_liked",
                actor_user_id=f"user_{i}",
                actor_display_name=f"User {i}",
                batch_key="liked:post_789",
                title=f"User {i} liked",
                details={"post_id": "post_789"},
            )
        # Read the batch record directly
        resp = T.alerts.get_item(
            Key={"user_sub": "alice", "alert_id": "BATCH#liked:post_789"}
        )
        item = resp["Item"]
        assert len(item["actors"]) == 10  # Trimmed to 10
        assert int(item["actor_count"]) == 15  # Accurate count


class TestTypePreferences:
    def test_disabled_type_suppresses_alert(self, alert_tables):
        """Disable post_reaction for user -> no alert written."""
        update_type_preference("alice", "post_reaction", enabled=False)
        result = emit_social_alert(
            recipient_user_id="alice",
            alert_type="post_reaction",
            actor_user_id="bob",
            actor_display_name="Bob",
            batch_key="reaction:post_123",
            title="Bob reacted",
            details={},
        )
        assert result is None

    def test_email_off_for_type(self, alert_tables):
        """Disable email for post_comment -> alert written but no email."""
        update_type_preference("alice", "post_comment", email=False)
        channels = _get_alert_channels("alice", "post_comment")
        assert channels["email"] is False
        assert channels["push"] is True
        assert channels["in_app"] is True

    def test_default_enabled(self, alert_tables):
        """No explicit preference -> alert is emitted (default enabled)."""
        assert _is_alert_type_enabled("alice", "post_reaction") is True

    def test_get_all_preferences_includes_defaults(self, alert_tables):
        """All known types appear with default values."""
        prefs = get_all_type_preferences("alice")
        assert "new_follower" in prefs
        assert prefs["new_follower"]["enabled"] is True
        assert "post_reaction" in prefs


class TestUnreadCount:
    def test_unread_count_correct(self, alert_tables):
        """Write 5 alerts (3 unread, 2 read) -> unread_count=3."""
        for i in range(5):
            T.alerts.put_item(Item={
                "user_sub": "alice",
                "alert_id": f"ALERT#{i}",
                "read": i >= 3,  # First 3 unread, last 2 read
            })
        count = get_unread_alert_count("alice")
        assert count == 3

    def test_unread_count_capped_at_99(self, alert_tables):
        """Write 150 unread alerts -> response unread_count=99."""
        for i in range(150):
            T.alerts.put_item(Item={
                "user_sub": "alice",
                "alert_id": f"ALERT#{i}",
                "read": False,
            })
        count = get_unread_alert_count("alice")
        assert count == 99

    def test_mark_all_read(self, alert_tables):
        """Write 5 unread alerts, mark all read -> all read."""
        for i in range(5):
            T.alerts.put_item(Item={
                "user_sub": "alice",
                "alert_id": f"ALERT#{i}",
                "read": False,
            })
        marked = mark_all_alerts_read("alice")
        assert marked == 5
        assert get_unread_alert_count("alice") == 0


class TestMentionDetection:
    def test_extract_simple_mentions(self):
        """Text 'Hello @alice and @bob.smith' -> ['alice', 'bob.smith']."""
        mentions = extract_mentions("Hello @alice and @bob.smith")
        assert "alice" in mentions
        assert "bob.smith" in mentions

    def test_extract_deduplicates(self):
        """@alice appears twice -> returns once."""
        mentions = extract_mentions("Hey @alice, talk to @alice")
        assert mentions.count("alice") == 1

    def test_extract_empty_text(self):
        """None/empty text -> empty list."""
        assert extract_mentions("") == []
        assert extract_mentions(None) == []

    @patch("app.services.social_alerts._resolve_username_to_user_sub")
    def test_resolve_known_username(self, mock_resolve):
        """Known username resolves to user_id."""
        mock_resolve.return_value = "sub_alice"
        with patch("app.services.social_alerts.get_profile_identity") as mock_identity:
            mock_identity.return_value = {"display_name": "Alice"}
            resolved = resolve_mentions_to_user_ids(["alice"])
            assert len(resolved) == 1
            assert resolved[0]["user_id"] == "sub_alice"

    @patch("app.services.social_alerts._resolve_username_to_user_sub")
    def test_resolve_unknown_username_skipped(self, mock_resolve):
        """Unknown username is skipped."""
        mock_resolve.return_value = None
        resolved = resolve_mentions_to_user_ids(["unknown_user"])
        assert len(resolved) == 0


class TestSSEPublish:
    @patch("app.services.social_alerts.sse_publish_alert")
    def test_sse_publish_on_social_alert(self, mock_sse, alert_tables):
        """Verify sse_publish_alert called with correct payload."""
        emit_social_alert(
            recipient_user_id="alice",
            alert_type="new_follower",
            actor_user_id="bob",
            actor_display_name="Bob",
            batch_key="follower:alice",
            title="Bob followed you",
            details={},
        )
        mock_sse.assert_called_once()
        payload = mock_sse.call_args[0][1]
        assert payload["alert_type"] == "new_follower"


class TestBatchingAcrossTypes:
    def test_reaction_and_like_batch_separately(self, alert_tables):
        """Reaction (post_reaction) and like (post_liked) batch separately."""
        emit_social_alert(
            recipient_user_id="alice",
            alert_type="post_reaction",
            actor_user_id="bob",
            actor_display_name="Bob",
            batch_key="reaction:post_123",
            title="Bob reacted",
            details={"post_id": "post_123"},
        )
        emit_social_alert(
            recipient_user_id="alice",
            alert_type="post_liked",
            actor_user_id="charlie",
            actor_display_name="Charlie",
            batch_key="liked:post_123",
            title="Charlie liked",
            details={"post_id": "post_123"},
        )
        # Verify two separate batch records
        r1 = T.alerts.get_item(Key={"user_sub": "alice", "alert_id": "BATCH#reaction:post_123"})
        r2 = T.alerts.get_item(Key={"user_sub": "alice", "alert_id": "BATCH#liked:post_123"})
        assert "Item" in r1
        assert "Item" in r2
        assert int(r1["Item"]["actor_count"]) == 1
        assert int(r2["Item"]["actor_count"]) == 1


class TestCommentReplyVsComment:
    def test_reply_generates_both_alerts(self, alert_tables):
        """Reply to comment -> comment_reply to comment author AND post_comment to post author."""
        # Comment reply to comment author
        r1 = emit_social_alert(
            recipient_user_id="comment_author",
            alert_type="comment_reply",
            actor_user_id="replier",
            actor_display_name="Replier",
            title="Replier replied to your comment",
            details={"post_id": "p1", "comment_id": "c2", "parent_comment_id": "c1"},
        )
        # Post comment to post author
        r2 = emit_social_alert(
            recipient_user_id="post_author",
            alert_type="post_comment",
            actor_user_id="replier",
            actor_display_name="Replier",
            batch_key="comment:p1",
            title="Replier commented on your post",
            details={"post_id": "p1", "comment_id": "c2"},
        )
        assert r1 is not None
        assert r2 is not None
        assert r1["alert_type"] == "comment_reply"
        assert r2["alert_type"] == "post_comment"
```

### 5.2 E2E Tests (`frontend/e2e/social-notifications.spec.ts`)

New file, ~450 lines.

**Section 105: Social Alert API (8 tests)**:

1. `New follower generates alert` — Alice follows Bob, verify Bob has `new_follower` alert.
2. `Post reaction generates alert to author` — Bob reacts to Alice's post, verify Alice has alert.
3. `Self-reaction does not generate alert` — Alice reacts to own post, verify no new alert.
4. `Comment generates alert to post author` — Bob comments on Alice's post, verify alert.
5. `Batched reactions show correct title` — 3 users react to Alice's post, verify "Bob and 2 others reacted to your post".
6. `Mention in post generates alert` — Alice creates post mentioning @bob, verify Bob has `mention` alert.
7. `Unread count endpoint returns correct count` — Generate alerts, verify count.
8. `Mark all read clears unread count` — Mark all read, verify count is 0.

**Section 106: Notification Preferences API (5 tests)**:

1. `Get default type preferences` — Verify all types default to enabled.
2. `Disable post_reaction notifications` — Set enabled=false, verify no alert generated.
3. `Disable email for new_follower` — Set email=false, verify alert written but email not sent.
4. `Re-enable disabled type` — Disable then enable, verify alerts resume.
5. `Preferences persist across sessions` — Set preference, reload, verify same.

**Section 107: Notification Badge UI (4 tests)**:

1. `Bell icon shows unread count badge` — Generate alerts, load page, verify red badge visible.
2. `Badge updates on new SSE alert` — Navigate to page, trigger alert via API, verify badge increments.
3. `Badge disappears after mark-all-read` — Click mark all read, verify badge gone.
4. `Badge shows "9+" for counts over 9` — Generate 15 alerts, verify badge text is "9+".

**Section 108: Notification Center UI (5 tests)**:

1. `Notification list shows batched alerts` — Verify grouped display.
2. `Clicking notification navigates to context` — Click post_comment notification, verify navigated to post.
3. `Per-type toggle switches work` — Toggle off post_reaction, verify saved.
4. `Notification list paginates` — Generate 30 alerts, verify pagination.
5. `Real-time update: new alert appears at top` — While on page, trigger alert, verify it appears.

### 5.3 Edge Cases

1. **High-frequency reactions** — A viral post receiving 1000 reactions/minute. Batching collapses these into a single batch entry updated atomically. DDB `update_item` with atomic operations handles concurrency.

2. **Actor list trim race condition** — Two concurrent batch updates may both read `actors` with length 11, both try to trim to 10. The second trim may overwrite the first's new actor. This is acceptable — the `actor_count` is always accurate (atomic ADD), only the `actors` display list may miss an entry.

3. **Notification during offline** — Alerts are stored in DDB persistently. When the user comes online, the unread count query returns all unread alerts. SSE reconnection replays missed events.

4. **Bulk follow (mass import)** — If a popular creator gains 1000 followers in 1 minute, the `new_follower` batch entry is updated 1000 times. The title shows "Alice and 999 others followed you". This is the desired behavior.

5. **Mention in edited post** — If a post is edited to add a mention, the mention notification should not fire again if the user was already mentioned. Track mention notifications per `{post_id, mentioned_user_id}` in the batch key.

6. **Deleted post/comment** — If a post is deleted after generating notifications, existing notifications remain. Clicking them should show a "This post has been deleted" message rather than a 404.

### 5.4 Performance Considerations

| Operation | DDB Reads | DDB Writes | Expected Latency |
|-----------|-----------|------------|-------------------|
| Emit social alert (non-batched) | 1 (prefs) | 1 (alert) | ~15ms |
| Emit social alert (batched) | 1 (prefs) | 1 (update_item) | ~15ms |
| Unread count | 1 (query + filter) | 0 | ~20ms |
| Mark all read | 1 (query) + N (updates) | N | ~50ms for 20 alerts |
| Type preferences read | 1 (get_item) | 0 | ~5ms |

---

## 6. Security Considerations

### 6.1 Notification Injection Prevention

Social alert details are stored in DDB and rendered in the frontend. All user-supplied content in the `details` map (post previews, display names, comment text) must be treated as untrusted:

- **Display name XSS**: Actor `display_name` is shown in notification titles. The frontend must use React's default JSX escaping (which escapes `<`, `>`, `&`). Never use `dangerouslySetInnerHTML` for notification text.
- **Batch title template injection**: `_format_batch_title` uses Python `.format()` only on the `{name}` placeholder. No user-controlled data reaches the format string template itself — templates are hardcoded.
- **Details map sanitization**: The `details` dict is stored as-is in DDB. Strip any keys that start with `_` (internal) before storing. Limit the total size of `details` to 4KB to prevent DDB item bloat.

### 6.2 Rate Limiting

Social alerts have an inherent amplification risk: one action (post) can trigger thousands of notifications (reactions from all viewers). Mitigations:

- **Batch key coalescence**: Multiple reactions on the same post collapse into one batch record. The author sees one notification, not N.
- **Alert emission rate limit**: `can_send_alert_channel(user_sub, channel)` (existing function in `app/services/rate_limit.py`) limits push/email/SMS to prevent flooding.
- **Mention cap**: `resolve_mentions_to_user_ids` hard-caps at 20 mentions per text to prevent a single post from generating 100 mention alerts.
- **SSE queue overflow**: `asyncio.Queue(maxsize=200)` drops messages when the client is slow. This prevents memory exhaustion from a flood of social events.

### 6.3 Privacy Concerns

- **Notification leaks follow status**: If Alice follows Bob, Bob receives a `new_follower` alert. If Alice then unfollows, the alert persists. This is standard social platform behavior but should be documented.
- **Mention resolution timing**: `_resolve_username_to_user_sub` does a profiles table scan. If a user changes their username between mention creation and notification display, the mention may show the old username in `details.text_preview` but link to the correct user via `user_id`.
- **Alert visibility**: Alerts are private to the recipient. The `GET /alerts/list` and `GET /alerts/unread-count` endpoints enforce `user_sub` from the authenticated session — there is no way to read another user's alerts.

### 6.4 CSRF Protection

All new endpoints use `Depends(require_ui_session)` which enforces CSRF token validation for non-GET requests. The `POST /alerts/type-preferences` and `POST /alerts/mark-all-read` endpoints require the `x-csrf-token` header matching the session's stored token.

---

## 7. Migration & Rollback Plan

### 7.1 Forward Migration

**Step 1: Deploy backend changes first (no frontend)**

1. Add `SOCIAL_ALERT_TYPES` to `ALERT_EVENT_TYPES` list. Existing code that iterates `ALERT_EVENT_TYPES` will see new types but no social events are emitted yet.
2. Deploy `social_alerts.py` service module. No callers yet — dormant code.
3. Deploy new router endpoints (`/alerts/unread-count`, `/alerts/type-preferences`, `/alerts/mark-all-read`). These endpoints are additive — they do not modify existing endpoint behavior.

**Step 2: Hook emission into existing handlers**

4. Deploy newsfeed.py changes (reaction/comment/tip alert hooks). Social alerts start flowing.
5. Deploy messaging.py changes (message tip alerts).
6. Deploy social.py changes (follow alerts).

**Step 3: Deploy frontend**

7. Deploy `useNotificationCount` hook and Header badge update.
8. Deploy NotificationCenter and NotificationPreferences UI.

### 7.2 Rollback

**If social alerts cause performance issues**:
- Remove `emit_social_alert()` calls from newsfeed.py, messaging.py, social.py (revert Step 2). Batch records remain in DDB but no new ones are created.
- The frontend badge will show stale unread count that decreases as users mark-all-read.

**If batching causes DDB hot partition**:
- The batch key `follower:{user_id}` concentrates all follow alerts for a popular creator on one item. If a creator gets 100K followers/hour, the single batch record receives 100K update_item calls/hour. DDB can handle this (3000 WCU per partition), but monitor `ThrottleCount`.
- Rollback: change `new_follower` from batched to non-batched by removing the `batch_key` parameter in the follow hook.

### 7.3 Data Migration

No schema migration required. The `alerts` table already exists. Batch records use a new SK format (`BATCH#{batch_key}`) that does not conflict with existing alert IDs (`ALERT#{uuid}`). The `type_preferences` field is added to existing `alert_prefs` records on first write (DDB is schemaless).

### 7.4 Rollback Script

```python
# scripts/rollback_social_alerts.py
"""Remove all social alert batch records from the alerts table."""
import boto3

def rollback_social_alerts():
    ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001")
    table = ddb.Table("alerts")
    
    # Scan for BATCH# records
    lek = None
    deleted = 0
    while True:
        kwargs = {
            "FilterExpression": "begins_with(alert_id, :prefix)",
            "ExpressionAttributeValues": {":prefix": "BATCH#"},
            "ProjectionExpression": "user_sub, alert_id",
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            table.delete_item(Key={"user_sub": item["user_sub"], "alert_id": item["alert_id"]})
            deleted += 1
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
    print(f"Deleted {deleted} batch alert records")
```

---

## 8. Operational Runbook

### 8.1 Monitoring Alerts

| Metric | Threshold | Action |
|--------|-----------|--------|
| `social_alert_emit_count` (per minute) | > 10,000 | Check for viral content; verify batching is working |
| `social_alert_emit_error_count` | > 100/min | Check DDB throttling; review CloudWatch logs |
| `alert_batch_trim_count` | Informational | Normal — indicates popular posts |
| `unread_count_query_latency_p99` | > 200ms | User has very large alert history; consider TTL cleanup |
| `sse_queue_overflow_count` | > 50/min | Clients are slow; check network |
| `mention_resolve_scan_count` | > 500/min | Many mentions being resolved; verify scan is bounded |

### 8.2 Debugging Common Issues

**Issue: "User reports not receiving notifications"**
1. Check `alert_prefs` table for user — is the alert type disabled?
   ```bash
   aws dynamodb get-item --table-name alert_prefs --key '{"user_sub": {"S": "USER_SUB"}}' --endpoint-url http://localhost:8001
   ```
2. Check if user follows the post author (for `comment_reply`, the recipient is the comment author, not necessarily a follower).
3. Check `_NO_ALERT_EVENTS` — is the event type in the suppression set?
4. Check SSE connection — is the user's browser connected to `/alerts/stream`?

**Issue: "Notification badge shows wrong count"**
1. Query alerts table for unread count manually:
   ```bash
   aws dynamodb query --table-name alerts --key-condition-expression "user_sub = :u" \
     --filter-expression "#r = :false" --expression-attribute-names '{"#r": "read"}' \
     --expression-attribute-values '{":u": {"S": "USER_SUB"}, ":false": {"BOOL": false}}' \
     --select COUNT --endpoint-url http://localhost:8001
   ```
2. If count differs from frontend badge, the SSE increment may have drifted. A page reload triggers `refetchInterval` which corrects the count.

**Issue: "Batch notification shows wrong actor count"**
1. Read the batch record:
   ```bash
   aws dynamodb get-item --table-name alerts --key '{"user_sub": {"S": "USER_SUB"}, "alert_id": {"S": "BATCH#reaction:POST_ID"}}' --endpoint-url http://localhost:8001
   ```
2. The `actor_count` should be accurate (atomic ADD). The `actors` list may be trimmed. If `actor_count` is wrong, check for concurrent trim race condition.

### 8.3 Emergency Kill Switch

To disable all social notifications without a code deploy:

```python
# Add to app/services/alerts.py at module level:
_SOCIAL_ALERTS_DISABLED = os.environ.get("SOCIAL_ALERTS_DISABLED", "").lower() == "true"

# In emit_social_alert():
if _SOCIAL_ALERTS_DISABLED:
    return None
```

Set `SOCIAL_ALERTS_DISABLED=true` in `.env.local` and restart the backend.

---

## 9. Performance & Capacity Planning

### 9.1 Write Throughput Estimation

| Scenario | Social events/min | DDB writes/min | Notes |
|----------|-------------------|-----------------|-------|
| Quiet platform (100 DAU) | ~50 | ~50 | Each event = 1 pref read + 1 write |
| Active platform (10K DAU) | ~5,000 | ~5,000 | Batching reduces individual alert writes |
| Viral post (100K reactions/hr) | ~1,667/min | ~1,667/min | All coalesce into 1 batch record per author |
| Popular creator (10K followers, posts daily) | ~10,000 follows/day | ~7/min avg | Batched into single follower alert |

### 9.2 Read Throughput Estimation

| Operation | Frequency | DDB reads/sec |
|-----------|-----------|---------------|
| Unread count (page load) | 10K DAU * 5 loads/day | ~0.6 RPS |
| Unread count (polling 30s) | 10K concurrent * 1/30s | ~333 RPS |
| Type preferences read (per emit) | Same as write throughput | Same |
| Alert list (notification page) | ~1% of page loads | ~0.06 RPS |

**Concern**: The 30-second polling for unread count generates 333 RPS at 10K concurrent users. Each query reads up to 500 items (FilterExpression on `read=false`). Mitigation:
- Cache unread count per user in a fast cache (DDB DAX or in-process TTL cache).
- SSE-driven increments reduce the need for frequent polling — increase `refetchInterval` to 60s.

### 9.3 DDB Item Size Budget

| Field | Typical Size | Max Size |
|-------|-------------|----------|
| user_sub | 36 bytes | 36 bytes |
| alert_id (batch) | ~50 bytes | ~100 bytes |
| actors (10 entries) | ~1.5 KB | ~3 KB |
| details | ~500 bytes | ~4 KB |
| Other fields | ~200 bytes | ~500 bytes |
| **Total per batch item** | **~2.3 KB** | **~7.6 KB** |

DDB maximum item size is 400 KB — batch items are well within limits.

### 9.4 SSE Connection Scaling

Each connected user holds one `asyncio.Queue` in memory (200 slots * ~1 KB per alert = ~200 KB max per user). At 10K concurrent SSE connections: ~2 GB memory for SSE alone. This is acceptable for single-process but requires Redis/SQS pubsub for multi-process.

---

## 10. Dependency Analysis

### 10.1 Upstream Dependencies

| Dependency | Type | Impact if Unavailable |
|------------|------|----------------------|
| SOC-001 (Follow System) | Required for `new_follower` alerts | Follow alerts won't fire; other social alerts still work |
| `app/services/alerts.py` | Core dependency | All alert functionality fails |
| `app/services/profile.py` | `get_profile_identity()` for display names | Mention resolution uses "Someone" fallback |
| `app/services/push.py` | Push notification delivery | Alerts still stored in DDB and sent via SSE |
| `app/services/rate_limit.py` | Channel rate limiting | Without it, email/push/SMS may flood |
| DynamoDB `alerts` table | Data store | All alert reads/writes fail |
| DynamoDB `alert_prefs` table | Preference store | Defaults used (all enabled) |

### 10.2 Downstream Dependents

| Dependent | How It Uses This Feature |
|-----------|------------------------|
| SOC-002 (Feed Fan-out) | Post creation triggers `post_comment`/`post_reaction` alerts via hooks |
| SOC-003 (User Search) | May use engagement metrics from alert data for trending ranking |
| SOC-005 (Public Profile) | Profile page links in notification actor avatars |
| Frontend Header | `useNotificationCount` hook reads unread count |
| Notification Center page | Renders alert list with batching |

### 10.3 Feature Flag

```python
# .env.local
SOCIAL_ALERTS_ENABLED=true
```

When `false`, `emit_social_alert()` returns `None` without any DDB access. This allows deploying the code without activating the feature.

---

## 11. Acceptance Criteria

### 11.1 Must Have

- [ ] 10 social alert types added to `ALERT_EVENT_TYPES`
- [ ] `emit_social_alert()` function handles self-suppression, pref check, batching
- [ ] Batch records coalesce multiple actors into one DDB item with atomic `actor_count`
- [ ] Actors list trimmed to 10 most recent entries
- [ ] Batch title shows "X and N others [action]" format
- [ ] `GET /alerts/unread-count` returns count capped at 99
- [ ] `POST /alerts/mark-all-read` marks all unread alerts as read
- [ ] Per-type preference CRUD via `GET/POST /alerts/type-preferences`
- [ ] Header bell icon shows red badge with unread count
- [ ] SSE publishes social alerts in real-time to connected clients
- [ ] Mention detection extracts `@username` patterns from text
- [ ] Mention resolution looks up user_sub and emits `mention` alert

### 11.2 Should Have

- [ ] Notification Center page groups alerts by category (Social / Security / System)
- [ ] Notification Preferences UI has per-type toggle switches
- [ ] Push notification delivery for social alerts (when push_enabled)
- [ ] Email delivery for enabled alert types (when email_enabled)
- [ ] Badge shows "9+" for counts above 9
- [ ] Frontend SSE handler dispatches `alert:new` custom event

### 11.3 Nice to Have

- [ ] Notification sound when badge increments
- [ ] "Mute this post" to suppress further alerts for a specific post
- [ ] Notification grouping by time window (last hour, today, this week)
- [ ] Rich notification preview (show post thumbnail in notification)

---

## 12. Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery |
|---|---|---|---|---|
| `emit_social_alert` DDB write fails | N/A (async) | — | None (silent) | Logged; user misses notification |
| `_batch_alert` DDB update_item fails | N/A (async) | — | None (silent) | Logged; falls back to None |
| `get_unread_count` DDB query fails | 500 | `INTERNAL_ERROR` | "Unable to load notifications" | Frontend shows badge with "!" |
| `mark_all_read` partial failure | 200 | — | Returns `marked_count` < total | Retry marks remaining |
| `update_type_preference` invalid type | 422 | `VALIDATION_ERROR` | "Unknown alert type" | User corrects selection |
| `extract_mentions` regex timeout | N/A | — | None (silent) | Text too long; return empty list |
| `_resolve_username_to_user_sub` scan fails | N/A | — | Mention skipped | Logged; username not resolved |
| SSE queue full (200 items) | N/A | — | Client disconnected | Client reconnects; loads from DDB |
| `send_push_for_alert` fails | N/A (async) | — | None (silent) | Push skipped; in-app alert still stored |
| Rate limit on email channel | N/A | — | Email skipped | In-app alert still stored |

---

## 13. Frontend Component Specifications

### 13.1 Component Tree

```
Header.tsx
  └── BellButton (modified)
        ├── useNotificationCount() hook
        ├── Badge (red circle with count)
        └── NotificationDropdown
              ├── NotificationItem (batched)
              │     ├── ActorAvatars (stacked, up to 3)
              │     ├── Title text (batched format)
              │     └── Timestamp (relative: "2h ago")
              ├── NotificationItem (individual)
              │     ├── ActorAvatar (single)
              │     ├── Title text
              │     └── Timestamp
              └── "Mark all as read" button

NotificationCenter.tsx (full page)
  ├── CategoryTabs (Social | Security | System)
  ├── NotificationList
  │     ├── NotificationCard (repeating)
  │     │     ├── ActorAvatars
  │     │     ├── Title + details preview
  │     │     ├── Timestamp
  │     │     └── Read/unread indicator
  │     └── "Load more" button (cursor pagination)
  └── NotificationPreferencesLink

NotificationPreferences.tsx (settings page)
  ├── CategorySection (Social Notifications)
  │     ├── PreferenceRow (New Followers)
  │     │     ├── Label
  │     │     ├── Enabled toggle
  │     │     ├── Email toggle
  │     │     ├── Push toggle
  │     │     └── In-App toggle
  │     ├── PreferenceRow (Post Reactions)
  │     └── PreferenceRow (Comments) ...
  └── CategorySection (Security Notifications) ...
```

### 13.2 NotificationItem Component

```tsx
// frontend/src/pages/alerts/NotificationItem.tsx

interface NotificationItemProps {
  alert: {
    alert_id: string;
    alert_type: string;
    title: string;
    actors?: Array<{ user_id: string; display_name: string }>;
    actor_count?: number;
    details?: Record<string, any>;
    read: boolean;
    updated_at: string;
    batch_key?: string;
  };
  onClick: (alert: NotificationItemProps["alert"]) => void;
}

export function NotificationItem({ alert, onClick }: NotificationItemProps) {
  const timeAgo = useRelativeTime(alert.updated_at);
  const icon = getAlertIcon(alert.alert_type);

  return (
    <div
      className={cn(
        "flex items-start gap-3 p-3 rounded-lg cursor-pointer hover:bg-accent transition-colors",
        !alert.read && "bg-accent/50"
      )}
      onClick={() => onClick(alert)}
      role="button"
      tabIndex={0}
      aria-label={`${alert.title} - ${timeAgo}`}
    >
      {/* Icon */}
      <div className="mt-1">{icon}</div>

      {/* Stacked actor avatars (if batched) */}
      {alert.actors && alert.actors.length > 1 && (
        <div className="flex -space-x-2">
          {alert.actors.slice(0, 3).map((actor) => (
            <Avatar key={actor.user_id} className="h-6 w-6 border-2 border-background">
              <AvatarFallback>{actor.display_name[0]}</AvatarFallback>
            </Avatar>
          ))}
        </div>
      )}

      {/* Content */}
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium">{alert.title}</p>
        <p className="text-xs text-muted-foreground">{timeAgo}</p>
      </div>

      {/* Unread dot */}
      {!alert.read && (
        <div className="h-2 w-2 rounded-full bg-primary mt-2" aria-label="Unread" />
      )}
    </div>
  );
}
```

### 13.3 useNotificationSSE Hook

```tsx
// frontend/src/hooks/useNotificationSSE.ts

import { useEffect, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";

export function useNotificationSSE() {
  const queryClient = useQueryClient();
  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const source = new EventSource("/ui/alerts/stream", { withCredentials: true });
    sourceRef.current = source;

    source.addEventListener("social_alert", (event) => {
      const alert = JSON.parse(event.data);

      // Dispatch custom event for useNotificationCount hook
      window.dispatchEvent(new CustomEvent("alert:new", { detail: alert }));

      // Invalidate alerts list if the notification center is open
      queryClient.invalidateQueries({ queryKey: ["alerts", "list"] });
    });

    source.addEventListener("error", () => {
      // EventSource auto-reconnects; log for monitoring
      console.warn("SSE connection error, will reconnect");
    });

    return () => {
      source.close();
      sourceRef.current = null;
    };
  }, [queryClient]);
}
```

### 13.4 Alert Navigation

When a notification is clicked, navigate to the relevant context:

```typescript
function navigateToAlert(alert: AlertItem, navigate: NavigateFunction) {
  const d = alert.details || {};
  switch (alert.alert_type) {
    case "post_liked":
    case "post_reaction":
    case "post_comment":
    case "post_tip":
    case "post_shared":
      navigate(`/feed/${d.post_id}`);
      break;
    case "comment_reply":
      navigate(`/feed/${d.post_id}#comment-${d.comment_id}`);
      break;
    case "new_follower":
      navigate(`/u/${d.follower_user_id}`);
      break;
    case "mention":
      navigate(`/feed/${d.post_id}`);
      break;
    case "message_tip":
      navigate(`/messages/${d.conversation_id}`);
      break;
    case "subscription_started":
      navigate("/subscriptions");
      break;
    default:
      navigate("/alerts");
  }
}
```

---

## 14. Internationalization Considerations

### 14.1 Translatable Strings

All user-facing notification titles must be translatable. Instead of hardcoding English templates in `_format_batch_title`, the function should return a structured object that the frontend can translate:

```python
# Backend returns structured title data:
{
    "title_key": "notification.post_reaction.plural",
    "title_params": {
        "actor_name": "Alice",
        "other_count": 3,
    },
    "title_fallback": "Alice and 3 others reacted to your post",
}
```

### 14.2 Frontend Translation Keys

```json
{
  "notification.new_follower.single": "{{name}} followed you",
  "notification.new_follower.plural": "{{name}} and {{count}} others followed you",
  "notification.post_reaction.single": "{{name}} reacted to your post",
  "notification.post_reaction.plural": "{{name}} and {{count}} others reacted to your post",
  "notification.post_liked.single": "{{name}} liked your post",
  "notification.post_liked.plural": "{{name}} and {{count}} others liked your post",
  "notification.post_comment.single": "{{name}} commented on your post",
  "notification.post_comment.plural": "{{name}} and {{count}} others commented on your post",
  "notification.comment_reply.single": "{{name}} replied to your comment",
  "notification.comment_reply.plural": "{{name}} and {{count}} others replied to your comment",
  "notification.mention.single": "{{name}} mentioned you",
  "notification.mention.plural": "{{name}} and {{count}} others mentioned you",
  "notification.post_tip.single": "{{name}} tipped your post",
  "notification.post_tip.plural": "{{name}} and {{count}} others tipped your post",
  "notification.message_tip.single": "{{name}} tipped your message",
  "notification.subscription_started.single": "{{name}} subscribed to your content",
  "notification.subscription_started.plural": "{{name}} and {{count}} others subscribed to your content",
  "notification.badge.overflow": "9+",
  "notification.mark_all_read": "Mark all as read",
  "notification.preferences.title": "Notification Preferences",
  "notification.preferences.social": "Social Notifications",
  "notification.preferences.security": "Security Notifications",
  "notification.preferences.in_app": "In-App",
  "notification.preferences.email": "Email",
  "notification.preferences.push": "Push",
  "notification.empty": "No notifications yet",
  "notification.load_more": "Load more"
}
```

### 14.3 Pluralization Rules

Different languages have different pluralization rules (e.g., Russian has 3 plural forms, Arabic has 6). The frontend i18n library (e.g., `i18next`) handles this via ICU MessageFormat:

```json
{
  "notification.post_reaction": "{count, plural, =0 {} =1 {{name} reacted to your post} other {{name} and {count} others reacted to your post}}"
}
```

### 14.4 RTL Support

For RTL languages (Arabic, Hebrew), the notification layout must mirror:
- Actor avatars on the right side
- Unread dot on the left side
- Timestamp aligned to the left

Tailwind handles this via `rtl:` variant prefixes (e.g., `rtl:flex-row-reverse`).

---

## Appendix A: SSE Event Format

Social alerts are published over the existing `GET /alerts/stream` SSE endpoint with this format:

```
event: social_alert
data: {"alert_id": "BATCH#reaction:post_abc", "alert_type": "post_reaction", "title": "Alice reacted to your post", "actor_count": 1, "actors": [{"user_id": "...", "display_name": "Alice"}], "read": false, "updated_at": "2026-05-26T14:30:00Z"}
```

The frontend event handler dispatches a `CustomEvent("alert:new")` on `window`, which the `useNotificationCount` hook listens for.

## Appendix B: Notification State Machine

```
                    ┌─────────────┐
                    │  NOT_SENT   │
                    │  (initial)  │
                    └──────┬──────┘
                           │
                    emit_social_alert()
                           │
               ┌───────────┼───────────┐
               │           │           │
               ▼           ▼           ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │ SUPPRESSED│ │ BATCHED  │ │INDIVIDUAL│
        │ (self /   │ │ (merged  │ │ (new     │
        │  pref off)│ │  into    │ │  alert   │
        └──────────┘ │  batch)  │ │  item)   │
                      └────┬─────┘ └────┬─────┘
                           │            │
                     ┌─────┴────────────┘
                     │
                     ▼
              ┌──────────────┐
              │   UNREAD     │
              │  (read=false)│
              └──────┬───────┘
                     │
              mark-read / mark-all-read
                     │
                     ▼
              ┌──────────────┐
              │    READ      │
              │  (read=true) │
              └──────┬───────┘
                     │
              TTL expiry (30 days)
                     │
                     ▼
              ┌──────────────┐
              │   EXPIRED    │
              │  (DDB TTL    │
              │   deleted)   │
              └──────────────┘
```

## Appendix C: Batch Key Distribution Analysis

For a platform with N users and M posts/day:

| Batch Key Pattern | Number of Unique Keys | Items per Key | Hot Partition Risk |
|---|---|---|---|
| `reaction:{post_id}` | M * N (each post) | 1 per post per author | Low — distributed by post_id |
| `liked:{post_id}` | M * N | 1 per post per author | Low |
| `comment:{post_id}` | M * N | 1 per post per author | Low |
| `follower:{user_id}` | N (each user) | 1 per user | Medium — popular creators get many updates |
| `tip:{post_id}` | Subset of M | 1 per tipped post per author | Low |

The `follower:{user_id}` key for a popular creator (100K followers) receives high write throughput. The batch record is a single DDB item — DDB can handle up to ~1000 writes/sec per item without throttling on a PAY_PER_REQUEST table.

## Appendix D: Related Tickets

- **SOC-001**: Follow system (source of `new_follower` events)
- **SOC-002**: Feed fan-out (post creation triggers fan-out AND notifications)
- **SOC-003**: User search/discovery (suggested users may leverage notification engagement data)
- **SOC-005**: Public profile page (profile links in notification actor avatars)

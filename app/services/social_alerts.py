"""Social alert system: emission, batching, mention detection, per-type preferences.

This module is the single entry-point for all social notifications.  Callers
invoke ``emit_social_alert()`` with a recipient, actor, alert type, and
optional batch key.  The function handles self-suppression, per-type prefs,
batching, channel routing, and SSE publish.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key

from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import (
    ALERT_EVENT_TYPES,
    get_alert_prefs,
    sse_publish_alert,
    write_alert,
)

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

    # The existing alert_prefs record uses event-type lists, not booleans.
    # For social alerts we default to True for in_app/push, False for sms.
    return {
        "email": type_pref.get("email", True),
        "push":  type_pref.get("push", True),
        "in_app": type_pref.get("in_app", True),
        "sms":   type_pref.get("sms", False),
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
    # Read current prefs record directly from DDB (not via get_alert_prefs
    # which normalises the shape and may drop type_preferences).
    raw = T.alert_prefs.get_item(Key={"user_sub": user_sub}).get("Item") or {}
    type_prefs: Dict[str, Any] = raw.get("type_preferences", {})
    pref = type_prefs.get(alert_type, {
        "enabled": True,
        "email": True,
        "push": True,
        "in_app": True,
        "sms": False,
    })

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

    # Atomic update of the type_preferences map on the DDB item.
    T.alert_prefs.update_item(
        Key={"user_sub": user_sub},
        UpdateExpression="SET type_preferences = :tp, updated_at = :now",
        ExpressionAttributeValues={
            ":tp": type_prefs,
            ":now": now_ts(),
        },
    )
    return pref


def get_all_type_preferences(user_sub: str) -> Dict[str, Dict[str, Any]]:
    """Return the full type_preferences map with defaults for missing types."""
    raw = T.alert_prefs.get_item(Key={"user_sub": user_sub}).get("Item") or {}
    type_prefs: Dict[str, Any] = raw.get("type_preferences", {})
    # Ensure every known social + system alert type has a preference entry
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

    # 5. Route through enabled channels (best-effort)
    try:
        channels = _get_alert_channels(recipient_user_id, alert_type)
        _dispatch_to_channels(
            recipient_user_id=recipient_user_id,
            alert_type=alert_type,
            alert_id=alert_obj.get("alert_id", ""),
            title=alert_obj.get("title", title),
            details=details,
            channels=channels,
        )
    except Exception:
        logger.warning("Channel dispatch failed", extra={
            "recipient": recipient_user_id, "alert_type": alert_type,
        })

    return alert_obj


def _dispatch_to_channels(
    *,
    recipient_user_id: str,
    alert_type: str,
    alert_id: str,
    title: str,
    details: Dict[str, Any],
    channels: Dict[str, bool],
) -> None:
    """Route the alert through the enabled delivery channels.

    Each channel is gated by rate-limit check to avoid flooding users.
    All imports and calls are wrapped in try/except so that missing or
    broken channel handlers never prevent the core alert from being written.
    """
    try:
        from app.services.rate_limit import can_send_alert_channel
    except ImportError:
        logger.warning("rate_limit module not available; skipping channel dispatch")
        return

    if channels.get("push"):
        try:
            if can_send_alert_channel(recipient_user_id, "push"):
                from app.services.push import send_push_for_alert
                send_push_for_alert(
                    recipient_user_id,
                    alert_type,
                    title,
                    title,  # body = title for social alerts
                    alert_id,
                )
        except Exception:
            logger.warning("Push delivery failed", extra={
                "user": recipient_user_id, "type": alert_type,
            })

    if channels.get("email"):
        try:
            if can_send_alert_channel(recipient_user_id, "email"):
                from app.services.alerts import send_alert_email
                prefs = get_alert_prefs(recipient_user_id)
                to_emails = prefs.get("emails") or []
                if to_emails:
                    send_alert_email(to_emails, title, f"{title}\n\nDetails: {details}")
        except Exception:
            logger.warning("Email delivery failed", extra={
                "user": recipient_user_id, "type": alert_type,
            })

    if channels.get("sms"):
        try:
            if can_send_alert_channel(recipient_user_id, "sms"):
                from app.services.alerts import send_alert_sms
                prefs = get_alert_prefs(recipient_user_id)
                to_numbers = prefs.get("sms_numbers") or []
                if to_numbers:
                    send_alert_sms(to_numbers, title)
        except Exception:
            logger.warning("SMS delivery failed", extra={
                "user": recipient_user_id, "type": alert_type,
            })


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
    now_str = str(now)
    actor_entry = {
        "user_id": actor_user_id,
        "display_name": actor_display_name,
        "timestamp": now_str,
    }

    try:
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
                ":now": now_str,
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
            "actors": actors[-_BATCH_SSE_ACTORS:],
            "details": details,
            "read": False,
            "updated_at": now_str,
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

    template = templates_plural.get(
        alert_type,
        f"{{name}} and {others} {other_word} interacted with your content",
    )
    return template.format(name=first_name)


# --------------------------------------------------------------------------- #
#  Unread count                                                                 #
# --------------------------------------------------------------------------- #


def get_unread_alert_count(user_sub: str, *, cap: int = 99) -> int:
    """Count unread alerts for a user, capped at ``cap``.

    Uses a DDB query with FilterExpression on the ``read`` attribute.
    Note: FilterExpression does NOT reduce the amount of data read -- DDB
    still reads up to 1MB per page.  We set Limit=500 to bound cost,
    and loop with LastEvaluatedKey only up to ``cap`` results.
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
                    UpdateExpression="SET #read = :true, read_at = :now",
                    ExpressionAttributeNames={"#read": "read"},
                    ExpressionAttributeValues={":true": True, ":now": now_ts()},
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
            try:
                from app.services.profile import get_profile_identity
                identity = get_profile_identity(user_sub)
            except Exception:
                identity = {}
            resolved.append({
                "username": username,
                "user_id": user_sub,
                "display_name": identity.get("display_name") or username,
            })
    return resolved


def _resolve_username_to_user_sub(username: str) -> Optional[str]:
    """Look up a user_sub by username/handle alias.

    Searches the profiles table for records with a matching alias field.
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

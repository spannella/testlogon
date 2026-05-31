"""Broadcast chat delegation service (DELEGATE-004).

Enables delegates to moderate broadcast chat (pin, delete, mute, ban,
announce) and control broadcast sessions (start, stop, schedule) on
behalf of a creator.  Multiple moderators can be active simultaneously.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.delegates import require_delegate_permission, _write_audit
from app.services.broadcast_chat_store import (
    delete_chat_message,
    send_chat_message,
    set_mute,
)
from app.services.broadcast_store import (
    get_session,
    transition_session_status,
    create_session as create_broadcast_session,
)
from app.services.broadcast_orchestrator import (
    start_session_with_provider,
    stop_session_with_provider,
)
from app.services.broadcast_sse import broadcast_sse_publish
from app.services.profile import get_profile

logger = logging.getLogger(__name__)

MAX_MUTE_DURATION_SECONDS = 86400  # 24 hours
MAX_ACTIVE_MODERATORS = 20


# ---------------------------------------------------------------------------
# Chat moderation
# ---------------------------------------------------------------------------


def pin_chat_message(
    *,
    session_id: str,
    message_id: str,
    moderator_id: str,
    creator_id: str,
) -> Dict[str, Any]:
    """Pin a message in broadcast chat."""
    _require_broadcast_moderator(session_id, moderator_id, creator_id)

    mod_profile = get_profile(moderator_id)
    mod_name = mod_profile.get("display_name") or moderator_id
    ts = now_ts()

    # Unpin any existing pinned message
    existing = _get_pinned_message(session_id)
    if existing:
        T.broadcast_moderation.update_item(
            Key={"pk": existing["pk"], "sk": existing["sk"]},
            UpdateExpression="SET pinned = :f",
            ExpressionAttributeValues={":f": False},
        )

    pin_item: Dict[str, Any] = {
        "pk": f"SESSION#{session_id}",
        "sk": f"PIN#{message_id}",
        "message_id": message_id,
        "pinned": True,
        "pinned_by": moderator_id,
        "pinned_by_display_name": mod_name,
        "pinned_at": ts,
    }
    T.broadcast_moderation.put_item(Item=pin_item)

    sys_text = f"[Moderator @{mod_name}] pinned a message"
    _send_system_message(session_id, sys_text, moderator_id, mod_name, "pin")

    broadcast_sse_publish(session_id, {
        "_type": "mod:pin",
        "message_id": message_id,
        "moderator_name": mod_name,
    })

    _write_moderation_audit(session_id, moderator_id, mod_name, "pin",
                            target_message_id=message_id)
    _increment_actions_count(session_id, moderator_id)

    return {
        "ok": True,
        "message_id": message_id,
        "pinned": True,
        "pinned_by": moderator_id,
        "pinned_at": ts,
    }


def unpin_chat_message(
    *,
    session_id: str,
    message_id: str,
    moderator_id: str,
    creator_id: str,
) -> Dict[str, Any]:
    """Unpin a previously pinned message."""
    _require_broadcast_moderator(session_id, moderator_id, creator_id)

    mod_profile = get_profile(moderator_id)
    mod_name = mod_profile.get("display_name") or moderator_id

    T.broadcast_moderation.delete_item(
        Key={"pk": f"SESSION#{session_id}", "sk": f"PIN#{message_id}"}
    )

    sys_text = f"[Moderator @{mod_name}] unpinned a message"
    _send_system_message(session_id, sys_text, moderator_id, mod_name, "unpin")

    broadcast_sse_publish(session_id, {
        "_type": "mod:unpin",
        "message_id": message_id,
        "moderator_name": mod_name,
    })

    _write_moderation_audit(session_id, moderator_id, mod_name, "unpin",
                            target_message_id=message_id)

    return {"ok": True, "message_id": message_id, "pinned": False}


def delete_moderated_message(
    *,
    session_id: str,
    message_id: str,
    moderator_id: str,
    creator_id: str,
) -> Dict[str, Any]:
    """Delete a message from broadcast chat as a moderator."""
    _require_broadcast_moderator(session_id, moderator_id, creator_id)

    mod_profile = get_profile(moderator_id)
    mod_name = mod_profile.get("display_name") or moderator_id

    delete_chat_message(session_id, message_id, moderator_id)

    sys_text = f"[Moderator @{mod_name}] removed a message"
    _send_system_message(session_id, sys_text, moderator_id, mod_name, "delete")

    broadcast_sse_publish(session_id, {
        "_type": "mod:delete",
        "message_id": message_id,
        "moderator_name": mod_name,
    })

    _write_moderation_audit(session_id, moderator_id, mod_name, "delete",
                            target_message_id=message_id)
    _increment_actions_count(session_id, moderator_id)

    return {"ok": True, "message_id": message_id}


def mute_viewer(
    *,
    session_id: str,
    user_id: str,
    moderator_id: str,
    creator_id: str,
    duration_seconds: int,
) -> Dict[str, Any]:
    """Mute a viewer in broadcast chat for a specified duration."""
    _require_broadcast_moderator(session_id, moderator_id, creator_id)

    if duration_seconds > MAX_MUTE_DURATION_SECONDS:
        raise HTTPException(400, f"Mute duration cannot exceed {MAX_MUTE_DURATION_SECONDS} seconds")

    session = get_session(session_id)
    if user_id == session.created_by:
        raise HTTPException(400, "Cannot mute the session creator")

    mod_profile = get_profile(moderator_id)
    mod_name = mod_profile.get("display_name") or moderator_id

    result = set_mute(session_id, user_id, duration_seconds, moderator_id)

    minutes = duration_seconds // 60
    duration_text = f"{minutes} minute{'s' if minutes != 1 else ''}" if minutes > 0 else f"{duration_seconds} seconds"
    sys_text = f"[Moderator @{mod_name}] muted a viewer for {duration_text}"
    _send_system_message(session_id, sys_text, moderator_id, mod_name, "mute")

    broadcast_sse_publish(session_id, {
        "_type": "mod:mute",
        "user_id": user_id,
        "moderator_name": mod_name,
        "duration": duration_seconds,
    })

    _write_moderation_audit(session_id, moderator_id, mod_name, "mute",
                            target_user_id=user_id,
                            details={"duration_seconds": duration_seconds})
    _increment_actions_count(session_id, moderator_id)

    return result


def ban_viewer(
    *,
    session_id: str,
    user_id: str,
    moderator_id: str,
    creator_id: str,
    reason: str = "",
) -> Dict[str, Any]:
    """Ban a viewer from broadcast chat for the session duration."""
    _require_broadcast_moderator(session_id, moderator_id, creator_id)

    session = get_session(session_id)
    if user_id == session.created_by:
        raise HTTPException(400, "Cannot ban the session creator")

    ts = now_ts()
    mod_profile = get_profile(moderator_id)
    mod_name = mod_profile.get("display_name") or moderator_id

    ban_item: Dict[str, Any] = {
        "pk": f"SESSION#{session_id}",
        "sk": f"BAN#{user_id}",
        "user_id": user_id,
        "banned_by": moderator_id,
        "banned_by_display_name": mod_name,
        "banned_at": ts,
        "reason": reason,
    }
    T.broadcast_moderation.put_item(Item=ban_item)

    sys_text = f"[Moderator @{mod_name}] banned a viewer from chat"
    _send_system_message(session_id, sys_text, moderator_id, mod_name, "ban")

    broadcast_sse_publish(session_id, {
        "_type": "mod:ban",
        "user_id": user_id,
        "moderator_name": mod_name,
    })

    _write_moderation_audit(session_id, moderator_id, mod_name, "ban",
                            target_user_id=user_id,
                            details={"reason": reason})
    _increment_actions_count(session_id, moderator_id)

    return ban_item


def unban_viewer(
    *,
    session_id: str,
    user_id: str,
    moderator_id: str,
    creator_id: str,
) -> Dict[str, Any]:
    """Unban a viewer from broadcast chat."""
    _require_broadcast_moderator(session_id, moderator_id, creator_id)

    mod_profile = get_profile(moderator_id)
    mod_name = mod_profile.get("display_name") or moderator_id

    T.broadcast_moderation.delete_item(
        Key={"pk": f"SESSION#{session_id}", "sk": f"BAN#{user_id}"}
    )

    broadcast_sse_publish(session_id, {
        "_type": "mod:unban",
        "user_id": user_id,
        "moderator_name": mod_name,
    })

    _write_moderation_audit(session_id, moderator_id, mod_name, "unban",
                            target_user_id=user_id)

    return {"ok": True, "user_id": user_id}


def post_announcement(
    *,
    session_id: str,
    moderator_id: str,
    creator_id: str,
    text: str,
) -> Dict[str, Any]:
    """Post a highlighted announcement in broadcast chat."""
    _require_broadcast_moderator(session_id, moderator_id, creator_id)

    mod_profile = get_profile(moderator_id)
    mod_name = mod_profile.get("display_name") or moderator_id

    msg = send_chat_message(
        session_id,
        moderator_id,
        f"[Moderator] {mod_name}",
        text,
        skip_rate_limit=True,
    )

    ts = now_ts()
    ann_id = f"ann_{uuid4().hex[:12]}"

    ann_item: Dict[str, Any] = {
        "pk": f"SESSION#{session_id}",
        "sk": f"ANN#{ann_id}",
        "announcement_id": ann_id,
        "message_id": msg["message_id"],
        "is_announcement": True,
        "announcement_by": moderator_id,
        "announcement_by_display_name": mod_name,
        "text": text,
        "created_at": ts,
    }
    T.broadcast_moderation.put_item(Item=ann_item)

    broadcast_sse_publish(session_id, {
        "_type": "mod:announcement",
        "text": text,
        "moderator_name": mod_name,
        "message_id": msg["message_id"],
    })

    _write_moderation_audit(session_id, moderator_id, mod_name, "announcement",
                            details={"text": text[:200]})
    _increment_actions_count(session_id, moderator_id)

    return {
        "ok": True,
        "message_id": msg["message_id"],
        "is_announcement": True,
        "announcement_by": moderator_id,
        "text": text,
        "created_at": ts,
    }


# ---------------------------------------------------------------------------
# Broadcast control
# ---------------------------------------------------------------------------


def start_broadcast_as_delegate(
    *,
    session_id: str,
    delegate_id: str,
    creator_id: str,
) -> Dict[str, Any]:
    """Start a broadcast on behalf of the creator."""
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="broadcast_control",
    )

    session = get_session(session_id)
    if session.created_by != creator_id:
        raise HTTPException(403, "Session does not belong to specified creator")

    updated = start_session_with_provider(
        session_id=session_id,
        actor=delegate_id,
        reason=f"Started by delegate {delegate_id}",
    )

    _write_audit(
        creator_id,
        delegate_id,
        "delegate",
        "broadcast_started",
        session_id,
        {"session_id": session_id},
    )

    return {
        "ok": True,
        "session_id": session_id,
        "status": updated.status,
    }


def stop_broadcast_as_delegate(
    *,
    session_id: str,
    delegate_id: str,
    creator_id: str,
) -> Dict[str, Any]:
    """Stop a broadcast on behalf of the creator."""
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="broadcast_control",
    )

    session = get_session(session_id)
    if session.created_by != creator_id:
        raise HTTPException(403, "Session does not belong to specified creator")

    updated = stop_session_with_provider(
        session_id=session_id,
        actor=delegate_id,
        reason=f"Stopped by delegate {delegate_id}",
    )

    _write_audit(
        creator_id,
        delegate_id,
        "delegate",
        "broadcast_stopped",
        session_id,
        {"session_id": session_id},
    )

    return {
        "ok": True,
        "session_id": session_id,
        "status": updated.status,
    }


def schedule_broadcast_as_delegate(
    *,
    delegate_id: str,
    creator_id: str,
    title: str,
    scheduled_at: int,
    profile_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Schedule a broadcast on behalf of the creator."""
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="broadcast_control",
    )

    if scheduled_at <= now_ts():
        raise HTTPException(400, "scheduled_at must be in the future")

    session = create_broadcast_session(
        profile_id=profile_id or "default",
        created_by=creator_id,
    )

    updated = transition_session_status(
        session_id=session.id,
        to_status="scheduled",
        reason=f"Scheduled by delegate {delegate_id}",
        actor=delegate_id,
        extra_fields={
            "name": title,
            "scheduled_at": scheduled_at,
            "schedule_status": "scheduled",
        },
    )

    _write_audit(
        creator_id,
        delegate_id,
        "delegate",
        "broadcast_scheduled",
        session.id,
        {"title": title, "scheduled_at": scheduled_at},
    )

    return {
        "ok": True,
        "session_id": session.id,
        "status": updated.status,
        "title": title,
        "scheduled_at": scheduled_at,
        "created_by": creator_id,
    }


# ---------------------------------------------------------------------------
# Moderator presence
# ---------------------------------------------------------------------------


def register_moderator(
    *,
    session_id: str,
    moderator_id: str,
    creator_id: str,
) -> Dict[str, Any]:
    """Register a moderator as active for a broadcast session."""
    _require_broadcast_moderator(session_id, moderator_id, creator_id)

    ts = now_ts()
    mod_profile = get_profile(moderator_id)
    mod_name = mod_profile.get("display_name") or moderator_id

    mod_item: Dict[str, Any] = {
        "pk": f"SESSION#{session_id}",
        "sk": f"MOD#{moderator_id}",
        "delegate_id": moderator_id,
        "display_name": mod_name,
        "connected_at": ts,
        "status": "online",
        "actions_count": 0,
    }
    T.broadcast_moderation.put_item(Item=mod_item)

    broadcast_sse_publish(session_id, {
        "_type": "mod:join",
        "moderator_name": mod_name,
    })

    return mod_item


def list_active_moderators(session_id: str) -> List[Dict[str, Any]]:
    """List all moderators currently active in a broadcast session."""
    from boto3.dynamodb.conditions import Key

    resp = T.broadcast_moderation.query(
        KeyConditionExpression=Key("pk").eq(f"SESSION#{session_id}")
        & Key("sk").begins_with("MOD#"),
    )
    return [
        {
            "delegate_id": item.get("delegate_id", ""),
            "display_name": item.get("display_name", ""),
            "connected_at": int(item.get("connected_at", 0)),
            "status": item.get("status", "offline"),
            "actions_count": int(item.get("actions_count", 0)),
        }
        for item in resp.get("Items", [])
    ]


def list_banned_viewers(session_id: str) -> List[Dict[str, Any]]:
    """List all viewers banned from broadcast chat."""
    from boto3.dynamodb.conditions import Key

    resp = T.broadcast_moderation.query(
        KeyConditionExpression=Key("pk").eq(f"SESSION#{session_id}")
        & Key("sk").begins_with("BAN#"),
    )
    return [
        {
            "user_id": item.get("user_id", ""),
            "banned_by": item.get("banned_by", ""),
            "banned_by_display_name": item.get("banned_by_display_name", ""),
            "banned_at": int(item.get("banned_at", 0)),
            "reason": item.get("reason", ""),
        }
        for item in resp.get("Items", [])
    ]


def is_viewer_banned(session_id: str, user_id: str) -> bool:
    """Check if a viewer is banned from broadcast chat."""
    resp = T.broadcast_moderation.get_item(
        Key={"pk": f"SESSION#{session_id}", "sk": f"BAN#{user_id}"}
    )
    return resp.get("Item") is not None


def get_broadcast_moderation_log(
    session_id: str,
    *,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Get moderation actions for a broadcast session."""
    from boto3.dynamodb.conditions import Key

    resp = T.broadcast_moderation.query(
        KeyConditionExpression=Key("pk").eq(f"SESSION#{session_id}")
        & Key("sk").begins_with("LOG#"),
        ScanIndexForward=False,
        Limit=limit,
    )
    return [
        {
            "event_id": item.get("event_id", ""),
            "moderator_id": item.get("moderator_id", ""),
            "moderator_display_name": item.get("moderator_display_name", ""),
            "moderation_type": item.get("moderation_type", ""),
            "target_user_id": item.get("target_user_id"),
            "target_message_id": item.get("target_message_id"),
            "details": item.get("details"),
            "ts": int(item.get("ts", 0)),
        }
        for item in resp.get("Items", [])
    ]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_broadcast_moderator(
    session_id: str, moderator_id: str, creator_id: str
) -> None:
    """Verify the caller has broadcast_moderate permission for the creator."""
    session = get_session(session_id)
    if session.created_by != creator_id:
        raise HTTPException(403, "Session does not belong to specified creator")
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=moderator_id,
        required_permission="broadcast_moderate",
    )


def _send_system_message(
    session_id: str,
    text: str,
    moderator_id: str,
    moderator_display_name: str,
    moderation_type: str,
) -> Dict[str, Any]:
    """Send a system message into broadcast chat for a moderation action."""
    return send_chat_message(
        session_id,
        "system",
        "System",
        text,
        skip_rate_limit=True,
    )


def _write_moderation_audit(
    session_id: str,
    moderator_id: str,
    moderator_display_name: str,
    moderation_type: str,
    *,
    target_user_id: Optional[str] = None,
    target_message_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Write a moderation log entry to the broadcast_moderation table."""
    ts = now_ts()
    event_id = f"mevt_{uuid4().hex[:12]}"

    log_item: Dict[str, Any] = {
        "pk": f"SESSION#{session_id}",
        "sk": f"LOG#{ts}#{event_id}",
        "event_id": event_id,
        "moderator_id": moderator_id,
        "moderator_display_name": moderator_display_name,
        "moderation_type": moderation_type,
        "ts": ts,
    }
    if target_user_id:
        log_item["target_user_id"] = target_user_id
    if target_message_id:
        log_item["target_message_id"] = target_message_id
    if details:
        log_item["details"] = details

    T.broadcast_moderation.put_item(Item=log_item)


def _get_pinned_message(session_id: str) -> Optional[Dict[str, Any]]:
    """Find the currently pinned message for a session."""
    from boto3.dynamodb.conditions import Key, Attr

    resp = T.broadcast_moderation.query(
        KeyConditionExpression=Key("pk").eq(f"SESSION#{session_id}")
        & Key("sk").begins_with("PIN#"),
        FilterExpression=Attr("pinned").eq(True),
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def _increment_actions_count(session_id: str, moderator_id: str) -> None:
    """Increment the actions_count for a moderator."""
    try:
        T.broadcast_moderation.update_item(
            Key={"pk": f"SESSION#{session_id}", "sk": f"MOD#{moderator_id}"},
            UpdateExpression="SET actions_count = if_not_exists(actions_count, :zero) + :one",
            ExpressionAttributeValues={":zero": 0, ":one": 1},
        )
    except Exception:
        pass  # Non-critical; moderator may not be registered

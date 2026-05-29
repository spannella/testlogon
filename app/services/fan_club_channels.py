"""Exclusive chat channel CRUD + messaging for fan clubs."""
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
    """Validate that a user has the required tier level for a channel."""
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
    channel_id = f"chan_{uuid.uuid4().hex[:12]}"
    now = now_ts()

    item: Dict[str, Any] = {
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


def get_channel(channel_id: str) -> Optional[Dict[str, Any]]:
    resp = T.fan_club_channels.get_item(Key={"channel_id": channel_id})
    return resp.get("Item")


def list_channels_for_user(creator_id: str, user_id: str) -> List[Dict[str, Any]]:
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
    channel = get_channel(channel_id)
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")

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

    msg_id = f"msg_{uuid.uuid4().hex[:12]}"
    now = now_ts()
    sort_key = f"{now}#{msg_id}"

    message_item: Dict[str, Any] = {
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

    _update_channel_last_message(channel_id, now, text[:100])

    return message_item


def get_channel_messages(
    channel_id: str,
    *,
    limit: int = 50,
    before_sort_key: Optional[str] = None,
) -> List[Dict[str, Any]]:
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


def delete_channel_message(channel_id: str, message_id: str, deleted_by: str) -> None:
    """Soft-delete a message. Only creator/admin can do this."""
    messages = T.fan_club_messages.query(
        KeyConditionExpression=Key("channel_id").eq(channel_id),
        ScanIndexForward=False,
        Limit=200,
    ).get("Items", [])

    for msg in messages:
        if msg.get("message_id") == message_id:
            T.fan_club_messages.update_item(
                Key={"channel_id": channel_id, "sort_key": msg["sort_key"]},
                UpdateExpression="SET deleted = :t, deleted_by = :by, deleted_at = :now",
                ExpressionAttributeValues={":t": True, ":by": deleted_by, ":now": now_ts()},
            )
            return

    raise HTTPException(status_code=404, detail="Message not found")


def add_reaction(channel_id: str, message_id: str, user_id: str, emoji: str) -> None:
    messages = T.fan_club_messages.query(
        KeyConditionExpression=Key("channel_id").eq(channel_id),
        ScanIndexForward=False,
        Limit=200,
    ).get("Items", [])

    for msg in messages:
        if msg.get("message_id") == message_id:
            reactions = msg.get("reactions") or {}
            if emoji not in reactions:
                reactions[emoji] = {}
            reactions[emoji][user_id] = True
            T.fan_club_messages.update_item(
                Key={"channel_id": channel_id, "sort_key": msg["sort_key"]},
                UpdateExpression="SET reactions = :r",
                ExpressionAttributeValues={":r": reactions},
            )
            return

    raise HTTPException(status_code=404, detail="Message not found")


def pin_message(channel_id: str, message_id: str) -> None:
    T.fan_club_channels.update_item(
        Key={"channel_id": channel_id},
        UpdateExpression="SET pinned_message_id = :mid, updated_at = :now",
        ExpressionAttributeValues={":mid": message_id, ":now": now_ts()},
    )


def _update_channel_last_message(channel_id: str, timestamp: int, preview: str) -> None:
    try:
        T.fan_club_channels.update_item(
            Key={"channel_id": channel_id},
            UpdateExpression="SET last_message_at = :ts, last_message_preview = :preview, message_count = if_not_exists(message_count, :zero) + :one, updated_at = :ts",
            ExpressionAttributeValues={":ts": timestamp, ":preview": preview, ":one": 1, ":zero": 0},
        )
    except Exception:
        logger.warning("Failed to update channel last message", extra={"channel_id": channel_id})


# Simple in-memory slowmode enforcement
_SLOWMODE_BUCKETS: Dict[str, int] = {}


def _enforce_slowmode(channel_id: str, user_id: str, slowmode_seconds: int) -> None:
    import time
    key = f"fanclub#{channel_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    limit_ms = slowmode_seconds * 1000

    last = _SLOWMODE_BUCKETS.get(key, 0)
    if now_ms - last < limit_ms:
        raise HTTPException(
            status_code=429,
            detail=f"Slowmode active. Please wait {slowmode_seconds} seconds between messages.",
        )
    _SLOWMODE_BUCKETS[key] = now_ms

"""Broadcast live chat service — DynamoDB CRUD for chat messages and mutes (BCAST-005)."""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish


# ─── Rate Limiting (in-memory) ──────────────────────────────────

_CHAT_RATE_LOCK = threading.Lock()
_CHAT_RATE_BUCKETS: Dict[str, int] = {}  # "{session_id}#{user_id}" -> last_send_ts_ms
_PRODUCT_LINK_RATE_BUCKETS: Dict[str, int] = {}  # separate bucket for product links


def _enforce_chat_rate_limit(session_id: str, user_id: str) -> None:
    """Raise 429 if user is sending faster than allowed."""
    key = f"{session_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    limit_ms = S.broadcast_chat_rate_limit_ms
    with _CHAT_RATE_LOCK:
        last = _CHAT_RATE_BUCKETS.get(key, 0)
        if now_ms - last < limit_ms:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=429,
                detail={
                    "code": "BROADCAST_CHAT_RATE_LIMITED",
                    "message": "You can send one message every 2 seconds.",
                    "retry_after_ms": limit_ms - (now_ms - last),
                },
            )
        _CHAT_RATE_BUCKETS[key] = now_ms


def _enforce_product_link_rate_limit(session_id: str, user_id: str) -> None:
    """Raise 429 if broadcaster is sharing products faster than 1 per 5 seconds."""
    key = f"{session_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    limit_ms = 5000
    with _CHAT_RATE_LOCK:
        last = _PRODUCT_LINK_RATE_BUCKETS.get(key, 0)
        if now_ms - last < limit_ms:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=429,
                detail={
                    "code": "BROADCAST_PRODUCT_LINK_RATE_LIMITED",
                    "message": "You can share one product every 5 seconds.",
                    "retry_after_ms": limit_ms - (now_ms - last),
                },
            )
        _PRODUCT_LINK_RATE_BUCKETS[key] = now_ms


def reset_rate_limits() -> None:
    """Clear all rate limit state (for tests)."""
    with _CHAT_RATE_LOCK:
        _CHAT_RATE_BUCKETS.clear()
        _PRODUCT_LINK_RATE_BUCKETS.clear()


# ─── Mute Enforcement ───────────────────────────────────────────


def get_mute_status(session_id: str, user_id: str) -> Optional[int]:
    """Return muted_until timestamp if user is currently muted, else None."""
    key = f"{session_id}#{user_id}"
    resp = T.broadcast_chat_mutes.get_item(Key={"session_user": key})
    item = resp.get("Item")
    if not item:
        return None
    muted_until = int(item.get("muted_until", 0) or 0)
    if muted_until > now_ts():
        return muted_until
    return None


def set_mute(session_id: str, user_id: str, duration_seconds: int, actor: str) -> Dict[str, Any]:
    """Mute a user in a broadcast chat session."""
    muted_until = now_ts() + duration_seconds
    item = {
        "session_user": f"{session_id}#{user_id}",
        "muted_until": muted_until,
        "muted_by": actor,
        "created_at": now_ts(),
        "session_id": session_id,
        "user_id": user_id,
    }
    T.broadcast_chat_mutes.put_item(Item=item)

    # Publish mute event via SSE
    broadcast_sse_publish(session_id, {
        "_type": "chat:mute",
        "target_user_id": user_id,
        "muted_until": muted_until,
    })

    return {
        "target_user_id": user_id,
        "muted_until": muted_until,
        "session_id": session_id,
    }


def _enforce_chat_ban(session_id: str, user_id: str) -> None:
    """Raise 403 if the viewer is banned from this broadcast session (GAP-0157).

    The per-session ban is written by ``ban_viewer`` in
    ``app/services/delegate_broadcast.py`` to ``T.broadcast_moderation`` keyed by
    ``SESSION#{session_id}`` / ``BAN#{user_id}``. It is consulted here so that a
    banned viewer cannot continue posting chat messages. The import is deferred
    to avoid a circular import (``delegate_broadcast`` imports from this module).
    """
    from app.services.delegate_broadcast import is_viewer_banned

    if is_viewer_banned(session_id, user_id):
        from fastapi import HTTPException

        raise HTTPException(
            status_code=403,
            detail={
                "code": "BROADCAST_CHAT_BANNED",
                "message": "You have been banned from this broadcast.",
            },
        )


def _enforce_chat_mute(session_id: str, user_id: str) -> None:
    """Raise 403 if user is muted."""
    muted_until = get_mute_status(session_id, user_id)
    if muted_until is not None:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=403,
            detail={
                "code": "BROADCAST_CHAT_MUTED",
                "message": "You are temporarily muted in this chat.",
                "muted_until": muted_until,
            },
        )


# ─── Message CRUD ───────────────────────────────────────────────


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
    """Send a chat message. Enforces rate limit and mute checks.

    Extended for BCAST-015:
      - reply_to_message_id: reply to a parent message (Phase B)
      - expires_in_seconds: auto-expire after N seconds (Phase C, broadcaster-only)
      - lock_price_cents: paywall price in cents (Phase D, broadcaster-only)
      - lock_description: teaser text for locked messages (Phase D)
    """
    from fastapi import HTTPException

    _enforce_chat_ban(session_id, user_id)
    _enforce_chat_mute(session_id, user_id)
    if not skip_rate_limit:
        _enforce_chat_rate_limit(session_id, user_id)

    ts = now_ts()
    ts_ms = int(time.time() * 1000)
    msg_id = "cm_" + uuid4().hex
    sort_key = f"{ts_ms:016d}#{msg_id}"

    item: Dict[str, Any] = {
        "session_id": session_id,
        "sort_key": sort_key,
        "message_id": msg_id,
        "sender_id": user_id,
        "sender_display_name": display_name,
        "text": text.strip(),
        "created_at": ts,
        "deleted": False,
        "ttl": ts + 7 * 24 * 3600,
    }

    # Phase B — Reply
    if reply_to_message_id:
        parent_sk = _find_sort_key(session_id, reply_to_message_id)
        if not parent_sk:
            raise HTTPException(status_code=400, detail="Reply target message not found")
        parent_item = T.broadcast_chat_messages.get_item(
            Key={"session_id": session_id, "sort_key": parent_sk}
        ).get("Item")
        if not parent_item or parent_item.get("deleted"):
            raise HTTPException(status_code=400, detail="Reply target message not found")
        item["reply_to_message_id"] = reply_to_message_id
        parent_text = parent_item.get("text", "")
        item["reply_to_preview"] = {
            "sender_display_name": parent_item.get("sender_display_name", ""),
            "text": parent_text[:100] if parent_text else "[Hidden content]",
        }

    # Phase C — Expiry
    if expires_in_seconds is not None:
        expires_at = ts + expires_in_seconds
        item["expires_at"] = expires_at
        # DDB TTL = min(default_ttl, expires_at + 3600)
        item["ttl"] = min(item["ttl"], expires_at + 3600)

    # Phase D — Locked messages
    if lock_price_cents is not None:
        item["lock_price_cents"] = lock_price_cents
        if lock_description:
            item["lock_description"] = lock_description
        item["unlocked_by"] = {}

    T.broadcast_chat_messages.put_item(Item=item)

    # Publish via SSE for real-time delivery
    out = _chat_msg_out(item)
    broadcast_sse_publish(session_id, {"_type": "chat:message", **out})

    return {**out, "sort_key": sort_key}


def send_product_link_message(
    session_id: str,
    user_id: str,
    display_name: str,
    product_link: Dict[str, Any],
) -> Dict[str, Any]:
    """Send a product link card into broadcast chat. Enforces separate rate limit."""
    _enforce_chat_ban(session_id, user_id)
    _enforce_chat_mute(session_id, user_id)
    _enforce_product_link_rate_limit(session_id, user_id)

    ts = now_ts()
    ts_ms = int(time.time() * 1000)
    msg_id = "cm_" + uuid4().hex
    sort_key = f"{ts_ms:016d}#{msg_id}"

    item: Dict[str, Any] = {
        "session_id": session_id,
        "sort_key": sort_key,
        "message_id": msg_id,
        "sender_id": user_id,
        "sender_display_name": display_name,
        "text": f"shared product: {product_link.get('name', '')}",
        "kind": "product_link",
        "product_link": product_link,
        "created_at": ts,
        "deleted": False,
        "ttl": ts + 7 * 24 * 3600,
    }
    T.broadcast_chat_messages.put_item(Item=item)

    out = _chat_msg_out(item)
    broadcast_sse_publish(session_id, {"_type": "chat:product_link", **out})

    return {**out, "sort_key": sort_key}


def get_chat_history(
    session_id: str,
    limit: int = 100,
    before_sort_key: Optional[str] = None,
    viewer_user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Get recent chat history in chronological order (oldest first)."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("session_id").eq(session_id),
        "Limit": limit,
        "ScanIndexForward": False,  # newest first for fetch
        # Exclude soft-deleted items and private-chat messages (GAP-0125):
        # private_chat-kind messages share this table but must never appear
        # in the public chat history.
        "FilterExpression": Attr("deleted").ne(True) & Attr("kind").ne("private_chat") & Attr("moderation_hidden").ne(True),
    }
    if before_sort_key:
        kwargs["KeyConditionExpression"] = (
            Key("session_id").eq(session_id) & Key("sort_key").lt(before_sort_key)
        )

    resp = T.broadcast_chat_messages.query(**kwargs)
    items = resp.get("Items", [])
    # Filter out LOTTERY#/LENTRY# config/entry items (BCAST-014)
    items = [i for i in items if not (i.get("sort_key", "").startswith("LOTTERY#") or i.get("sort_key", "").startswith("LENTRY#"))]
    # Reverse to chronological order for display
    items.reverse()

    messages = [_chat_msg_out(item, viewer_user_id=viewer_user_id) for item in items]
    return {
        "messages": messages,
        "has_more": bool(resp.get("LastEvaluatedKey")),
        "oldest_sort_key": items[0]["sort_key"] if items else None,
    }


def fetch_chat_messages_after(
    session_id: str,
    after_sort_key: Optional[str],
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Fetch messages after a cursor (for SSE polling). Returns chronological order."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("session_id").eq(session_id),
        "Limit": limit,
        "ScanIndexForward": True,
        # Exclude soft-deleted items and private-chat messages (GAP-0125):
        # the SSE polling path must never leak private_chat-kind messages
        # into the public chat stream.
        "FilterExpression": Attr("deleted").ne(True) & Attr("kind").ne("private_chat") & Attr("moderation_hidden").ne(True),
    }
    if after_sort_key:
        kwargs["KeyConditionExpression"] = (
            Key("session_id").eq(session_id) & Key("sort_key").gt(after_sort_key)
        )

    resp = T.broadcast_chat_messages.query(**kwargs)
    return resp.get("Items", [])


def delete_chat_message(session_id: str, message_id: str, actor_sub: str) -> bool:
    """Soft-delete a chat message. Returns True if found and deleted."""
    # Find the sort_key for this message_id
    sort_key = _find_sort_key(session_id, message_id)
    if not sort_key:
        return False

    T.broadcast_chat_messages.update_item(
        Key={"session_id": session_id, "sort_key": sort_key},
        UpdateExpression="SET deleted = :t, deleted_by = :u",
        ExpressionAttributeValues={":t": True, ":u": actor_sub},
    )

    # Publish delete event via SSE
    broadcast_sse_publish(session_id, {
        "_type": "chat:delete",
        "message_id": message_id,
    })

    return True


def _find_sort_key(session_id: str, message_id: str) -> Optional[str]:
    """Find sort_key by message_id using the MessageIdIndex GSI (O(1))."""
    resp = T.broadcast_chat_messages.query(
        IndexName="MessageIdIndex",
        KeyConditionExpression=Key("message_id").eq(message_id),
    )
    items = resp.get("Items", [])
    if not items:
        return None
    # Confirm the message belongs to the requested session (partition ownership).
    for item in items:
        if item.get("session_id") == session_id:
            return item["sort_key"]
    return None


def _chat_msg_out(item: Dict[str, Any], viewer_user_id: Optional[str] = None) -> Dict[str, Any]:
    """Convert DDB item to output dict with rich messaging fields (BCAST-015).

    When viewer_user_id is provided, applies per-viewer visibility rules:
      - Expired messages: text=None, expired=True
      - Locked messages (viewer has not unlocked): text=None, is_unlocked=False
      - Sender always sees their own content.
    """
    ts = now_ts()
    sender_id = item.get("sender_id", "")
    is_sender = viewer_user_id is not None and viewer_user_id == sender_id

    out: Dict[str, Any] = {
        "message_id": item["message_id"],
        "session_id": item["session_id"],
        "sender_id": sender_id,
        "sender_display_name": item.get("sender_display_name", ""),
        "text": item.get("text", ""),
        "kind": item.get("kind", "text"),
        "created_at": int(item.get("created_at", 0)),
        "deleted": bool(item.get("deleted", False)),
    }
    if item.get("product_link"):
        out["product_link"] = item["product_link"]
    # Tip fields (BCAST-013)
    if item.get("kind") == "tip":
        out["tip_amount_cents"] = int(item.get("tip_amount_cents", 0))
        out["tip_currency"] = item.get("tip_currency", "USD")
        out["tip_payment_id"] = item.get("tip_payment_id", "")

    # Phase A — Reactions
    reactions = item.get("reactions") or {}
    if reactions:
        counts: Dict[str, int] = {}
        mine: List[str] = []
        for emoji, user_set in reactions.items():
            count = len(user_set) if isinstance(user_set, (set, dict)) else 0
            if count > 0:
                counts[emoji] = count
            if viewer_user_id and viewer_user_id in user_set:
                mine.append(emoji)
        if counts:
            out["reactions_counts"] = counts
        if mine:
            out["my_reactions"] = mine

    # Phase B — Replies
    if item.get("reply_to_message_id"):
        out["reply_to_message_id"] = item["reply_to_message_id"]
    if item.get("reply_to_preview"):
        out["reply_to_preview"] = item["reply_to_preview"]

    # Phase C — Expiry
    expires_at = item.get("expires_at")
    if expires_at is not None:
        out["expires_at"] = int(expires_at)
        if int(expires_at) < ts and not is_sender:
            out["text"] = None
            out["expired"] = True

    # Phase D — Locked messages
    lock_price = item.get("lock_price_cents")
    if lock_price is not None:
        out["lock_price_cents"] = int(lock_price)
        out["lock_description"] = item.get("lock_description")
        unlocked_by = item.get("unlocked_by") or {}
        is_unlocked = is_sender or (viewer_user_id is not None and viewer_user_id in unlocked_by)
        out["is_unlocked"] = is_unlocked
        if not is_unlocked:
            out["text"] = None

    # Phase D — Tip totals on messages
    if item.get("tip_total_cents"):
        out["tip_total_cents"] = int(item["tip_total_cents"])

    # Lottery fields (BCAST-014)
    if item.get("lottery_id"):
        out["lottery_id"] = item["lottery_id"]

    return out

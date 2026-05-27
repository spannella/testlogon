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
) -> Dict[str, Any]:
    """Send a chat message. Enforces rate limit and mute checks."""
    _enforce_chat_mute(session_id, user_id)
    if not skip_rate_limit:
        _enforce_chat_rate_limit(session_id, user_id)

    ts = now_ts()
    ts_ms = int(time.time() * 1000)
    msg_id = "cm_" + uuid4().hex
    sort_key = f"{ts_ms:016d}#{msg_id}"

    item = {
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
) -> Dict[str, Any]:
    """Get recent chat history in chronological order (oldest first)."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("session_id").eq(session_id),
        "Limit": limit,
        "ScanIndexForward": False,  # newest first for fetch
        "FilterExpression": Attr("deleted").ne(True),
    }
    if before_sort_key:
        kwargs["KeyConditionExpression"] = (
            Key("session_id").eq(session_id) & Key("sort_key").lt(before_sort_key)
        )

    resp = T.broadcast_chat_messages.query(**kwargs)
    items = resp.get("Items", [])
    # Reverse to chronological order for display
    items.reverse()

    messages = [_chat_msg_out(item) for item in items]
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
    """Find sort_key by message_id via a filter on the partition."""
    resp = T.broadcast_chat_messages.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
        FilterExpression=Attr("message_id").eq(message_id),
        Limit=200,
        ScanIndexForward=False,
    )
    items = resp.get("Items", [])
    if items:
        return items[0]["sort_key"]
    return None


def _chat_msg_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert DDB item to output dict."""
    out: Dict[str, Any] = {
        "message_id": item["message_id"],
        "session_id": item["session_id"],
        "sender_id": item["sender_id"],
        "sender_display_name": item.get("sender_display_name", ""),
        "text": item.get("text", ""),
        "kind": item.get("kind", "text"),
        "created_at": int(item.get("created_at", 0)),
        "deleted": bool(item.get("deleted", False)),
    }
    if item.get("product_link"):
        out["product_link"] = item["product_link"]
    return out

"""Notification engine — social notification system with batching & unread badge.

Notification types: follow, like, comment, mention, tip, message, system.
Supports batching similar notifications (e.g., "3 people liked your post").

DynamoDB table: notifications_engine
  PK: user_id (str)
  SK: timestamp#notification_id (str) — reverse-chronological ordering
  TTL: ttl_epoch (int)
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr, Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import decode_cursor, encode_cursor

logger = logging.getLogger(__name__)

NOTIFICATION_TYPES = [
    "follow",
    "like",
    "comment",
    "mention",
    "tip",
    "message",
    "system",
]

_DEFAULT_TTL_DAYS = 90


def _ttl_seconds() -> int:
    days = getattr(S, "notification_ttl_days", _DEFAULT_TTL_DAYS)
    return int(days) * 86400


def _batch_window_seconds() -> int:
    return int(getattr(S, "notification_batch_window_seconds", 300))


# ---------------------------------------------------------------------------
# Send notification
# ---------------------------------------------------------------------------


def send_notification(
    *,
    user_id: str,
    notification_type: str,
    title: str,
    body: str = "",
    data: Optional[Dict[str, Any]] = None,
    batch_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Send a notification to a user.

    If batch_key is provided and a recent notification with the same batch_key
    exists within the batch window, the existing notification is updated
    (count incremented, actors list appended) instead of creating a new one.

    Returns the notification item dict.
    """
    if batch_key:
        batched = _try_batch(
            user_id=user_id,
            notification_type=notification_type,
            title=title,
            body=body,
            data=data or {},
            batch_key=batch_key,
        )
        if batched:
            return batched

    ts = now_ts()
    notification_id = uuid.uuid4().hex[:16]
    sk = f"{ts}#{notification_id}"

    actor_id = (data or {}).get("actor_id", "")
    batch_actors = [actor_id] if actor_id else []

    item: Dict[str, Any] = {
        "user_id": user_id,
        "sk": sk,
        "notification_id": notification_id,
        "notification_type": notification_type,
        "title": title,
        "body": body,
        "data": data or {},
        "read": False,
        "created_at": ts,
        "batch_key": batch_key or "",
        "batch_count": 1,
        "batch_actors": batch_actors,
        "ttl_epoch": ts + _ttl_seconds(),
    }

    T.notifications_engine.put_item(Item=item)
    logger.debug(
        "Sent notification: user=%s type=%s title=%s",
        user_id,
        notification_type,
        title,
    )
    return item


def _try_batch(
    *,
    user_id: str,
    notification_type: str,
    title: str,
    body: str,
    data: Dict[str, Any],
    batch_key: str,
) -> Optional[Dict[str, Any]]:
    """Try to batch this notification into an existing recent one.

    Scans recent notifications for a matching batch_key within the batch window.
    If found, atomically increments count and appends actor.

    Returns the updated item if batched, None otherwise.
    """
    window = _batch_window_seconds()
    cutoff = now_ts() - window

    # Query recent notifications for this user (reverse chronological)
    resp = T.notifications_engine.query(
        KeyConditionExpression=Key("user_id").eq(user_id),
        ScanIndexForward=False,
        Limit=50,
    )
    items = resp.get("Items", [])

    for item in items:
        item_ts = int(item.get("created_at", 0))
        if item_ts < cutoff:
            break  # Past the batch window
        if item.get("batch_key") == batch_key and item.get("notification_type") == notification_type:
            # Found a matching batch — update it
            actor_id = data.get("actor_id", "")
            existing_actors = list(item.get("batch_actors", []))
            if actor_id and actor_id not in existing_actors:
                existing_actors.append(actor_id)
            # Cap actors list at 10
            if len(existing_actors) > 10:
                existing_actors = existing_actors[-10:]

            new_count = int(item.get("batch_count", 1)) + 1
            ts = now_ts()

            try:
                T.notifications_engine.update_item(
                    Key={"user_id": user_id, "sk": item["sk"]},
                    UpdateExpression=(
                        "SET batch_count = :cnt, batch_actors = :actors, "
                        "title = :title, body = :body, updated_at = :now, "
                        "#read_attr = :false"
                    ),
                    ExpressionAttributeNames={"#read_attr": "read"},
                    ExpressionAttributeValues={
                        ":cnt": new_count,
                        ":actors": existing_actors,
                        ":title": title,
                        ":body": body,
                        ":now": ts,
                        ":false": False,
                    },
                )
                item["batch_count"] = new_count
                item["batch_actors"] = existing_actors
                item["title"] = title
                item["body"] = body
                item["read"] = False
                logger.debug(
                    "Batched notification: user=%s batch_key=%s count=%d",
                    user_id,
                    batch_key,
                    new_count,
                )
                return item
            except Exception:
                logger.warning(
                    "Failed to batch notification, will create new",
                    extra={"user_id": user_id, "batch_key": batch_key},
                )
                return None

    return None


# ---------------------------------------------------------------------------
# List notifications
# ---------------------------------------------------------------------------


def list_notifications(
    user_id: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 20,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Get paginated notifications for a user, reverse chronological.

    Returns (items, next_cursor) tuple.
    """
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("user_id").eq(user_id),
        "ScanIndexForward": False,
        "Limit": min(limit, 100),
    }

    eks = decode_cursor(cursor)
    if eks:
        kwargs["ExclusiveStartKey"] = eks

    resp = T.notifications_engine.query(**kwargs)
    items = resp.get("Items", [])
    last_key = resp.get("LastEvaluatedKey")
    next_cursor = encode_cursor(last_key) if last_key else None

    return items, next_cursor


# ---------------------------------------------------------------------------
# Mark read
# ---------------------------------------------------------------------------


def mark_read(user_id: str, notification_ids: List[str]) -> int:
    """Mark specific notifications as read by their IDs.

    Returns the number of notifications marked read.
    """
    if not notification_ids:
        return 0

    id_set = set(notification_ids)
    marked = 0

    # Query all unread items to find matching notification_ids
    lek: Optional[Dict[str, Any]] = None
    pages = 0

    while pages < 10:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("user_id").eq(user_id),
            "FilterExpression": Attr("read").eq(False),
            "ScanIndexForward": False,
            "Limit": 500,
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek

        resp = T.notifications_engine.query(**kwargs)
        items = resp.get("Items", [])

        for item in items:
            nid = item.get("notification_id", "")
            if nid in id_set:
                try:
                    T.notifications_engine.update_item(
                        Key={"user_id": user_id, "sk": item["sk"]},
                        UpdateExpression="SET #read_attr = :true, read_at = :now",
                        ExpressionAttributeNames={"#read_attr": "read"},
                        ExpressionAttributeValues={":true": True, ":now": now_ts()},
                    )
                    marked += 1
                except Exception:
                    logger.warning(
                        "Failed to mark notification read",
                        extra={"user_id": user_id, "notification_id": nid},
                    )
                id_set.discard(nid)
                if not id_set:
                    return marked

        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        pages += 1

    return marked


# ---------------------------------------------------------------------------
# Mark all read
# ---------------------------------------------------------------------------


def mark_all_read(user_id: str) -> int:
    """Mark all notifications as read for a user.

    Returns the number of notifications marked read.
    """
    marked = 0
    lek: Optional[Dict[str, Any]] = None
    pages = 0
    ts = now_ts()

    while pages < 10:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("user_id").eq(user_id),
            "FilterExpression": Attr("read").eq(False),
            "ScanIndexForward": False,
            "Limit": 500,
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek

        resp = T.notifications_engine.query(**kwargs)
        items = resp.get("Items", [])

        for item in items:
            try:
                T.notifications_engine.update_item(
                    Key={"user_id": user_id, "sk": item["sk"]},
                    UpdateExpression="SET #read_attr = :true, read_at = :now",
                    ExpressionAttributeNames={"#read_attr": "read"},
                    ExpressionAttributeValues={":true": True, ":now": ts},
                )
                marked += 1
            except Exception:
                logger.warning(
                    "Failed to mark notification read",
                    extra={"user_id": user_id, "sk": item.get("sk")},
                )

        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        pages += 1

    return marked


# ---------------------------------------------------------------------------
# Unread count
# ---------------------------------------------------------------------------


def get_unread_count(user_id: str, *, cap: int = 99) -> int:
    """Count unread notifications for a user, capped at `cap`.

    Uses FilterExpression with SELECT COUNT to minimize data transfer.
    """
    total = 0
    lek: Optional[Dict[str, Any]] = None

    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("user_id").eq(user_id),
            "FilterExpression": Attr("read").eq(False),
            "Select": "COUNT",
            "Limit": 500,
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek

        resp = T.notifications_engine.query(**kwargs)
        total += resp.get("Count", 0)

        if total >= cap:
            return cap

        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break

    return min(total, cap)


# ---------------------------------------------------------------------------
# Batch notifications helper
# ---------------------------------------------------------------------------


def batch_notifications(
    user_id: str,
    notification_type: str,
    items: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Create a pre-batched notification from multiple items.

    Used to consolidate similar events: e.g., "3 people liked your post".

    Each item in `items` should have: actor_id, title (optional), data (optional).

    Returns the consolidated notification item.
    """
    if not items:
        raise ValueError("items list must not be empty")

    actors = []
    for it in items:
        aid = it.get("actor_id", "")
        if aid and aid not in actors:
            actors.append(aid)

    # Build consolidated title
    count = len(items)
    first_actor = actors[0] if actors else "Someone"
    if count == 1:
        title = items[0].get("title", f"{first_actor} interacted with your content")
    elif count == 2:
        second_actor = actors[1] if len(actors) > 1 else "someone"
        title = f"{first_actor} and {second_actor} interacted with your content"
    else:
        title = f"{first_actor} and {count - 1} others interacted with your content"

    # Merge data from all items
    merged_data: Dict[str, Any] = {}
    for it in items:
        merged_data.update(it.get("data", {}))

    batch_key = f"{notification_type}:{merged_data.get('target_id', uuid.uuid4().hex[:8])}"

    ts = now_ts()
    notification_id = uuid.uuid4().hex[:16]
    sk = f"{ts}#{notification_id}"

    item: Dict[str, Any] = {
        "user_id": user_id,
        "sk": sk,
        "notification_id": notification_id,
        "notification_type": notification_type,
        "title": title,
        "body": "",
        "data": merged_data,
        "read": False,
        "created_at": ts,
        "batch_key": batch_key,
        "batch_count": count,
        "batch_actors": actors[:10],
        "ttl_epoch": ts + _ttl_seconds(),
    }

    T.notifications_engine.put_item(Item=item)
    logger.debug(
        "Created batched notification: user=%s type=%s count=%d",
        user_id,
        notification_type,
        count,
    )
    return item

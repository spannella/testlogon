"""Activity feed engine — unified activity stream for social events.

Stores activity items in a dedicated DynamoDB table with auto-expiry TTL.
Activity types: follow, like, comment, post, mention, share, tip.
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

ACTIVITY_TYPES = [
    "follow",
    "like",
    "comment",
    "post",
    "mention",
    "share",
    "tip",
    "quote_converted",
]

_TTL_DAYS = 30


def _ttl_seconds() -> int:
    days = getattr(S, "activity_feed_ttl_days", _TTL_DAYS)
    return int(days) * 86400


# ---------------------------------------------------------------------------
# Record activity
# ---------------------------------------------------------------------------


def record_activity(
    *,
    user_id: str,
    actor_id: str,
    activity_type: str,
    target_type: str = "",
    target_id: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Record an activity event in the user's activity feed.

    Parameters:
        user_id: The user whose feed receives this activity.
        actor_id: The user who performed the action.
        activity_type: One of ACTIVITY_TYPES.
        target_type: What was acted on (e.g., "post", "message", "user").
        target_id: ID of the target entity.
        metadata: Additional context (e.g., post title, tip amount).

    Returns:
        The activity item dict as stored.
    """
    ts = now_ts()
    activity_id = uuid.uuid4().hex[:16]
    # Sort key: timestamp#activity_id for reverse-chronological ordering
    sk = f"{ts}#{activity_id}"

    item: Dict[str, Any] = {
        "user_id": user_id,
        "sk": sk,
        "activity_id": activity_id,
        "actor_id": actor_id,
        "activity_type": activity_type,
        "target_type": target_type,
        "target_id": target_id,
        "metadata": metadata or {},
        "created_at": ts,
        "read": False,
        "ttl_epoch": ts + _ttl_seconds(),
    }

    T.activity_feed.put_item(Item=item)
    logger.debug(
        "Recorded activity: user=%s type=%s actor=%s",
        user_id,
        activity_type,
        actor_id,
    )
    return item


# ---------------------------------------------------------------------------
# Get activity feed
# ---------------------------------------------------------------------------


def get_activity_feed(
    user_id: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 20,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Get paginated activity feed for a user, reverse chronological.

    Returns:
        (items, next_cursor) tuple.
    """
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("user_id").eq(user_id),
        "ScanIndexForward": False,
        "Limit": min(limit, 100),
    }

    eks = decode_cursor(cursor)
    if eks:
        kwargs["ExclusiveStartKey"] = eks

    resp = T.activity_feed.query(**kwargs)
    items = resp.get("Items", [])
    last_key = resp.get("LastEvaluatedKey")
    next_cursor = encode_cursor(last_key) if last_key else None

    return items, next_cursor


# ---------------------------------------------------------------------------
# Filter by activity type
# ---------------------------------------------------------------------------


def get_activity_feed_filtered(
    user_id: str,
    *,
    activity_type: str,
    cursor: Optional[str] = None,
    limit: int = 20,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Get activity feed filtered by a specific activity type.

    Uses FilterExpression, so DDB still reads up to 1MB per page. We loop
    until we have enough items or exhaust the partition.
    """
    collected: List[Dict[str, Any]] = []
    lek: Optional[Dict[str, Any]] = decode_cursor(cursor)
    max_pages = 5

    for _ in range(max_pages):
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("user_id").eq(user_id),
            "FilterExpression": Attr("activity_type").eq(activity_type),
            "ScanIndexForward": False,
            "Limit": 200,
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek

        resp = T.activity_feed.query(**kwargs)
        collected.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")

        if len(collected) >= limit or not lek:
            break

    result = collected[:limit]
    next_cursor = encode_cursor(lek) if lek and len(collected) >= limit else None

    return result, next_cursor


# ---------------------------------------------------------------------------
# Mark activities read
# ---------------------------------------------------------------------------


def mark_activities_read(user_id: str, up_to_ts: int) -> int:
    """Mark all activities as read up to a given timestamp.

    Returns the number of activities marked read.
    """
    marked = 0
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

        resp = T.activity_feed.query(**kwargs)
        items = resp.get("Items", [])

        for item in items:
            item_ts = int(item.get("created_at", 0))
            if item_ts > up_to_ts:
                continue
            try:
                T.activity_feed.update_item(
                    Key={"user_id": item["user_id"], "sk": item["sk"]},
                    UpdateExpression="SET #read = :true, read_at = :now",
                    ExpressionAttributeNames={"#read": "read"},
                    ExpressionAttributeValues={":true": True, ":now": now_ts()},
                )
                marked += 1
            except Exception:
                logger.warning(
                    "Failed to mark activity read",
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
    """Count unread activities for a user, capped at `cap`.

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

        resp = T.activity_feed.query(**kwargs)
        total += resp.get("Count", 0)

        if total >= cap:
            return cap

        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break

    return min(total, cap)

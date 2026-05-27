"""Atomic unread alert counter using a DDB sentinel row.

The sentinel row lives in the existing ``alerts`` table with:
    PK = user_sub
    SK = "UNREAD_COUNT"
    count = <integer>
    updated_at = <unix timestamp>

All mutations use DDB atomic update expressions so they are safe
under concurrent writes (no read-modify-write race).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_SENTINEL_SK = "UNREAD_COUNT"


def increment_unread_count(user_sub: str, delta: int = 1) -> int:
    """Atomically increment the unread counter by *delta*.

    Creates the sentinel row if it does not yet exist (``if_not_exists``).
    Returns the new count after the increment.
    """
    try:
        resp = T.alerts.update_item(
            Key={"user_sub": user_sub, "alert_id": _SENTINEL_SK},
            UpdateExpression="SET #c = if_not_exists(#c, :zero) + :delta, updated_at = :now",
            ExpressionAttributeNames={"#c": "count"},
            ExpressionAttributeValues={
                ":delta": delta,
                ":zero": 0,
                ":now": now_ts(),
            },
            ReturnValues="ALL_NEW",
        )
        return int(resp.get("Attributes", {}).get("count", 0))
    except Exception:
        logger.warning("Failed to increment unread count", extra={"user_sub": user_sub})
        return 0


def get_unread_count(user_sub: str) -> int:
    """Read the current unread counter value.

    Returns 0 when the sentinel row does not exist.
    """
    try:
        resp = T.alerts.get_item(
            Key={"user_sub": user_sub, "alert_id": _SENTINEL_SK},
        )
        item = resp.get("Item")
        if not item:
            return 0
        return max(0, int(item.get("count", 0)))
    except Exception:
        logger.warning("Failed to get unread count", extra={"user_sub": user_sub})
        return 0


def reset_unread_count(user_sub: str) -> None:
    """Reset the unread counter to zero.

    Uses a SET expression (not delete) so the sentinel row persists
    and can immediately accept subsequent increments.
    """
    try:
        T.alerts.update_item(
            Key={"user_sub": user_sub, "alert_id": _SENTINEL_SK},
            UpdateExpression="SET #c = :zero, updated_at = :now",
            ExpressionAttributeNames={"#c": "count"},
            ExpressionAttributeValues={
                ":zero": 0,
                ":now": now_ts(),
            },
        )
    except Exception:
        logger.warning("Failed to reset unread count", extra={"user_sub": user_sub})


def decrement_unread_count(user_sub: str, delta: int = 1) -> int:
    """Atomically decrement the unread counter, flooring at 0.

    Uses a conditional expression to avoid going negative.
    If the counter is already 0 or the condition fails, returns 0.
    """
    try:
        resp = T.alerts.update_item(
            Key={"user_sub": user_sub, "alert_id": _SENTINEL_SK},
            UpdateExpression="SET #c = #c - :delta, updated_at = :now",
            ConditionExpression="#c >= :delta",
            ExpressionAttributeNames={"#c": "count"},
            ExpressionAttributeValues={
                ":delta": delta,
                ":now": now_ts(),
            },
            ReturnValues="ALL_NEW",
        )
        return max(0, int(resp.get("Attributes", {}).get("count", 0)))
    except Exception:
        # ConditionalCheckFailedException means count < delta; that's fine.
        return 0

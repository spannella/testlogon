"""Milestone detection and recording service (CREATOR-003).

Detects when a creator crosses a metric threshold, records the milestone in
DynamoDB (app single table), and optionally sends notifications.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.time import now_ts

logger = logging.getLogger(__name__)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")

MILESTONE_THRESHOLDS: Dict[str, List[int]] = {
    "subscribers": [10, 50, 100, 500, 1000, 5000, 10000, 50000, 100000],
    "tips_total_cents": [1000, 5000, 10000, 50000, 100000, 500000, 1000000],
    "views": [100, 1000, 10000, 100000, 1000000],
    "earnings_total_cents": [10000, 50000, 100000, 500000, 1000000, 5000000],
}


def _format_threshold(metric: str, threshold: int) -> str:
    """Return a human-readable string for a milestone threshold."""
    if metric in ("tips_total_cents", "earnings_total_cents"):
        dollars = threshold // 100
        if dollars >= 1000:
            return f"${dollars // 1000}K"
        return f"${dollars}"
    if threshold >= 1_000_000:
        return f"{threshold // 1_000_000}M"
    if threshold >= 1000:
        return f"{threshold // 1000}K"
    return str(threshold)


def _get_table():
    return ddb.Table(APP_TABLE)


def check_milestone(user_id: str, metric: str, current_value: int) -> Optional[Dict[str, Any]]:
    """Check if a milestone threshold has been crossed and record it.

    Returns the milestone dict if a NEW milestone was achieved, else None.
    Uses a ConditionExpression to prevent duplicate writes.
    """
    thresholds = MILESTONE_THRESHOLDS.get(metric, [])
    if not thresholds:
        return None

    # Find the highest threshold that current_value meets
    achieved_threshold = None
    for t in sorted(thresholds):
        if current_value >= t:
            achieved_threshold = t
        else:
            break

    if achieved_threshold is None:
        return None

    pk = f"USER#{user_id}"
    sk = f"MILESTONE#{metric}#{achieved_threshold}"
    now = now_ts()

    milestone = {
        "pk": pk,
        "sk": sk,
        "milestone_id": f"{metric}_{achieved_threshold}",
        "user_id": user_id,
        "metric": metric,
        "threshold": achieved_threshold,
        "current_value": current_value,
        "formatted": _format_threshold(metric, achieved_threshold),
        "achieved_at": now,
        "acknowledged": False,
    }

    try:
        _get_table().put_item(
            Item=milestone,
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
        logger.info("Milestone achieved: user=%s metric=%s threshold=%s", user_id, metric, achieved_threshold)
        return milestone
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Already recorded
            return None
        raise


def acknowledge_milestone(user_id: str, metric: str, threshold: int) -> bool:
    """Mark a milestone as acknowledged."""
    pk = f"USER#{user_id}"
    sk = f"MILESTONE#{metric}#{threshold}"
    try:
        _get_table().update_item(
            Key={"pk": pk, "sk": sk},
            UpdateExpression="SET acknowledged = :t",
            ExpressionAttributeValues={":t": True},
            ConditionExpression="attribute_exists(pk)",
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


def list_milestones(user_id: str, *, acknowledged: Optional[bool] = None) -> List[Dict[str, Any]]:
    """List all milestones for a user, optionally filtered by acknowledged status."""
    pk = f"USER#{user_id}"
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(pk) & Key("sk").begins_with("MILESTONE#"),
    }

    items: List[Dict[str, Any]] = []
    while True:
        resp = _get_table().query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key

    # Optional filter
    if acknowledged is not None:
        items = [i for i in items if bool(i.get("acknowledged", False)) == acknowledged]

    # Sort by achieved_at descending
    items.sort(key=lambda x: int(x.get("achieved_at", 0)), reverse=True)

    return items


def get_milestone_settings(user_id: str) -> Dict[str, Any]:
    """Get milestone notification preferences for a user."""
    pk = f"USER#{user_id}"
    sk = "MILESTONE_PREFS"
    try:
        resp = _get_table().get_item(Key={"pk": pk, "sk": sk})
        item = resp.get("Item")
        if item:
            return {
                "push_enabled": bool(item.get("push_enabled", True)),
                "email_enabled": bool(item.get("email_enabled", True)),
                "celebration_enabled": bool(item.get("celebration_enabled", True)),
            }
    except Exception:
        logger.exception("Failed to get milestone settings for %s", user_id)
    return {
        "push_enabled": True,
        "email_enabled": True,
        "celebration_enabled": True,
    }


def update_milestone_settings(user_id: str, settings: Dict[str, Any]) -> Dict[str, Any]:
    """Update milestone notification preferences for a user."""
    pk = f"USER#{user_id}"
    sk = "MILESTONE_PREFS"
    now = now_ts()

    item: Dict[str, Any] = {
        "pk": pk,
        "sk": sk,
        "updated_at": now,
    }
    for key in ("push_enabled", "email_enabled", "celebration_enabled"):
        if key in settings:
            item[key] = bool(settings[key])

    _get_table().put_item(Item=item)
    return get_milestone_settings(user_id)

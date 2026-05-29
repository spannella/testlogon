"""Achievement progress tracking and unlock logic.

ENGAGE-001: Achievements & Gamification System.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import sse_publish_alert

logger = logging.getLogger(__name__)


def _achievements_enabled() -> bool:
    return getattr(S, "achievements_enabled", False)


# ---------------------------------------------------------------------------
# Progress advance
# ---------------------------------------------------------------------------

def advance_progress(user_sub: str, metric_key: str, delta: int = 1) -> List[Dict[str, Any]]:
    """Atomically increment a user's progress counter and check for unlocks.

    Returns list of newly unlocked achievements (may be empty).
    """
    if not _achievements_enabled():
        return []

    resp = T.user_achievement_progress.update_item(
        Key={"user_sub": user_sub, "metric_key": metric_key},
        UpdateExpression=(
            "SET current_value = if_not_exists(current_value, :zero) + :delta, "
            "last_updated_at = :now, "
            "last_updated_date = :today, "
            "highest_value = if_not_exists(highest_value, :zero)"
        ),
        ExpressionAttributeValues={
            ":delta": delta,
            ":zero": 0,
            ":now": now_ts(),
            ":today": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        },
        ReturnValues="ALL_NEW",
    )
    attrs = resp["Attributes"]
    new_value = int(attrs["current_value"])

    # Update highest_value if exceeded
    highest = int(attrs.get("highest_value", 0))
    if new_value > highest:
        try:
            T.user_achievement_progress.update_item(
                Key={"user_sub": user_sub, "metric_key": metric_key},
                UpdateExpression="SET highest_value = :hv",
                ConditionExpression="highest_value < :hv OR attribute_not_exists(highest_value)",
                ExpressionAttributeValues={":hv": new_value},
            )
        except Exception:
            pass  # best-effort

    # Check thresholds
    from app.services.achievement_definitions import list_achievements_for_metric
    definitions = list_achievements_for_metric(metric_key)
    already_unlocked = _get_user_achievement_ids(user_sub)
    newly_unlocked = []

    for defn in definitions:
        ach_id = defn["achievement_id"]
        if ach_id in already_unlocked:
            continue
        threshold = int(defn["threshold"])
        if new_value >= threshold:
            unlock = _unlock_achievement(
                user_sub, defn,
                trigger_event=f"{metric_key}:{new_value}",
            )
            newly_unlocked.append(unlock)

    return newly_unlocked


# ---------------------------------------------------------------------------
# Streak handling
# ---------------------------------------------------------------------------

def update_streak(user_sub: str, metric_key: str) -> int:
    """Update a daily streak counter. Returns the new streak value."""
    if not _achievements_enabled():
        return 0

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    resp = T.user_achievement_progress.get_item(
        Key={"user_sub": user_sub, "metric_key": metric_key},
    )
    progress = resp.get("Item")

    if progress is None:
        T.user_achievement_progress.put_item(Item={
            "user_sub": user_sub,
            "metric_key": metric_key,
            "current_value": 1,
            "last_updated_at": now_ts(),
            "last_updated_date": today,
            "streak_anchor_date": today,
            "highest_value": 1,
        })
        _check_streak_unlocks(user_sub, metric_key, 1)
        return 1

    last_date = progress.get("last_updated_date", "")
    if last_date == today:
        return int(progress["current_value"])  # already counted today

    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    if last_date == yesterday:
        new_value = int(progress["current_value"]) + 1
        anchor = progress.get("streak_anchor_date", today)
    else:
        new_value = 1
        anchor = today

    highest = max(new_value, int(progress.get("highest_value", 0)))
    T.user_achievement_progress.update_item(
        Key={"user_sub": user_sub, "metric_key": metric_key},
        UpdateExpression=(
            "SET current_value = :val, "
            "last_updated_at = :now, "
            "last_updated_date = :today, "
            "streak_anchor_date = :anchor, "
            "highest_value = :highest"
        ),
        ExpressionAttributeValues={
            ":val": new_value,
            ":now": now_ts(),
            ":today": today,
            ":anchor": anchor,
            ":highest": highest,
        },
    )

    _check_streak_unlocks(user_sub, metric_key, new_value)
    return new_value


def _check_streak_unlocks(user_sub: str, metric_key: str, streak_value: int) -> None:
    from app.services.achievement_definitions import list_achievements_for_metric
    definitions = list_achievements_for_metric(metric_key)
    already_unlocked = _get_user_achievement_ids(user_sub)
    for defn in definitions:
        ach_id = defn["achievement_id"]
        if ach_id in already_unlocked:
            continue
        if streak_value >= int(defn["threshold"]):
            _unlock_achievement(user_sub, defn, trigger_event=f"{metric_key}:{streak_value}")


# ---------------------------------------------------------------------------
# Progress queries
# ---------------------------------------------------------------------------

def get_progress(user_sub: str, metric_key: str) -> Optional[Dict[str, Any]]:
    resp = T.user_achievement_progress.get_item(
        Key={"user_sub": user_sub, "metric_key": metric_key},
    )
    item = resp.get("Item")
    if not item:
        return None
    return _progress_out(item)


def list_all_progress(user_sub: str) -> List[Dict[str, Any]]:
    resp = T.user_achievement_progress.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub),
    )
    return [_progress_out(item) for item in resp.get("Items", [])]


def _progress_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "metric_key": item["metric_key"],
        "current_value": int(item.get("current_value", 0)),
        "last_updated_at": int(item.get("last_updated_at", 0)),
        "last_updated_date": item.get("last_updated_date", ""),
        "streak_anchor_date": item.get("streak_anchor_date"),
        "highest_value": int(item.get("highest_value", 0)),
    }


# ---------------------------------------------------------------------------
# User achievements queries
# ---------------------------------------------------------------------------

def _get_user_achievement_ids(user_sub: str) -> set:
    resp = T.user_achievements.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub),
        ProjectionExpression="achievement_id",
    )
    return {item["achievement_id"] for item in resp.get("Items", [])}


def get_user_achievements(user_sub: str) -> List[Dict[str, Any]]:
    resp = T.user_achievements.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub),
    )
    return [_unlock_out(item) for item in resp.get("Items", [])]


# ---------------------------------------------------------------------------
# Unlock logic
# ---------------------------------------------------------------------------

def _unlock_achievement(
    user_sub: str,
    defn: Dict[str, Any],
    trigger_event: str,
) -> Dict[str, Any]:
    ach_id = defn["achievement_id"]
    ts = now_ts()
    points = int(defn.get("points", 0))

    unlock_item: Dict[str, Any] = {
        "user_sub": user_sub,
        "achievement_id": ach_id,
        "unlocked_at": ts,
        "trigger_event": trigger_event,
        "points": points,
        "displayed": False,
        "label": defn.get("label", ""),
        "icon_url": defn.get("icon_url", ""),
        "rarity": defn.get("rarity", "common"),
    }

    try:
        T.user_achievements.put_item(
            Item=unlock_item,
            ConditionExpression="attribute_not_exists(achievement_id)",
        )
    except T.user_achievements.meta.client.exceptions.ConditionalCheckFailedException:
        existing = T.user_achievements.get_item(
            Key={"user_sub": user_sub, "achievement_id": ach_id},
        ).get("Item", {})
        return _unlock_out(existing)

    _update_leaderboard(user_sub, points)
    _emit_achievement_alert(user_sub, defn, trigger_event, ts)

    logger.info(
        "Achievement unlocked: user=%s achievement=%s trigger=%s",
        user_sub, ach_id, trigger_event,
    )
    return _unlock_out(unlock_item)


def _emit_achievement_alert(
    user_sub: str,
    defn: Dict[str, Any],
    trigger_event: str,
    ts: int,
) -> None:
    try:
        from app.services.social_alerts import _is_alert_type_enabled
        if not _is_alert_type_enabled(user_sub, "achievement_unlocked"):
            return
    except Exception:
        pass

    alert_obj = {
        "alert_id": f"ach_{uuid4().hex[:12]}",
        "event_type": "achievement_unlocked",
        "user_sub": user_sub,
        "created_at": ts,
        "data": {
            "achievement_id": defn["achievement_id"],
            "label": defn.get("label", ""),
            "description": defn.get("description", ""),
            "icon_url": defn.get("icon_url", ""),
            "rarity": defn.get("rarity", "common"),
            "points": int(defn.get("points", 0)),
            "trigger_event": trigger_event,
        },
    }

    try:
        from app.services.alerts import write_alert
        write_alert(
            user_sub,
            event="achievement_unlocked",
            outcome="success",
            title=defn.get("label", "Achievement Unlocked"),
            details=alert_obj.get("data", {}),
        )
    except Exception:
        logger.warning("Failed to write achievement alert", exc_info=True)

    sse_publish_alert(user_sub, alert_obj)


def _update_leaderboard(user_sub: str, points: int) -> None:
    now = datetime.now(timezone.utc)
    week = now.strftime("%Y-W%W")
    month = now.strftime("%Y-%m")

    for period_key in [f"weekly#{week}", f"monthly#{month}", "alltime"]:
        T.achievement_leaderboard.update_item(
            Key={"period_key": period_key, "user_sub": user_sub},
            UpdateExpression=(
                "SET total_points = if_not_exists(total_points, :zero) + :pts, "
                "achievement_count = if_not_exists(achievement_count, :zero) + :one, "
                "updated_at = :now, "
                "GSI1PK = :pk, "
                "GSI1SK = if_not_exists(GSI1SK, :zero) + :pts"
            ),
            ExpressionAttributeValues={
                ":pts": points,
                ":one": 1,
                ":zero": 0,
                ":now": now_ts(),
                ":pk": period_key,
            },
        )


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _unlock_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "achievement_id": item.get("achievement_id", ""),
        "label": item.get("label", ""),
        "description": item.get("description", ""),
        "icon_url": item.get("icon_url", ""),
        "rarity": item.get("rarity", "common"),
        "points": int(item.get("points", 0)),
        "unlocked_at": int(item.get("unlocked_at", 0)),
        "trigger_event": item.get("trigger_event", ""),
        "displayed": bool(item.get("displayed", False)),
    }

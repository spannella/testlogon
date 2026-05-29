"""Achievement badge display management.

ENGAGE-001: Achievements & Gamification System.
"""
from __future__ import annotations

from typing import Any, Dict, List

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T

MAX_DISPLAY_BADGES = 3


def set_display_badges(user_sub: str, achievement_ids: List[str]) -> List[Dict[str, Any]]:
    """Set which badges the user displays (max 3)."""
    if len(achievement_ids) > MAX_DISPLAY_BADGES:
        raise HTTPException(400, f"maximum {MAX_DISPLAY_BADGES} display badges")

    # Validate all achievements are unlocked
    for ach_id in achievement_ids:
        resp = T.user_achievements.get_item(
            Key={"user_sub": user_sub, "achievement_id": ach_id},
        )
        if not resp.get("Item"):
            raise HTTPException(400, f"achievement {ach_id} not unlocked")

    # Clear all current display flags
    current = _get_all_user_achievements(user_sub)
    for ach in current:
        if ach.get("displayed"):
            T.user_achievements.update_item(
                Key={"user_sub": user_sub, "achievement_id": ach["achievement_id"]},
                UpdateExpression="SET displayed = :f REMOVE GSI2PK, GSI2SK",
                ExpressionAttributeValues={":f": False},
            )

    # Set new display flags
    results = []
    for i, ach_id in enumerate(achievement_ids):
        T.user_achievements.update_item(
            Key={"user_sub": user_sub, "achievement_id": ach_id},
            UpdateExpression="SET displayed = :t, GSI2PK = :dpk, GSI2SK = :dsk",
            ExpressionAttributeValues={
                ":t": True,
                ":dpk": f"DISPLAY#{user_sub}",
                ":dsk": i,
            },
        )
        item = T.user_achievements.get_item(
            Key={"user_sub": user_sub, "achievement_id": ach_id},
        ).get("Item", {})
        results.append(_badge_summary(item))

    # Invalidate cache
    from app.services.achievement_badge_cache import _invalidate_badge_cache
    _invalidate_badge_cache(user_sub)

    return results


def get_display_badges(user_sub: str) -> List[Dict[str, Any]]:
    """Get badges the user has chosen to display (max 3)."""
    resp = T.user_achievements.query(
        IndexName="ByDisplay",
        KeyConditionExpression=Key("GSI2PK").eq(f"DISPLAY#{user_sub}"),
        ScanIndexForward=True,
    )
    return [_badge_summary(item) for item in resp.get("Items", [])]


def _get_all_user_achievements(user_sub: str) -> List[Dict[str, Any]]:
    resp = T.user_achievements.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub),
    )
    return resp.get("Items", [])


def _badge_summary(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "achievement_id": item.get("achievement_id", ""),
        "label": item.get("label", ""),
        "icon_url": item.get("icon_url", ""),
        "rarity": item.get("rarity", "common"),
    }

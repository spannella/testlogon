"""Achievement leaderboard queries.

ENGAGE-001: Achievements & Gamification System.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.cursor import encode_cursor, decode_cursor


def get_leaderboard(
    period: str = "weekly",
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Get ranked leaderboard for a time period."""
    period_key = _resolve_period_key(period)

    kwargs: Dict[str, Any] = {
        "IndexName": "ByPoints",
        "KeyConditionExpression": Key("GSI1PK").eq(period_key),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.achievement_leaderboard.query(**kwargs)
    items = resp.get("Items", [])

    entries = []
    for i, item in enumerate(items):
        entries.append({
            "rank": i + 1,
            "user_sub": item.get("user_sub", ""),
            "display_name": item.get("display_name", ""),
            "total_points": int(item.get("total_points", 0)),
            "achievement_count": int(item.get("achievement_count", 0)),
            "display_badges": item.get("display_badges", []),
        })

    next_cursor = None
    last_key = resp.get("LastEvaluatedKey")
    if last_key:
        next_cursor = encode_cursor(last_key)

    return entries, next_cursor


def get_my_rank(user_sub: str, period: str = "weekly") -> Dict[str, Any]:
    """Get the current user's rank and points for a period."""
    period_key = _resolve_period_key(period)

    resp = T.achievement_leaderboard.get_item(
        Key={"period_key": period_key, "user_sub": user_sub},
    )
    entry = resp.get("Item")
    if not entry:
        return {
            "rank": None,
            "user_sub": user_sub,
            "total_points": 0,
            "achievement_count": 0,
            "period": period,
        }

    user_points = int(entry.get("total_points", 0))

    count_resp = T.achievement_leaderboard.query(
        IndexName="ByPoints",
        KeyConditionExpression=(
            Key("GSI1PK").eq(period_key) &
            Key("GSI1SK").gt(user_points)
        ),
        Select="COUNT",
    )
    rank = count_resp.get("Count", 0) + 1

    return {
        "rank": rank,
        "user_sub": user_sub,
        "total_points": user_points,
        "achievement_count": int(entry.get("achievement_count", 0)),
        "display_badges": entry.get("display_badges", []),
        "period": period,
    }


def _resolve_period_key(period: str) -> str:
    now = datetime.now(timezone.utc)
    if period == "weekly":
        return f"weekly#{now.strftime('%Y-W%W')}"
    elif period == "monthly":
        return f"monthly#{now.strftime('%Y-%m')}"
    elif period == "alltime":
        return "alltime"
    else:
        return f"weekly#{now.strftime('%Y-W%W')}"

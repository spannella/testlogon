"""Achievement definition CRUD (admin-only).

ENGAGE-001: Achievements & Gamification System.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def create_definition(
    *,
    achievement_id: str,
    category: str,
    subcategory: str,
    label: str,
    description: str,
    icon_url: str,
    rarity: str,
    threshold: int,
    points: int,
    metric_key: str,
    sort_order: int = 0,
) -> Dict[str, Any]:
    """Create a new achievement definition (admin only)."""
    valid_rarities = {"common", "uncommon", "rare", "epic", "legendary"}
    if rarity not in valid_rarities:
        raise HTTPException(400, f"rarity must be one of {sorted(valid_rarities)}")

    if category not in ("creator", "viewer", "general"):
        raise HTTPException(400, "category must be creator, viewer, or general")

    if icon_url and not icon_url.startswith("/"):
        raise HTTPException(400, "icon_url must be a relative path (same-origin)")

    ts = now_ts()
    item: Dict[str, Any] = {
        "achievement_id": achievement_id,
        "category": category,
        "subcategory": subcategory,
        "label": label,
        "description": description,
        "icon_url": icon_url,
        "rarity": rarity,
        "threshold": threshold,
        "points": points,
        "metric_key": metric_key,
        "active": True,
        "sort_order": sort_order,
        "created_at": ts,
        "updated_at": ts,
        "GSI1PK": f"METRIC#{metric_key}",
        "GSI1SK": threshold,
    }

    try:
        T.achievements.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(achievement_id)",
        )
    except T.achievements.meta.client.exceptions.ConditionalCheckFailedException:
        raise HTTPException(409, f"achievement {achievement_id} already exists")

    return _definition_out(item)


def update_definition(achievement_id: str, **updates: Any) -> Dict[str, Any]:
    """Update fields on an existing achievement definition."""
    allowed_fields = {
        "label", "description", "icon_url", "rarity", "threshold",
        "points", "active", "sort_order", "subcategory",
    }
    filtered = {k: v for k, v in updates.items() if k in allowed_fields and v is not None}
    if not filtered:
        raise HTTPException(400, "no valid fields to update")

    parts = []
    vals: Dict[str, Any] = {":now": now_ts()}
    names: Dict[str, str] = {}
    for k, v in filtered.items():
        placeholder = f":v_{k}"
        name_placeholder = f"#n_{k}"
        parts.append(f"{name_placeholder} = {placeholder}")
        vals[placeholder] = v
        names[name_placeholder] = k

    parts.append("updated_at = :now")

    if "threshold" in filtered:
        parts.append("GSI1SK = :v_threshold")

    try:
        T.achievements.update_item(
            Key={"achievement_id": achievement_id},
            UpdateExpression="SET " + ", ".join(parts),
            ExpressionAttributeValues=vals,
            ExpressionAttributeNames=names,
            ConditionExpression="attribute_exists(achievement_id)",
        )
    except T.achievements.meta.client.exceptions.ConditionalCheckFailedException:
        raise HTTPException(404, "achievement not found")

    return get_definition(achievement_id)


def delete_definition(achievement_id: str) -> None:
    """Soft-delete by deactivating."""
    update_definition(achievement_id, active=False)


def get_definition(achievement_id: str) -> Dict[str, Any]:
    resp = T.achievements.get_item(Key={"achievement_id": achievement_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, "achievement not found")
    return _definition_out(item)


def list_definitions(active_only: bool = True) -> List[Dict[str, Any]]:
    """List all achievement definitions, optionally filtered to active only."""
    resp = T.achievements.scan()
    items = resp.get("Items", [])
    if active_only:
        items = [i for i in items if i.get("active", True)]
    items.sort(key=lambda i: (i.get("category", ""), int(i.get("sort_order", 0))))
    return [_definition_out(i) for i in items]


def list_achievements_for_metric(metric_key: str) -> List[Dict[str, Any]]:
    """List active achievement definitions for a given metric key."""
    resp = T.achievements.query(
        IndexName="ByMetric",
        KeyConditionExpression=Key("GSI1PK").eq(f"METRIC#{metric_key}"),
        ScanIndexForward=True,
    )
    return [
        _definition_out(item)
        for item in resp.get("Items", [])
        if item.get("active", True)
    ]


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _definition_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "achievement_id": item.get("achievement_id", ""),
        "category": item.get("category", ""),
        "subcategory": item.get("subcategory", ""),
        "label": item.get("label", ""),
        "description": item.get("description", ""),
        "icon_url": item.get("icon_url", ""),
        "rarity": item.get("rarity", "common"),
        "threshold": int(item.get("threshold", 0)),
        "points": int(item.get("points", 0)),
        "metric_key": item.get("metric_key", ""),
        "active": bool(item.get("active", True)),
        "sort_order": int(item.get("sort_order", 0)),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }

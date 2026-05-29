"""Fan club tier CRUD — stored in the subscriptions table under CREATOR#{creator_id} / TIER#{tier_id}."""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def _pk_creator(creator_id: str) -> str:
    return f"CREATOR#{creator_id}"


def _sk_tier(tier_id: str) -> str:
    return f"TIER#{tier_id}"


def create_tier(
    *,
    creator_id: str,
    plan_id: str,
    name: str,
    level: int,
    color: str,
    badge_emoji: Optional[str] = None,
    description: Optional[str] = None,
    benefits: Optional[List[Dict[str, Any]]] = None,
    welcome_message: Optional[str] = None,
    sort_order: int = 0,
) -> Dict[str, Any]:
    # Validate level uniqueness among active tiers
    existing = list_tiers(creator_id)
    for t in existing:
        if int(t.get("level", 0)) == level and t.get("active", True):
            raise HTTPException(status_code=409, detail=f"Tier level {level} already exists for this creator")

    tier_id = f"tier_{uuid.uuid4().hex[:12]}"
    now = now_ts()
    item: Dict[str, Any] = {
        "pk": _pk_creator(creator_id),
        "sk": _sk_tier(tier_id),
        "tier_id": tier_id,
        "creator_id": creator_id,
        "plan_id": plan_id,
        "name": name,
        "level": level,
        "color": color,
        "badge_emoji": badge_emoji,
        "badge_image_url": None,
        "description": description,
        "benefits": benefits or [],
        "welcome_message": welcome_message,
        "member_count": 0,
        "sort_order": sort_order,
        "active": True,
        "created_at": now,
        "updated_at": now,
    }
    T.subscriptions.put_item(Item=item)
    return item


def list_tiers(creator_id: str) -> List[Dict[str, Any]]:
    try:
        resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(_pk_creator(creator_id))
            & Key("sk").begins_with("TIER#"),
        )
    except Exception:
        return []
    items = resp.get("Items", [])
    items.sort(key=lambda t: int(t.get("level", 0)))
    return items


def get_tier(creator_id: str, tier_id: str) -> Optional[Dict[str, Any]]:
    try:
        resp = T.subscriptions.get_item(
            Key={"pk": _pk_creator(creator_id), "sk": _sk_tier(tier_id)}
        )
        return resp.get("Item")
    except Exception:
        return None


def update_tier(creator_id: str, tier_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    tier = get_tier(creator_id, tier_id)
    if not tier:
        raise HTTPException(status_code=404, detail="Tier not found")

    allowed = {"name", "color", "badge_emoji", "description", "benefits", "welcome_message", "sort_order", "active"}
    for k, v in updates.items():
        if k in allowed and v is not None:
            tier[k] = v

    tier["updated_at"] = now_ts()
    T.subscriptions.put_item(Item=tier)
    return tier


def delete_tier(creator_id: str, tier_id: str) -> None:
    """Soft-delete: set active=False."""
    tier = get_tier(creator_id, tier_id)
    if not tier:
        raise HTTPException(status_code=404, detail="Tier not found")
    tier["active"] = False
    tier["updated_at"] = now_ts()
    T.subscriptions.put_item(Item=tier)


def reorder_tiers(creator_id: str, tier_ids: List[str]) -> List[Dict[str, Any]]:
    for idx, tid in enumerate(tier_ids):
        tier = get_tier(creator_id, tid)
        if tier:
            tier["sort_order"] = idx
            tier["updated_at"] = now_ts()
            T.subscriptions.put_item(Item=tier)
    return list_tiers(creator_id)


def get_tier_members(creator_id: str, tier_id: str, limit: int = 50, cursor: Optional[str] = None) -> Dict[str, Any]:
    """List subscribers on a specific tier by scanning subscriptions."""
    tier = get_tier(creator_id, tier_id)
    if not tier:
        raise HTTPException(status_code=404, detail="Tier not found")

    plan_id = tier.get("plan_id")

    # Scan all subscribers to this creator and filter by plan_id
    # In production this would use a GSI; for dev we scan
    try:
        resp = T.subscriptions.scan(
            FilterExpression="creator_id = :cid AND plan_id = :pid AND begins_with(sk, :sub_prefix)",
            ExpressionAttributeValues={
                ":cid": creator_id,
                ":pid": plan_id,
                ":sub_prefix": "SUB#",
            },
            Limit=limit,
        )
    except Exception:
        return {"members": [], "next_cursor": None}

    members = []
    for item in resp.get("Items", []):
        status = (item.get("status") or "").lower()
        if status not in {"active", "past_due", "trialing"}:
            continue
        members.append({
            "user_id": item.get("subscriber_id"),
            "subscribed_at": int(item.get("created_at", 0)),
            "tier_name": tier["name"],
            "tier_level": int(tier["level"]),
            "total_spent_cents": int(item.get("total_paid_cents", 0)),
        })

    return {"members": members, "next_cursor": None}


def increment_tier_member_count(creator_id: str, tier_id: str, delta: int = 1) -> None:
    try:
        T.subscriptions.update_item(
            Key={"pk": _pk_creator(creator_id), "sk": _sk_tier(tier_id)},
            UpdateExpression="SET member_count = if_not_exists(member_count, :zero) + :delta, updated_at = :now",
            ExpressionAttributeValues={":delta": delta, ":zero": 0, ":now": now_ts()},
        )
    except Exception:
        logger.warning("Failed to update tier member count", extra={"tier_id": tier_id, "delta": delta})

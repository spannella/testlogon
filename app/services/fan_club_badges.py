"""Badge resolution with in-memory cache (60s TTL)."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# In-memory cache: {f"{user_id}#{creator_id}": (badge_data, expires_at)}
_BADGE_CACHE: Dict[str, tuple] = {}
_BADGE_CACHE_TTL_SECONDS = 60


def resolve_member_badge(user_id: str, creator_id: str) -> Optional[Dict[str, Any]]:
    """Resolve the highest-tier badge for a user within a creator's fan club."""
    cache_key = f"{user_id}#{creator_id}"
    now = now_ts()

    cached = _BADGE_CACHE.get(cache_key)
    if cached and cached[1] > now:
        return cached[0]

    sub = _get_active_subscription(user_id, creator_id)
    if not sub:
        _BADGE_CACHE[cache_key] = (None, now + _BADGE_CACHE_TTL_SECONDS)
        return None

    tier = _get_tier_by_plan(creator_id, sub["plan_id"])
    if not tier or not tier.get("active"):
        _BADGE_CACHE[cache_key] = (None, now + _BADGE_CACHE_TTL_SECONDS)
        return None

    badge: Dict[str, Any] = {
        "tier_name": tier["name"],
        "tier_level": int(tier["level"]),
        "badge_emoji": tier.get("badge_emoji"),
        "badge_color": tier.get("color"),
        "badge_image_url": tier.get("badge_image_url"),
    }
    _BADGE_CACHE[cache_key] = (badge, now + _BADGE_CACHE_TTL_SECONDS)
    return badge


def _get_active_subscription(user_id: str, creator_id: str) -> Optional[Dict[str, Any]]:
    """Return the active subscription whose tier has the highest level."""
    try:
        resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(f"SUBSCRIBER#{user_id}")
            & Key("sk").begins_with("SUB#"),
        )
    except Exception:
        return None

    active_subs: list = []
    for item in resp.get("Items", []):
        if item.get("creator_id") != creator_id:
            continue
        status = (item.get("status") or "").lower()
        if status in {"active", "past_due", "trialing"}:
            active_subs.append(item)

    if not active_subs:
        return None
    if len(active_subs) == 1:
        return active_subs[0]

    # Multiple active subs — pick the one whose tier has the highest level
    best_sub = active_subs[0]
    best_level = -1
    for sub in active_subs:
        tier = _get_tier_by_plan(creator_id, sub["plan_id"])
        level = int(tier.get("level", 0)) if tier and tier.get("active") else 0
        if level > best_level:
            best_level = level
            best_sub = sub
    return best_sub


def _get_tier_by_plan(creator_id: str, plan_id: str) -> Optional[Dict[str, Any]]:
    try:
        resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(f"CREATOR#{creator_id}")
            & Key("sk").begins_with("TIER#"),
        )
    except Exception:
        return None

    for item in resp.get("Items", []):
        if item.get("plan_id") == plan_id:
            return item
    return None


def get_subscriber_tier_level(subscriber_id: str, creator_id: str) -> Optional[int]:
    badge = resolve_member_badge(subscriber_id, creator_id)
    if badge:
        return badge["tier_level"]
    return None


def get_creator_tiers(creator_id: str) -> List[Dict[str, Any]]:
    try:
        resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(f"CREATOR#{creator_id}")
            & Key("sk").begins_with("TIER#"),
        )
    except Exception:
        return []

    tiers = [item for item in resp.get("Items", []) if item.get("active", True)]
    tiers.sort(key=lambda t: int(t.get("level", 0)))
    return tiers


def invalidate_badge_cache(user_id: str, creator_id: str) -> None:
    cache_key = f"{user_id}#{creator_id}"
    _BADGE_CACHE.pop(cache_key, None)

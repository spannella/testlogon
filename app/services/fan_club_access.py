"""Early access content gating for fan club tiers."""
from __future__ import annotations

from typing import Any, Dict

from app.core.time import now_ts
from app.services.fan_club_badges import get_subscriber_tier_level
from app.services.subscription_access import can_access_creator


def can_view_content(user_id: str, creator_id: str, content: Dict[str, Any]) -> bool:
    """Check if user can view content considering early access.

    1. Creator can always see their own content
    2. If no early_access_tier_level, use standard subscription check
    3. If past general_release_at, use standard subscription check
    4. Before general release: require tier level >= early_access_tier_level
    """
    if user_id == creator_id:
        return True

    early_access = content.get("early_access_tier_level")
    if not early_access:
        return can_access_creator(user_id, creator_id)

    general_release = content.get("general_release_at", 0)
    if now_ts() >= general_release:
        return can_access_creator(user_id, creator_id)

    tier_level = get_subscriber_tier_level(user_id, creator_id)
    return tier_level is not None and tier_level >= early_access


def compute_general_release_at(publish_at: int, delay_hours: int) -> int:
    return publish_at + (delay_hours * 3600)


def get_early_access_status(
    user_id: str,
    creator_id: str,
    content: Dict[str, Any],
) -> Dict[str, Any]:
    early_access = content.get("early_access_tier_level")
    if not early_access:
        return {"can_view": can_access_creator(user_id, creator_id), "is_early_access": False}

    general_release = content.get("general_release_at", 0)
    now = now_ts()
    tier_level = get_subscriber_tier_level(user_id, creator_id)
    can_view = (
        user_id == creator_id
        or now >= general_release
        or (tier_level is not None and tier_level >= early_access)
    )

    return {
        "can_view": can_view,
        "is_early_access": True,
        "user_tier_level": tier_level,
        "required_tier_level": early_access,
        "general_release_at": general_release,
        "time_until_release_seconds": max(0, general_release - now) if now < general_release else 0,
    }

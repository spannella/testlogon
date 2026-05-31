"""Ad Targeting service (ADS-003).

Handles targeting set CRUD, audience estimation, and targeting evaluation.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.models import TargetingCreateIn

logger = logging.getLogger(__name__)


def create_targeting(campaign_id: str, account_id: str, data: TargetingCreateIn) -> Dict[str, Any]:
    """Create a new targeting set for a campaign."""
    target_set_id = f"tgt_{uuid.uuid4().hex[:12]}"
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": f"CAMP#{campaign_id}",
        "sk": f"TARGETING#{target_set_id}",
        "target_set_id": target_set_id,
        "campaign_id": campaign_id,
        "account_id": account_id,
        "name": data.name,
        "new_user_only": data.new_user_only,
        "created_at": ts,
        "updated_at": ts,
    }
    # Add optional fields only if provided
    for field in (
        "age_ranges", "genders", "country_codes", "regions", "cities",
        "content_categories", "active_hours", "device_types",
        "creator_ids", "content_types", "exclude_creator_ids", "exclude_categories",
    ):
        val = getattr(data, field)
        if val is not None:
            item[field] = val

    T.ad_targeting.put_item(Item=item)
    return item


def get_targeting(campaign_id: str, target_set_id: str) -> Optional[Dict[str, Any]]:
    """Get a single targeting set by campaign + target_set_id."""
    resp = T.ad_targeting.get_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"TARGETING#{target_set_id}"}
    )
    return resp.get("Item")


def list_targeting_sets(campaign_id: str) -> List[Dict[str, Any]]:
    """List all targeting sets for a campaign."""
    resp = T.ad_targeting.query(
        KeyConditionExpression=Key("pk").eq(f"CAMP#{campaign_id}") & Key("sk").begins_with("TARGETING#"),
    )
    return resp.get("Items", [])


def update_targeting(campaign_id: str, target_set_id: str, data: TargetingCreateIn) -> Optional[Dict[str, Any]]:
    """Replace targeting set with new values."""
    existing = get_targeting(campaign_id, target_set_id)
    if not existing:
        return None
    updated = {**existing, "updated_at": now_ts()}
    # Apply all fields from the input
    for field in (
        "name", "age_ranges", "genders", "country_codes", "regions", "cities",
        "content_categories", "active_hours", "device_types", "new_user_only",
        "creator_ids", "content_types", "exclude_creator_ids", "exclude_categories",
    ):
        val = getattr(data, field, None)
        if val is not None:
            updated[field] = val
        elif field != "new_user_only" and field != "name":
            # Allow clearing optional list fields by setting them explicitly
            updated.pop(field, None)

    # Filter None values to avoid DynamoDB errors
    clean = {k: v for k, v in updated.items() if v is not None}
    T.ad_targeting.put_item(Item=clean)
    return updated


def delete_targeting(campaign_id: str, target_set_id: str) -> Dict[str, Any]:
    """Delete a targeting set."""
    T.ad_targeting.delete_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"TARGETING#{target_set_id}"}
    )
    return {"ok": True}


def estimate_audience(targeting: TargetingCreateIn) -> Dict[str, Any]:
    """Estimate audience size based on targeting dimensions (mock implementation).

    In dev mode, returns a deterministic count based on targeting breadth.
    Each restriction reduces the base audience proportionally.
    """
    base = 100_000
    multiplier = 1.0
    if targeting.country_codes:
        multiplier *= min(1.0, len(targeting.country_codes) * 0.15)
    if targeting.age_ranges:
        multiplier *= min(1.0, len(targeting.age_ranges) * 0.2)
    if targeting.genders:
        multiplier *= min(1.0, len(targeting.genders) * 0.4)
    if targeting.device_types:
        multiplier *= min(1.0, len(targeting.device_types) * 0.4)
    if targeting.content_categories:
        multiplier *= min(1.0, len(targeting.content_categories) * 0.1)
    if targeting.creator_ids:
        multiplier *= min(1.0, len(targeting.creator_ids) * 0.01)
    estimated = int(base * multiplier)
    return {
        "estimated_reach": max(100, estimated),
        "targeting_summary": targeting.model_dump(exclude_none=True),
    }


def evaluate_targeting(targeting: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """Evaluate whether an ad request context matches a targeting set.

    context keys: user_age, user_gender, user_country, device_type,
                  content_type, creator_id, content_categories, user_created_at, hour_utc
    """
    # Age range check
    if targeting.get("age_ranges"):
        user_age = context.get("user_age")
        if user_age is not None and not _age_in_ranges(user_age, targeting["age_ranges"]):
            return False
    # Gender check
    if targeting.get("genders"):
        if context.get("user_gender") and context["user_gender"] not in targeting["genders"]:
            return False
    # Country check
    if targeting.get("country_codes"):
        if context.get("user_country") and context["user_country"] not in targeting["country_codes"]:
            return False
    # Device type check
    if targeting.get("device_types"):
        if context.get("device_type") and context["device_type"] not in targeting["device_types"]:
            return False
    # Content type check
    if targeting.get("content_types"):
        if context.get("content_type") and context["content_type"] not in targeting["content_types"]:
            return False
    # Creator targeting
    if targeting.get("creator_ids"):
        if context.get("creator_id") and context["creator_id"] not in targeting["creator_ids"]:
            return False
    # Creator exclusions
    if targeting.get("exclude_creator_ids"):
        if context.get("creator_id") and context["creator_id"] in targeting["exclude_creator_ids"]:
            return False
    # Category exclusions
    if targeting.get("exclude_categories"):
        content_cats = set(context.get("content_categories", []))
        if content_cats & set(targeting["exclude_categories"]):
            return False
    # New user check
    if targeting.get("new_user_only"):
        created_at = context.get("user_created_at", 0)
        if now_ts() - created_at > 30 * 86400:  # > 30 days old
            return False
    return True


def _age_in_ranges(age: int, ranges: List[str]) -> bool:
    """Check if an age falls within any of the given age range strings."""
    for r in ranges:
        if r == "55+":
            if age >= 55:
                return True
        elif "-" in r:
            lo, hi = r.split("-")
            if int(lo) <= age <= int(hi):
                return True
    return False

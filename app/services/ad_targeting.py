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
    resp = T.ad_targeting.get_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"TARGETING#{target_set_id}"}
    )
    return resp.get("Item")


def list_targeting_sets(campaign_id: str) -> List[Dict[str, Any]]:
    resp = T.ad_targeting.query(
        KeyConditionExpression=Key("pk").eq(f"CAMP#{campaign_id}") & Key("sk").begins_with("TARGETING#"),
    )
    return resp.get("Items", [])


def update_targeting(campaign_id: str, target_set_id: str, data: TargetingCreateIn) -> Optional[Dict[str, Any]]:
    existing = get_targeting(campaign_id, target_set_id)
    if not existing:
        return None
    updated = {**existing, "updated_at": now_ts()}
    for field in (
        "name", "age_ranges", "genders", "country_codes", "regions", "cities",
        "content_categories", "active_hours", "device_types", "new_user_only",
        "creator_ids", "content_types", "exclude_creator_ids", "exclude_categories",
    ):
        val = getattr(data, field, None)
        if val is not None:
            updated[field] = val
        elif field != "new_user_only" and field != "name":
            updated.pop(field, None)

    clean = {k: v for k, v in updated.items() if v is not None}
    T.ad_targeting.put_item(Item=clean)
    return updated


def delete_targeting(campaign_id: str, target_set_id: str) -> Dict[str, Any]:
    T.ad_targeting.delete_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"TARGETING#{target_set_id}"}
    )
    return {"ok": True}


def evaluate_targeting(targeting: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """Evaluate whether an ad request context matches a targeting set."""
    if targeting.get("age_ranges"):
        user_age = context.get("user_age")
        if user_age is not None and not _age_in_ranges(user_age, targeting["age_ranges"]):
            return False
    if targeting.get("genders"):
        if context.get("user_gender") and context["user_gender"] not in targeting["genders"]:
            return False
    if targeting.get("country_codes"):
        if context.get("user_country") and context["user_country"] not in targeting["country_codes"]:
            return False
    if targeting.get("device_types"):
        if context.get("device_type") and context["device_type"] not in targeting["device_types"]:
            return False
    if targeting.get("content_types"):
        if context.get("content_type") and context["content_type"] not in targeting["content_types"]:
            return False
    if targeting.get("creator_ids"):
        if context.get("creator_id") and context["creator_id"] not in targeting["creator_ids"]:
            return False
    if targeting.get("exclude_creator_ids"):
        if context.get("creator_id") and context["creator_id"] in targeting["exclude_creator_ids"]:
            return False
    if targeting.get("exclude_categories"):
        content_cats = set(context.get("content_categories", []))
        if content_cats & set(targeting["exclude_categories"]):
            return False
    if targeting.get("new_user_only"):
        created_at = context.get("user_created_at", 0)
        if now_ts() - created_at > 30 * 86400:
            return False
    return True


def _age_in_ranges(age: int, ranges: List[str]) -> bool:
    for r in ranges:
        if r == "55+":
            if age >= 55:
                return True
        elif "-" in r:
            lo, hi = r.split("-")
            if int(lo) <= age <= int(hi):
                return True
    return False

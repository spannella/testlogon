"""Creator Ad Preferences service (ADS-003).

Manages creator ad settings and advertiser block lists.
Uses the billing table with per-user keys.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.models import CreatorAdSettingsIn

logger = logging.getLogger(__name__)


def get_creator_ad_settings(creator_sub: str) -> Dict[str, Any]:
    """Get ad settings for a creator. Returns defaults if none set."""
    resp = T.billing.get_item(
        Key={"pk": f"USER#{creator_sub}", "sk": "AD_SETTINGS"}
    )
    item = resp.get("Item")
    if not item:
        return {
            "allow_ads": True,
            "allowed_ad_categories": [],
            "min_cpm_cents": 0,
        }
    return {
        "allow_ads": item.get("allow_ads", True),
        "allowed_ad_categories": item.get("allowed_ad_categories", []),
        "min_cpm_cents": int(item.get("min_cpm_cents", 0)),
        "updated_at": item.get("updated_at"),
    }


def update_creator_ad_settings(creator_sub: str, data: CreatorAdSettingsIn) -> Dict[str, Any]:
    updates: Dict[str, Any] = {}
    if data.allow_ads is not None:
        updates["allow_ads"] = data.allow_ads
    if data.allowed_ad_categories is not None:
        updates["allowed_ad_categories"] = data.allowed_ad_categories
    if data.min_cpm_cents is not None:
        updates["min_cpm_cents"] = data.min_cpm_cents
    updates["updated_at"] = now_ts()

    existing = T.billing.get_item(
        Key={"pk": f"USER#{creator_sub}", "sk": "AD_SETTINGS"}
    ).get("Item", {})

    merged = {**existing, **updates}
    merged["pk"] = f"USER#{creator_sub}"
    merged["sk"] = "AD_SETTINGS"

    T.billing.put_item(Item=merged)
    return {"ok": True}


def block_advertiser(creator_sub: str, account_id: str, reason: str = "") -> Dict[str, Any]:
    T.billing.put_item(Item={
        "pk": f"USER#{creator_sub}",
        "sk": f"AD_BLOCK#{account_id}",
        "account_id": account_id,
        "blocked_at": now_ts(),
        "reason": reason,
    })
    return {"ok": True}


def unblock_advertiser(creator_sub: str, account_id: str) -> Dict[str, Any]:
    T.billing.delete_item(
        Key={"pk": f"USER#{creator_sub}", "sk": f"AD_BLOCK#{account_id}"}
    )
    return {"ok": True}


def list_blocked_advertisers(creator_sub: str) -> List[Dict[str, Any]]:
    resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq(f"USER#{creator_sub}") & Key("sk").begins_with("AD_BLOCK#"),
    )
    return resp.get("Items", [])


def is_advertiser_blocked(creator_sub: str, account_id: str) -> bool:
    resp = T.billing.get_item(
        Key={"pk": f"USER#{creator_sub}", "sk": f"AD_BLOCK#{account_id}"}
    )
    return resp.get("Item") is not None

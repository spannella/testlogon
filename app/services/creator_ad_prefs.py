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
    """Update ad settings for a creator using atomic UpdateExpression (no read-then-write race)."""
    set_parts: List[str] = []
    expr_names: Dict[str, str] = {}
    expr_values: Dict[str, Any] = {}

    field_map = {
        "allow_ads": data.allow_ads,
        "allowed_ad_categories": data.allowed_ad_categories,
        "min_cpm_cents": data.min_cpm_cents,
    }
    for idx, (field, value) in enumerate(field_map.items()):
        if value is None:
            continue
        name_alias = f"#f{idx}"
        val_alias = f":v{idx}"
        expr_names[name_alias] = field
        expr_values[val_alias] = value
        set_parts.append(f"{name_alias} = {val_alias}")

    if not set_parts:
        return {"ok": True}  # Nothing to update; avoid empty UpdateExpression error

    # Always stamp updated_at
    expr_names["#ua"] = "updated_at"
    expr_values[":ua"] = now_ts()
    set_parts.append("#ua = :ua")

    T.billing.update_item(
        Key={"pk": f"USER#{creator_sub}", "sk": "AD_SETTINGS"},
        UpdateExpression="SET " + ", ".join(set_parts),
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
    )
    return {"ok": True}


def block_advertiser(creator_sub: str, account_id: str, reason: str = "") -> Dict[str, Any]:
    """Block an advertiser from showing ads on creator's content."""
    T.billing.put_item(Item={
        "pk": f"USER#{creator_sub}",
        "sk": f"AD_BLOCK#{account_id}",
        "account_id": account_id,
        "blocked_at": now_ts(),
        "reason": reason,
    })
    return {"ok": True}


def unblock_advertiser(creator_sub: str, account_id: str) -> Dict[str, Any]:
    """Remove an advertiser from the block list."""
    T.billing.delete_item(
        Key={"pk": f"USER#{creator_sub}", "sk": f"AD_BLOCK#{account_id}"}
    )
    return {"ok": True}


def list_blocked_advertisers(creator_sub: str) -> List[Dict[str, Any]]:
    """List all blocked advertisers for a creator."""
    resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq(f"USER#{creator_sub}") & Key("sk").begins_with("AD_BLOCK#"),
    )
    return resp.get("Items", [])


def is_advertiser_blocked(creator_sub: str, account_id: str) -> bool:
    """Check if an advertiser is blocked by a creator."""
    resp = T.billing.get_item(
        Key={"pk": f"USER#{creator_sub}", "sk": f"AD_BLOCK#{account_id}"}
    )
    return resp.get("Item") is not None

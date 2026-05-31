"""Ad creative CRUD and review workflow (ADS-002)."""
from __future__ import annotations

import logging
import uuid
from typing import Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.models import CreativeCreateIn, CreativeUpdateIn

logger = logging.getLogger(__name__)


# ── CRUD ─────────────────────────────────────────────────────────────


def create_creative(campaign_id: str, account_id: str, data: CreativeCreateIn) -> dict:
    """Create a new creative in draft status."""
    creative_id = f"cr_{uuid.uuid4().hex[:12]}"
    ts = now_ts()
    item = {
        "pk": f"CAMP#{campaign_id}",
        "sk": f"CREATIVE#{creative_id}",
        "creative_id": creative_id,
        "campaign_id": campaign_id,
        "account_id": account_id,
        "format": data.format,
        "title": data.title,
        "status": "draft",
        "rotation_weight": data.rotation_weight,
        "skip_after_seconds": data.skip_after_seconds if data.skip_after_seconds is not None else 5,
        "created_at": ts,
        "updated_at": ts,
    }
    for field_name in (
        "headline", "body_text", "cta_text", "cta_url", "alt_text",
        "width", "height", "duration_seconds",
        "promo_code_id", "affiliate_link_id",
    ):
        val = getattr(data, field_name, None)
        if val is not None:
            item[field_name] = val

    T.ad_creatives.put_item(Item=item)
    return item


def get_creative(campaign_id: str, creative_id: str) -> Optional[dict]:
    resp = T.ad_creatives.get_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"CREATIVE#{creative_id}"}
    )
    return resp.get("Item")


def get_creative_by_id(creative_id: str) -> Optional[dict]:
    resp = T.ad_creatives.query(
        IndexName="ByCreativeId",
        KeyConditionExpression=Key("creative_id").eq(creative_id),
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def list_creatives(campaign_id: str) -> list[dict]:
    resp = T.ad_creatives.query(
        KeyConditionExpression=Key("pk").eq(f"CAMP#{campaign_id}") & Key("sk").begins_with("CREATIVE#"),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


def update_creative(campaign_id: str, creative_id: str, data: CreativeUpdateIn) -> dict:
    updates = {k: v for k, v in data.model_dump(exclude_none=True).items()}
    if not updates:
        return {"ok": True}
    updates["updated_at"] = now_ts()

    expr_parts: list[str] = []
    attr_values: dict = {}
    attr_names: dict = {}
    for i, (k, v) in enumerate(updates.items()):
        alias = f"#f{i}"
        val_alias = f":v{i}"
        attr_names[alias] = k
        attr_values[val_alias] = v
        expr_parts.append(f"{alias} = {val_alias}")

    T.ad_creatives.update_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"CREATIVE#{creative_id}"},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeNames=attr_names,
        ExpressionAttributeValues=attr_values,
    )
    return {"ok": True}


def delete_creative(campaign_id: str, creative_id: str) -> dict:
    T.ad_creatives.delete_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"CREATIVE#{creative_id}"}
    )
    return {"ok": True}


def submit_creative_for_review(campaign_id: str, creative_id: str) -> dict:
    T.ad_creatives.update_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"CREATIVE#{creative_id}"},
        UpdateExpression="SET #s = :s, updated_at = :u",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "pending_review", ":u": now_ts()},
        ConditionExpression="#s = :draft",
    )
    return {"ok": True}


def list_creatives_by_status(status: str) -> list[dict]:
    resp = T.ad_creatives.query(
        IndexName="ByStatus",
        KeyConditionExpression=Key("status").eq(status),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


def review_creative(
    creative_id: str, reviewer_sub: str, decision: str, notes: str = ""
) -> Optional[dict]:
    item = get_creative_by_id(creative_id)
    if not item:
        return None
    new_status = "approved" if decision == "approve" else "rejected"
    T.ad_creatives.update_item(
        Key={"pk": item["pk"], "sk": item["sk"]},
        UpdateExpression="SET #s = :s, reviewed_by = :r, review_notes = :n, updated_at = :u",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": new_status,
            ":r": reviewer_sub,
            ":n": notes,
            ":u": now_ts(),
        },
    )
    return {"ok": True, "status": new_status}


def list_approved_creatives(campaign_id: str) -> list[dict]:
    """List only approved creatives for a campaign (used by ad serving)."""
    all_cr = list_creatives(campaign_id)
    return [c for c in all_cr if c.get("status") == "approved"]

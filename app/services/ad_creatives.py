"""Ad creative CRUD, asset upload, review workflow (ADS-002)."""
from __future__ import annotations

import logging
import uuid
from typing import Optional

from boto3.dynamodb.conditions import Key

from app.core.aws_clients import s3_client
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import CreativeCreateIn, CreativeUpdateIn

logger = logging.getLogger(__name__)

UPLOAD_BUCKET = S.filemgr_bucket or "local-uploads"
_s3 = None


def _get_s3():
    global _s3
    if _s3 is None:
        _s3 = s3_client()
    return _s3


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
    # Add optional fields only if set
    for field_name in (
        "headline", "body_text", "cta_text", "cta_url", "alt_text",
        "width", "height", "duration_seconds",
        "promo_code_id", "affiliate_link_id",
    ):
        val = getattr(data, field_name, None)
        if val is not None:
            item[field_name] = val

    if getattr(data, "ctas", None):
        item["ctas"] = [c.model_dump() for c in data.ctas]
    T.ad_creatives.put_item(Item=item)
    logger.info("creative_created creative_id=%s campaign_id=%s format=%s", creative_id, campaign_id, data.format)
    return item


def get_creative(campaign_id: str, creative_id: str) -> Optional[dict]:
    resp = T.ad_creatives.get_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"CREATIVE#{creative_id}"}
    )
    return resp.get("Item")


def get_creative_by_id(creative_id: str) -> Optional[dict]:
    """Lookup a creative by creative_id via GSI (without knowing campaign)."""
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


# ── Asset upload ─────────────────────────────────────────────────────


def upload_creative_asset(
    creative_id: str,
    campaign_id: str,
    file_data: bytes,
    content_type: str,
    asset_type: str,
) -> str:
    """Upload image/video/thumbnail to S3, update creative record with URL."""
    ext = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp",
        "video/mp4": ".mp4",
    }.get(content_type, "")
    key = f"ads/creatives/{creative_id}/{asset_type}{ext}"

    _get_s3().put_object(
        Bucket=UPLOAD_BUCKET,
        Key=key,
        Body=file_data,
        ContentType=content_type,
    )

    url = f"/mock/s3/{UPLOAD_BUCKET}/{key}" if S.dev_mode else f"https://{UPLOAD_BUCKET}.s3.amazonaws.com/{key}"

    # Determine which URL field to update
    url_field = {
        "image": "image_url",
        "video": "video_url",
        "thumbnail": "thumbnail_url",
    }.get(asset_type, "image_url")

    T.ad_creatives.update_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"CREATIVE#{creative_id}"},
        UpdateExpression=f"SET {url_field} = :u, updated_at = :t",
        ExpressionAttributeValues={":u": url, ":t": now_ts()},
    )
    logger.info(
        "creative_asset_uploaded creative_id=%s asset_type=%s content_type=%s size_bytes=%d",
        creative_id, asset_type, content_type, len(file_data),
    )
    return url


# ── Review workflow ──────────────────────────────────────────────────


def submit_creative_for_review(campaign_id: str, creative_id: str) -> dict:
    """Transition creative from draft to pending_review."""
    T.ad_creatives.update_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"CREATIVE#{creative_id}"},
        UpdateExpression="SET #s = :s, updated_at = :u",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "pending_review", ":u": now_ts(), ":draft": "draft"},
        ConditionExpression="#s = :draft",
    )
    logger.info("creative_submitted creative_id=%s campaign_id=%s", creative_id, campaign_id)
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
    """Admin review: approve or reject a creative (looks up by creative_id GSI)."""
    item = get_creative_by_id(creative_id)
    if not item:
        logger.warning("creative_review_not_found creative_id=%s reviewer_sub=%s", creative_id, reviewer_sub)
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
    logger.info(
        "creative_reviewed creative_id=%s decision=%s reviewer_sub=%s notes=%s",
        creative_id, decision, reviewer_sub, notes,
    )
    return {"ok": True, "status": new_status}


def list_approved_creatives(campaign_id: str) -> list[dict]:
    """List only approved creatives for a campaign (used by ad serving)."""
    all_cr = list_creatives(campaign_id)
    return [c for c in all_cr if c.get("status") == "approved"]

"""Tracking codes — visit + order attribution (MKT-010)."""
from __future__ import annotations

import secrets
from typing import Optional

from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import TrackingCodeCreateIn


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_enabled() -> None:
    if not S.marketing_campaigns_enabled:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=403,
            detail={"code": "marketing_campaigns_disabled",
                    "message": "Marketing campaigns module is not enabled."},
        )


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def create_tracking_code(owner_id: str, data: TrackingCodeCreateIn) -> dict:
    """Create a tracking code META row. Duplicate slugs → HTTP 409."""
    _require_enabled()

    ts = now_ts()
    meta: dict = {
        "pk": f"TRACK#{data.code_slug}",
        "sk": "META",
        "code_slug": data.code_slug,
        "campaign_id": data.campaign_id,
        "owner_id": owner_id,
        "visit_count": 0,
        "order_count": 0,
        "created_at": ts,
        "updated_at": ts,
    }

    try:
        T.tracking_codes.put_item(
            Item=meta,
            ConditionExpression="attribute_not_exists(pk)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Check if same campaign_id → idempotent
            existing = get_tracking_code(data.code_slug)
            if existing and existing.get("campaign_id") == data.campaign_id:
                return existing
            # Different campaign owns this slug → 409
            from fastapi import HTTPException
            raise HTTPException(
                status_code=409,
                detail={"code": "slug_conflict",
                        "message": f"Tracking code slug '{data.code_slug}' is already in use."},
            )
        raise

    try:
        from app.services.alerts import audit_event
        audit_event("marketing.tracking_code.created", owner_id,
                    code_slug=data.code_slug, campaign_id=data.campaign_id)
    except Exception:
        pass

    return meta


def get_tracking_code(code_slug: str) -> Optional[dict]:
    """Return the META row for a tracking code or None."""
    resp = T.tracking_codes.get_item(
        Key={"pk": f"TRACK#{code_slug}", "sk": "META"}
    )
    return resp.get("Item")


def list_tracking_codes_for_campaign(campaign_id: str) -> list[dict]:
    """Return all tracking code META rows for a campaign via ByCampaignCreatedAt GSI."""
    resp = T.tracking_codes.query(
        IndexName="ByCampaignCreatedAt",
        KeyConditionExpression=Key("campaign_id").eq(campaign_id),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


# ---------------------------------------------------------------------------
# Visit recording
# ---------------------------------------------------------------------------


def record_visit(
    code_slug: str,
    party_id: Optional[str] = None,
    referrer: Optional[str] = None,
) -> None:
    """Append a VISIT row and increment visit_count on META. Anonymous if party_id=None."""
    ts = now_ts()
    nonce = secrets.token_hex(4)
    sk = f"VISIT#{ts:010d}#{nonce}"

    visit_row: dict = {
        "pk": f"TRACK#{code_slug}",
        "sk": sk,
        "ts": ts,
        "party_id": party_id or "anon",
    }
    if referrer:
        visit_row["referrer"] = referrer

    T.tracking_codes.put_item(Item=visit_row)

    # Increment denormalized counter on META
    try:
        T.tracking_codes.update_item(
            Key={"pk": f"TRACK#{code_slug}", "sk": "META"},
            UpdateExpression=(
                "SET visit_count = if_not_exists(visit_count, :zero) + :one, "
                "updated_at = :ts"
            ),
            ExpressionAttributeValues={":zero": 0, ":one": 1, ":ts": ts},
        )
    except Exception:
        pass  # META row may not exist yet; ignore


# ---------------------------------------------------------------------------
# Order recording
# ---------------------------------------------------------------------------


def record_order(code_slug: str, order_id: str, campaign_id: str) -> None:
    """Append an ORDER row idempotently. Second call for same order_id is a no-op."""
    ts = now_ts()

    order_row: dict = {
        "pk": f"TRACK#{code_slug}",
        "sk": f"ORDER#{order_id}",
        "order_id": order_id,
        "campaign_id": campaign_id,
        "attributed_at": ts,
        "ts": ts,
    }

    try:
        T.tracking_codes.put_item(
            Item=order_row,
            ConditionExpression="attribute_not_exists(sk)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return  # Already recorded — idempotent
        raise

    # Increment order_count on META
    try:
        T.tracking_codes.update_item(
            Key={"pk": f"TRACK#{code_slug}", "sk": "META"},
            UpdateExpression=(
                "SET order_count = if_not_exists(order_count, :zero) + :one, "
                "updated_at = :ts"
            ),
            ExpressionAttributeValues={":zero": 0, ":one": 1, ":ts": ts},
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Promo redemption linkage
# ---------------------------------------------------------------------------


def link_promo_redemption(
    code_slug: str, promo_code_id: str, user_id: str
) -> None:
    """
    Record the linkage between a promo redemption and a tracking code.
    Writes to tracking_codes only — T.promo_codes is untouched.
    """
    ts = now_ts()
    T.tracking_codes.put_item(
        Item={
            "pk": f"TRACK#{code_slug}",
            "sk": f"PROMO#{promo_code_id}#{user_id}#{ts}",
            "promo_code_id": promo_code_id,
            "user_id": user_id,
            "linked_at": ts,
            "ts": ts,
        }
    )

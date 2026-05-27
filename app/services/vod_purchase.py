"""VOD pay-per-view purchase service (MON-001 + MON-005).

Handles entitlement checks, video purchases, purchase history,
and subscription-gated VOD access.
"""

from __future__ import annotations

import logging
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import new_ledger_entry, user_pk
from app.services.subscription_access import has_active_subscription

if TYPE_CHECKING:
    from app.models_video import VideoMetadataModel

logger = logging.getLogger(__name__)


# ─── MON-005: VodAccessResult ─────────────────────────────────────────────────


class VodAccessResult:
    """Result of a VOD access check (MON-005).

    Encapsulates the full entitlement decision for a single video+viewer pair.
    Used by the video detail endpoint and list endpoints.

    Fields:
        entitled: Whether the viewer can watch right now.
        reason: Why they can (or cannot) watch.
            "owner" | "free" | "purchased" | "subscription" | "none"
        subscription_available: True if subscribing would grant access.
        purchase_available: True if individual purchase is an option.
        price_cents: The video's price, if purchase is available.
        subscription_upsell: True for subscriber_free videos when viewer
            is NOT subscribed — frontend shows both purchase and subscribe.
    """

    def __init__(
        self,
        *,
        entitled: bool,
        reason: str,
        subscription_available: bool = False,
        purchase_available: bool = False,
        price_cents: Optional[int] = None,
        subscription_upsell: bool = False,
    ):
        self.entitled = entitled
        self.reason = reason
        self.subscription_available = subscription_available
        self.purchase_available = purchase_available
        self.price_cents = price_cents
        self.subscription_upsell = subscription_upsell

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict for inclusion in API response."""
        return {
            "entitled": self.entitled,
            "access_reason": self.reason,
            "subscription_available": self.subscription_available,
            "purchase_available": self.purchase_available,
            "price_cents": self.price_cents,
            "subscription_upsell": self.subscription_upsell,
        }


def check_vod_access(
    *,
    user_id: str,
    video_id: str,
    video: "VideoMetadataModel",
) -> VodAccessResult:
    """Comprehensive VOD access check with entitlement cascade (MON-005).

    Check order:
    1. Owner -> always entitled
    2. Free video -> entitled
    3. Explicit purchase -> entitled
    4. Active subscription + compatible access_mode -> entitled
    5. Not entitled -> determine available options
    """
    creator_id = video.owner_user_id
    access_mode = video.access_mode or "free"
    price = video.price_cents or 0

    # 1. Owner check
    if user_id == creator_id:
        return VodAccessResult(entitled=True, reason="owner")

    # 2. Free video check
    if price == 0 or access_mode == "free":
        return VodAccessResult(entitled=True, reason="free")

    # 3. Explicit purchase check (skips subscription-source records)
    if check_entitlement_purchase_only(user_id=user_id, video_id=video_id):
        return VodAccessResult(entitled=True, reason="purchased")

    # 4. Subscription check (only for subscription-compatible access modes)
    if access_mode in ("subscriber_only", "subscriber_free"):
        has_sub = has_active_subscription(subscriber_id=user_id, creator_id=creator_id)
        if has_sub:
            # Write audit record (best-effort, won't overwrite paid purchases)
            _record_subscription_access(
                user_id=user_id,
                video_id=video_id,
                creator_id=creator_id,
            )
            return VodAccessResult(entitled=True, reason="subscription")

    # 5. Not entitled — determine options
    if access_mode == "subscriber_only":
        return VodAccessResult(
            entitled=False,
            reason="none",
            subscription_available=True,
            purchase_available=False,
            price_cents=None,
        )
    elif access_mode == "ppv":
        return VodAccessResult(
            entitled=False,
            reason="none",
            subscription_available=False,
            purchase_available=True,
            price_cents=price,
        )
    elif access_mode == "subscriber_free":
        return VodAccessResult(
            entitled=False,
            reason="none",
            subscription_available=True,
            purchase_available=True,
            price_cents=price,
            subscription_upsell=True,
        )

    # Fallback: treat as ppv
    return VodAccessResult(
        entitled=False,
        reason="none",
        purchase_available=True,
        price_cents=price,
    )


def _record_subscription_access(
    *,
    user_id: str,
    video_id: str,
    creator_id: str,
) -> None:
    """Write a subscription-based entitlement record for audit trail.

    Uses ConditionExpression to never overwrite a paid purchase record.
    """
    try:
        ts = now_ts()
        T.vod_entitlements.put_item(
            Item={
                "pk": f"USER#{user_id}",
                "sk": f"VIDEO#{video_id}",
                "video_id": video_id,
                "buyer_id": user_id,
                "seller_id": creator_id,
                "grant_type": "subscription",
                "amount_cents": 0,
                "currency": "USD",
                "created_at": ts,
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
    except Exception:
        pass  # Ignore — audit optimization, not critical


def _batch_check_entitlements(*, user_id: str, video_ids: List[str]) -> set:
    """Batch check multiple video entitlements via DDB batch_get_item.

    Returns set of video IDs that the user has purchase entitlements for.
    Subscription-source records are excluded (need live subscription check).
    Max 100 keys per batch (DDB limit).
    """
    if not video_ids:
        return set()

    pk = f"USER#{user_id}"
    keys = [{"pk": pk, "sk": f"VIDEO#{vid}"} for vid in video_ids[:100]]

    try:
        resp = T.vod_entitlements.meta.client.batch_get_item(
            RequestItems={
                T.vod_entitlements.table_name: {
                    "Keys": keys,
                    "ProjectionExpression": "sk, grant_type",
                }
            }
        )
        items = resp.get("Responses", {}).get(T.vod_entitlements.table_name, [])
        # Exclude subscription-source records — they need live subscription check
        return {
            item["sk"].replace("VIDEO#", "")
            for item in items
            if item.get("grant_type") != "subscription"
        }
    except Exception:
        return set()


def check_entitlement_purchase_only(*, user_id: str, video_id: str) -> bool:
    """Check for a PURCHASE entitlement (not subscription-based).

    Subscription records are skipped — subscription access is checked
    separately via has_active_subscription() in check_vod_access().
    """
    pk = f"USER#{user_id}"
    sk = f"VIDEO#{video_id}"
    resp = T.vod_entitlements.get_item(Key={"pk": pk, "sk": sk})
    item = resp.get("Item")
    if not item:
        return False
    # Subscription records need live subscription check, not trusted here
    if item.get("grant_type") == "subscription":
        return False
    return True


def check_entitlement(user_id: str, video_id: str) -> Dict[str, Any]:
    """Check if a user has access to a video.

    Returns {"entitled": bool, "reason": str, "entitlement": dict|None}

    Note: This returns True for ALL entitlement types including subscription
    records. For purchase-only checks, use check_entitlement_purchase_only().
    """
    pk = f"USER#{user_id}"
    sk = f"VIDEO#{video_id}"
    resp = T.vod_entitlements.get_item(Key={"pk": pk, "sk": sk})
    item = resp.get("Item")
    if item:
        return {
            "entitled": True,
            "reason": item.get("grant_type", "purchase"),
            "entitlement": {
                "video_id": video_id,
                "granted_at": int(item.get("created_at", 0)),
                "grant_type": item.get("grant_type", "purchase"),
                "amount_cents": int(item.get("amount_cents", 0)),
            },
        }
    return {"entitled": False, "reason": "not_purchased", "entitlement": None}


def purchase_video(
    *,
    buyer_id: str,
    video_id: str,
    price_cents: int,
    seller_id: str,
    payment_method_id: Optional[str] = None,
    idempotency_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Purchase a video. Returns the entitlement record.

    Writes:
    - Entitlement record (USER#{buyer}  VIDEO#{video_id})
    - Debit ledger entry for buyer
    - Credit ledger entry for seller
    - Increments purchase_count and revenue_cents on video metadata
    """
    pk = f"USER#{buyer_id}"
    sk = f"VIDEO#{video_id}"

    # Check idempotency — already purchased?
    existing = T.vod_entitlements.get_item(Key={"pk": pk, "sk": sk}).get("Item")
    if existing:
        return {
            "video_id": video_id,
            "already_owned": True,
            "granted_at": int(existing.get("created_at", 0)),
            "grant_type": existing.get("grant_type", "purchase"),
            "amount_cents": int(existing.get("amount_cents", 0)),
            "purchase_id": existing.get("purchase_id", ""),
        }

    ts = now_ts()
    purchase_id = f"vpurch_{uuid.uuid4().hex}"

    # Write entitlement
    entitlement_item: Dict[str, Any] = {
        "pk": pk,
        "sk": sk,
        "video_id": video_id,
        "buyer_id": buyer_id,
        "seller_id": seller_id,
        "purchase_id": purchase_id,
        "amount_cents": price_cents,
        "currency": "USD",
        "grant_type": "purchase",
        "created_at": ts,
    }
    if payment_method_id:
        entitlement_item["payment_method_id"] = payment_method_id
    if idempotency_key:
        entitlement_item["idempotency_key"] = idempotency_key

    T.vod_entitlements.put_item(Item=entitlement_item)

    # Debit buyer
    try:
        _sk, debit_item = new_ledger_entry(
            key_name="pk",
            key_value=user_pk(buyer_id),
            entry_type="vod_purchase_debit",
            amount_cents=price_cents,
            state="settled",
            reason="VOD purchase",
            meta={
                "video_id": video_id,
                "seller_id": seller_id,
                "purchase_id": purchase_id,
                "payment_method_id": payment_method_id or "",
            },
        )
        T.billing.put_item(Item=debit_item)
    except Exception:
        logger.exception("Failed to write buyer debit ledger for %s", purchase_id)

    # Credit seller
    try:
        _sk, credit_item = new_ledger_entry(
            key_name="pk",
            key_value=user_pk(seller_id),
            entry_type="vod_purchase_credit",
            amount_cents=price_cents,
            state="settled",
            reason="VOD sale",
            meta={
                "video_id": video_id,
                "buyer_id": buyer_id,
                "purchase_id": purchase_id,
            },
        )
        T.billing.put_item(Item=credit_item)
    except Exception:
        logger.exception("Failed to write seller credit ledger for %s", purchase_id)

    # Increment purchase stats on video
    try:
        T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression="SET purchase_count = if_not_exists(purchase_count, :z) + :one, "
            "revenue_cents = if_not_exists(revenue_cents, :z) + :price",
            ExpressionAttributeValues={
                ":z": 0,
                ":one": 1,
                ":price": price_cents,
            },
        )
    except Exception:
        logger.exception("Failed to update purchase stats for video %s", video_id)

    return {
        "video_id": video_id,
        "already_owned": False,
        "granted_at": ts,
        "grant_type": "purchase",
        "amount_cents": price_cents,
        "purchase_id": purchase_id,
    }


def list_purchases(user_id: str, *, limit: int = 50) -> List[Dict[str, Any]]:
    """List all video purchases for a user."""
    pk = f"USER#{user_id}"
    resp = T.vod_entitlements.query(
        KeyConditionExpression=Key("pk").eq(pk) & Key("sk").begins_with("VIDEO#"),
        ScanIndexForward=False,
        Limit=limit,
    )
    items = resp.get("Items", [])
    return [
        {
            "video_id": item["video_id"],
            "granted_at": int(item.get("created_at", 0)),
            "grant_type": item.get("grant_type", "purchase"),
            "amount_cents": int(item.get("amount_cents", 0)),
            "purchase_id": item.get("purchase_id", ""),
        }
        for item in items
    ]


def grant_entitlement(
    *,
    user_id: str,
    video_id: str,
    grant_type: str = "subscription",
    seller_id: str = "",
) -> Dict[str, Any]:
    """Grant free entitlement (e.g., subscription access, promo)."""
    pk = f"USER#{user_id}"
    sk = f"VIDEO#{video_id}"

    existing = T.vod_entitlements.get_item(Key={"pk": pk, "sk": sk}).get("Item")
    if existing:
        return {
            "video_id": video_id,
            "already_owned": True,
            "granted_at": int(existing.get("created_at", 0)),
            "grant_type": existing.get("grant_type", ""),
        }

    ts = now_ts()
    T.vod_entitlements.put_item(
        Item={
            "pk": pk,
            "sk": sk,
            "video_id": video_id,
            "buyer_id": user_id,
            "seller_id": seller_id,
            "grant_type": grant_type,
            "amount_cents": 0,
            "currency": "USD",
            "created_at": ts,
        }
    )
    return {
        "video_id": video_id,
        "already_owned": False,
        "granted_at": ts,
        "grant_type": grant_type,
    }

"""VOD pay-per-view purchase service (MON-001 + MON-005 + VOD-019).

Handles entitlement checks, video purchases, purchase history,
subscription-gated VOD access, and purchase tier lifecycle
(view-once, rental, permanent, download).
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


# ─── VOD-019: EntitlementStatus ───────────────────────────────────────────────


class EntitlementStatus:
    """Rich entitlement check result (VOD-019).

    Extends the simple boolean check with purchase type details
    so the frontend can display rental countdown, view-once badge,
    or download button.
    """

    def __init__(
        self,
        *,
        entitled: bool,
        purchase_type: str = "permanent",
        views_remaining: int = -1,
        expires_at: int = 0,
        download_allowed: bool = False,
        reason: str = "valid",
    ):
        self.entitled = entitled
        self.purchase_type = purchase_type
        self.views_remaining = views_remaining
        self.expires_at = expires_at
        self.download_allowed = download_allowed
        self.reason = reason


# ─── MON-005: VodAccessResult ─────────────────────────────────────────────────


class VodAccessResult:
    """Result of a VOD access check (MON-005 + VOD-019).

    Encapsulates the full entitlement decision for a single video+viewer pair.
    Used by the video detail endpoint and list endpoints.

    Fields:
        entitled: Whether the viewer can watch right now.
        reason: Why they can (or cannot) watch.
            "owner" | "free" | "purchased" | "subscription" | "none"
            | "consumed" | "expired"  (VOD-019)
        subscription_available: True if subscribing would grant access.
        purchase_available: True if individual purchase is an option.
        price_cents: The video's price, if purchase is available.
        subscription_upsell: True for subscriber_free videos when viewer
            is NOT subscribed — frontend shows both purchase and subscribe.
        purchase_type: "permanent" | "view_once" | "rental" | "download" (VOD-019)
        views_remaining: -1 = unlimited, 0 = consumed, 1+ = remaining (VOD-019)
        expires_at: 0 = no expiry, >0 = Unix timestamp (VOD-019)
        download_allowed: True if download entitlement exists (VOD-019)
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
        # VOD-019 fields
        purchase_type: str = "permanent",
        views_remaining: int = -1,
        expires_at: int = 0,
        download_allowed: bool = False,
        # VOD-018: ad-supported tier
        ads_enabled: bool = False,
    ):
        self.entitled = entitled
        self.reason = reason
        self.subscription_available = subscription_available
        self.purchase_available = purchase_available
        self.price_cents = price_cents
        self.subscription_upsell = subscription_upsell
        self.purchase_type = purchase_type
        self.views_remaining = views_remaining
        self.expires_at = expires_at
        self.download_allowed = download_allowed
        self.ads_enabled = ads_enabled

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict for inclusion in API response."""
        d: Dict[str, Any] = {
            "entitled": self.entitled,
            "access_reason": self.reason,
            "subscription_available": self.subscription_available,
            "purchase_available": self.purchase_available,
            "price_cents": self.price_cents,
            "subscription_upsell": self.subscription_upsell,
            "purchase_type": self.purchase_type,
            "views_remaining": self.views_remaining,
            "download_allowed": self.download_allowed,
            "ads_enabled": self.ads_enabled,
        }
        if self.expires_at > 0:
            d["expires_at"] = self.expires_at
        return d


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

    # 1.5 Ad-supported check (VOD-018) — inserted BEFORE free check
    # so that ad_supported videos with price_cents=0 don't get caught
    # by the free check (which would bypass ad insertion).
    if access_mode == "ad_supported":
        ads_enabled = True
        if getattr(video, "ads_free_for_subscribers", False):
            has_sub = has_active_subscription(
                subscriber_id=user_id, creator_id=creator_id
            )
            if has_sub:
                ads_enabled = False
        return VodAccessResult(
            entitled=True,
            reason="ad",
            ads_enabled=ads_enabled,
        )

    # 2. Free video check
    if price == 0 or access_mode == "free":
        return VodAccessResult(entitled=True, reason="free")

    # 3. Explicit purchase check (skips subscription-source records) — VOD-019 enriched
    ent_status = check_entitlement_purchase_only(user_id=user_id, video_id=video_id)
    if ent_status.entitled:
        return VodAccessResult(
            entitled=True,
            reason="purchased",
            purchase_type=ent_status.purchase_type,
            views_remaining=ent_status.views_remaining,
            expires_at=ent_status.expires_at,
            download_allowed=ent_status.download_allowed,
        )

    # If entitlement exists but is consumed/expired, preserve the reason (VOD-019)
    consumed_reason = ent_status.reason if ent_status.reason in ("consumed", "expired") else None

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
    # VOD-019: Use consumed/expired reason if applicable
    base_reason = consumed_reason or "none"

    if access_mode == "subscriber_only":
        return VodAccessResult(
            entitled=False,
            reason=base_reason,
            subscription_available=True,
            purchase_available=False,
            price_cents=None,
        )
    elif access_mode == "ppv":
        return VodAccessResult(
            entitled=False,
            reason=base_reason,
            subscription_available=False,
            purchase_available=True,
            price_cents=price,
        )
    elif access_mode == "subscriber_free":
        return VodAccessResult(
            entitled=False,
            reason=base_reason,
            subscription_available=True,
            purchase_available=True,
            price_cents=price,
            subscription_upsell=True,
        )

    # Fallback: treat as ppv
    return VodAccessResult(
        entitled=False,
        reason=base_reason,
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
    VOD-019: Consumed view-once and expired rental entitlements are excluded.
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
                    "ProjectionExpression": "sk, grant_type, purchase_type, views_remaining, expires_at",
                }
            }
        )
        items = resp.get("Responses", {}).get(T.vod_entitlements.table_name, [])
        ts = now_ts()
        result: set = set()
        for item in items:
            # Exclude subscription-source records — they need live subscription check
            if item.get("grant_type") == "subscription":
                continue
            # VOD-019: Exclude consumed view-once entitlements
            pt = item.get("purchase_type", "permanent")
            vr = int(item.get("views_remaining", -1))
            if pt == "view_once" and vr == 0:
                continue
            # VOD-019: Exclude expired rental entitlements
            exp = int(item.get("expires_at", 0))
            if pt == "rental" and exp > 0 and exp < ts:
                continue
            result.add(item["sk"].replace("VIDEO#", ""))
        return result
    except Exception:
        return set()


def check_entitlement_purchase_only(*, user_id: str, video_id: str) -> EntitlementStatus:
    """Check for a PURCHASE entitlement with VOD-019 validations.

    Returns EntitlementStatus with:
    - entitled=True if purchase exists AND is still valid (not consumed, not expired)
    - entitled=False if no purchase, consumed (view_once), or expired (rental)
    - Subscription records are skipped (checked separately by check_vod_access).

    Backward compatible: Records without purchase_type/views_remaining/expires_at
    are treated as permanent (unlimited, no expiry).
    """
    pk = f"USER#{user_id}"
    sk = f"VIDEO#{video_id}"
    resp = T.vod_entitlements.get_item(Key={"pk": pk, "sk": sk})
    item = resp.get("Item")

    if not item:
        return EntitlementStatus(entitled=False, reason="not_purchased")

    # Subscription records need live subscription check, not trusted here
    if item.get("grant_type") == "subscription":
        return EntitlementStatus(entitled=False, reason="not_purchased")

    purchase_type = item.get("purchase_type", "permanent")
    views_remaining = int(item.get("views_remaining", -1))
    expires_at = int(item.get("expires_at", 0))
    download_allowed = bool(item.get("download_allowed", False))

    # Check view-once consumption
    if purchase_type == "view_once" and views_remaining == 0:
        return EntitlementStatus(
            entitled=False,
            purchase_type="view_once",
            views_remaining=0,
            reason="consumed",
        )

    # Check rental expiry
    if purchase_type == "rental" and expires_at > 0 and expires_at < now_ts():
        return EntitlementStatus(
            entitled=False,
            purchase_type="rental",
            expires_at=expires_at,
            reason="expired",
        )

    return EntitlementStatus(
        entitled=True,
        purchase_type=purchase_type,
        views_remaining=views_remaining,
        expires_at=expires_at,
        download_allowed=download_allowed,
        reason="valid",
    )


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
    purchase_type: str = "permanent",
    rental_duration_hours: int = 48,
) -> Dict[str, Any]:
    """Purchase a video with purchase type support (VOD-019).

    Purchase types:
    - "permanent": unlimited views, no expiry (default, backward compatible)
    - "view_once": views_remaining=1, no expiry
    - "rental": unlimited views, expires_at = now + rental_hours
    - "download": unlimited views, no expiry, download_allowed=True

    Writes:
    - Entitlement record (USER#{buyer}  VIDEO#{video_id})
    - Debit ledger entry for buyer
    - Credit ledger entry for seller
    - Increments purchase_count and revenue_cents on video metadata
    """
    pk = f"USER#{buyer_id}"
    sk = f"VIDEO#{video_id}"

    # Check idempotency — already purchased?
    # VOD-019: Allow re-purchase if entitlement is consumed (view_once) or expired (rental)
    existing = T.vod_entitlements.get_item(Key={"pk": pk, "sk": sk}).get("Item")
    if existing:
        existing_type = existing.get("purchase_type", "permanent")
        views = int(existing.get("views_remaining", -1))
        exp = int(existing.get("expires_at", 0))

        allow_repurchase = False
        if existing_type == "view_once" and views == 0:
            allow_repurchase = True  # Consumed view-once
        elif existing_type == "rental" and exp > 0 and exp < now_ts():
            allow_repurchase = True  # Expired rental

        if not allow_repurchase:
            return {
                "video_id": video_id,
                "already_owned": True,
                "granted_at": int(existing.get("created_at", 0)),
                "grant_type": existing.get("grant_type", "purchase"),
                "amount_cents": int(existing.get("amount_cents", 0)),
                "purchase_id": existing.get("purchase_id", ""),
                "purchase_type": existing_type,
                "views_remaining": views,
                "expires_at": exp if exp > 0 else None,
                "download_allowed": bool(existing.get("download_allowed", False)),
            }

    ts = now_ts()
    purchase_id = f"vpurch_{uuid.uuid4().hex}"

    # VOD-019: Compute entitlement fields based on purchase type
    views_remaining = -1  # unlimited by default
    expires_at = 0  # no expiry by default
    download_allowed = False

    if purchase_type == "view_once":
        views_remaining = 1
    elif purchase_type == "rental":
        expires_at = ts + (rental_duration_hours * 3600)
    elif purchase_type == "download":
        download_allowed = True

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
        # VOD-019 fields
        "purchase_type": purchase_type,
        "views_remaining": views_remaining,
        "expires_at": expires_at,
        "download_allowed": download_allowed,
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
                "content_id": video_id,
                "content_type": "vod",
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
        # VOD-019 fields
        "purchase_type": purchase_type,
        "views_remaining": views_remaining,
        "expires_at": expires_at if expires_at > 0 else None,
        "download_allowed": download_allowed,
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
    result = []
    for item in items:
        exp = int(item.get("expires_at", 0))
        entry: Dict[str, Any] = {
            "video_id": item["video_id"],
            "granted_at": int(item.get("created_at", 0)),
            "grant_type": item.get("grant_type", "purchase"),
            "amount_cents": int(item.get("amount_cents", 0)),
            "purchase_id": item.get("purchase_id", ""),
            # VOD-019 fields
            "purchase_type": item.get("purchase_type", "permanent"),
            "views_remaining": int(item.get("views_remaining", -1)),
            "expires_at": exp if exp > 0 else None,
            "download_allowed": bool(item.get("download_allowed", False)),
        }
        result.append(entry)
    return result


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


# ─── VOD-019: Playback Complete ──────────────────────────────────────────────


def record_playback_complete(*, user_id: str, video_id: str) -> Dict[str, Any]:
    """Record that a viewer has completed playback (VOD-019).

    For view_once purchases: atomically decrements views_remaining to 0.
    For other purchase types: no-op (returned for analytics).

    Returns {"ok": True, "views_remaining": int, "purchase_type": str}
    """
    pk = f"USER#{user_id}"
    sk = f"VIDEO#{video_id}"

    resp = T.vod_entitlements.get_item(Key={"pk": pk, "sk": sk})
    item = resp.get("Item")

    if not item:
        return {"ok": False, "error": "no_entitlement"}

    purchase_type = item.get("purchase_type", "permanent")
    views_remaining = int(item.get("views_remaining", -1))

    if purchase_type == "view_once" and views_remaining > 0:
        # Atomically consume the view with ConditionExpression
        try:
            T.vod_entitlements.update_item(
                Key={"pk": pk, "sk": sk},
                UpdateExpression="SET views_remaining = :zero, consumed_at = :ca",
                ConditionExpression="views_remaining > :zero_check",
                ExpressionAttributeValues={
                    ":zero": 0,
                    ":ca": now_ts(),
                    ":zero_check": 0,
                },
            )
            return {"ok": True, "views_remaining": 0, "purchase_type": "view_once"}
        except Exception:
            # ConditionalCheckFailedException = already consumed (race condition)
            return {"ok": True, "views_remaining": 0, "purchase_type": "view_once"}

    return {"ok": True, "views_remaining": views_remaining, "purchase_type": purchase_type}

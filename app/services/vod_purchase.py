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
from app.services.subscription_access import has_active_subscription, is_platform_admin
from botocore.exceptions import ClientError
from boto3.dynamodb.types import TypeSerializer as _VodTypeSerializer
from app.core.settings import S
from app.core.aws_clients import ddb_transact_client

if TYPE_CHECKING:
    from app.models_video import VideoMetadataModel

logger = logging.getLogger(__name__)

# ─── DISP-004: low-level transact serializer for reverse_vod_purchase ────────
# reverse_vod_purchase writes its clawback+refund+marker in ONE TransactWriteItems
# (all-or-nothing, mirroring tips.reverse_tip), which requires the bare low-level
# client + DDB attribute-value maps. _vod_av serializes a plain dict into that map
# (floats -> Decimal first; the boto3 TypeSerializer rejects floats).
_VOD_SERIALIZER = _VodTypeSerializer()


def _vod_to_decimal(obj: Any) -> Any:
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _vod_to_decimal(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_vod_to_decimal(v) for v in obj]
    return obj


def _vod_av(item: Dict[str, Any]) -> Dict[str, Any]:
    return {k: _VOD_SERIALIZER.serialize(v) for k, v in _vod_to_decimal(item).items()}



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

    # SUB-E3: platform admins bypass subscriber gating on every surface.
    try:
        if is_platform_admin(user_id):
            return VodAccessResult(entitled=True, reason="admin")
    except Exception:
        pass

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
        _req_level = int(getattr(video, "required_tier_level", 0) or 0)  # SUBX-31
        has_sub = has_active_subscription(subscriber_id=user_id, creator_id=creator_id, required_level=_req_level)
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
    """List all video purchases for a user.

    Paginates via LastEvaluatedKey: a single query() call returns at most
    one DynamoDB page, so a busy account with many entitlements could miss
    purchases beyond the first page. Loop until we accumulate `limit` items
    or exhaust the table.
    """
    pk = f"USER#{user_id}"
    items: List[Dict[str, Any]] = []
    last_key: Optional[Dict[str, Any]] = None
    while len(items) < limit:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(pk) & Key("sk").begins_with("VIDEO#"),
            "ScanIndexForward": False,
            "Limit": limit - len(items),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.vod_entitlements.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

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


# ─── DISP-004 (N1): reverse a VOD pay-to-unlock purchase ─────────────────────
#
# The ONE true code gap in the payment-disputes program: VOD pay-to-unlock
# (purchase_video above) writes a buyer debit + a seller credit + the
# T.vod_entitlements access row, but has NO reverse function — refunding a VOD
# purchase today would leave the buyer with BOTH the money back AND continued
# access. reverse_vod_purchase mirrors the tips.reverse_tip / _reverse_subscription_charge
# shape and, crucially, DELETES the entitlement row so a refunded buyer LOSES
# access (playback re-locks).
#
# Money-safety invariants (identical to reverse_tip):
#   * the seller CLAWBACK entry (type="reversal") and the buyer REFUND entry
#     (type="refund") are NOT type="credit", so a reversal can never inflate
#     seller earnings (get_available_balance sums only type=="credit").
#   * the ORIGINAL seller credit row is flipped to state="reversed" so it drops
#     out of get_available_balance. NOTE: the seller-credit entry_type differs by
#     environment — prod writes type="credit" (counts toward balance), the dev
#     clone writes type="vod_purchase_credit" (does not) — so the original credit
#     is located by meta.purchase_id (type-agnostic), and the flip is correct in
#     both. On prod this genuinely claws spendable balance back; on dev the flip
#     is still recorded for audit/reconciliation honesty.
#   * a VODREVERSAL#{purchase_id} marker (conditional put) makes it idempotent +
#     guards double-reversal; a second call returns the stored receipt as a no-op.
#   * clawback_only=True suppresses the buyer refund leg (for the chargeback path
#     in E3: the processor already pulled the buyer's money, so we only claw the
#     seller credit and revoke access — no double buyer credit).
#
# Access revocation (delete_item) is a best-effort adjunct AFTER the atomic
# ledger transact, on the FIRST reversal only, exactly like reverse_tip flips the
# original credit only on the first (winning) call.

def _vod_reversal_sk(purchase_id: str) -> str:
    return f"VODREVERSAL#{purchase_id}"


def _find_vod_purchase_debit_row(buyer_id: str, purchase_id: str) -> Optional[Dict[str, Any]]:
    """Return the buyer's DEBIT ledger row for ``purchase_id`` (or None)."""
    pk = user_pk(buyer_id)
    for row in T.billing.query(
        KeyConditionExpression=Key("pk").eq(pk),
    ).get("Items", []):
        if not str(row.get("sk", "")).startswith("LEDGER#"):
            continue
        if str(row.get("type", "")) != "vod_purchase_debit":
            continue
        meta = row.get("meta") or {}
        if meta.get("purchase_id") == purchase_id:
            return row
    return None


def _find_vod_credit_row(seller_id: str, purchase_id: str) -> Optional[Dict[str, Any]]:
    """Return the seller's original CREDIT ledger row for ``purchase_id`` (or None).

    Located by ``meta.purchase_id`` and NOT by a fixed ``type`` value: prod writes
    the seller credit as type="credit" while the dev clone writes
    type="vod_purchase_credit". We accept either credit-direction type so the
    state="reversed" flip is correct in both environments; refund/reversal/debit
    rows (which also carry the purchase_id) are excluded so a replay never
    re-flips a reversal entry.
    """
    _CREDIT_TYPES = {"credit", "vod_purchase_credit", "vod_rental_credit"}
    pk = user_pk(seller_id)
    for row in T.billing.query(
        KeyConditionExpression=Key("pk").eq(pk),
    ).get("Items", []):
        if not str(row.get("sk", "")).startswith("LEDGER#"):
            continue
        if str(row.get("type", "")) not in _CREDIT_TYPES:
            continue
        meta = row.get("meta") or {}
        if meta.get("purchase_id") == purchase_id:
            return row
    return None


def reverse_vod_purchase(
    *,
    purchase_id: str,
    buyer_id: str,
    seller_id: Optional[str] = None,
    video_id: Optional[str] = None,
    gross_cents: Optional[int] = None,
    currency: str = "USD",
    reason: str = "admin_reversal",
    actor: Optional[str] = None,
    clawback_only: bool = False,
) -> Dict[str, Any]:
    """DISP-004 (N1): idempotently reverse a VOD pay-to-unlock purchase.

    Writes, in a single TransactWriteItems on T.billing:
      * a seller CLAWBACK ledger entry (type="reversal", amount = gross) —
      * a buyer REFUND ledger entry (type="refund", amount = gross) — UNLESS
        ``clawback_only`` (chargeback path: buyer already got their money) —
      * a ``VODREVERSAL#{purchase_id}`` marker claimed with attribute_not_exists.

    NEITHER money entry uses type "credit", so a reversal can never inflate seller
    earnings. The marker makes it idempotent + guards double-reversal.

    Best-effort adjuncts (FIRST reversal only): flip the original seller credit to
    state="reversed" (drops it out of get_available_balance) and — the code gap
    this ticket exists to close — DELETE the T.vod_entitlements row so the
    refunded buyer LOSES access (check_entitlement -> not_purchased, playback 403).

    Charge fields (seller_id/video_id/gross_cents) are resolved from the ledger
    when omitted, so an admin/dispatch caller can reverse a purchase knowing only
    (purchase_id, buyer_id).
    """
    if not purchase_id:
        raise HTTPException(400, {"code": "missing_purchase_id", "message": "purchase_id is required to reverse a VOD purchase."})
    if not buyer_id:
        raise HTTPException(400, {"code": "missing_buyer", "message": "buyer_id is required to locate the purchase."})

    marker_key = _vod_reversal_sk(purchase_id)

    # Idempotency short-circuit BEFORE the ledger scan: already reversed -> receipt.
    prior = T.billing.get_item(Key={"pk": user_pk(buyer_id), "sk": marker_key}).get("Item")
    if prior and prior.get("purchase_id"):
        return {**{k: v for k, v in prior.items() if k not in ("pk", "sk")}, "idempotent_replay": True}

    # Resolve missing charge fields from the buyer debit row.
    debit = _find_vod_purchase_debit_row(buyer_id, purchase_id)
    dmeta = (debit or {}).get("meta") or {}
    seller = seller_id or str(dmeta.get("seller_id") or "")
    vid = video_id or str(dmeta.get("video_id") or "")
    if gross_cents is None:
        gross_cents = abs(int((debit or {}).get("amount_cents", 0) or 0))
    if debit is not None:
        currency = str(debit.get("currency") or currency)
    if not seller:
        raise HTTPException(400, {"code": "missing_seller", "message": "Could not resolve VOD seller."})
    if gross_cents <= 0:
        raise HTTPException(400, {"code": "invalid_amount", "message": "VOD reversal amount must be positive."})

    ts = now_ts()
    reversal_id = uuid.uuid4().hex
    refund_id = uuid.uuid4().hex

    # Locate the original seller credit so we can flip it to state="reversed".
    credit = _find_vod_credit_row(seller, purchase_id)

    base_meta: Dict[str, Any] = {
        "content_type": "vod",
        "content_id": vid,
        "video_id": vid,
        "buyer_id": buyer_id,
        "buyer_user_id": buyer_id,
        "seller_id": seller,
        "recipient_user_id": seller,
        "purchase_id": purchase_id,
        "reversal_of": purchase_id,
        "reversal_reason": reason,
        "clawback_only": bool(clawback_only),
    }
    if actor:
        base_meta["reversal_actor"] = actor

    # Seller clawback (type != "credit" -> earnings not inflated).
    clawback_item = {
        "pk": user_pk(seller),
        "sk": f"LEDGER#{ts}#{reversal_id}",
        "entry_id": reversal_id,
        "ts": ts,
        "type": "reversal",
        "amount_cents": int(gross_cents),
        "currency": currency,
        "state": "settled",
        "reason": "Reversal: VOD purchase refund",
        "meta": base_meta,
    }
    # Buyer refund (type != "credit"). Suppressed on the chargeback (clawback_only) path.
    refund_item = {
        "pk": user_pk(buyer_id),
        "sk": f"LEDGER#{ts}#{refund_id}",
        "entry_id": refund_id,
        "ts": ts,
        "type": "refund",
        "amount_cents": int(gross_cents),
        "currency": currency,
        "state": "settled",
        "reason": "Refund: VOD purchase",
        "meta": base_meta,
    }

    receipt: Dict[str, Any] = {
        "purchase_id": purchase_id,
        "video_id": vid,
        "buyer_id": buyer_id,
        "seller_id": seller,
        "refunded_cents": 0 if clawback_only else int(gross_cents),
        "clawback_cents": int(gross_cents),
        "reversal_entry_id": reversal_id,
        "refund_entry_id": "" if clawback_only else refund_id,
        "clawback_only": bool(clawback_only),
        "reason": reason,
        "created_at": ts,
        "idempotent_replay": False,
    }
    marker_item = {
        "pk": user_pk(buyer_id),
        "sk": marker_key,
        **receipt,
    }

    table_name = S.billing_table_name
    tx_items = [
        {"Put": {"TableName": table_name, "Item": _vod_av(clawback_item)}},
    ]
    if not clawback_only:
        tx_items.append({"Put": {"TableName": table_name, "Item": _vod_av(refund_item)}})
    tx_items.append({
        "Put": {
            "TableName": table_name,
            "Item": _vod_av(marker_item),
            "ConditionExpression": "attribute_not_exists(sk)",
        }
    })

    client = ddb_transact_client()
    try:
        client.transact_write_items(TransactItems=tx_items)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "TransactionCanceledException":
            # Lost the race / already reversed -> return the stored receipt.
            winner = T.billing.get_item(Key={"pk": user_pk(buyer_id), "sk": marker_key}).get("Item")
            if winner and winner.get("purchase_id"):
                return {**{k: v for k, v in winner.items() if k not in ("pk", "sk")}, "idempotent_replay": True}
            receipt["idempotent_replay"] = True
            return receipt
        raise

    # --- best-effort adjuncts, FIRST reversal only ---
    # 1. Flip the original seller credit out of spendable balance.
    if credit is not None:
        try:
            T.billing.update_item(
                Key={"pk": user_pk(seller), "sk": credit.get("sk")},
                UpdateExpression="SET #s = :r",
                ConditionExpression="attribute_exists(sk)",
                ExpressionAttributeNames={"#s": "state"},
                ExpressionAttributeValues={":r": "reversed"},
            )
        except Exception:
            logger.warning("original VOD credit state flip skipped for purchase=%s", purchase_id, exc_info=True)

    # 2. THE CODE GAP: delete the entitlement row so the buyer LOSES access.
    if vid:
        try:
            T.vod_entitlements.delete_item(Key={"pk": f"USER#{buyer_id}", "sk": f"VIDEO#{vid}"})
        except Exception:
            logger.warning("VOD entitlement delete skipped for buyer=%s video=%s", buyer_id, vid, exc_info=True)

    # 3. Back the revenue stats out of the video metadata (best-effort).
    if vid:
        try:
            T.video_metadata.update_item(
                Key={"video_id": vid},
                UpdateExpression="SET purchase_count = if_not_exists(purchase_count, :z) - :one, "
                "revenue_cents = if_not_exists(revenue_cents, :z) - :price",
                ConditionExpression="attribute_exists(video_id)",
                ExpressionAttributeValues={":z": 0, ":one": 1, ":price": int(gross_cents)},
            )
        except Exception:
            logger.warning("VOD revenue stat back-out skipped for video=%s", vid, exc_info=True)

    return receipt

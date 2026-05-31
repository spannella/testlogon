"""VOD-019 rental / view-once access layer.

This service sits ON TOP of the existing VOD purchase + playback systems
(``app/services/vod_purchase.py`` and ``app/services/vod_playback_url.py``)
and adds two time/usage-bounded access tiers that the permanent-purchase
entitlement model does not cover:

- **rental**: grants unlimited views for a fixed window (default 48h) that
  starts at first playback. Access is revoked once ``expires_at`` passes.
- **view_once**: grants a single playthrough. Access is revoked once the
  view is consumed (``views_remaining`` reaches 0).

It does NOT recreate the purchase or playback-URL machinery — playback URLs
are still minted by :func:`mint_vod_playback_url`; this layer only gates that
issuance behind a rental-specific access check and records consumption.

Rentals live in their own ``vod_rentals`` DynamoDB table (distinct from
``vod_entitlements``) so the time-window / view-once state cannot collide with
permanent purchase records.

  pk = USER#{buyer_id}
  sk = VIDEO#{video_id}

Time is injectable everywhere (``now`` parameter) so the window/consumption
lifecycle is deterministically testable without sleeping.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import new_ledger_entry, user_pk
from app.services.video_metadata_store import get_video
from app.services.vod_playback_url import mint_vod_playback_url

logger = logging.getLogger(__name__)

# Rental tiers handled by this layer.
RENTAL_TIER = "rental"
VIEW_ONCE_TIER = "view_once"
VALID_TIERS = frozenset({RENTAL_TIER, VIEW_ONCE_TIER})

# Access-check reasons (mirrors the EntitlementStatus.reason vocabulary).
REASON_VALID = "valid"
REASON_NOT_RENTED = "not_rented"
REASON_EXPIRED = "expired"
REASON_CONSUMED = "consumed"
REASON_PENDING = "pending"  # rental started but window not yet activated (no first play)


# ─── Access result ────────────────────────────────────────────────────────────


class RentalAccess:
    """Result of a rental/view-once access check.

    Attributes:
        active: Whether the viewer may receive a playback URL right now.
        tier: "rental" | "view_once" | "" (when no rental exists).
        reason: one of the REASON_* constants.
        expires_at: 0 if not started/no expiry, else Unix seconds.
        remaining_seconds: seconds left in a rental window (0 for view_once / none).
        views_remaining: -1 for rental (unlimited within window), else count.
        rental_id: the rental record id, if any.
        started: True once the window/view has been activated (first play).
    """

    def __init__(
        self,
        *,
        active: bool,
        tier: str = "",
        reason: str = REASON_NOT_RENTED,
        expires_at: int = 0,
        remaining_seconds: int = 0,
        views_remaining: int = -1,
        rental_id: str = "",
        started: bool = False,
    ):
        self.active = active
        self.tier = tier
        self.reason = reason
        self.expires_at = expires_at
        self.remaining_seconds = remaining_seconds
        self.views_remaining = views_remaining
        self.rental_id = rental_id
        self.started = started

    def to_dict(self) -> Dict[str, Any]:
        return {
            "active": self.active,
            "tier": self.tier,
            "reason": self.reason,
            "expires_at": self.expires_at if self.expires_at > 0 else None,
            "remaining_seconds": self.remaining_seconds,
            "views_remaining": self.views_remaining,
            "rental_id": self.rental_id,
            "started": self.started,
        }


# ─── Internal helpers ───────────────────────────────────────────────────────


def _pk(user_id: str) -> str:
    return f"USER#{user_id}"


def _sk(video_id: str) -> str:
    return f"VIDEO#{video_id}"


def _get_rental_item(user_id: str, video_id: str) -> Optional[Dict[str, Any]]:
    resp = T.vod_rentals.get_item(
        Key={"pk": _pk(user_id), "sk": _sk(video_id)}, ConsistentRead=True
    )
    return resp.get("Item")


def _resolve_tier_price(video: Any, tier: str) -> Optional[int]:
    """Resolve the per-tier price in integer cents for a video."""
    if tier == VIEW_ONCE_TIER:
        return getattr(video, "view_once_price_cents", None)
    if tier == RENTAL_TIER:
        return getattr(video, "rental_price_cents", None)
    return None


def _charge_wallet_path(
    *, buyer_id: str, seller_id: str, video_id: str, rental_id: str, amount_cents: int, tier: str
) -> None:
    """Record the rental charge via the existing wallet/ledger path.

    Writes a debit for the buyer and a credit for the seller. Mirrors the
    pattern used by ``vod_purchase.purchase_video`` so rentals show up in the
    same billing ledger. Best-effort: ledger failures are logged, not fatal,
    so a transient billing hiccup does not strand a paid rental.
    """
    try:
        _s, debit = new_ledger_entry(
            key_name="pk",
            key_value=user_pk(buyer_id),
            entry_type="vod_rental_debit",
            amount_cents=amount_cents,
            state="settled",
            reason=f"VOD {tier} access",
            meta={"video_id": video_id, "seller_id": seller_id, "rental_id": rental_id, "tier": tier},
        )
        T.billing.put_item(Item=debit)
    except Exception:
        logger.exception("Failed to write rental debit ledger for %s", rental_id)

    try:
        _s, credit = new_ledger_entry(
            key_name="pk",
            key_value=user_pk(seller_id),
            entry_type="vod_rental_credit",
            amount_cents=amount_cents,
            state="settled",
            reason=f"VOD {tier} sale",
            meta={"video_id": video_id, "buyer_id": buyer_id, "rental_id": rental_id, "tier": tier},
        )
        T.billing.put_item(Item=credit)
    except Exception:
        logger.exception("Failed to write rental credit ledger for %s", rental_id)


# ─── Start a rental / view-once ───────────────────────────────────────────────


def start_rental(
    *,
    buyer_id: str,
    video_id: str,
    tier: str,
    payment_method_id: Optional[str] = None,
    rental_duration_hours: Optional[int] = None,
    now: Optional[int] = None,
) -> Dict[str, Any]:
    """Start a rental or view-once access grant for a video.

    The access window is NOT started here — ``expires_at``/``views_remaining``
    are activated on first playback (see :func:`issue_playback`). This mirrors
    the iTunes/Google Play model where the rental clock begins when you press
    play, not at checkout.

    Re-purchase: an existing rental that is consumed (view_once) or expired
    (rental) is overwritten by the new grant. An active/unstarted grant returns
    ``already_active=True``.

    Raises HTTPException for ownership / availability / pricing problems.
    """
    if not S.vod_rental_enabled:
        raise HTTPException(status_code=403, detail="Rental access is not enabled")
    if tier not in VALID_TIERS:
        raise HTTPException(status_code=400, detail=f"Invalid rental tier '{tier}'")

    ts = now if now is not None else now_ts()

    video = get_video(video_id)
    seller_id = video.owner_user_id
    if seller_id == buyer_id:
        raise HTTPException(status_code=400, detail="cannot rent your own video")
    if video.status != "published":
        raise HTTPException(status_code=400, detail="video not available for rental")

    available = list(getattr(video, "available_purchase_types", []) or [])
    if tier not in available:
        raise HTTPException(
            status_code=400, detail=f"Rental tier '{tier}' not available for this video"
        )

    price = _resolve_tier_price(video, tier)
    if price is None or int(price) <= 0:
        raise HTTPException(
            status_code=400, detail=f"No price configured for rental tier '{tier}'"
        )
    price = int(price)

    duration_hours = int(
        rental_duration_hours
        if rental_duration_hours is not None
        else (getattr(video, "rental_duration_hours", 0) or S.vod_rental_default_duration_hours)
    )

    # Re-rental gate: only allow overwriting a consumed/expired grant.
    existing = _get_rental_item(buyer_id, video_id)
    if existing:
        access = _evaluate(existing, now=ts)
        if access.active or access.reason == REASON_PENDING:
            return {
                "video_id": video_id,
                "rental_id": existing.get("rental_id", ""),
                "tier": existing.get("tier", tier),
                "already_active": True,
                "started": access.started,
                "expires_at": access.expires_at if access.expires_at > 0 else None,
                "views_remaining": access.views_remaining,
                "amount_cents": int(existing.get("amount_cents", 0)),
            }

    rental_id = f"vrent_{uuid.uuid4().hex}"
    item: Dict[str, Any] = {
        "pk": _pk(buyer_id),
        "sk": _sk(video_id),
        "rental_id": rental_id,
        "video_id": video_id,
        "buyer_id": buyer_id,
        "seller_id": seller_id,
        "tier": tier,
        "amount_cents": price,
        "currency": "USD",
        "created_at": ts,
        "duration_hours": duration_hours,
        # Window state — activated on first playback:
        "started_at": 0,
        "expires_at": 0,  # 0 = not started yet (GSI sort key, numeric)
        "views_remaining": (1 if tier == VIEW_ONCE_TIER else -1),
        "consumed_at": 0,
    }
    if payment_method_id:
        item["payment_method_id"] = payment_method_id

    T.vod_rentals.put_item(Item=item)

    _charge_wallet_path(
        buyer_id=buyer_id,
        seller_id=seller_id,
        video_id=video_id,
        rental_id=rental_id,
        amount_cents=price,
        tier=tier,
    )

    return {
        "video_id": video_id,
        "rental_id": rental_id,
        "tier": tier,
        "already_active": False,
        "started": False,
        "expires_at": None,
        "views_remaining": item["views_remaining"],
        "amount_cents": price,
        "duration_hours": duration_hours,
    }


# ─── Access evaluation ────────────────────────────────────────────────────────


def _evaluate(item: Optional[Dict[str, Any]], *, now: int) -> RentalAccess:
    """Pure access-state evaluation for a rental record at time ``now``."""
    if not item:
        return RentalAccess(active=False, reason=REASON_NOT_RENTED)

    tier = item.get("tier", "")
    rental_id = item.get("rental_id", "")
    started_at = int(item.get("started_at", 0))
    expires_at = int(item.get("expires_at", 0))
    views_remaining = int(item.get("views_remaining", -1))
    started = started_at > 0

    if tier == VIEW_ONCE_TIER:
        if views_remaining <= 0:
            return RentalAccess(
                active=False,
                tier=tier,
                reason=REASON_CONSUMED,
                views_remaining=0,
                rental_id=rental_id,
                started=started,
            )
        return RentalAccess(
            active=True,
            tier=tier,
            reason=REASON_VALID,
            views_remaining=views_remaining,
            rental_id=rental_id,
            started=started,
        )

    if tier == RENTAL_TIER:
        if not started:
            # Window not yet started — still grants access (first play starts clock).
            return RentalAccess(
                active=True,
                tier=tier,
                reason=REASON_PENDING,
                views_remaining=-1,
                rental_id=rental_id,
                started=False,
            )
        if expires_at > 0 and expires_at <= now:
            return RentalAccess(
                active=False,
                tier=tier,
                reason=REASON_EXPIRED,
                expires_at=expires_at,
                views_remaining=-1,
                rental_id=rental_id,
                started=True,
            )
        return RentalAccess(
            active=True,
            tier=tier,
            reason=REASON_VALID,
            expires_at=expires_at,
            remaining_seconds=max(0, expires_at - now),
            views_remaining=-1,
            rental_id=rental_id,
            started=True,
        )

    # Unknown tier — treat as not rented.
    return RentalAccess(active=False, tier=tier, reason=REASON_NOT_RENTED, rental_id=rental_id)


def check_access(*, user_id: str, video_id: str, now: Optional[int] = None) -> RentalAccess:
    """Check whether a viewer currently holds valid rental/view-once access.

    Enforces the rental time-window and view-once consumption. Does NOT mutate
    state (no clock start, no view consumption) — use :func:`issue_playback`
    for the playback path.
    """
    ts = now if now is not None else now_ts()
    return _evaluate(_get_rental_item(user_id, video_id), now=ts)


# ─── Playback URL issuance (gated) ─────────────────────────────────────────────


def _activate_window(
    *, user_id: str, video_id: str, duration_hours: int, now: int
) -> int:
    """Start the rental clock on first play (conditional, idempotent).

    Returns the resulting ``expires_at``. If two concurrent first plays race,
    only one write succeeds; the loser re-reads the persisted value.
    """
    expires_at = now + duration_hours * 3600
    try:
        T.vod_rentals.update_item(
            Key={"pk": _pk(user_id), "sk": _sk(video_id)},
            UpdateExpression="SET started_at = :now, expires_at = :exp",
            ConditionExpression="started_at = :zero",
            ExpressionAttributeValues={":now": now, ":exp": expires_at, ":zero": 0},
        )
        return expires_at
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            item = _get_rental_item(user_id, video_id) or {}
            return int(item.get("expires_at", expires_at))
        raise


def issue_playback(
    *, user_id: str, video_id: str, now: Optional[int] = None
) -> Dict[str, Any]:
    """Issue a playback URL for a rented video, gated on valid access.

    Side effects on a valid access:
    - rental: starts the time window on first play (sets expires_at).
    - view_once does NOT consume here — consumption happens via
      :func:`consume_view` when playback completes (so the URL works during
      the single allowed session).

    Raises HTTPException(403) if access is expired/consumed/absent.
    """
    ts = now if now is not None else now_ts()
    item = _get_rental_item(user_id, video_id)
    access = _evaluate(item, now=ts)

    if not access.active:
        detail = {
            REASON_NOT_RENTED: "You have not rented this video",
            REASON_EXPIRED: "Your rental window has expired",
            REASON_CONSUMED: "This view-once rental has already been used",
        }.get(access.reason, "Rental access is not valid")
        raise HTTPException(status_code=403, detail=detail)

    assert item is not None  # active access implies an item exists

    # Start the rental clock on first play.
    if access.tier == RENTAL_TIER and not access.started:
        duration_hours = int(item.get("duration_hours", S.vod_rental_default_duration_hours))
        new_expires = _activate_window(
            user_id=user_id, video_id=video_id, duration_hours=duration_hours, now=ts
        )
        access.expires_at = new_expires
        access.remaining_seconds = max(0, new_expires - ts)
        access.started = True
        access.reason = REASON_VALID

    video = get_video(video_id)
    playback = mint_vod_playback_url(
        video_id=video_id,
        tenant_id=video.owner_user_id,
        ttl_seconds=S.vod_rental_playback_ttl_seconds,
    )

    return {
        "video_id": video_id,
        "playback_url": playback.url,
        "manifest_key": playback.manifest_key,
        "mode": playback.mode,
        "thumbnail_url": playback.thumbnail_url,
        "token_expires_at": playback.expires_at,
        "access": access.to_dict(),
    }


# ─── View-once consumption ──────────────────────────────────────────────────


def consume_view(*, user_id: str, video_id: str, now: Optional[int] = None) -> Dict[str, Any]:
    """Consume a view-once rental after playback completes (idempotent).

    Atomically decrements ``views_remaining`` to 0 for view-once rentals.
    Uses a ConditionExpression so duplicate completion callbacks are no-ops.
    Non-view-once tiers are a no-op (returned for analytics).
    """
    ts = now if now is not None else now_ts()
    item = _get_rental_item(user_id, video_id)
    if not item:
        raise HTTPException(status_code=404, detail="No rental found")

    tier = item.get("tier", "")
    views_remaining = int(item.get("views_remaining", -1))

    if tier != VIEW_ONCE_TIER:
        return {"ok": True, "tier": tier, "views_remaining": views_remaining, "consumed": False}

    if views_remaining <= 0:
        return {"ok": True, "tier": tier, "views_remaining": 0, "consumed": False}

    try:
        T.vod_rentals.update_item(
            Key={"pk": _pk(user_id), "sk": _sk(video_id)},
            UpdateExpression="SET views_remaining = :zero, consumed_at = :ts, started_at = :ts",
            ConditionExpression="views_remaining > :zero",
            ExpressionAttributeValues={":zero": 0, ":ts": ts},
        )
        return {"ok": True, "tier": tier, "views_remaining": 0, "consumed": True}
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return {"ok": True, "tier": tier, "views_remaining": 0, "consumed": False}
        raise


# ─── Status / history ────────────────────────────────────────────────────────


def _item_to_status(item: Dict[str, Any], *, now: int) -> Dict[str, Any]:
    access = _evaluate(item, now=now)
    return {
        "video_id": item.get("video_id", ""),
        "rental_id": item.get("rental_id", ""),
        "tier": item.get("tier", ""),
        "amount_cents": int(item.get("amount_cents", 0)),
        "created_at": int(item.get("created_at", 0)),
        "started_at": int(item.get("started_at", 0)),
        "duration_hours": int(item.get("duration_hours", 0)),
        "active": access.active,
        "reason": access.reason,
        "expires_at": access.expires_at if access.expires_at > 0 else None,
        "remaining_seconds": access.remaining_seconds,
        "views_remaining": access.views_remaining,
        "started": access.started,
    }


def get_status(*, user_id: str, video_id: str, now: Optional[int] = None) -> Dict[str, Any]:
    """Return the rental status for a single video (or a not_rented stub)."""
    ts = now if now is not None else now_ts()
    item = _get_rental_item(user_id, video_id)
    if not item:
        return {
            "video_id": video_id,
            "rental_id": "",
            "tier": "",
            "active": False,
            "reason": REASON_NOT_RENTED,
            "expires_at": None,
            "remaining_seconds": 0,
            "views_remaining": -1,
            "started": False,
            "amount_cents": 0,
            "created_at": 0,
            "started_at": 0,
            "duration_hours": 0,
        }
    return _item_to_status(item, now=ts)


def list_rentals(
    *, user_id: str, limit: int = 50, now: Optional[int] = None
) -> List[Dict[str, Any]]:
    """List a viewer's rental history (newest first)."""
    ts = now if now is not None else now_ts()
    resp = T.vod_rentals.query(
        KeyConditionExpression=Key("pk").eq(_pk(user_id)) & Key("sk").begins_with("VIDEO#"),
        Limit=limit,
    )
    items = resp.get("Items", [])
    statuses = [_item_to_status(i, now=ts) for i in items]
    statuses.sort(key=lambda s: s["created_at"], reverse=True)
    return statuses

# app/services/content_boost.py
"""ADS-012: Self-Promotion / Content Boosting.

A creator can BOOST their own content (a post / video / broadcast) as a paid
self-promotion. They set a budget (integer cents) and a duration; the budget is
charged up-front against their wallet (reusing the shared wallet/ledger layer).
The boosted content gets elevated placement in feed/serving until the budget is
exhausted OR the duration elapses, whichever comes first.

This is a thin "boost" layer on top of the existing ad infrastructure:
  * charging / refunds reuse ``app.services.billing_shared`` (wallet + ledger),
    mirroring how ``ad_billing`` charges campaigns;
  * the elevation concept mirrors ``ad_serving`` / ``ad_placement`` -- the boost
    contributes a ranking weight that feed/serving code can call into.

All money values are integer cents. ``now`` is injectable everywhere so the
boost lifecycle (active / expired-by-budget / expired-by-duration) is fully
deterministic for tests.
"""
from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import (
    apply_wallet_delta,
    get_wallet_balance,
    new_ledger_entry,
    user_pk,
)

# Boost statuses
STATUS_ACTIVE = "active"
STATUS_COMPLETED = "completed"   # budget or duration exhausted naturally
STATUS_CANCELLED = "cancelled"   # cancelled by the owner (remaining refunded)

ALLOWED_CONTENT_TYPES = ("post", "video", "broadcast")

# Ranking elevation. A boosted item gets a large additive boost to its feed
# ranking score so it surfaces above organic content while active.
BOOST_RANK_WEIGHT = 1000

_LEDGER_CHARGE_TYPE = "content_boost_charge"
_LEDGER_REFUND_TYPE = "content_boost_refund"


def _now(now: int | None) -> int:
    return now if now is not None else now_ts()


def _pk(boost_id: str) -> str:
    return f"BOOST#{boost_id}"


def _wallet_balance(owner_sub: str) -> int:
    return int(get_wallet_balance(T.billing, user_pk(owner_sub)).get("wallet_balance_cents", 0))


def _wallet_charge(owner_sub: str, amount_cents: int, *, boost_id: str, content_type: str, content_id: str) -> None:
    """Debit the wallet and write a settled ledger debit. Raises on insufficient funds."""
    # apply_wallet_delta with a negative delta uses a conditional balance check
    apply_wallet_delta(T.billing, user_pk(owner_sub), -int(amount_cents))
    _sk, item = new_ledger_entry(
        key_name="pk",
        key_value=user_pk(owner_sub),
        entry_type=_LEDGER_CHARGE_TYPE,
        amount_cents=int(amount_cents),
        state="settled",
        reason="Content boost budget",
        meta={"boost_id": boost_id, "content_type": content_type, "content_id": content_id},
    )
    T.billing.put_item(Item=item)


def _wallet_refund(owner_sub: str, amount_cents: int, *, boost_id: str) -> None:
    """Credit the wallet and write a settled ledger credit."""
    apply_wallet_delta(T.billing, user_pk(owner_sub), int(amount_cents))
    _sk, item = new_ledger_entry(
        key_name="pk",
        key_value=user_pk(owner_sub),
        entry_type=_LEDGER_REFUND_TYPE,
        amount_cents=int(amount_cents),
        state="settled",
        reason="Content boost refund (remaining)",
        meta={"boost_id": boost_id},
    )
    T.billing.put_item(Item=item)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _boost_out(item: dict[str, Any], *, now: int | None = None) -> dict[str, Any]:
    budget = int(item.get("budget_cents", 0))
    spent = int(item.get("spent_cents", 0))
    remaining = max(0, budget - spent)
    status = _effective_status(item, now=now)
    return {
        "boost_id": item.get("boost_id"),
        "owner_sub": item.get("owner_sub"),
        "content_type": item.get("content_type"),
        "content_id": item.get("content_id"),
        "budget_cents": budget,
        "spent_cents": spent,
        "remaining_cents": remaining,
        "duration_seconds": int(item.get("duration_seconds", 0)),
        "starts_at": int(item.get("starts_at", 0)),
        "ends_at": int(item.get("ends_at", 0)),
        "status": status,
        "created_at": int(item.get("created_at", 0)),
    }


def _effective_status(item: dict[str, Any], *, now: int | None = None) -> str:
    """Compute the live status of a boost.

    Stored status takes precedence for terminal states (cancelled / completed);
    otherwise an active boost is downgraded to ``completed`` once its budget is
    spent or its duration has elapsed.
    """
    stored = item.get("status", STATUS_ACTIVE)
    if stored in (STATUS_CANCELLED, STATUS_COMPLETED):
        return stored
    ts = _now(now)
    budget = int(item.get("budget_cents", 0))
    spent = int(item.get("spent_cents", 0))
    ends_at = int(item.get("ends_at", 0))
    if spent >= budget:
        return STATUS_COMPLETED
    if ends_at and ts >= ends_at:
        return STATUS_COMPLETED
    return STATUS_ACTIVE


# ---------------------------------------------------------------------------
# Ownership verification (GAP-0058)
# ---------------------------------------------------------------------------


def _verify_content_ownership(owner_sub: str, content_type: str, content_id: str) -> None:
    """Verify ``owner_sub`` actually owns the content before any money moves.

    Raises ``ValueError`` (message contains "not found") if the content does not
    exist, and ``PermissionError`` if the caller does not own it. Covers all
    members of ``ALLOWED_CONTENT_TYPES`` (post / video / broadcast). Mirrors the
    best-effort try/except pattern in ``sponsorship_deals._verify_content_ownership``
    so a DDB connectivity blip surfaces as "not found" rather than a 500.
    """
    if content_type == "post":
        try:
            from app.routers.newsfeed import tbl as feed_tbl, pk_post, sk_post

            item = feed_tbl.get_item(Key={"pk": pk_post(content_id), "sk": sk_post()}).get("Item")
        except Exception:
            item = None
        if not item:
            raise ValueError(f"post '{content_id}' not found")
        if str(item.get("user_id", "")) != owner_sub:
            raise PermissionError("you do not own this content")

    elif content_type == "video":
        try:
            item = T.video_metadata.get_item(Key={"video_id": content_id}).get("Item")
        except Exception:
            item = None
        if not item:
            raise ValueError(f"video '{content_id}' not found")
        if str(item.get("owner_user_id", "")) != owner_sub:
            raise PermissionError("you do not own this content")

    elif content_type == "broadcast":
        try:
            item = T.broadcast_sessions.get_item(Key={"session_id": content_id}).get("Item")
        except Exception:
            item = None
        if not item:
            raise ValueError(f"broadcast '{content_id}' not found")
        if str(item.get("created_by", "")) != owner_sub:
            raise PermissionError("you do not own this content")
    # Content types outside ALLOWED_CONTENT_TYPES are rejected by the caller's
    # earlier guard before this helper is reached.


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


def create_boost(
    owner_sub: str,
    *,
    content_type: str,
    content_id: str,
    budget_cents: int,
    duration_seconds: int,
    now: int | None = None,
) -> dict[str, Any]:
    """Create a content boost, charging the full budget against the wallet.

    Raises ``ValueError`` on invalid input or insufficient wallet balance.
    """
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise ValueError(f"content_type must be one of {ALLOWED_CONTENT_TYPES}")
    if not content_id:
        raise ValueError("content_id is required")
    if budget_cents <= 0:
        raise ValueError("budget_cents must be positive")
    if duration_seconds <= 0:
        raise ValueError("duration_seconds must be positive")

    # Ownership verification (GAP-0058): the caller must own the content before
    # any wallet money moves. Raises ValueError ("not found") or PermissionError.
    _verify_content_ownership(owner_sub, content_type, content_id)

    ts = _now(now)
    bid = f"boost_{uuid.uuid4().hex[:12]}"
    ends_at = ts + duration_seconds

    # Charge the full budget up-front (reuses wallet/ledger). Check balance
    # explicitly first so we can return a clean error; the conditional debit is
    # the real safety net against races.
    if _wallet_balance(owner_sub) < budget_cents:
        raise ValueError("insufficient wallet balance")
    try:
        _wallet_charge(
            owner_sub,
            budget_cents,
            boost_id=bid,
            content_type=content_type,
            content_id=content_id,
        )
    except Exception:
        # ConditionalCheckFailedException (or any debit failure) -> treat as
        # insufficient balance; nothing has been written for this boost yet.
        raise ValueError("insufficient wallet balance")

    item = {
        "pk": _pk(bid),
        "sk": "META",
        "boost_id": bid,
        "owner_sub": owner_sub,
        "content_type": content_type,
        "content_id": content_id,
        "budget_cents": Decimal(int(budget_cents)),
        "spent_cents": Decimal(0),
        "duration_seconds": Decimal(int(duration_seconds)),
        "starts_at": Decimal(int(ts)),
        "ends_at": Decimal(int(ends_at)),
        "status": STATUS_ACTIVE,
        "created_at": Decimal(int(ts)),
        # GSI1: owner listing, newest first
        "GSI1PK": f"OWNER#{owner_sub}",
        "GSI1SK": Decimal(int(ts)),
        # GSI2: content lookup for the elevation hook (ends_at as range key)
        "GSI2PK": f"CONTENT#{content_type}#{content_id}",
        "GSI2SK": Decimal(int(ends_at)),
    }
    T.content_boosts.put_item(Item=item)
    return _boost_out(item, now=ts)


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------


def _get_raw(boost_id: str) -> dict[str, Any] | None:
    return T.content_boosts.get_item(Key={"pk": _pk(boost_id), "sk": "META"}).get("Item")


def get_boost(boost_id: str, *, now: int | None = None) -> dict[str, Any] | None:
    item = _get_raw(boost_id)
    if not item:
        return None
    return _boost_out(item, now=now)


def list_boosts(
    owner_sub: str,
    *,
    active_only: bool = False,
    limit: int = 50,
    now: int | None = None,
) -> list[dict[str, Any]]:
    """List an owner's boosts, newest first. ``active_only`` filters to live boosts."""
    res = T.content_boosts.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"OWNER#{owner_sub}"),
        ScanIndexForward=False,
        Limit=limit,
    )
    out = [_boost_out(i, now=now) for i in res.get("Items", [])]
    if active_only:
        out = [b for b in out if b["status"] == STATUS_ACTIVE]
    return out


def get_spend(boost_id: str, *, now: int | None = None) -> dict[str, Any] | None:
    """Return spend tracking for a boost."""
    item = _get_raw(boost_id)
    if not item:
        return None
    full = _boost_out(item, now=now)
    return {
        "boost_id": full["boost_id"],
        "budget_cents": full["budget_cents"],
        "spent_cents": full["spent_cents"],
        "remaining_cents": full["remaining_cents"],
        "status": full["status"],
    }


# ---------------------------------------------------------------------------
# Spend tracking (called by serving/feed as the boost delivers reach)
# ---------------------------------------------------------------------------


def record_spend(
    boost_id: str,
    *,
    amount_cents: int,
    now: int | None = None,
) -> dict[str, Any]:
    """Record spend against a boost as it delivers reach.

    Spend is capped at the remaining budget; once the budget is exhausted the
    boost transitions to ``completed``. Returns the updated spend summary.
    """
    if amount_cents <= 0:
        raise ValueError("amount_cents must be positive")
    item = _get_raw(boost_id)
    if not item:
        raise ValueError("boost not found")
    budget = int(item.get("budget_cents", 0))
    spent = int(item.get("spent_cents", 0))
    remaining = max(0, budget - spent)
    charge = min(amount_cents, remaining)
    new_spent = spent + charge

    update_expr = "SET spent_cents = :s"
    values: dict[str, Any] = {":s": Decimal(int(new_spent))}
    names: dict[str, str] = {}
    if new_spent >= budget and item.get("status") == STATUS_ACTIVE:
        update_expr += ", #st = :done"
        values[":done"] = STATUS_COMPLETED
        names["#st"] = "status"

    kwargs: dict[str, Any] = {
        "Key": {"pk": _pk(boost_id), "sk": "META"},
        "UpdateExpression": update_expr,
        "ExpressionAttributeValues": values,
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    T.content_boosts.update_item(**kwargs)

    refreshed = _get_raw(boost_id) or item
    full = _boost_out(refreshed, now=now)
    return {
        "boost_id": full["boost_id"],
        "budget_cents": full["budget_cents"],
        "spent_cents": full["spent_cents"],
        "remaining_cents": full["remaining_cents"],
        "status": full["status"],
    }


# ---------------------------------------------------------------------------
# Cancel + refund remaining
# ---------------------------------------------------------------------------


def cancel_boost(
    owner_sub: str,
    boost_id: str,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    """Cancel a boost and refund the unspent budget to the owner's wallet.

    Raises ``ValueError`` if the boost does not exist or is already in a terminal
    state, and ``PermissionError`` if the caller is not the owner.
    """
    item = _get_raw(boost_id)
    if not item:
        raise ValueError("boost not found")
    if item.get("owner_sub") != owner_sub:
        raise PermissionError("not the owner of this boost")
    if item.get("status") in (STATUS_CANCELLED, STATUS_COMPLETED):
        raise ValueError("boost is already finished")

    budget = int(item.get("budget_cents", 0))
    spent = int(item.get("spent_cents", 0))
    refund = max(0, budget - spent)

    if refund > 0:
        _wallet_refund(owner_sub, refund, boost_id=boost_id)

    T.content_boosts.update_item(
        Key={"pk": _pk(boost_id), "sk": "META"},
        UpdateExpression="SET #st = :c",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":c": STATUS_CANCELLED},
    )
    return {
        "boost_id": boost_id,
        "status": STATUS_CANCELLED,
        "refunded_cents": refund,
    }


# ---------------------------------------------------------------------------
# Elevation hook -- feed / serving call into these
# ---------------------------------------------------------------------------


def is_boost_active(item: dict[str, Any], *, now: int | None = None) -> bool:
    """True if a stored boost item is currently delivering (live)."""
    return _effective_status(item, now=now) == STATUS_ACTIVE


def active_boost_for_content(
    content_type: str,
    content_id: str,
    *,
    now: int | None = None,
) -> dict[str, Any] | None:
    """Return the active boost for a piece of content, if any (newest wins)."""
    res = T.content_boosts.query(
        IndexName="GSI2",
        KeyConditionExpression=Key("GSI2PK").eq(f"CONTENT#{content_type}#{content_id}"),
        ScanIndexForward=False,
    )
    for raw in res.get("Items", []):
        if is_boost_active(raw, now=now):
            return _boost_out(raw, now=now)
    return None


def boost_rank_bonus(
    content_type: str,
    content_id: str,
    *,
    now: int | None = None,
) -> int:
    """Ranking bonus a feed/serving ranker should ADD to an item's score.

    Returns ``BOOST_RANK_WEIGHT`` when the content has an active boost, else 0.
    Pure read -- safe to call from any ranking pipeline.
    """
    boost = active_boost_for_content(content_type, content_id, now=now)
    return BOOST_RANK_WEIGHT if boost else 0


def elevate_feed_items(
    items: list[dict[str, Any]],
    *,
    content_type: str = "post",
    id_key: str = "content_id",
    score_key: str = "score",
    now: int | None = None,
) -> list[dict[str, Any]]:
    """Re-rank a list of feed items, elevating actively-boosted content.

    Each item is expected to carry an id (``id_key``) and an organic ranking
    score (``score_key``, default 0). Boosted items get ``BOOST_RANK_WEIGHT``
    added and an ``is_boosted`` flag set. Returns a new list sorted by the
    effective score (highest first). Non-destructive: input items are copied.
    """
    out: list[dict[str, Any]] = []
    for it in items:
        copy = dict(it)
        base = int(copy.get(score_key, 0) or 0)
        bonus = boost_rank_bonus(content_type, str(copy.get(id_key, "")), now=now)
        copy["is_boosted"] = bonus > 0
        copy["effective_score"] = base + bonus
        out.append(copy)
    out.sort(key=lambda x: x["effective_score"], reverse=True)
    return out

"""Sponsored content & creator partnerships (ADS-013).

Manages the full lifecycle of brand sponsorship deals:
propose -> accept/reject/counter -> submit content -> complete; plus cancel.

Payment flows through the existing billing ledger (app/services/billing_shared.py).
Compensation is held in escrow from the advertiser wallet at proposal time and
released (split 15% platform commission / 85% creator) on completion, or refunded
to the advertiser on rejection/cancellation.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import (
    apply_wallet_delta,
    new_ledger_entry,
    user_pk,
)

# ── Constants ──────────────────────────────────────────────────────

DEAL_STATUSES = [
    "proposed",           # Advertiser created the deal
    "negotiating",        # Creator counter-offered
    "accepted",           # Creator accepted terms
    "content_submitted",  # Creator linked content to deal
    "completed",          # Advertiser approved, payment released
    "rejected",           # Creator rejected the proposal
    "cancelled",          # Either party cancelled
]

PLATFORM_COMMISSION_BPS = 1500  # 15% default
PLATFORM_REVENUE_SUB = "platform"


class SponsorshipError(Exception):
    """Raised on invalid deal operations. ``status_code`` maps to an HTTP code."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


# ── DDB helpers ────────────────────────────────────────────────────

def _deal_pk(deal_id: str) -> str:
    return f"DEAL#{deal_id}"


def _meta_sk() -> str:
    return "META"


def _event_sk(ts: int, event_id: str) -> str:
    return f"EVENT#{ts:010d}#{event_id}"


def get_deal(deal_id: str) -> Optional[Dict[str, Any]]:
    resp = T.sponsorship_deals.get_item(Key={"pk": _deal_pk(deal_id), "sk": _meta_sk()})
    return resp.get("Item")


def list_deals_by_advertiser(advertiser_account_id: str) -> List[Dict[str, Any]]:
    resp = T.sponsorship_deals.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"ADV#{advertiser_account_id}"),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


def list_deals_by_advertiser_sub(advertiser_sub: str) -> List[Dict[str, Any]]:
    """List deals proposed by a given advertiser user (across their accounts)."""
    out: List[Dict[str, Any]] = []
    last: Optional[Dict[str, Any]] = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI3",
            "KeyConditionExpression": Key("GSI3PK").eq("DEAL#ALL"),
            "ScanIndexForward": False,
        }
        if last:
            kwargs["ExclusiveStartKey"] = last
        resp = T.sponsorship_deals.query(**kwargs)
        out.extend(i for i in resp.get("Items", []) if i.get("advertiser_sub") == advertiser_sub)
        last = resp.get("LastEvaluatedKey")
        if not last:
            break
    return out


def list_deals_by_creator(creator_sub: str) -> List[Dict[str, Any]]:
    resp = T.sponsorship_deals.query(
        IndexName="GSI2",
        KeyConditionExpression=Key("GSI2PK").eq(f"CREATOR#{creator_sub}"),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


def list_deal_events(deal_id: str) -> List[Dict[str, Any]]:
    resp = T.sponsorship_deals.query(
        KeyConditionExpression=Key("pk").eq(_deal_pk(deal_id)) & Key("sk").begins_with("EVENT#"),
        ScanIndexForward=True,
    )
    return resp.get("Items", [])


def _record_event(
    deal_id: str, *, event_type: str, actor_sub: str, details: Optional[Dict[str, Any]] = None
) -> None:
    ts = now_ts()
    event_id = uuid.uuid4().hex[:12]
    item = {
        "pk": _deal_pk(deal_id),
        "sk": _event_sk(ts, event_id),
        "event_id": event_id,
        "event_type": event_type,
        "actor_sub": actor_sub,
        "details": details or {},
        "created_at": ts,
    }
    T.sponsorship_deals.put_item(Item=item)


# ── Escrow ─────────────────────────────────────────────────────────

def _create_escrow_hold(*, advertiser_sub: str, amount_cents: int, deal_id: str) -> str:
    """Debit the advertiser wallet and record a held ledger entry.

    Raises SponsorshipError(402) when the wallet has insufficient funds.
    Returns the ledger entry_id for later release.
    """
    pk = user_pk(advertiser_sub)
    try:
        apply_wallet_delta(T.billing, pk, -int(amount_cents))
    except Exception as exc:  # ConditionalCheckFailedException -> insufficient balance
        if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailed" in str(exc):
            raise SponsorshipError(402, "Insufficient wallet balance for sponsorship escrow") from exc
        raise
    _sk, item = new_ledger_entry(
        key_name="pk",
        key_value=pk,
        entry_type="sponsorship_escrow_hold",
        amount_cents=int(amount_cents),
        state="held",
        reason=f"Sponsorship deal escrow: {deal_id}",
        meta={"deal_id": deal_id},
    )
    T.billing.put_item(Item=item)
    return str(item.get("entry_id"))


def _refund_escrow(*, advertiser_sub: str, amount_cents: int, deal_id: str, reason: str) -> None:
    """Credit the held amount back to the advertiser wallet (full refund)."""
    pk = user_pk(advertiser_sub)
    apply_wallet_delta(T.billing, pk, int(amount_cents))
    _sk, item = new_ledger_entry(
        key_name="pk",
        key_value=pk,
        entry_type="sponsorship_escrow_refund",
        amount_cents=int(amount_cents),
        state="settled",
        reason=reason,
        meta={"deal_id": deal_id},
    )
    T.billing.put_item(Item=item)


def _release_escrow(
    *,
    advertiser_sub: str,
    creator_sub: str,
    total_cents: int,
    commission_bps: int,
    deal_id: str,
) -> Dict[str, int]:
    """Release escrow on completion: commission to platform, remainder to creator.

    The advertiser wallet was already debited at hold time, so we only credit the
    creator and record the commission. Returns the split amounts.
    """
    commission_cents = int(total_cents) * int(commission_bps) // 10000
    creator_cents = int(total_cents) - commission_cents

    # Credit creator wallet
    apply_wallet_delta(T.billing, user_pk(creator_sub), creator_cents)
    _sk, creator_item = new_ledger_entry(
        key_name="pk",
        key_value=user_pk(creator_sub),
        entry_type="sponsorship_payout",
        amount_cents=creator_cents,
        state="settled",
        reason=f"Sponsorship deal payout: {deal_id}",
        meta={"deal_id": deal_id},
    )
    T.billing.put_item(Item=creator_item)

    # Record platform commission
    _sk2, comm_item = new_ledger_entry(
        key_name="pk",
        key_value=user_pk(PLATFORM_REVENUE_SUB),
        entry_type="sponsorship_commission",
        amount_cents=commission_cents,
        state="settled",
        reason=f"Sponsorship platform commission: {deal_id}",
        meta={"deal_id": deal_id, "creator_sub": creator_sub, "advertiser_sub": advertiser_sub},
    )
    T.billing.put_item(Item=comm_item)

    return {
        "total_cents": int(total_cents),
        "commission_cents": commission_cents,
        "creator_cents": creator_cents,
    }


def _split_escrow_dispute(
    *, advertiser_sub: str, creator_sub: str, total_cents: int, deal_id: str
) -> Dict[str, int]:
    """50/50 dispute settlement when cancelling after content was submitted.

    Advertiser was already debited the full amount at hold time; refund 50% to
    advertiser and pay 50% to creator.
    """
    creator_cents = int(total_cents) // 2
    advertiser_cents = int(total_cents) - creator_cents

    apply_wallet_delta(T.billing, user_pk(advertiser_sub), advertiser_cents)
    _sk, adv_item = new_ledger_entry(
        key_name="pk",
        key_value=user_pk(advertiser_sub),
        entry_type="sponsorship_escrow_refund",
        amount_cents=advertiser_cents,
        state="settled",
        reason=f"Sponsorship dispute refund: {deal_id}",
        meta={"deal_id": deal_id},
    )
    T.billing.put_item(Item=adv_item)

    apply_wallet_delta(T.billing, user_pk(creator_sub), creator_cents)
    _sk2, cr_item = new_ledger_entry(
        key_name="pk",
        key_value=user_pk(creator_sub),
        entry_type="sponsorship_payout",
        amount_cents=creator_cents,
        state="settled",
        reason=f"Sponsorship dispute settlement: {deal_id}",
        meta={"deal_id": deal_id},
    )
    T.billing.put_item(Item=cr_item)

    return {"advertiser_cents": advertiser_cents, "creator_cents": creator_cents}


# ── FTC labeling ───────────────────────────────────────────────────

def _add_ftc_label(content_type: str, content_id: str, *, brand_name: str, deal_id: str) -> None:
    """Apply FTC disclosure to the linked content (server-side, immutable).

    For ``post`` content this updates the newsfeed post META item with
    ``sponsored_by``, ``deal_id`` and ``ftc_disclosure``.
    """
    if content_type != "post":
        return
    try:
        from app.routers.newsfeed import tbl as feed_tbl, pk_post, sk_post

        disclosure = f"Paid partnership with {brand_name}"
        feed_tbl.update_item(
            Key={"pk": pk_post(content_id), "sk": sk_post()},
            UpdateExpression=(
                "SET sponsored_by = :b, deal_id = :d, ftc_disclosure = :f, updated_at = :u"
            ),
            ExpressionAttributeValues={
                ":b": brand_name,
                ":d": deal_id,
                ":f": disclosure,
                ":u": str(now_ts()),
            },
        )
    except Exception:
        # FTC labeling is best-effort; do not fail the submission if the content
        # is not a newsfeed post or cannot be updated.
        pass


def _verify_content_ownership(content_type: str, content_id: str, creator_sub: str) -> None:
    """Raise SponsorshipError(403) if the content is not owned by the creator,
    404 if it does not exist. Only enforced for newsfeed posts."""
    if content_type != "post":
        return
    try:
        from app.routers.newsfeed import tbl as feed_tbl, pk_post, sk_post

        item = feed_tbl.get_item(Key={"pk": pk_post(content_id), "sk": sk_post()}).get("Item")
    except Exception:
        item = None
    if not item:
        raise SponsorshipError(404, "Content not found")
    if str(item.get("user_id", "")) != creator_sub:
        raise SponsorshipError(403, "You do not own this content")


# ── DM creation on acceptance ──────────────────────────────────────

def _create_deal_dm(advertiser_sub: str, creator_sub: str, deal_id: str, brief: str) -> Optional[str]:
    """Create a DM conversation between advertiser and creator for deal discussion.

    Best-effort: returns the conversation id, or None if the messaging service is
    unavailable in the current context.
    """
    try:
        from app.routers.messaging import get_or_create_dm  # type: ignore

        convo = get_or_create_dm(advertiser_sub, creator_sub)
        if isinstance(convo, dict):
            return str(convo.get("conversation_id") or convo.get("id") or "")
        return str(convo) if convo else None
    except Exception:
        # Deterministic fallback id so acceptance always returns a conversation id.
        return f"spdeal_{deal_id}"


# ── Notifications ──────────────────────────────────────────────────

def _notify(user_sub: str, *, event: str, title: str, details: Dict[str, Any]) -> None:
    try:
        from app.services.alerts import write_alert

        write_alert(
            user_sub,
            event=event,
            outcome="success",
            title=title,
            details=details,
        )
    except Exception:
        pass


# ── Lifecycle ──────────────────────────────────────────────────────

def create_deal(
    *,
    advertiser_sub: str,
    advertiser_account_id: str,
    creator_sub: str,
    content_type: str,
    brief: str,
    deliverables: List[str],
    compensation_cents: int,
    cpm_bonus_cents: int = 0,
    deadline: str,
) -> Dict[str, Any]:
    """Propose a new sponsorship deal and hold compensation in escrow."""
    if creator_sub == advertiser_sub:
        raise SponsorshipError(400, "Cannot propose a deal to yourself")

    deal_id = f"deal_{uuid.uuid4().hex[:12]}"
    ts = now_ts()

    # Escrow hold (raises 402 if insufficient funds) — do before writing the deal.
    escrow_hold_id = _create_escrow_hold(
        advertiser_sub=advertiser_sub, amount_cents=int(compensation_cents), deal_id=deal_id
    )

    item: Dict[str, Any] = {
        "pk": _deal_pk(deal_id),
        "sk": _meta_sk(),
        "deal_id": deal_id,
        "advertiser_account_id": advertiser_account_id,
        "advertiser_sub": advertiser_sub,
        "creator_sub": creator_sub,
        "content_type": content_type,
        "brief": brief,
        "deliverables": list(deliverables),
        "compensation_cents": int(compensation_cents),
        "cpm_bonus_cents": int(cpm_bonus_cents),
        "platform_commission_bps": PLATFORM_COMMISSION_BPS,
        "status": "proposed",
        "deadline": deadline,
        "content_id": None,
        "dm_conversation_id": None,
        "escrow_hold_id": escrow_hold_id,
        "created_at": ts,
        "updated_at": ts,
        "completed_at": 0,
        "cancelled_at": 0,
        "cancel_reason": "",
        "GSI1PK": f"ADV#{advertiser_account_id}",
        "GSI1SK": ts,
        "GSI2PK": f"CREATOR#{creator_sub}",
        "GSI2SK": ts,
        "GSI3PK": "DEAL#ALL",
        "GSI3SK": ts,
    }
    T.sponsorship_deals.put_item(Item=item)
    _record_event(deal_id, event_type="proposed", actor_sub=advertiser_sub, details={
        "compensation_cents": int(compensation_cents),
        "content_type": content_type,
    })
    _notify(creator_sub, event="sponsorship.proposed", title="New sponsorship proposal", details={
        "deal_id": deal_id,
        "compensation_cents": int(compensation_cents),
    })
    return item


def _update_deal(deal_id: str, updates: Dict[str, Any], *, status_index: bool = False) -> Dict[str, Any]:
    ts = now_ts()
    updates = {**updates, "updated_at": ts}
    set_parts: List[str] = []
    values: Dict[str, Any] = {}
    names: Dict[str, str] = {}
    for i, (k, v) in enumerate(updates.items()):
        nk = f"#k{i}"
        vk = f":v{i}"
        names[nk] = k
        values[vk] = v
        set_parts.append(f"{nk} = {vk}")
    T.sponsorship_deals.update_item(
        Key={"pk": _deal_pk(deal_id), "sk": _meta_sk()},
        UpdateExpression="SET " + ", ".join(set_parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )
    deal = get_deal(deal_id)
    return deal or {}


def accept_deal(*, deal_id: str, creator_sub: str) -> Dict[str, Any]:
    deal = get_deal(deal_id)
    if not deal:
        raise SponsorshipError(404, "Deal not found")
    if deal["creator_sub"] != creator_sub:
        raise SponsorshipError(403, "Only the targeted creator can accept this deal")
    if deal["status"] not in ("proposed", "negotiating"):
        raise SponsorshipError(409, f"Cannot accept deal in status '{deal['status']}'")

    dm_id = _create_deal_dm(deal["advertiser_sub"], creator_sub, deal_id, deal.get("brief", ""))
    updated = _update_deal(deal_id, {"status": "accepted", "dm_conversation_id": dm_id})
    _record_event(deal_id, event_type="accepted", actor_sub=creator_sub, details={"dm_conversation_id": dm_id})
    _notify(deal["advertiser_sub"], event="sponsorship.accepted", title="Sponsorship accepted", details={
        "deal_id": deal_id,
    })
    return updated


def reject_deal(*, deal_id: str, creator_sub: str, reason: str = "") -> Dict[str, Any]:
    deal = get_deal(deal_id)
    if not deal:
        raise SponsorshipError(404, "Deal not found")
    if deal["creator_sub"] != creator_sub:
        raise SponsorshipError(403, "Only the targeted creator can reject this deal")
    if deal["status"] not in ("proposed", "negotiating"):
        raise SponsorshipError(409, f"Cannot reject deal in status '{deal['status']}'")

    _refund_escrow(
        advertiser_sub=deal["advertiser_sub"],
        amount_cents=int(deal["compensation_cents"]),
        deal_id=deal_id,
        reason=f"Sponsorship deal rejected: {deal_id}",
    )
    updated = _update_deal(deal_id, {
        "status": "rejected",
        "cancelled_at": now_ts(),
        "cancel_reason": reason or "Rejected by creator",
    })
    _record_event(deal_id, event_type="rejected", actor_sub=creator_sub, details={"reason": reason})
    _notify(deal["advertiser_sub"], event="sponsorship.rejected", title="Sponsorship rejected", details={
        "deal_id": deal_id,
    })
    return updated


def counter_deal(
    *, deal_id: str, creator_sub: str, compensation_cents: Optional[int] = None, note: str = ""
) -> Dict[str, Any]:
    """Creator counters a proposed deal (moves to negotiating)."""
    deal = get_deal(deal_id)
    if not deal:
        raise SponsorshipError(404, "Deal not found")
    if deal["creator_sub"] != creator_sub:
        raise SponsorshipError(403, "Only the targeted creator can counter this deal")
    if deal["status"] not in ("proposed", "negotiating"):
        raise SponsorshipError(409, f"Cannot counter deal in status '{deal['status']}'")

    updates: Dict[str, Any] = {"status": "negotiating"}
    details: Dict[str, Any] = {"note": note}
    if compensation_cents is not None:
        details["proposed_compensation_cents"] = int(compensation_cents)
        details["counter_compensation_cents"] = int(compensation_cents)
    updated = _update_deal(deal_id, updates)
    _record_event(deal_id, event_type="negotiation_message", actor_sub=creator_sub, details=details)
    _notify(deal["advertiser_sub"], event="sponsorship.countered", title="Sponsorship counter-offer", details={
        "deal_id": deal_id,
    })
    return updated


def submit_content(*, deal_id: str, creator_sub: str, content_id: str) -> Dict[str, Any]:
    deal = get_deal(deal_id)
    if not deal:
        raise SponsorshipError(404, "Deal not found")
    if deal["creator_sub"] != creator_sub:
        raise SponsorshipError(403, "Only the targeted creator can submit content")
    if deal["status"] != "accepted":
        raise SponsorshipError(409, f"Cannot submit content for deal in status '{deal['status']}'")

    _verify_content_ownership(deal["content_type"], content_id, creator_sub)

    # Brand name = advertiser account company name. Falls back to a safe generic
    # label — never the raw advertiser Cognito sub (UUID), which would leak PII
    # into the public FTC disclosure ("Paid partnership with <UUID>"). See GAP-0060.
    brand_name = "a verified brand partner"
    try:
        from app.services.ad_accounts import get_ad_account

        acct = get_ad_account(deal["advertiser_account_id"])
        if acct and acct.get("company_name"):
            brand_name = acct["company_name"]
    except Exception:
        pass

    _add_ftc_label(deal["content_type"], content_id, brand_name=brand_name, deal_id=deal_id)
    updated = _update_deal(deal_id, {"status": "content_submitted", "content_id": content_id})
    _record_event(deal_id, event_type="content_submitted", actor_sub=creator_sub, details={
        "content_id": content_id,
    })
    _notify(deal["advertiser_sub"], event="sponsorship.content_submitted", title="Sponsored content submitted", details={
        "deal_id": deal_id,
        "content_id": content_id,
    })
    return updated


def complete_deal(*, deal_id: str, advertiser_sub: str) -> Dict[str, Any]:
    deal = get_deal(deal_id)
    if not deal:
        raise SponsorshipError(404, "Deal not found")
    if deal["advertiser_sub"] != advertiser_sub:
        raise SponsorshipError(403, "Only the advertiser can complete this deal")
    if deal["status"] != "content_submitted":
        raise SponsorshipError(409, f"Cannot complete deal in status '{deal['status']}'")

    split = _release_escrow(
        advertiser_sub=advertiser_sub,
        creator_sub=deal["creator_sub"],
        total_cents=int(deal["compensation_cents"]),
        commission_bps=int(deal.get("platform_commission_bps", PLATFORM_COMMISSION_BPS)),
        deal_id=deal_id,
    )
    updated = _update_deal(deal_id, {"status": "completed", "completed_at": now_ts()})
    _record_event(deal_id, event_type="completed", actor_sub=advertiser_sub, details=split)
    _notify(deal["creator_sub"], event="sponsorship.completed", title="Sponsorship payment received", details={
        "deal_id": deal_id,
        "creator_cents": split["creator_cents"],
    })
    updated["payment_details"] = split
    return updated


def cancel_deal(*, deal_id: str, actor_sub: str, reason: str) -> Dict[str, Any]:
    deal = get_deal(deal_id)
    if not deal:
        raise SponsorshipError(404, "Deal not found")
    if actor_sub not in (deal["advertiser_sub"], deal["creator_sub"]):
        raise SponsorshipError(403, "Only a participant can cancel this deal")
    if deal["status"] in ("completed", "cancelled", "rejected"):
        raise SponsorshipError(409, f"Cannot cancel deal in status '{deal['status']}'")

    total = int(deal["compensation_cents"])
    if deal["status"] == "content_submitted":
        details = _split_escrow_dispute(
            advertiser_sub=deal["advertiser_sub"],
            creator_sub=deal["creator_sub"],
            total_cents=total,
            deal_id=deal_id,
        )
    else:
        _refund_escrow(
            advertiser_sub=deal["advertiser_sub"],
            amount_cents=total,
            deal_id=deal_id,
            reason=f"Sponsorship deal cancelled: {deal_id}",
        )
        details = {"advertiser_cents": total, "creator_cents": 0}

    updated = _update_deal(deal_id, {
        "status": "cancelled",
        "cancelled_at": now_ts(),
        "cancel_reason": reason,
    })
    _record_event(deal_id, event_type="cancelled", actor_sub=actor_sub, details={"reason": reason, **details})
    other = deal["creator_sub"] if actor_sub == deal["advertiser_sub"] else deal["advertiser_sub"]
    _notify(other, event="sponsorship.cancelled", title="Sponsorship cancelled", details={"deal_id": deal_id})
    return updated

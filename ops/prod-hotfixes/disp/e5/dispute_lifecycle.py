"""Payment-disputes USER-TRACK lifecycle (DISP E1: DISP-010/011/012).

This module holds the *policy* layer of the user-initiated dispute flow — the
pieces that decide WHEN a dispute may be opened, HOW it transitions, and the
creator/seller response window + SLA sweep. The money-movement itself is NOT
here: a winning ``resolved`` transition delegates to the E0 dispatcher
(``dispute_dispatch.dispatch_reversal``) via ``billing_disputes.resolve_dispute``
(DISP-013).

Design mirrors the shipped moderation lifecycle so the two humane-response
subsystems behave identically:

* reason gating per charge type          <- moderation_case CATEGORIES gating
* forward-only state machine (_ALLOWED)  <- moderation_case.ALLOWED_TRANSITIONS
* respond_by response window + sweep     <- moderation_lifecycle.sweep_expired_holds

Everything here is real-now and mock-testable; no external key required.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert, audit_event
from app.services import dispute_dispatch as DD

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# DISP-010 — Dispute REASONS + per-charge-type gating
# ═══════════════════════════════════════════════════════════════════════════
# The canonical reason enum. Free-text ``reason_detail`` is carried separately.
REASON_NOT_RECEIVED = "not_received"
REASON_NOT_AS_DESCRIBED = "not_as_described"
REASON_UNAUTHORIZED = "unauthorized"
REASON_DUPLICATE = "duplicate"
REASON_QUALITY = "quality"

REASONS: Set[str] = {
    REASON_NOT_RECEIVED,
    REASON_NOT_AS_DESCRIBED,
    REASON_UNAUTHORIZED,
    REASON_DUPLICATE,
    REASON_QUALITY,
}

# Which reasons are valid for which charge type. A tip/subscription is not a
# delivered good, so "not_received"/"not_as_described" don't apply; an ad is a
# self-serve spend the advertiser controls, so only unauthorized/duplicate make
# sense. ecom + vod are goods/media, so the full set applies.
_REASONS_BY_CHARGE_TYPE: Dict[str, Set[str]] = {
    # tips / pay-to-message: a gift/spend, not a delivered good.
    "tip":     {REASON_UNAUTHORIZED, REASON_DUPLICATE, REASON_QUALITY},
    "message": {REASON_UNAUTHORIZED, REASON_DUPLICATE, REASON_QUALITY},
    # subscription: recurring access; unauthorized/duplicate/quality (not delivered good).
    "subscription": {REASON_UNAUTHORIZED, REASON_DUPLICATE, REASON_QUALITY},
    # ad: advertiser-controlled spend — only unauthorized charge or duplicate.
    "ad": {REASON_UNAUTHORIZED, REASON_DUPLICATE},
    # ecom: physical/digital goods — the full set.
    "ecom": {REASON_NOT_RECEIVED, REASON_NOT_AS_DESCRIBED, REASON_UNAUTHORIZED,
             REASON_DUPLICATE, REASON_QUALITY},
    # vod: pay-to-unlock media — not_received (never unlocked) / quality / etc.
    "vod": {REASON_NOT_RECEIVED, REASON_NOT_AS_DESCRIBED, REASON_UNAUTHORIZED,
            REASON_DUPLICATE, REASON_QUALITY},
}


def detect_charge_from_entry(user_id: str, transaction_entry_id: str) -> Dict[str, Any]:
    """Best-effort: infer ``(charge_type, charge_ref, recipient_id, amount_cents)``
    from a payer's ledger DEBIT row when the caller only passed a
    ``transaction_entry_id`` (the "dispute from a receipt" path). Returns {} when
    the row can't be classified (the generic/legacy path — no gating, no rail).

    Mapping is by the debit row's ``type`` + ``meta``:
      * meta.tip_payment_id + meta.content_type=="message" -> message
      * meta.tip_payment_id                                 -> tip
      * type=="vod_purchase_debit" (meta.purchase_id)       -> vod
      * meta.subscription_id                                -> subscription
      * meta.order_id / ecom debit                          -> ecom
    """
    from app.services.billing_shared import user_pk
    row = None
    for r in T.billing.query(KeyConditionExpression="pk = :p",
                             ExpressionAttributeValues={":p": user_pk(user_id)}).get("Items", []):
        if str(r.get("sk", "")).startswith("LEDGER#") and r.get("entry_id") == transaction_entry_id:
            row = r
            break
    if not row:
        return {}
    meta = row.get("meta") or {}
    rtype = str(row.get("type") or "")
    amt = abs(int(row.get("amount_cents", 0) or 0))
    if meta.get("tip_payment_id"):
        ct = "message" if str(meta.get("content_type") or "") == "message" else "tip"
        return {"charge_type": ct, "charge_ref": meta["tip_payment_id"],
                "recipient_id": meta.get("recipient_user_id"), "amount_cents": amt}
    if rtype in ("vod_purchase_debit",) or meta.get("purchase_id"):
        return {"charge_type": "vod", "charge_ref": meta.get("purchase_id") or transaction_entry_id,
                "recipient_id": meta.get("seller_id"), "amount_cents": amt}
    if meta.get("subscription_id") or row.get("subscription_id"):
        sid = meta.get("subscription_id") or row.get("subscription_id")
        return {"charge_type": "subscription", "charge_ref": sid,
                "recipient_id": meta.get("creator_id"), "amount_cents": amt}
    if meta.get("order_id") or str(meta.get("content_type") or "") in ("ecom", "order", "purchase"):
        return {"charge_type": "ecom", "charge_ref": transaction_entry_id,
                "recipient_id": None, "amount_cents": amt}
    return {}


def reasons_for_charge_type(charge_type: str) -> Set[str]:
    """The set of reasons valid to open a dispute against ``charge_type``.

    Unknown charge types fall back to the full reason set (no gating) so the
    generic/legacy ``transaction_entry_id`` path keeps working.
    """
    ct = (charge_type or "").strip().lower()
    return _REASONS_BY_CHARGE_TYPE.get(ct, set(REASONS))


def validate_reason(reason: str, charge_type: str) -> None:
    """DISP-010 gate: raise 400 if ``reason`` is not a known enum member OR is
    not applicable to ``charge_type``. Called at open time."""
    r = (reason or "").strip().lower()
    if r not in REASONS:
        raise HTTPException(400, {"code": "invalid_reason",
                                  "message": f"reason must be one of {sorted(REASONS)}."})
    allowed = reasons_for_charge_type(charge_type)
    if r not in allowed:
        raise HTTPException(400, {"code": "reason_not_applicable",
                                  "message": f"reason {r!r} does not apply to a {charge_type or 'generic'} charge; "
                                             f"allowed: {sorted(allowed)}."})


# ═══════════════════════════════════════════════════════════════════════════
# DISP-011 — User dispute STATE MACHINE
# ═══════════════════════════════════════════════════════════════════════════
STATE_OPEN = "open"
STATE_NEEDS_RESPONSE = "needs_response"
STATE_UNDER_REVIEW = "under_review"
STATE_RESOLVED = "resolved"
STATE_WITHDRAWN = "withdrawn"
STATE_ESCALATED = "escalated"

TERMINAL_STATES: Set[str] = {STATE_RESOLVED, STATE_WITHDRAWN}
# escalated is NOT terminal — it just means "in the admin queue, awaiting a call".
NON_TERMINAL_STATES: Set[str] = {STATE_OPEN, STATE_NEEDS_RESPONSE, STATE_UNDER_REVIEW,
                                 STATE_ESCALATED}

# Forward-only legal transitions (mirrors moderation_case.ALLOWED_TRANSITIONS).
# same->same is a no-op (handled by the guarded transition); illegal skips reject.
_ALLOWED: Dict[str, Set[str]] = {
    STATE_OPEN:            {STATE_NEEDS_RESPONSE, STATE_UNDER_REVIEW, STATE_RESOLVED, STATE_WITHDRAWN},
    STATE_NEEDS_RESPONSE:  {STATE_UNDER_REVIEW, STATE_ESCALATED, STATE_RESOLVED, STATE_WITHDRAWN},
    STATE_UNDER_REVIEW:    {STATE_ESCALATED, STATE_RESOLVED, STATE_WITHDRAWN},
    STATE_ESCALATED:       {STATE_UNDER_REVIEW, STATE_RESOLVED, STATE_WITHDRAWN},
    STATE_RESOLVED:        set(),
    STATE_WITHDRAWN:       set(),
}

# Resolution sub-states carried on ``resolution`` when status==resolved.
RESOLUTION_REFUNDED = "refunded"
RESOLUTION_PARTIAL = "partial"
RESOLUTION_DENIED = "denied"
RESOLUTIONS: Set[str] = {RESOLUTION_REFUNDED, RESOLUTION_PARTIAL, RESOLUTION_DENIED}


def can_transition(frm: str, to: str) -> bool:
    if frm == to:
        return True
    return to in _ALLOWED.get(frm, set())


def assert_transition(frm: str, to: str) -> None:
    if not can_transition(frm, to):
        raise HTTPException(409, {"code": "illegal_transition",
                                  "message": f"Dispute cannot move {frm!r} -> {to!r}."})


# ═══════════════════════════════════════════════════════════════════════════
# DISP-012 — Creator/seller RESPONSE WINDOW + SLA sweep
# ═══════════════════════════════════════════════════════════════════════════

def _dp_key(dispute_id: str) -> Dict[str, str]:
    return {"pk": f"DISPUTE#{dispute_id}", "sk": "META"}


def _response_window_seconds() -> int:
    return int(getattr(S, "dispute_response_window_days", 7)) * 86400


def _auto_refund_threshold() -> int:
    return int(getattr(S, "dispute_auto_refund_threshold_cents", 0) or 0)


def _skip_window(reason: str, amount_cents: int) -> bool:
    """Auto-skip policy (DISP-012): an ``unauthorized`` claim OR a small-amount
    charge under the auto-refund threshold skips the creator response window and
    goes straight into the admin queue (``under_review``). Everything else opens
    a ``needs_response`` window first."""
    if (reason or "").strip().lower() == REASON_UNAUTHORIZED:
        return True
    thr = _auto_refund_threshold()
    if thr > 0 and int(amount_cents or 0) < thr:
        return True
    return False


def open_response_window(
    *,
    dispute_id: str,
    creator_id: Optional[str],
    reason: str,
    amount_cents: int,
    now: Optional[int] = None,
    force_manual_review: bool = False,
) -> Dict[str, Any]:
    """Called right after a dispute is filed (DISP-012). Advances the freshly
    ``open`` dispute either to ``needs_response`` (sets ``respond_by`` + notifies
    the creator to rebut) or, when the auto-skip policy applies, straight to
    ``under_review`` (lands in the admin queue). Idempotent: only fires on an
    ``open`` row.

    Returns ``{status, respond_by}``.
    """
    ts = int(now or now_ts())
    # DISP-041: a serial disputer is never auto-fast-pathed -- force the human
    # response/review window even for unauthorized/under-threshold claims.
    if not force_manual_review and _skip_window(reason, amount_cents):
        changed, item = DD.guarded_dispute_transition(
            dispute_id, STATE_UNDER_REVIEW,
            expected_from=[STATE_OPEN],
            extra={"window_skipped": True, "window_skip_reason":
                   "unauthorized" if (reason or "").lower() == REASON_UNAUTHORIZED else "under_threshold"},
        )
        if changed:
            audit_event("billing_dispute_window_skipped", creator_id or "system", None,
                        outcome="info", dispute_id=dispute_id, reason=reason)
        return {"status": item.get("status", STATE_UNDER_REVIEW), "respond_by": None}

    respond_by = ts + _response_window_seconds()
    changed, item = DD.guarded_dispute_transition(
        dispute_id, STATE_NEEDS_RESPONSE,
        expected_from=[STATE_OPEN],
        extra={"respond_by": respond_by, "respond_by_scope": "RESPONDBY#needs_response"},
    )
    if changed and creator_id:
        # DISP-050: invite the creator/seller into the window with a tappable push.
        try:
            from app.services import dispute_notify as DN
            DN.notify_needs_response(
                dispute_id=dispute_id,
                recipient_id=creator_id,
                amount_cents=int(amount_cents),
                respond_by=respond_by,
                reason=reason,
            )
        except Exception:
            logger.warning("open_response_window: notify failed for %s", dispute_id, exc_info=True)
        audit_event("billing_dispute_response_invited", creator_id, None,
                    outcome="info", dispute_id=dispute_id, respond_by=respond_by)
    return {"status": item.get("status", STATE_NEEDS_RESPONSE), "respond_by": respond_by}


def record_creator_response(
    *,
    dispute_id: str,
    creator_id: str,
    response_text: str,
    evidence_files: Optional[List[str]] = None,
    now: Optional[int] = None,
) -> Dict[str, Any]:
    """DISP-012 (also backs DISP-021): the creator/seller rebuts within the
    window. A response while ``needs_response`` advances to ``under_review``
    (admin decides). A LATE response (after the sweep already moved it to
    ``under_review``/``escalated``) is NOT rejected — it is attached as a comment
    on the existing row (illegal state skip avoided), so the creator's evidence is
    never lost. Returns the updated item.
    """
    ts = int(now or now_ts())
    item = T.billing_disputes.get_item(Key=_dp_key(dispute_id)).get("Item")
    if not item:
        raise HTTPException(404, {"code": "dispute_not_found", "message": "Dispute not found"})
    status = str(item.get("status") or "")
    if status in TERMINAL_STATES:
        raise HTTPException(409, {"code": "dispute_terminal",
                                  "message": f"Dispute is {status}; no further response accepted."})

    comment = {
        "author": creator_id,
        "role": "creator",
        "text": (response_text or "")[:5000],
        "evidence_files": evidence_files or [],
        "ts": ts,
    }
    # Always append the rebuttal (auditable trail), regardless of window state.
    T.billing_disputes.update_item(
        Key=_dp_key(dispute_id),
        UpdateExpression=("SET creator_response = :ct, creator_responded_at = :ts, "
                          "responses = list_append(if_not_exists(responses, :empty), :one), "
                          "updated_at = :ts"),
        ExpressionAttributeValues={":ct": comment["text"], ":ts": ts,
                                   ":empty": [], ":one": [comment]},
    )

    # In-window response -> advance to under_review (admin decides). Late response
    # (already under_review/escalated) -> just the comment above (no transition).
    if status == STATE_NEEDS_RESPONSE:
        DD.guarded_dispute_transition(dispute_id, STATE_UNDER_REVIEW,
                                      expected_from=[STATE_NEEDS_RESPONSE])
        # DISP-050: tell the payer the counterparty responded + it is under review.
        try:
            from app.services import dispute_notify as DN
            DN.notify_creator_responded(dispute_id=dispute_id, payer_id=str(item.get("user_id") or "") or None)
        except Exception:
            logger.warning("record_creator_response: notify failed for %s", dispute_id, exc_info=True)

    audit_event("billing_dispute_creator_responded", creator_id, None,
                outcome="info", dispute_id=dispute_id, late=(status != STATE_NEEDS_RESPONSE))
    return T.billing_disputes.get_item(Key=_dp_key(dispute_id)).get("Item") or item


def _escalate_expired_dispute(item: Dict[str, Any], *, now_ts: int) -> bool:
    """A ``needs_response`` dispute whose ``respond_by`` elapsed with NO creator
    response advances to ``under_review`` (NOT auto-loss — the admin decides).
    Idempotent via the guarded transition. Returns True if it moved."""
    dispute_id = str(item.get("dispute_id") or "")
    if not dispute_id:
        return False
    changed, _ = DD.guarded_dispute_transition(
        dispute_id, STATE_UNDER_REVIEW,
        expected_from=[STATE_NEEDS_RESPONSE],
        extra={"sla_expired": True, "sla_expired_at": now_ts},
    )
    if changed:
        creator = item.get("creator_id") or item.get("recipient_id")
        payer = item.get("user_id")
        for uid, role in ((creator, "creator"), (payer, "payer")):
            if uid:
                write_alert(uid, event="dispute_sla_expired", outcome="warning",
                            title="Dispute moved to review (no response in time)",
                            details={"dispute_id": dispute_id, "role": role},
                            action_url=f"/billing/disputes/{dispute_id}")
        audit_event("billing_dispute_sla_expired", "system", None,
                    outcome="info", dispute_id=dispute_id)
    return changed


def sweep_expired_dispute_responses(*, now: Optional[int] = None, limit: int = 200) -> Dict[str, Any]:
    """DISP-012 SLA sweep (mirrors moderation_lifecycle.sweep_expired_holds).

    Every ``needs_response`` dispute whose ``respond_by`` elapsed WITHOUT a creator
    response auto-advances to ``under_review`` so it lands in the admin queue — it
    is NOT auto-refunded and NOT auto-lost; a human makes the call. Idempotent.

    Uses the ``ByStatusCreatedAt`` GSI to page ``needs_response`` rows (no
    dedicated respond_by GSI needed at user-track volumes) and filters on
    ``respond_by <= now``.
    """
    ts = int(now or now_ts())
    escalated: List[str] = []
    start_key = None
    scanned = 0
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByStatusCreatedAt",
            "KeyConditionExpression": Key("status_scope").eq(f"STATUS#{STATE_NEEDS_RESPONSE}"),
            "FilterExpression": Attr("respond_by").lte(ts),
            "Limit": 50,
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        try:
            resp = T.billing_disputes.query(**kwargs)
        except Exception:
            logger.exception("sweep_expired_dispute_responses: query failed")
            break
        for it in resp.get("Items", []):
            scanned += 1
            if scanned > limit:
                break
            did = str(it.get("dispute_id") or "")
            try:
                if _escalate_expired_dispute(it, now_ts=ts):
                    escalated.append(did)
            except Exception:
                logger.exception("sweep_expired_dispute_responses: failed on %s", did)
        start_key = resp.get("LastEvaluatedKey")
        if not start_key or scanned > limit:
            break
    if escalated:
        logger.info("dispute SLA sweep: advanced %d expired needs_response -> under_review",
                    len(escalated))
    return {"escalated": len(escalated), "dispute_ids": escalated}

"""Payment-disputes FRAUD/ABUSE wire + cross-track link (DISP E4: DISP-040/041/042).

This is the abuse-control + dedupe layer that must land BEFORE either dispute
track goes live. It does three things and NOTHING that moves money on its own:

* DISP-040  ``record_dispute_fraud_signal`` -- on a LOST/ACCEPTED processor
  chargeback (and a user-refunded/partial dispute, which is the same "the buyer
  got their money back off this charge" signal), feed the existing fraud engine:
  ``fraud_detection.record_chargeback`` (increments the risk row + auto-flags at
  the chargeback threshold) and, for an egregious repeat disputer, optionally
  ``freeze_user``. Idempotent per (charge) so a redelivered webhook never
  double-counts a chargeback.

* DISP-041  serial-disputer guards (user track) -- ``guard_new_dispute`` enforces
  a per-payer rolling-30d dispute cap (over-cap opens rejected) and classifies a
  repeat/losing disputer as "serial", who is flagged and ALWAYS routed to the
  admin queue (the auto-refund fast-path is suppressed -- a repeat offender is
  never auto-refunded).

* DISP-042  cross-track link/dedupe -- ``link_and_moot_on_processor_open`` is
  called the instant a processor ``charge.dispute.created`` lands: if a user
  dispute is already open on the SAME charge it is auto-mooted ("a processor
  chargeback opened") and the two records are cross-linked (``linked_dispute_id``
  both ways). The credit-flip mutex (E0) remains the actual no-double-debit
  enforcement point; this layer just makes the two tracks converge on ONE record
  and one admin view. Symmetrically, a user refund that already reversed the
  charge makes the later processor-LOST clawback a mutex no-op (already true in
  E0); here we also stamp the link so the admin board shows both under one charge.

Everything is real-now + mock-testable; no external key required.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event, write_alert

logger = logging.getLogger(__name__)


# ===========================================================================
# DISP-040 -- fraud signal wire
# ===========================================================================

def _fraud_marker_sk(kind: str, ref: str) -> str:
    return f"DISPUTE_FRAUDSIG#{kind}#{ref}"


def _claim_fraud_signal(payer_id: str, kind: str, ref: str) -> bool:
    """Idempotency claim so the SAME chargeback/refund never increments the fraud
    counter twice (webhook redelivery / resolve retry). Writes a marker on the
    payer's billing partition; returns True only for the first caller."""
    from app.services.billing_shared import user_pk
    from botocore.exceptions import ClientError
    try:
        T.billing.put_item(
            Item={"pk": user_pk(payer_id), "sk": _fraud_marker_sk(kind, ref),
                  "kind": kind, "ref": ref, "claimed_at": now_ts()},
            ConditionExpression="attribute_not_exists(sk)",
        )
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def record_dispute_fraud_signal(
    *,
    payer_id: str,
    amount_cents: int = 0,
    tx_id: str = "",
    kind: str = "chargeback",
    signal_ref: str = "",
    actor: str = "system",
) -> Dict[str, Any]:
    """DISP-040: feed the fraud engine when a charge is reversed against the payer.

    ``kind`` is ``chargeback`` (processor LOST/ACCEPTED) or ``user_refund`` (a
    user dispute resolved refunded/partial) -- both are a real "money came back off
    this payer's charge" abuse signal. Calls ``fraud_detection.record_chargeback``
    (increments the risk row, auto-flags at the chargeback threshold) exactly once
    per ``signal_ref`` (idempotent), then auto-freezes an egregious repeat
    disputer when ``S.dispute_fraud_autofreeze_chargebacks`` is reached.

    Returns ``{recorded, chargeback_count, auto_flagged, auto_frozen, flag_id}``.
    Best-effort by design: never raises into the money path.
    """
    if not payer_id:
        return {"recorded": False, "reason": "no_payer"}
    if not getattr(S, "dispute_fraud_signal_enabled", True):
        return {"recorded": False, "reason": "disabled"}

    ref = signal_ref or tx_id or ""
    # idempotency: one signal per (kind, ref). Fall back to always-record when we
    # have no stable ref (still safe -- record_chargeback is monotonic anyway, but
    # a ref lets a redelivery no-op cleanly).
    if ref and not _claim_fraud_signal(payer_id, kind, ref):
        logger.info("dispute fraud signal replay payer=%s kind=%s ref=%s", payer_id, kind, ref)
        return {"recorded": False, "idempotent_replay": True, "kind": kind, "ref": ref}

    try:
        from app.services import fraud_detection as FD
        res = FD.record_chargeback(user_id=payer_id, amount_cents=int(amount_cents or 0), tx_id=tx_id or ref)
    except Exception:
        logger.exception("record_dispute_fraud_signal: record_chargeback failed payer=%s", payer_id)
        return {"recorded": False, "error": True, "kind": kind, "ref": ref}

    cb_count = int(res.get("chargeback_count", 0) or 0)
    auto_frozen = False
    freeze_at = int(getattr(S, "dispute_fraud_autofreeze_chargebacks", 5) or 0)
    if freeze_at > 0 and cb_count >= freeze_at:
        try:
            from app.services import fraud_detection as FD
            FD.freeze_user(user_id=payer_id, admin_sub=actor,
                           reason=f"auto: {cb_count} disputes/chargebacks reversed")
            auto_frozen = True
        except Exception:
            logger.exception("record_dispute_fraud_signal: auto-freeze failed payer=%s", payer_id)

    audit_event("dispute_fraud_signal", actor, None, outcome="warning",
                payer_id=payer_id, kind=kind, ref=ref, chargeback_count=cb_count,
                auto_flagged=bool(res.get("auto_flagged")), auto_frozen=auto_frozen)
    return {
        "recorded": True,
        "kind": kind,
        "ref": ref,
        "chargeback_count": cb_count,
        "auto_flagged": bool(res.get("auto_flagged")),
        "flag_id": res.get("flag_id"),
        "auto_frozen": auto_frozen,
    }


# ===========================================================================
# DISP-041 -- serial-disputer guards (user track)
# ===========================================================================

def _disputes_last_30d(user_id: str) -> List[Dict[str, Any]]:
    """All of the payer's disputes opened in the rolling 30d window (any status),
    newest first, via the ByUserCreatedAt GSI."""
    from app.services import billing_disputes as BD
    since = now_ts() - 30 * 86400
    out: List[Dict[str, Any]] = []
    for d in BD.list_user_disputes(user_id, limit=100):
        if int(d.get("created_at", 0) or 0) >= since:
            out.append(d)
    return out


def dispute_stats(user_id: str) -> Dict[str, Any]:
    """DISP-041: rolling-30d dispute stats for a payer: total opened, how many
    resolved AGAINST them (denied) vs in their favor (refunded/partial), the
    win-rate, and whether they clear the serial-disputer threshold. Read-only."""
    recent = _disputes_last_30d(user_id)
    total = len(recent)
    won = lost = terminal = 0
    for d in recent:
        res = str(d.get("resolution") or "").strip().lower()
        if res in ("refunded", "partial"):
            won += 1
            terminal += 1
        elif res == "denied":
            lost += 1
            terminal += 1
    win_rate = (won / terminal) if terminal else None
    thr = int(getattr(S, "dispute_serial_disputer_threshold", 3) or 3)
    return {
        "user_id": user_id,
        "disputes_30d": total,
        "won_30d": won,          # resolved in payer's favor (refunded/partial)
        "lost_30d": lost,        # resolved against payer (denied)
        "terminal_30d": terminal,
        "win_rate_30d": win_rate,
        "serial_disputer": total >= thr,
        "serial_threshold": thr,
    }


def guard_new_dispute(user_id: str, *, actor: str = "system") -> Dict[str, Any]:
    """DISP-041: called at open time (from ``file_dispute``) BEFORE the row is
    written. Enforces the per-payer rolling-30d cap (over-cap -> 429) and returns
    the serial-disputer classification so the caller can suppress the auto-refund
    fast-path for a repeat offender.

    Returns ``{serial_disputer: bool, disputes_30d, ...}``. Raises 429 when the
    payer is over the monthly cap.
    """
    stats = dispute_stats(user_id)
    cap = int(getattr(S, "dispute_max_disputes_per_month", 5) or 5)
    if cap > 0 and stats["disputes_30d"] >= cap:
        audit_event("dispute_rate_limited", user_id, None, outcome="warning",
                    disputes_30d=stats["disputes_30d"], cap=cap)
        raise HTTPException(429, {"code": "dispute_rate_limited",
                                  "message": f"You have reached the limit of {cap} disputes in 30 days. "
                                             f"Contact support for further help."})
    if stats["serial_disputer"]:
        audit_event("dispute_serial_flagged", user_id, None, outcome="warning",
                    disputes_30d=stats["disputes_30d"],
                    threshold=stats["serial_threshold"], win_rate=stats["win_rate_30d"])
    return stats


# ===========================================================================
# DISP-042 -- cross-track link + auto-moot
# ===========================================================================

def _open_user_disputes_for_charge(charge_type: str, charge_ref: str,
                                   payer_id: Optional[str]) -> List[Dict[str, Any]]:
    """Every NON-terminal USER-track dispute on the same charge. Prefers the
    payer's ByUser GSI (cheap); falls back to scanning the open/needs_response/
    under_review/escalated status queues when the payer is unknown."""
    from app.services import billing_disputes as BD
    from app.services import dispute_lifecycle as DL
    ref = str(charge_ref or "")
    ct = str(charge_type or "")
    found: Dict[str, Dict[str, Any]] = {}

    def _match(d: Dict[str, Any]) -> bool:
        if str(d.get("source") or "user") != "user":
            return False
        if str(d.get("status") or "") not in DL.NON_TERMINAL_STATES:
            return False
        if str(d.get("charge_ref") or d.get("transaction_entry_id") or "") != ref:
            return False
        if ct and str(d.get("charge_type") or "") and str(d.get("charge_type")) != ct:
            return False
        return True

    if payer_id:
        for d in BD.list_user_disputes(payer_id, limit=100):
            if _match(d):
                found[str(d.get("dispute_id"))] = d
    else:
        for status in DL.NON_TERMINAL_STATES:
            for d in BD.list_disputes_by_status(status, limit=100):
                if _match(d):
                    found[str(d.get("dispute_id"))] = d
    return list(found.values())


def _stamp_link(dispute_id: str, other_id: str, *, extra: Optional[Dict[str, Any]] = None) -> None:
    names = {}
    vals: Dict[str, Any] = {":l": other_id, ":ts": now_ts()}
    set_clause = "linked_dispute_id = :l, updated_at = :ts"
    if extra:
        for i, (k, v) in enumerate(extra.items()):
            nk, vk = f"#l{i}", f":l{i}"
            names[nk] = k
            vals[vk] = v
            set_clause += f", {nk} = {vk}"
    kw: Dict[str, Any] = {
        "Key": {"pk": f"DISPUTE#{dispute_id}", "sk": "META"},
        "UpdateExpression": "SET " + set_clause,
        "ExpressionAttributeValues": vals,
    }
    if names:
        kw["ExpressionAttributeNames"] = names
    T.billing_disputes.update_item(**kw)


def link_and_moot_on_processor_open(
    incident: Dict[str, Any],
    *,
    actor: str = "processor",
) -> Dict[str, Any]:
    """DISP-042: called the instant a processor ``charge.dispute.created`` lands
    (from the chargeback reconciler's hold-on-open path). If a USER dispute is
    already open on the SAME charge, auto-moot it (guarded transition ->
    ``withdrawn`` with ``mooted_by_chargeback``) and cross-link the two records so
    the admin board shows both under one charge -- and, critically, so only ONE
    track drives the rail (the processor chargeback now owns the money move; the
    user dispute no longer resolves independently -> no double-debit).

    The credit-flip mutex still backstops double-debit even if this moot races;
    this makes the convergence explicit + auditable. Idempotent; never raises.

    Returns ``{linked, mooted_dispute_ids, incident_id}``.
    """
    from app.services import dispute_dispatch as DD
    from app.services import dispute_chargeback as CB
    from app.services import dispute_lifecycle as DL

    incident_id = str(incident.get("incident_id") or "")
    charge = CB.resolve_incident_charge(incident)
    if not charge:
        return {"linked": 0, "mooted_dispute_ids": [], "incident_id": incident_id,
                "resolvable": False}

    ct = str(charge.get("charge_type") or "")
    ref = str(charge.get("charge_ref") or "")
    payer = charge.get("payer_id")
    mooted: List[str] = []

    try:
        open_disputes = _open_user_disputes_for_charge(ct, ref, payer)
    except Exception:
        logger.exception("link_and_moot: open-dispute lookup failed incident=%s", incident_id)
        open_disputes = []

    for d in open_disputes:
        did = str(d.get("dispute_id") or "")
        if not did:
            continue
        try:
            # Auto-moot: guarded flip -> withdrawn. Marks WHY + links the incident.
            changed, _ = DD.guarded_dispute_transition(
                did, DL.STATE_WITHDRAWN,
                expected_from=list(DL.NON_TERMINAL_STATES),
                extra={
                    "mooted_by_chargeback": True,
                    "mooted_incident_id": incident_id,
                    "linked_dispute_id": f"incident:{incident_id}",
                    "withdrawn_at": now_ts(),
                    "withdrawn_by": "processor_chargeback",
                },
            )
            if changed:
                mooted.append(did)
                payer_uid = str(d.get("user_id") or "")
                if payer_uid:
                    write_alert(
                        payer_uid, event="dispute_superseded_by_chargeback", outcome="info",
                        title="Your dispute was taken over by your bank",
                        details={"dispute_id": did, "incident_id": incident_id},
                        action_url=f"/billing/disputes/{did}",
                    )
                audit_event("dispute_mooted_by_chargeback", actor, None, outcome="info",
                            dispute_id=did, incident_id=incident_id,
                            charge_type=ct, charge_ref=ref)
        except Exception:
            logger.exception("link_and_moot: moot failed dispute=%s incident=%s", did, incident_id)

    # Record the link on the incident side too (best-effort -- the incident store
    # is the processor track's record; we stamp a cross-ref marker on the payer
    # ledger partition so a reconciliation can join them).
    if mooted and payer:
        try:
            from app.services.billing_shared import user_pk
            T.billing.put_item(Item={
                "pk": user_pk(payer),
                "sk": f"DISPUTE_LINK#{ct}#{ref}",
                "incident_id": incident_id,
                "linked_user_disputes": mooted,
                "charge_type": ct, "charge_ref": ref,
                "linked_at": now_ts(),
            })
        except Exception:
            logger.warning("link_and_moot: link marker write failed incident=%s", incident_id, exc_info=True)

    return {"linked": len(mooted), "mooted_dispute_ids": mooted,
            "incident_id": incident_id, "charge_type": ct, "charge_ref": ref,
            "resolvable": True}

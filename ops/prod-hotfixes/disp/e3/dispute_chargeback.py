"""Payment-disputes PROCESSOR-TRACK chargeback reconciler (DISP E3: DISP-031..035).

The user-track resolver (E1) drives a rail when a human resolves a dispute.
This module is the parallel money layer for the PROCESSOR track: when the card
network / Stripe raises a chargeback, funds are pulled from us regardless of the
creator, and we must:

  * DISP-031  HOLD the contested funds the instant the dispute opens (flip the
    original creator credit state="held" so it drops out of the withdrawable
    balance) -- reversible, because a WON dispute must restore the exact credit.
  * DISP-032  assemble the evidence packet from the charge meta + creator
    rebuttal and stamp the response_due_at deadline (Stripe evidence_details
    .due_by); submitting to Stripe is the real-when-keyed adapter seam.
  * DISP-033  on LOST, drive the CORRECT rail in clawback_only mode (the
    processor already refunded the cardholder, so NO buyer refund + NO Stripe
    refund -- only the creator clawback + credit flip fire).
  * DISP-034  record a chargeback_fee non-credit ledger entry, atomic with
    the clawback, idempotent, creator-eats vs platform-eats per policy flag.
  * DISP-035  the LOST/WON/ACCEPTED reconciler: LOST/ACCEPTED convert held->
    reversed + fee; WON flips held->credit (restore) + clears the disputed flag.

Everything is real-now + mock-testable against the live DDB; the only
real-when-keyed pieces are the Stripe I/O (verify / Dispute.retrieve / evidence
submit / real fee lookup), which stay behind the rollout flags. When the
processor incident carries no resolvable internal charge (the charge_meta
coordinates), every ledger step is a safe no-op that still records audit -- so an
unmapped external charge never crashes the webhook.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import user_pk
from app.services.alerts import audit_event
from app.services import dispute_dispatch as DD

logger = logging.getLogger(__name__)


# =====================================================================
# charge-coordinate resolution (from charge_meta / payment_reference)
# =====================================================================

def resolve_incident_charge(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Best-effort: pull the internal charge coordinates the reconciler drives
    the ledger rail off of. Real-when-keyed we stamp
    charge_type/charge_ref/payer_id/recipient_id into the Stripe dispute.metadata
    at charge time; the mock webhook carries the same map. Falls back to the
    incident subscription_id / order_id. Returns {} when nothing resolvable."""
    meta = _incident_charge_meta(incident)
    ct = str(meta.get("charge_type") or "").strip().lower()
    ref = str(meta.get("charge_ref") or "")
    payer = meta.get("payer_id") or incident.get("customer_id")
    recipient = meta.get("recipient_id")
    if not ct and incident.get("subscription_id"):
        ct, ref = "subscription", str(incident.get("subscription_id"))
    if not ct and incident.get("order_id"):
        ct, ref = "ecom", str(incident.get("order_id"))
    if not ct or not ref:
        return {}
    out: Dict[str, Any] = {
        "charge_type": ct,
        "charge_ref": ref,
        "payer_id": str(payer) if payer and str(payer) != "unknown" else None,
        "recipient_id": str(recipient) if recipient else None,
    }
    if meta.get("ad_account_id"):
        out["ad_account_id"] = str(meta["ad_account_id"])
    if meta.get("video_id"):
        out["video_id"] = str(meta["video_id"])
    return out


def _incident_charge_meta(incident: Dict[str, Any]) -> Dict[str, Any]:
    m = incident.get("charge_meta")
    if isinstance(m, dict):
        return m
    return {}


def _chargeback_amount_cents(incident: Dict[str, Any]) -> int:
    try:
        return abs(int(float(str(incident.get("amount") or "0"))))
    except Exception:
        return 0


# =====================================================================
# DISP-031 -- HOLD on open
# =====================================================================

def _hold_marker_sk(incident_id: str) -> str:
    return f"CHARGEBACK_HOLD#{incident_id}"


def _find_original_credit_rows(charge: Dict[str, Any]) -> List[Dict[str, Any]]:
    ct = charge["charge_type"]
    ref = charge["charge_ref"]
    recipient = charge.get("recipient_id")
    rows: List[Dict[str, Any]] = []
    try:
        if ct in ("tip", "message") and recipient:
            from app.services.tips import _find_tip_credit_row
            r = _find_tip_credit_row(recipient, ref)
            if r:
                rows.append(r)
        elif ct == "subscription":
            from app.routers.subscription_server import _find_subscription_credit_row
            rec = recipient
            if not rec:
                from app.routers.subscription_server import ddb_get_item, pk_subscription
                sub = ddb_get_item(pk_subscription(ref), "META") or {}
                rec = sub.get("creator_id")
            if rec:
                r = _find_subscription_credit_row(rec, ref)
                if r:
                    rows.append(r)
        elif ct == "vod" and recipient:
            from app.services.vod_purchase import _find_vod_credit_row
            r = _find_vod_credit_row(recipient, ref)
            if r:
                rows.append(r)
        elif ct == "ecom":
            rows.extend(_find_ecom_credit_rows(charge))
        elif ct == "ad" and recipient:
            rows.extend(_scan_credit_rows_by_meta(recipient, charge_ref=ref))
    except Exception:
        logger.warning("chargeback: original-credit lookup failed ct=%s ref=%s", ct, ref, exc_info=True)
    return rows


def _find_ecom_credit_rows(charge: Dict[str, Any]) -> List[Dict[str, Any]]:
    payer = charge.get("payer_id")
    ref = charge["charge_ref"]
    if not payer:
        return []
    debit = None
    for row in _iter_ledger(payer):
        if str(row.get("sk", "")).startswith("LEDGER#") and row.get("entry_id") == ref:
            debit = row
            break
    if not debit:
        return []
    dmeta = debit.get("meta") or {}
    order_id = dmeta.get("order_id")
    if not order_id:
        return []
    parties: List[str] = []
    for cand in ([dmeta.get("recipient_user_id")] + list(dmeta.get("refund_seller_ids") or []) + [dmeta.get("refund_host_id")]):
        if cand and cand != payer and cand not in parties:
            parties.append(cand)
    out: List[Dict[str, Any]] = []
    for party in parties:
        for e in _iter_ledger(party):
            if not str(e.get("sk", "")).startswith("LEDGER#"):
                continue
            if str(e.get("type") or "") != "credit":
                continue
            if str((e.get("meta") or {}).get("order_id") or "") != str(order_id):
                continue
            out.append(e)
    return out


def _scan_credit_rows_by_meta(user_id: str, *, charge_ref: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for e in _iter_ledger(user_id):
        if not str(e.get("sk", "")).startswith("LEDGER#"):
            continue
        if str(e.get("type") or "") != "credit":
            continue
        m = e.get("meta") or {}
        if charge_ref and charge_ref in (str(m.get("entry_id") or ""), str(e.get("entry_id") or ""), str(m.get("campaign_id") or "")):
            out.append(e)
    return out


def _iter_ledger(user_id: str) -> List[Dict[str, Any]]:
    pk = user_pk(user_id)
    items: List[Dict[str, Any]] = []
    last = None
    while True:
        kw: Dict[str, Any] = {"KeyConditionExpression": "pk = :pk", "ExpressionAttributeValues": {":pk": pk}}
        if last:
            kw["ExclusiveStartKey"] = last
        resp = T.billing.query(**kw)
        items.extend(resp.get("Items", []))
        last = resp.get("LastEvaluatedKey")
        if not last:
            break
    return items


# A "live" (spendable) credit carries state settled/absent — NOT the literal
# string "credit" (that is the *type*). HELD drops it out of the balance; on WON
# it goes back to its original state, on LOST to "reversed".
_LIVE_CREDIT_STATES = ("settled", "", "available", "cleared")


def _set_credit_state(row: Dict[str, Any], new_state: str, *, expect_state: Optional[str] = None) -> bool:
    """Flip one credit row's ``state`` guarded so hold/restore/reverse are safe
    under redelivery. ``expect_state="__live__"`` means "only a live (non-held,
    non-reversed) credit" (settled/absent); otherwise an exact match."""
    cond = "attribute_exists(sk)"
    names = {"#s": "state"}
    vals: Dict[str, Any] = {":ns": new_state}
    if expect_state == "__live__":
        cond += " AND (attribute_not_exists(#s) OR (#s <> :held AND #s <> :rev))"
        vals[":held"] = "held"
        vals[":rev"] = "reversed"
    elif expect_state is not None:
        cond += " AND #s = :es"
        vals[":es"] = expect_state
    try:
        T.billing.update_item(
            Key={"pk": row["pk"], "sk": row["sk"]},
            UpdateExpression="SET #s = :ns",
            ConditionExpression=cond,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=vals,
        )
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def hold_charge_on_open(incident: Dict[str, Any], *, actor: str = "processor") -> Dict[str, Any]:
    """DISP-031: on opened, flip the original creator/seller credit row(s) to
    state="held" (drops out of get_available_balance) + write a
    CHARGEBACK_HOLD#{incident} marker (idempotent across created/funds_withdrawn
    redelivery). No-op (records audit) for an unmapped charge."""
    incident_id = str(incident.get("incident_id") or "")
    charge = resolve_incident_charge(incident)
    payer_anchor = charge.get("payer_id") or incident.get("customer_id") or "system"

    marker_sk = _hold_marker_sk(incident_id)
    prior = T.billing.get_item(Key={"pk": user_pk(payer_anchor), "sk": marker_sk}).get("Item")
    if prior:
        return {**{k: v for k, v in prior.items() if k not in ("pk", "sk")}, "idempotent_replay": True}

    held_rows: List[str] = []
    held_detail: List[Dict[str, Any]] = []
    held_cents = 0
    if charge:
        for row in _find_original_credit_rows(charge):
            prior_state = str(row.get("state") or "")
            if prior_state in ("reversed", "held"):
                continue  # already clawed by a user refund, or already held
            if _set_credit_state(row, "held", expect_state="__live__"):
                sk = str(row.get("sk"))
                held_rows.append(sk)
                # remember the ORIGINAL state so a WON can restore it exactly.
                held_detail.append({"sk": sk, "pk": str(row.get("pk")), "prior_state": prior_state})
                held_cents += abs(int(row.get("amount_cents", 0) or 0))

    receipt = {
        "incident_id": incident_id,
        "charge_type": charge.get("charge_type"),
        "charge_ref": charge.get("charge_ref"),
        "held_credit_sks": held_rows,
        "held_credit_detail": held_detail,
        "held_cents": held_cents,
        "resolvable": bool(charge),
        "created_at": now_ts(),
        "idempotent_replay": False,
    }
    try:
        T.billing.put_item(
            Item={"pk": user_pk(payer_anchor), "sk": marker_sk, **receipt},
            ConditionExpression="attribute_not_exists(sk)",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            winner = T.billing.get_item(Key={"pk": user_pk(payer_anchor), "sk": marker_sk}).get("Item") or receipt
            return {**{k: v for k, v in winner.items() if k not in ("pk", "sk")}, "idempotent_replay": True}
        raise
    audit_event("chargeback_hold_placed", actor, None, outcome="info",
                incident_id=incident_id, held_cents=held_cents,
                charge_type=charge.get("charge_type"), resolvable=bool(charge))
    logger.info("chargeback_hold incident=%s held_cents=%s rows=%d resolvable=%s",
                incident_id, held_cents, len(held_rows), bool(charge))
    return receipt


# =====================================================================
# DISP-032 -- evidence assembler + response window
# =====================================================================

def build_dispute_evidence(incident: Dict[str, Any], *, creator_rebuttal: str = "") -> Dict[str, Any]:
    """DISP-032: assemble the Stripe evidence packet from the charge meta +
    creator rebuttal. Field names mirror Stripe dispute.evidence."""
    meta = _incident_charge_meta(incident)
    return {
        "product_description": str(meta.get("product_description") or meta.get("charge_type") or "digital service"),
        "receipt": str(meta.get("receipt") or meta.get("charge_ref") or ""),
        "customer_name": str(meta.get("customer_name") or ""),
        "customer_email_address": str(meta.get("customer_email") or ""),
        "service_date": str(meta.get("service_date") or ""),
        "billing_address": str(meta.get("billing_address") or ""),
        "customer_purchase_ip": str(meta.get("purchase_ip") or ""),
        "uncategorized_text": (creator_rebuttal or str(meta.get("creator_rebuttal") or ""))[:20000],
    }


def response_due_at(incident: Dict[str, Any]) -> Optional[int]:
    """DISP-032: the response deadline. Prefer Stripe evidence_details.due_by,
    else fall back to the configured response window."""
    meta = _incident_charge_meta(incident)
    for src in (incident.get("due_by"), meta.get("due_by")):
        if src:
            try:
                return int(src)
            except Exception:
                pass
    window_days = int(getattr(S, "dispute_response_window_days", 7))
    return now_ts() + window_days * 86400


# =====================================================================
# DISP-034 -- chargeback_fee ledger entry
# =====================================================================

def chargeback_fee_cents(incident: Dict[str, Any]) -> int:
    """Real-when-keyed: the Stripe balance_transactions fee (charge_meta.fee_cents).
    Else the configured flat default (Stripe $15)."""
    meta = _incident_charge_meta(incident)
    if meta.get("fee_cents"):
        try:
            return abs(int(meta["fee_cents"]))
        except Exception:
            pass
    return max(0, int(getattr(S, "dispute_chargeback_fee_cents", 1500)))


def _fee_bearer(charge: Dict[str, Any]) -> Optional[str]:
    policy = str(getattr(S, "dispute_chargeback_fee_policy", "creator_eats")).strip().lower()
    if policy == "platform_eats":
        return None
    return charge.get("recipient_id")


def build_chargeback_fee_item(incident: Dict[str, Any], charge: Dict[str, Any], *, ts: int) -> Optional[Dict[str, Any]]:
    """Build the chargeback_fee ledger row (type != "credit" -> excluded from
    earnings by the existing balance credit filter). None when fee 0."""
    fee = chargeback_fee_cents(incident)
    if fee <= 0:
        return None
    bearer = _fee_bearer(charge)
    pk = user_pk(bearer) if bearer else "PLATFORM#revenue"
    from uuid import uuid4
    fee_id = uuid4().hex
    return {
        "pk": pk,
        "sk": f"LEDGER#{ts}#{fee_id}",
        "entry_id": fee_id,
        "ts": ts,
        "type": "chargeback_fee",
        "amount_cents": int(fee),
        "currency": str(incident.get("currency") or "usd"),
        "state": "settled",
        "reason": "Chargeback fee",
        "meta": {
            "content_type": "chargeback_fee",
            "incident_id": str(incident.get("incident_id") or ""),
            "charge_type": charge.get("charge_type"),
            "charge_ref": charge.get("charge_ref"),
            "policy": str(getattr(S, "dispute_chargeback_fee_policy", "creator_eats")),
        },
    }


# =====================================================================
# DISP-035 -- LOST / WON / ACCEPTED reconciler
# =====================================================================

def _release_marker_sk(incident_id: str) -> str:
    return f"CHARGEBACK_RELEASE#{incident_id}"


def _lost_marker_sk(incident_id: str) -> str:
    return f"CHARGEBACK_LOST#{incident_id}"


def reconcile_terminal(incident: Dict[str, Any], outcome: str, *, actor: str = "processor") -> Dict[str, Any]:
    """DISP-035: LOST/ACCEPTED -> clawback-only rail + held->reversed + fee;
    WON -> held->credit restore. Idempotent per incident. Gated by
    S.dispute_chargeback_reconcile_enabled."""
    incident_id = str(incident.get("incident_id") or "")
    outcome = (outcome or "").strip().lower()
    charge = resolve_incident_charge(incident)
    payer_anchor = charge.get("payer_id") or incident.get("customer_id") or "system"

    if not getattr(S, "dispute_chargeback_reconcile_enabled", True):
        audit_event("chargeback_reconcile_skipped", actor, None, outcome="info",
                    incident_id=incident_id, reason="reconcile_disabled", terminal=outcome)
        return {"incident_id": incident_id, "outcome": outcome, "skipped": "reconcile_disabled"}

    if outcome == "won":
        return _reconcile_won(incident, charge, payer_anchor, actor=actor)
    if outcome in ("lost", "accepted"):
        return _reconcile_lost(incident, charge, payer_anchor, outcome=outcome, actor=actor)
    return {"incident_id": incident_id, "outcome": outcome, "skipped": "non_terminal"}


def _hold_marker(incident_id: str, payer_anchor: str) -> Dict[str, Any]:
    return T.billing.get_item(Key={"pk": user_pk(payer_anchor), "sk": _hold_marker_sk(incident_id)}).get("Item") or {}


def _held_detail_from_marker(incident_id: str, payer_anchor: str) -> List[Dict[str, Any]]:
    """The per-row hold detail [{pk, sk, prior_state}] recorded at hold time (so a
    WON restores each row to its EXACT original state)."""
    marker = _hold_marker(incident_id, payer_anchor)
    detail = marker.get("held_credit_detail")
    if detail:
        return list(detail)
    # legacy marker without detail -> synthesize from sks (restore to settled).
    return [{"sk": sk, "pk": None, "prior_state": "settled"} for sk in (marker.get("held_credit_sks") or [])]


def _reconcile_won(incident: Dict[str, Any], charge: Dict[str, Any], payer_anchor: str, *, actor: str) -> Dict[str, Any]:
    incident_id = str(incident.get("incident_id") or "")
    rel_sk = _release_marker_sk(incident_id)
    prior = T.billing.get_item(Key={"pk": user_pk(payer_anchor), "sk": rel_sk}).get("Item")
    if prior:
        return {**{k: v for k, v in prior.items() if k not in ("pk", "sk")}, "idempotent_replay": True}

    restored: List[str] = []
    recipient = charge.get("recipient_id")
    for d in _held_detail_from_marker(incident_id, payer_anchor):
        sk = d.get("sk")
        pk = d.get("pk") or (user_pk(recipient) if recipient else None)
        prior_state = str(d.get("prior_state") or "settled")
        if not sk or not pk:
            continue
        row = T.billing.get_item(Key={"pk": pk, "sk": sk}).get("Item")
        # inverse of the hold: held -> its ORIGINAL state (exact restore).
        if row and _set_credit_state(row, prior_state, expect_state="held"):
            restored.append(sk)
    if not restored and charge:
        # fallback: restore any still-held row we can find for the charge.
        for row in _find_original_credit_rows(charge):
            if str(row.get("state") or "") == "held" and _set_credit_state(row, "settled", expect_state="held"):
                restored.append(str(row.get("sk")))

    receipt = {
        "incident_id": incident_id, "outcome": "won",
        "restored_credit_sks": restored, "restored_count": len(restored),
        "created_at": now_ts(), "idempotent_replay": False,
    }
    try:
        T.billing.put_item(Item={"pk": user_pk(payer_anchor), "sk": rel_sk, **receipt},
                           ConditionExpression="attribute_not_exists(sk)")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            winner = T.billing.get_item(Key={"pk": user_pk(payer_anchor), "sk": rel_sk}).get("Item") or receipt
            return {**{k: v for k, v in winner.items() if k not in ("pk", "sk")}, "idempotent_replay": True}
        raise
    audit_event("chargeback_won_released", actor, None, outcome="info",
                incident_id=incident_id, restored=len(restored))
    return receipt


def _reconcile_lost(incident: Dict[str, Any], charge: Dict[str, Any], payer_anchor: str, *, outcome: str, actor: str) -> Dict[str, Any]:
    incident_id = str(incident.get("incident_id") or "")
    lost_sk = _lost_marker_sk(incident_id)
    prior = T.billing.get_item(Key={"pk": user_pk(payer_anchor), "sk": lost_sk}).get("Item")
    if prior:
        return {**{k: v for k, v in prior.items() if k not in ("pk", "sk")}, "idempotent_replay": True}

    ts = now_ts()
    rail_receipt: Dict[str, Any] = {}
    fee_written = 0
    reason = f"chargeback_{outcome}"

    if charge and charge.get("charge_type") and charge.get("charge_ref"):
        try:
            rail_receipt = DD.dispatch_reversal(
                charge_type=charge["charge_type"],
                charge_ref=charge["charge_ref"],
                payer_id=charge.get("payer_id"),
                recipient_id=charge.get("recipient_id"),
                ad_account_id=charge.get("ad_account_id"),
                video_id=charge.get("video_id"),
                clawback_only=True,
                reason=reason,
                actor=f"chargeback:{incident_id}",
                use_mutex=True,
            )
        except Exception as exc:
            logger.exception("chargeback clawback rail failed incident=%s", incident_id)
            rail_receipt = {"error": str(exc)}

        # Backstop: any credit still "held" (the rail may key its flip off a
        # different row, or the mutex made the rail a replay) -> reversed now, so
        # a LOST never leaves contested funds in the recoverable "held" limbo.
        for d in _held_detail_from_marker(incident_id, payer_anchor):
            sk = d.get("sk")
            pk = d.get("pk") or (user_pk(charge["recipient_id"]) if charge.get("recipient_id") else None)
            if not sk or not pk:
                continue
            row = T.billing.get_item(Key={"pk": pk, "sk": sk}).get("Item")
            if row and str(row.get("state")) == "held":
                _set_credit_state(row, "reversed", expect_state="held")

        fee_item = build_chargeback_fee_item(incident, charge, ts=ts)
        if fee_item is not None:
            try:
                T.billing.put_item(Item=fee_item)
                fee_written = int(fee_item["amount_cents"])
            except Exception:
                logger.warning("chargeback fee write failed incident=%s", incident_id, exc_info=True)

    receipt = {
        "incident_id": incident_id, "outcome": outcome,
        "clawback_only": True,
        "rail": charge.get("charge_type"),
        "rail_mutex_won": bool(rail_receipt.get("mutex_won", False)),
        "rail_idempotent": bool(rail_receipt.get("idempotent_replay", False)),
        "clawback_cents": int(rail_receipt.get("clawback_cents", rail_receipt.get("creator_clawback_cents", 0)) or 0),
        "chargeback_fee_cents": fee_written,
        "resolvable": bool(charge),
        "created_at": ts, "idempotent_replay": False,
    }
    try:
        T.billing.put_item(Item={"pk": user_pk(payer_anchor), "sk": lost_sk, **receipt},
                           ConditionExpression="attribute_not_exists(sk)")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            winner = T.billing.get_item(Key={"pk": user_pk(payer_anchor), "sk": lost_sk}).get("Item") or receipt
            return {**{k: v for k, v in winner.items() if k not in ("pk", "sk")}, "idempotent_replay": True}
        raise
    audit_event("chargeback_lost_reconciled", actor, None, outcome="warning",
                incident_id=incident_id, outcome_terminal=outcome,
                clawback_cents=receipt["clawback_cents"], fee_cents=fee_written,
                resolvable=bool(charge))
    logger.info("chargeback_%s incident=%s clawback=%s fee=%s resolvable=%s",
                outcome, incident_id, receipt["clawback_cents"], fee_written, bool(charge))
    return receipt


# =====================================================================
# webhook entrypoint -- called from billing.py after a transition lands
# =====================================================================

_TERMINAL = {"won", "lost", "accepted"}


def on_incident_transition(incident: Dict[str, Any], *, target_status: str, source_event_type: str = "",
                           actor: str = "processor") -> Dict[str, Any]:
    """Single reconciler seam the webhook calls after each LIVE (non-shadow)
    dispute/chargeback transition commits. Routes to hold-on-open or the
    LOST/WON/ACCEPTED reconciler. Idempotent; never raises into the webhook."""
    incident_type = str(incident.get("incident_type") or "")
    if incident_type not in ("dispute", "chargeback"):
        return {"skipped": "not_a_dispute"}
    status = (target_status or "").strip().lower()
    try:
        if status == "opened":
            return {"hold": hold_charge_on_open(incident, actor=actor)}
        if status in _TERMINAL:
            return {"reconcile": reconcile_terminal(incident, status, actor=actor)}
    except Exception:
        logger.exception("chargeback reconciler failed incident=%s status=%s",
                         incident.get("incident_id"), status)
        return {"error": True, "status": status}
    return {"skipped": status}

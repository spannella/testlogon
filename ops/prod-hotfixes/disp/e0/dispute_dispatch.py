"""Payment-disputes reversal-rail dispatcher (DISP E0: DISP-002/003/005).

This is the money-correctness core of the payment-disputes program. It does NOT
own any dispute UI or lifecycle — it is the seam that BOTH dispute tracks
(user-level ``billing_disputes`` and processor-level ``PaymentIncident``)
converge on when a resolution actually moves money.

Central defect it closes: today NEITHER dispute stack touches the shared
``T.billing`` ledger. This module wires a resolved dispute to the CORRECT
EXISTING reversal rail for the underlying charge type, so money REALLY moves,
entitlement/access is revoked, the creator credit is clawed back
(``type != "credit"`` + original credit flipped ``state="reversed"``, never
inflating earnings), and every path is idempotent.

Contents
--------
* ``resolve_charge``  (DISP-002) — charge_ref + charge_type -> the ledger rows +
  the dispatch params each rail needs.
* ``dispatch_reversal`` (DISP-003) — one function: charge_type -> the right rail
  (tip/message -> ``reverse_tip_by_payment_id``, subscription ->
  ``_reverse_subscription_charge``, ad -> ``reverse_ad_charge``, ecom ->
  ``refund_requests`` create+approve, vod -> ``reverse_vod_purchase``), with
  full/partial amount, idempotent.
* ``claim_charge_reversal_mutex`` + ``guarded_dispute_transition`` (DISP-005) —
  the credit-flip mutex primitive so a charge cannot be reversed twice (a user
  refund and a processor chargeback on the SAME charge can never double-debit),
  and the guarded, act-after-guard dispute status wrapper.

Nothing here reinvents a rail; it dispatches to the six shipped rails. No
external key is required (all ledger reconciliation is real-now); the rails'
own best-effort Stripe legs stay real-when-keyed.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import user_pk

logger = logging.getLogger(__name__)

# Canonical charge types the dispatcher understands. ``message`` (pay-to-message)
# rides the tip rail (tips.py stores it with content_type="message").
CHARGE_TYPES = ("tip", "message", "subscription", "ad", "ecom", "vod")

# v1 partial-amount support: only rails with a native partial/proration path.
# ecom uses override_amount_cents on approve_request; subscription uses
# refund_fraction. tip/ad/vod are full-amount-only in v1 (DISP-003 AC).
_PARTIAL_CAPABLE = ("ecom", "subscription")


# ---------------------------------------------------------------------------
# DISP-002 — Charge resolver
# ---------------------------------------------------------------------------

def _iter_ledger(user_id: str) -> List[Dict[str, Any]]:
    pk = user_pk(user_id)
    items: List[Dict[str, Any]] = []
    last = None
    while True:
        kw: Dict[str, Any] = {
            "KeyConditionExpression": "pk = :pk",
            "ExpressionAttributeValues": {":pk": pk},
        }
        if last:
            kw["ExclusiveStartKey"] = last
        resp = T.billing.query(**kw)
        items.extend(resp.get("Items", []))
        last = resp.get("LastEvaluatedKey")
        if not last:
            break
    return items


def _find_ledger_row(user_id: str, *, entry_id: Optional[str] = None,
                     meta_key: Optional[str] = None, meta_val: Optional[str] = None,
                     want_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
    for row in _iter_ledger(user_id):
        if not str(row.get("sk", "")).startswith("LEDGER#"):
            continue
        if entry_id is not None and row.get("entry_id") != entry_id:
            continue
        if want_type is not None and str(row.get("type", "")) != want_type:
            continue
        if meta_key is not None:
            if (row.get("meta") or {}).get(meta_key) != meta_val:
                continue
        return row
    return None


def resolve_charge(
    charge_ref: str,
    charge_type: str,
    *,
    payer_id: Optional[str] = None,
    recipient_id: Optional[str] = None,
) -> Dict[str, Any]:
    """DISP-002: given a charge reference + its type, return the dispatch params
    the correct reversal rail needs.

    ``charge_ref`` semantics per type (the id the rail reverses off of):
      * tip / message : tip_payment_id           (tips ledger meta.tip_payment_id)
      * subscription  : subscription_id          (SUB#{id} META)
      * ad            : ad ledger entry_id        (needs ad ``account_id`` too)
      * ecom          : buyer-debit transaction entry_id (T.billing entry_id)
      * vod           : purchase_id               (vod_entitlements / ledger meta)

    Returns a dict always carrying ``charge_type`` + ``charge_ref``, plus the
    per-type fields the dispatcher forwards to the rail, and (best-effort) the
    ledger rows + counterpart parties. Raises 400 for an unknown charge_type.
    Never moves money.
    """
    ct = (charge_type or "").strip().lower()
    if ct not in CHARGE_TYPES:
        raise HTTPException(400, {"code": "unknown_charge_type", "message": f"Unknown charge_type {charge_type!r}."})
    if not charge_ref:
        raise HTTPException(400, {"code": "missing_charge_ref", "message": "charge_ref is required."})

    out: Dict[str, Any] = {
        "charge_type": ct,
        "charge_ref": charge_ref,
        "content_type": ct,
        "payer_id": payer_id,
        "recipient_id": recipient_id,
        "ledger_rows": [],
        "partial_capable": ct in _PARTIAL_CAPABLE,
    }

    if ct in ("tip", "message"):
        out["content_type"] = ct if ct == "message" else "tip"
        out["tip_payment_id"] = charge_ref
        if payer_id:
            debit = _find_ledger_row(payer_id, meta_key="tip_payment_id", meta_val=charge_ref, want_type="debit")
            if debit:
                m = debit.get("meta") or {}
                out["ledger_rows"].append(debit)
                out["recipient_id"] = recipient_id or m.get("recipient_user_id")
                out["gross_cents"] = int(debit.get("amount_cents", 0) or 0)
        return out

    if ct == "subscription":
        out["subscription_id"] = charge_ref
        try:
            from app.routers.subscription_server import ddb_get_item, pk_subscription, normalize_subscription
            sub = ddb_get_item(pk_subscription(charge_ref), "META")
            if sub:
                sub = normalize_subscription(sub)
                out["subscription"] = sub
                out["recipient_id"] = recipient_id or sub.get("creator_id")
                out["payer_id"] = payer_id or sub.get("gifter_id") or sub.get("subscriber_id")
                out["period_end"] = int(sub.get("current_period_end") or 0)
        except Exception:
            logger.warning("resolve_charge: subscription %s lookup failed", charge_ref, exc_info=True)
        return out

    if ct == "ad":
        # ad charges reverse off (account_id, entry_id). account_id is the payer's
        # ad account; caller passes it as payer_id (advertiser account id) OR we
        # leave it for the dispatcher to require.
        out["ad_entry_id"] = charge_ref
        out["ad_account_id"] = payer_id or recipient_id  # advertiser account
        return out

    if ct == "ecom":
        out["transaction_entry_id"] = charge_ref
        if payer_id:
            debit = _find_ledger_row(payer_id, entry_id=charge_ref)
            if debit:
                out["ledger_rows"].append(debit)
                out["gross_cents"] = abs(int(debit.get("amount_cents", 0) or 0))
                out["order_id"] = (debit.get("meta") or {}).get("order_id")
        return out

    # vod
    out["purchase_id"] = charge_ref
    if payer_id:
        debit = _find_ledger_row(payer_id, meta_key="purchase_id", meta_val=charge_ref, want_type="vod_purchase_debit")
        if debit:
            m = debit.get("meta") or {}
            out["ledger_rows"].append(debit)
            out["recipient_id"] = recipient_id or m.get("seller_id")
            out["video_id"] = m.get("video_id")
            out["gross_cents"] = abs(int(debit.get("amount_cents", 0) or 0))
    return out


# ---------------------------------------------------------------------------
# DISP-005 — credit-flip mutex + guarded transition
# ---------------------------------------------------------------------------

def _mutex_sk(charge_type: str, charge_ref: str) -> str:
    return f"CHARGEMUTEX#{charge_type}#{charge_ref}"


def claim_charge_reversal_mutex(
    charge_type: str,
    charge_ref: str,
    *,
    owner: str,
    anchor_user_id: str,
) -> Tuple[bool, Dict[str, Any]]:
    """DISP-005: the cross-track credit-flip mutex. Returns ``(won, marker)``.

    Exactly ONE caller can ever win the right to reverse a given charge: the
    winner writes a ``CHARGEMUTEX#{type}#{ref}`` marker (conditional put on the
    anchor user's billing partition) and gets ``won=True``; any later caller
    (a second user refund, or a processor chargeback on the same charge) reads
    the stored marker and gets ``won=False`` — it MUST NOT fire the rail, so a
    user refund and a processor chargeback on the same charge can never
    double-debit. The rails are ALSO individually idempotent on their own markers
    (TIPREVERSAL#/SUBREVERSAL#/REVERSAL#/VODREVERSAL#); this mutex is the
    cross-track guard on TOP of that.

    ``anchor_user_id`` is the billing partition the marker lives on (the payer for
    most charges) so the conditional put is atomic against that partition.
    """
    sk = _mutex_sk(charge_type, charge_ref)
    ts = now_ts()
    item = {
        "pk": user_pk(anchor_user_id),
        "sk": sk,
        "charge_type": charge_type,
        "charge_ref": charge_ref,
        "owner": owner,
        "claimed_at": ts,
    }
    try:
        T.billing.put_item(Item=item, ConditionExpression="attribute_not_exists(sk)")
        return True, item
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            prior = T.billing.get_item(Key={"pk": user_pk(anchor_user_id), "sk": sk}).get("Item") or item
            return False, prior
        raise


def guarded_dispute_transition(
    dispute_id: str,
    to_status: str,
    *,
    expected_from: Optional[List[str]] = None,
    table: Any = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """DISP-005: act-after-guard dispute status wrapper (mirrors
    ``moderation_case.transition_result``).

    Performs a CONDITIONAL update that flips ``status`` from its current value to
    ``to_status`` only when the row is still in an ``expected_from`` state and is
    not already ``to_status``. Returns ``(changed, item)``. The money-moving rail
    must fire ONLY when ``changed=True`` — so a concurrent double-resolve /
    withdraw-vs-resolve yields exactly one money move; the loser is a no-op
    returning the stored record.

    ``table`` defaults to ``T.billing_disputes`` (the unified dispute table);
    ``pk=DISPUTE#{id}, sk=META``.
    """
    tbl = table if table is not None else T.billing_disputes
    ts = now_ts()
    key = {"pk": f"DISPUTE#{dispute_id}", "sk": "META"}
    cur = tbl.get_item(Key=key).get("Item")
    if cur is None:
        raise HTTPException(404, {"code": "dispute_not_found", "message": f"Dispute {dispute_id} not found."})
    frm = str(cur.get("status") or "")
    if frm == to_status:
        return False, cur
    if expected_from is not None and frm not in set(expected_from):
        # illegal skip -> reject BEFORE any side-effect
        raise HTTPException(409, {"code": "illegal_transition",
                                  "message": f"Dispute {dispute_id} is {frm!r}, not one of {list(expected_from)}."})

    names = {"#s": "status", "#ss": "status_scope"}
    vals: Dict[str, Any] = {":to": to_status, ":ts": ts, ":scope": f"STATUS#{to_status}"}
    set_clause = "#s = :to, #ss = :scope, updated_at = :ts"
    cond = "attribute_exists(sk) AND #s = :from"
    vals[":from"] = frm
    if extra:
        for i, (k, v) in enumerate(extra.items()):
            nk, vk = f"#e{i}", f":e{i}"
            names[nk] = k
            vals[vk] = v
            set_clause += f", {nk} = {vk}"
    try:
        resp = tbl.update_item(
            Key=key,
            UpdateExpression="SET " + set_clause,
            ConditionExpression=cond,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=vals,
            ReturnValues="ALL_NEW",
        )
        return True, resp.get("Attributes", {})
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            # lost the race -> return the current stored row, changed=False
            latest = tbl.get_item(Key=key).get("Item") or cur
            return False, latest
        raise


# ---------------------------------------------------------------------------
# DISP-003 — Reversal-rail dispatcher
# ---------------------------------------------------------------------------

def _rail_tip(params: Dict[str, Any], *, override_amount_cents: Optional[int],
              clawback_only: bool, reason: str, actor: Optional[str]) -> Dict[str, Any]:
    if override_amount_cents is not None:
        raise HTTPException(400, {"code": "partial_unsupported",
                                  "message": "Partial reversal is not supported for tip/message charges in v1."})
    if clawback_only:
        # E3 chargeback fork lands the clawback-only variant; E0 dispatches the
        # full (buyer-refunding) rail only.
        raise HTTPException(501, {"code": "clawback_only_unsupported",
                                  "message": "tip clawback-only fork lands in E3 (DISP-033)."})
    from app.services.tips import reverse_tip_by_payment_id
    payer = params.get("payer_id")
    if not payer:
        raise HTTPException(400, {"code": "missing_payer", "message": "payer_id (tipper) is required to reverse a tip."})
    res = reverse_tip_by_payment_id(
        tip_payment_id=params["tip_payment_id"],
        tipper_id=payer,
        recipient_id=params.get("recipient_id"),
        reason=reason,
        actor=actor,
    )
    # ReversalResult dataclass -> dict
    from dataclasses import asdict, is_dataclass
    return asdict(res) if is_dataclass(res) else dict(res)


def _rail_subscription(params: Dict[str, Any], *, override_amount_cents: Optional[int],
                       clawback_only: bool, reason: str, actor: Optional[str]) -> Dict[str, Any]:
    if clawback_only:
        raise HTTPException(501, {"code": "clawback_only_unsupported",
                                  "message": "subscription clawback-only fork lands in E3 (DISP-033)."})
    from app.routers.subscription_server import _reverse_subscription_charge, ddb_get_item, pk_subscription, normalize_subscription
    sub = params.get("subscription")
    if not sub:
        sub = ddb_get_item(pk_subscription(params["subscription_ref"]), "META") if params.get("subscription_ref") else None
        if not sub:
            sub = ddb_get_item(pk_subscription(params["charge_ref"]), "META")
        if not sub:
            raise HTTPException(404, {"code": "subscription_not_found", "message": "Subscription not found."})
        sub = normalize_subscription(sub)
    # partial: derive a refund_fraction from override_amount_cents against the cycle gross
    frac = 1.0
    if override_amount_cents is not None:
        try:
            from app.routers.subscription_server import _current_cycle_charge_cents
            gross = int(_current_cycle_charge_cents(sub["subscription_id"], sub) or 0)
            frac = max(0.0, min(1.0, (override_amount_cents / gross) if gross else 0.0))
        except Exception:
            frac = 1.0
    return _reverse_subscription_charge(sub, now=now_ts(), refund_fraction=frac, reason=reason, actor=actor)


def _rail_ad(params: Dict[str, Any], *, override_amount_cents: Optional[int],
             clawback_only: bool, reason: str, actor: Optional[str]) -> Dict[str, Any]:
    if override_amount_cents is not None:
        raise HTTPException(400, {"code": "partial_unsupported",
                                  "message": "Partial reversal is not supported for ad charges in v1."})
    if clawback_only:
        raise HTTPException(501, {"code": "clawback_only_unsupported",
                                  "message": "ad clawback-only fork lands in E3 (DISP-033)."})
    from app.services.ad_billing import reverse_ad_charge
    account_id = params.get("ad_account_id")
    entry_id = params.get("ad_entry_id") or params.get("charge_ref")
    if not account_id:
        raise HTTPException(400, {"code": "missing_ad_account", "message": "ad_account_id is required to reverse an ad charge."})
    return reverse_ad_charge(account_id=account_id, entry_id=entry_id, reason=reason, actor=actor or "")


def _rail_ecom(params: Dict[str, Any], *, override_amount_cents: Optional[int],
               clawback_only: bool, reason: str, actor: Optional[str]) -> Dict[str, Any]:
    if clawback_only:
        raise HTTPException(501, {"code": "clawback_only_unsupported",
                                  "message": "ecom chargeback fork lands in E3 (DISP-033)."})
    from app.services import refund_requests
    payer = params.get("payer_id")
    entry_id = params.get("transaction_entry_id") or params.get("charge_ref")
    if not payer:
        raise HTTPException(400, {"code": "missing_payer", "message": "payer_id (buyer) is required to refund an ecom charge."})
    # ecom rides an admin refund-request approval: create-then-approve so the
    # existing multi-party clawback (all sellers + host commission) fires.
    req = refund_requests.create_refund_request(
        user_id=payer,
        transaction_entry_id=entry_id,
        reason=reason,
        amount_cents=override_amount_cents,
    )
    # the refund-request item keys its id as ``refund_request_id`` (pk REFUND#{id}).
    req_id = req.get("refund_request_id") or req.get("request_id")
    receipt = refund_requests.approve_request(
        req_id,
        actor or "dispute_dispatch",
        notes=reason,
        override_amount_cents=override_amount_cents,
    )
    out = dict(receipt) if isinstance(receipt, dict) else {"receipt": receipt}
    out.setdefault("refund_request_id", req_id)
    out.setdefault("request_id", req_id)
    return out


def _rail_vod(params: Dict[str, Any], *, override_amount_cents: Optional[int],
              clawback_only: bool, reason: str, actor: Optional[str]) -> Dict[str, Any]:
    if override_amount_cents is not None:
        raise HTTPException(400, {"code": "partial_unsupported",
                                  "message": "Partial reversal is not supported for VOD charges in v1."})
    from app.services.vod_purchase import reverse_vod_purchase
    payer = params.get("payer_id")
    if not payer:
        raise HTTPException(400, {"code": "missing_payer", "message": "payer_id (buyer) is required to reverse a VOD purchase."})
    return reverse_vod_purchase(
        purchase_id=params.get("purchase_id") or params.get("charge_ref"),
        buyer_id=payer,
        seller_id=params.get("recipient_id"),
        video_id=params.get("video_id"),
        reason=reason,
        actor=actor,
        clawback_only=clawback_only,
    )


_RAIL = {
    "tip": _rail_tip,
    "message": _rail_tip,
    "subscription": _rail_subscription,
    "ad": _rail_ad,
    "ecom": _rail_ecom,
    "vod": _rail_vod,
}


def dispatch_reversal(
    *,
    charge_type: str,
    charge_ref: str,
    payer_id: Optional[str] = None,
    recipient_id: Optional[str] = None,
    override_amount_cents: Optional[int] = None,
    clawback_only: bool = False,
    reason: str = "dispute_resolution",
    actor: Optional[str] = None,
    ad_account_id: Optional[str] = None,
    subscription: Optional[Dict[str, Any]] = None,
    video_id: Optional[str] = None,
    use_mutex: bool = True,
) -> Dict[str, Any]:
    """DISP-003: reverse a charge on the CORRECT existing rail.

    ``charge_type`` selects the rail (tip/message -> tip rail, subscription ->
    sub rail, ad -> ad rail, ecom -> refund_requests, vod -> reverse_vod_purchase).
    Full amount by default; ``override_amount_cents`` for partial (ecom/sub only;
    rejected for tip/ad/vod in v1). Idempotent via each rail's own marker AND, when
    ``use_mutex`` (default), guarded by the cross-track credit-flip mutex so the
    same charge can never be reversed twice across tracks.

    Returns the rail receipt plus ``{"charge_type", "charge_ref",
    "mutex_won": bool}``. When the mutex was already claimed by an earlier
    reversal, returns ``{"idempotent_replay": True, "mutex_won": False}`` WITHOUT
    firing the rail.
    """
    ct = (charge_type or "").strip().lower()
    if ct not in _RAIL:
        raise HTTPException(400, {"code": "unknown_charge_type", "message": f"Unknown charge_type {charge_type!r}."})

    params = resolve_charge(charge_ref, ct, payer_id=payer_id, recipient_id=recipient_id)
    if ad_account_id:
        params["ad_account_id"] = ad_account_id
    if subscription:
        params["subscription"] = subscription
    if video_id:
        params["video_id"] = video_id
    # ensure payer/recipient resolved onto params
    params["payer_id"] = params.get("payer_id") or payer_id
    params["recipient_id"] = params.get("recipient_id") or recipient_id

    # Cross-track mutex: the anchor partition is the payer's ledger (all six rails
    # write the payer refund / are keyed off the payer). Fall back to recipient
    # only if no payer is known (e.g. ad reversal keyed on account).
    anchor = params.get("payer_id") or params.get("ad_account_id") or params.get("recipient_id")
    mutex_won = True
    if use_mutex:
        if not anchor:
            raise HTTPException(400, {"code": "missing_anchor",
                                      "message": "Cannot claim reversal mutex without a payer/account anchor."})
        mutex_won, marker = claim_charge_reversal_mutex(ct, charge_ref, owner=actor or "dispute", anchor_user_id=anchor)
        if not mutex_won:
            logger.info("dispatch_reversal mutex already claimed charge_type=%s ref=%s owner=%s",
                        ct, charge_ref, marker.get("owner"))
            return {
                "charge_type": ct,
                "charge_ref": charge_ref,
                "mutex_won": False,
                "idempotent_replay": True,
                "mutex_owner": marker.get("owner"),
            }

    try:
        receipt = _RAIL[ct](params, override_amount_cents=override_amount_cents,
                            clawback_only=clawback_only, reason=reason, actor=actor)
    except Exception:
        # The rail failed AFTER we claimed the mutex — release it so a retry can
        # re-attempt (the rails are themselves idempotent, so releasing is safe).
        if use_mutex and mutex_won and anchor:
            try:
                T.billing.delete_item(Key={"pk": user_pk(anchor), "sk": _mutex_sk(ct, charge_ref)})
            except Exception:
                logger.warning("mutex release after rail failure skipped charge=%s/%s", ct, charge_ref, exc_info=True)
        raise

    out = dict(receipt) if isinstance(receipt, dict) else {"receipt": receipt}
    out["charge_type"] = ct
    out["charge_ref"] = charge_ref
    out["mutex_won"] = mutex_won
    return out

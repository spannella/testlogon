"""TIP-B0/B5: centralized tip charge service.

`charge_tip` is the single seam every tipping surface calls. It centralizes what
used to be copy-pasted across newsfeed / messaging / broadcast / video handlers:

  1. resolve the payment method via a fallback chain
     (explicit -> per-user tip_default_payment_method_id -> general default -> blank-in-dev)
  2. validate PM ownership ONCE (the `PM#`-prefix scan previously duplicated in
     send_message_tip / tip_post / unlock / broadcast_tip_store)
  3. delegate `can_tip` guard in ONE place (default-DENY)
  4. idempotency-key dedup (a replayed tip returns the stored receipt, no double write)
  5. the real stripe-mock charge (TIP-101) followed by the ledger write.

TIP-501 (B5): the debit + credit + idempotency receipt are now written as a single
DynamoDB `TransactWriteItems`, so a replay cannot double-charge (the receipt marker
is claimed with `attribute_not_exists`, atomically with the pair) and a partial
write can no longer orphan a credit -- the pair is all-or-nothing.

TIP-502 (B5): `reverse_tip` is an idempotent, admin/internal-safe reversal that
claws the net back from the recipient and refunds the tipper. Its ledger entries
use entry_type != "credit" so a reversal never inflates creator earnings, and a
`TIPREVERSAL#` marker guards against double-reversal.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

from botocore.exceptions import ClientError
from boto3.dynamodb.types import TypeSerializer
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T, _to_decimal
from app.core.time import now_ts
from app.services.billing_config import split_fee
from app.services.billing_shared import ddb_get, ddb_put, ddb_query_pk, user_pk
from app.services.tip_ledger import (
    TipLedgerEntry,
    build_tip_ledger_items,
    maybe_collaboration_split,
    publish_tip_dashboard_sse,
    write_tip_ledger,
    _reason_for_content_type,
)

logger = logging.getLogger(__name__)

_SERIALIZER = TypeSerializer()

# The set of content types `write_tip_ledger` accepts today (tip_ledger.py:51).
# Kept in lock-step with the ledger so charge_tip never accepts a type the ledger
# would reject. B2/B3 extend BOTH together (message_react/post_react/video_comment).
TIP_CONTENT_TYPES = ("message", "post", "comment", "broadcast", "video", "message_react", "post_react", "video_comment")


@dataclass
class TipResult:
    """Receipt returned by `charge_tip`.

    tip_payment_id     -- the tip transaction id (mock id in B0; PaymentIntent-linked in B1)
    charged_cents      -- gross amount debited from the tipper
    net_cents          -- amount credited to the recipient (gross - platform fee)
    fee_cents          -- platform fee retained
    recipient          -- recipient user id credited
    payment_intent_id  -- real processor intent id (None in B0; set in B1/TIP-101)
    idempotent_replay  -- True when this is a no-op replay of a prior identical call
    debit_entry_id     -- ledger debit entry id ("" on collaboration-split short-circuit)
    credit_entry_id    -- ledger credit entry id ("" on collaboration-split short-circuit)
    """

    tip_payment_id: str
    charged_cents: int
    net_cents: int
    fee_cents: int
    recipient: str
    payment_intent_id: Optional[str] = None
    idempotent_replay: bool = False
    debit_entry_id: str = ""
    credit_entry_id: str = ""


def _idem_sk(idempotency_key: str) -> str:
    return f"TIPIDEMP#{idempotency_key}"


def _reversal_sk(tip_payment_id: str) -> str:
    return f"TIPREVERSAL#{tip_payment_id}"


def _av(item: Dict[str, Any]) -> Dict[str, Any]:
    """Serialize a plain dict into the DynamoDB low-level attribute-value map used
    by TransactWriteItems. Floats are coerced to Decimal first (the boto3
    TypeSerializer rejects floats), matching the _FloatSafeTable resource writes."""
    return {k: _SERIALIZER.serialize(v) for k, v in _to_decimal(item).items()}


def _load_idempotent_receipt(tipper_id: str, idempotency_key: str) -> Optional[TipResult]:
    """Return a stored receipt for this key, or None. Best-effort (never raises)."""
    if not idempotency_key:
        return None
    try:
        row = ddb_get(T.billing, user_pk(tipper_id), _idem_sk(idempotency_key))
    except Exception:
        logger.warning("tip idempotency read failed", exc_info=True)
        return None
    if not row or "tip_payment_id" not in row:
        return None
    return TipResult(
        tip_payment_id=row["tip_payment_id"],
        charged_cents=int(row.get("charged_cents", 0)),
        net_cents=int(row.get("net_cents", 0)),
        fee_cents=int(row.get("fee_cents", 0)),
        recipient=row.get("recipient", ""),
        payment_intent_id=row.get("payment_intent_id"),
        idempotent_replay=True,
        debit_entry_id=row.get("debit_entry_id", ""),
        credit_entry_id=row.get("credit_entry_id", ""),
    )


def _store_idempotent_receipt(tipper_id: str, idempotency_key: str, result: TipResult) -> None:
    """Persist a receipt keyed by idempotency_key. Best-effort (never raises).

    Only used by the collaboration-split fallback path (which does not go through
    the transactional writer). The normal money-path writes the receipt marker
    ATOMICALLY inside the TransactWriteItems (see _transact_tip_ledger).
    """
    if not idempotency_key:
        return
    item = _receipt_marker_item(tipper_id, idempotency_key, result)
    try:
        ddb_put(T.billing, item, condition_expression="attribute_not_exists(sk)")
    except Exception:
        # ConditionalCheckFailed (a concurrent winner already stored it) or a
        # transient error -- neither should fail the tip that already credited.
        logger.warning("tip idempotency store skipped", exc_info=True)


def _receipt_marker_item(tipper_id: str, idempotency_key: str, result: TipResult) -> Dict[str, Any]:
    """Build the idempotency-receipt marker row (stored as the transaction's claim)."""
    item = {
        "pk": user_pk(tipper_id),
        "sk": _idem_sk(idempotency_key),
        "ts": now_ts(),
        **asdict(result),
    }
    item["idempotent_replay"] = False  # store the canonical (non-replay) receipt
    # payment_intent_id may be None -> drop it so the AV map stays clean.
    if item.get("payment_intent_id") is None:
        item.pop("payment_intent_id", None)
    return item


def _transact_tip_ledger(
    *,
    tipper_id: str,
    idempotency_key: str,
    debit_item: Dict[str, Any],
    credit_item: Dict[str, Any],
    receipt_item: Optional[Dict[str, Any]],
) -> bool:
    """TIP-501: atomically write debit + credit (+ the idempotency receipt claim).

    Returns True when the transaction committed. Returns False when it was
    cancelled because the receipt marker already exists (a concurrent/replayed
    identical call already wrote the pair) -- the caller then returns the stored
    receipt, so NO second debit/credit is written and the charge is not doubled.

    A non-cancellation error is re-raised: the (already-charged) tip is left with
    NO ledger rows (all-or-nothing) rather than a half-written orphan pair; that
    charged-but-uncredited case is what reverse_tip / the reconcile path handles.
    """
    table_name = S.billing_table_name
    tx_items = [
        {"Put": {"TableName": table_name, "Item": _av(debit_item)}},
        {"Put": {"TableName": table_name, "Item": _av(credit_item)}},
    ]
    if idempotency_key and receipt_item is not None:
        tx_items.append(
            {
                "Put": {
                    "TableName": table_name,
                    "Item": _av(receipt_item),
                    "ConditionExpression": "attribute_not_exists(sk)",
                }
            }
        )
    client = T.billing.meta.client
    try:
        client.transact_write_items(TransactItems=tx_items)
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "TransactionCanceledException":
            logger.info("tip ledger transaction cancelled (idempotent replay/race) tipper=%s", tipper_id)
            return False
        raise


def _guard_delegate_can_tip(creator_id: str, acting_delegate_id: Optional[str]) -> None:
    """Default-DENY delegate tip guard (folds prod messaging._delegate_guard_tip).

    A tip debits the CREATOR's wallet, so a delegate acting AS the creator may only
    tip when granted the per-delegate `can_tip` permission.
    """
    if not acting_delegate_id or acting_delegate_id == creator_id:
        return
    from app.services.delegates import get_delegate

    item = get_delegate(creator_id, acting_delegate_id) or {}
    if "can_tip" not in (item.get("permissions") or []):
        raise HTTPException(
            403,
            "delegate_tip_forbidden: tipping as the creator spends the "
            "creator's money; grant the can_tip delegate permission to allow it",
        )


def resolve_tip_payment_method(tipper_id: str, explicit_pm: Optional[str]) -> Optional[str]:
    """Resolve + validate the PM for a tip, ONCE, for every surface.

    Fallback chain: explicit -> per-user `tip_default_payment_method_id`
    (may be absent; tolerated) -> general `default_payment_method_id`
    (== billing.current_default_pm) -> blank.

    A resolved (non-blank) PM is validated to belong to the tipper (the `PM#` scan
    previously copy-pasted across surfaces). A blank result is allowed only in
    dev_mode (today's behavior: the mock charge does not require a PM); outside
    dev_mode a blank result raises 400 no_payment_method.
    """
    pm = explicit_pm
    if not pm:
        billing = ddb_get(T.billing, user_pk(tipper_id), "BILLING") or {}
        pm = billing.get("tip_default_payment_method_id") or billing.get("default_payment_method_id")

    if not pm:
        if S.dev_mode:
            return None
        raise HTTPException(400, {"code": "no_payment_method", "message": "No payment method on file for tipping."})

    # Validate ownership ONCE.
    items = ddb_query_pk(T.billing, user_pk(tipper_id))
    pm_ids = {
        it["payment_method_id"]
        for it in items
        if it.get("sk", "").startswith("PM#") and "payment_method_id" in it
    }
    if pm not in pm_ids:
        raise HTTPException(400, "Payment method not found")
    return pm


def _charge_tip_payment_intent(
    *,
    tipper_id: str,
    amount_cents: int,
    currency: str,
    payment_method_id: Optional[str],
    content_type: str,
    content_id: str,
    idempotency_key: str,
) -> Optional[str]:
    """TIP-101: real stripe-mock charge for a tip, mirroring billing.charge_once.

    Returns the PaymentIntent id on a successful charge, or None for the dev stub
    path (Stripe not configured, or a blank PM tolerated in dev_mode -- exactly the
    cases billing.py already tolerates, where a ledger-only mock stands in for a
    processor charge).

    On a declined card, any Stripe error, or a non-succeeded terminal status this
    raises HTTPException(402, payment_failed) so the CALLER (charge_tip) never
    reaches write_tip_ledger -- NO debit/credit row is written for a failed charge.
    The charge_tip idempotency_key is threaded into the PaymentIntent so a retry
    never double-charges at the processor.
    """
    # Dev stub: no processor configured, or a blank PM tolerated in dev_mode.
    if not getattr(S, "stripe_secret_key", "") or not payment_method_id:
        return None

    from app.routers.billing import ensure_stripe_configured, get_or_create_customer
    import stripe  # configured by ensure_stripe_configured() just below

    ensure_stripe_configured()
    customer_id = get_or_create_customer(tipper_id)
    try:
        pi = stripe.PaymentIntent.create(
            amount=int(amount_cents),
            currency=(currency or "usd").lower(),
            customer=customer_id,
            payment_method=payment_method_id,
            off_session=True,
            confirm=True,
            description=f"Tip ({content_type})",
            metadata={
                "app_user_id": tipper_id,
                "purpose": "tip",
                "content_type": content_type,
                "content_id": content_id,
            },
            idempotency_key=(idempotency_key or None),
        )
    except stripe.error.CardError as exc:
        logger.info("tip charge declined for tipper=%s: %s", tipper_id, exc)
        raise HTTPException(402, {"code": "payment_failed", "message": str(exc)})
    except stripe.error.StripeError as exc:
        logger.warning("tip charge stripe error for tipper=%s: %s", tipper_id, exc)
        raise HTTPException(402, {"code": "payment_failed", "message": "Tip charge failed at the payment processor."})

    status = (pi.get("status") or "").lower()
    charged_ok = status == "succeeded" or (
        bool(getattr(S, "stripe_api_base", "")) and status not in ("canceled", "payment_failed")
    )
    if not charged_ok:
        raise HTTPException(
            402,
            {"code": "payment_failed", "message": f"Tip charge did not succeed (status={status})."},
        )
    return pi.get("id")


def charge_tip(
    *,
    tipper_id: str,
    recipient_id: str,
    amount_cents: int,
    currency: str = "USD",
    payment_method_id: Optional[str] = None,
    content_type: str,
    content_id: str,
    meta: Optional[Dict[str, Any]] = None,
    idempotency_key: str,
    acting_delegate_id: Optional[str] = None,
    tip_payment_id: Optional[str] = None,
) -> TipResult:
    """Centralized tip charge + credit. See module docstring.

    Order of operations:
      validate args -> delegate can_tip guard -> idempotency replay short-circuit
      -> resolve+validate PM -> real charge -> ATOMIC debit+credit+receipt (TIP-501)
      -> dashboard SSE.

    Returns a TipResult receipt. Raises HTTPException(400/402/403) on failure.
    """
    # 1. Validate arguments.
    if amount_cents is None or amount_cents <= 0:
        raise HTTPException(400, {"code": "invalid_amount", "message": "Tip amount must be > 0."})
    if content_type not in TIP_CONTENT_TYPES:
        raise HTTPException(400, {"code": "invalid_content_type", "message": f"Invalid tip content_type: {content_type}"})
    if not recipient_id or recipient_id == tipper_id:
        raise HTTPException(400, {"code": "cannot_tip_self", "message": "Cannot tip yourself."})

    # 2. Delegate guard (one place, default-deny).
    _guard_delegate_can_tip(tipper_id, acting_delegate_id)

    # 3. Idempotency: a prior identical call returns its stored receipt, no re-charge.
    replay = _load_idempotent_receipt(tipper_id, idempotency_key)
    if replay is not None:
        return replay

    # 4. Resolve + validate the payment method ONCE.
    pm = resolve_tip_payment_method(tipper_id, payment_method_id)

    # 5. Real charge via stripe-mock PaymentIntent (TIP-101), mirroring
    # billing.charge_once (off_session=True, confirm=True, idempotency_key).
    tip_payment_id = tip_payment_id or ("tip_" + uuid.uuid4().hex)
    payment_intent_id: Optional[str] = _charge_tip_payment_intent(
        tipper_id=tipper_id,
        amount_cents=amount_cents,
        currency=currency,
        payment_method_id=pm,
        content_type=content_type,
        content_id=content_id,
        idempotency_key=idempotency_key,
    )

    # Precompute fee/net for the receipt (build_tip_ledger_items applies the same split).
    fee_cents, net_cents, _fee_bps = split_fee("tip_debit", amount_cents)

    entry = TipLedgerEntry(
        tipper_user_id=tipper_id,
        recipient_user_id=recipient_id,
        amount_cents=amount_cents,
        currency=currency,
        content_type=content_type,
        content_id=content_id,
        payment_method_id=pm,
        tip_payment_id=tip_payment_id,
        extra_meta=dict(meta or {}),
    )

    # 6a. Collaboration-split short-circuit keeps its own (non-transactional) writes.
    split = maybe_collaboration_split(entry)
    if split is not None:
        result = TipResult(
            tip_payment_id=tip_payment_id,
            charged_cents=amount_cents,
            net_cents=net_cents,
            fee_cents=fee_cents,
            recipient=recipient_id,
            payment_intent_id=payment_intent_id,
            idempotent_replay=False,
            debit_entry_id=split.get("debit_entry_id", ""),
            credit_entry_id=split.get("credit_entry_id", ""),
        )
        _store_idempotent_receipt(tipper_id, idempotency_key, result)
        return result

    # 6b. TIP-501: write the paired debit/credit + idempotency receipt ATOMICALLY.
    debit_item, credit_item, ledger_ids = build_tip_ledger_items(entry)
    result = TipResult(
        tip_payment_id=tip_payment_id,
        charged_cents=amount_cents,
        net_cents=net_cents,
        fee_cents=fee_cents,
        recipient=recipient_id,
        payment_intent_id=payment_intent_id,
        idempotent_replay=False,
        debit_entry_id=ledger_ids.get("debit_entry_id", ""),
        credit_entry_id=ledger_ids.get("credit_entry_id", ""),
    )
    receipt_item = _receipt_marker_item(tipper_id, idempotency_key, result) if idempotency_key else None

    committed = _transact_tip_ledger(
        tipper_id=tipper_id,
        idempotency_key=idempotency_key,
        debit_item=debit_item,
        credit_item=credit_item,
        receipt_item=receipt_item,
    )
    if not committed:
        # A concurrent/replayed identical call already wrote the pair + receipt.
        # Return the winner's receipt -- no second debit/credit, no double charge
        # (Stripe idempotency_key deduped the processor charge too).
        winner = _load_idempotent_receipt(tipper_id, idempotency_key)
        if winner is not None:
            return winner
        # No receipt to load (no idempotency_key): report the receipt we built.
        result.idempotent_replay = True
        return result

    # 7. Notify the recipient's dashboard stream (best-effort).
    publish_tip_dashboard_sse(entry)
    return result


# ---------------------------------------------------------------------------
# TIP-502 — reversal path (charged-but-not-credited / admin reversal).
# ---------------------------------------------------------------------------
@dataclass
class ReversalResult:
    """Receipt for a tip reversal."""

    tip_payment_id: str
    refunded_cents: int          # gross returned to the tipper
    clawback_cents: int          # net clawed back from the recipient
    reversal_entry_id: str       # recipient clawback ledger entry id
    refund_entry_id: str         # tipper refund ledger entry id
    idempotent_replay: bool = False


def _load_reversal_receipt(tipper_id: str, tip_payment_id: str) -> Optional[ReversalResult]:
    try:
        row = ddb_get(T.billing, user_pk(tipper_id), _reversal_sk(tip_payment_id))
    except Exception:
        logger.warning("reversal marker read failed", exc_info=True)
        return None
    if not row or "tip_payment_id" not in row:
        return None
    return ReversalResult(
        tip_payment_id=row.get("tip_payment_id", tip_payment_id),
        refunded_cents=int(row.get("refunded_cents", 0)),
        clawback_cents=int(row.get("clawback_cents", 0)),
        reversal_entry_id=row.get("reversal_entry_id", ""),
        refund_entry_id=row.get("refund_entry_id", ""),
        idempotent_replay=True,
    )


def reverse_tip(
    *,
    tipper_id: str,
    recipient_id: str,
    gross_cents: int,
    net_cents: int,
    tip_payment_id: str,
    content_type: str,
    content_id: str = "",
    currency: str = "USD",
    payment_intent_id: Optional[str] = None,
    credit_entry_id: Optional[str] = None,
    credit_ts: Optional[int] = None,
    reason: str = "admin_reversal",
    actor: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> ReversalResult:
    """TIP-502: idempotently reverse a tip.

    Writes, in a single TransactWriteItems:
      * a recipient CLAWBACK ledger entry (entry_type "reversal", amount = net) --
      * a tipper REFUND ledger entry (entry_type "refund", amount = gross) --
      * a `TIPREVERSAL#{tip_payment_id}` marker claimed with attribute_not_exists.

    NEITHER reversal entry uses type "credit", so a reversal can never inflate
    creator earnings (creator_earnings / get_available_balance only sum
    type=="credit"). The marker makes it idempotent + guards double-reversal: a
    second call returns the stored reversal receipt as a no-op.

    Best-effort adjuncts (run only on the FIRST reversal): flip the original
    credit row to state="reversed" so it drops out of get_available_balance
    (actually clawing the net back from the recipient's spendable balance), and
    issue a Stripe refund when a real PaymentIntent backed the charge.
    """
    if gross_cents <= 0 or net_cents < 0:
        raise HTTPException(400, {"code": "invalid_amount", "message": "Reversal amounts must be positive."})
    if not tip_payment_id:
        raise HTTPException(400, {"code": "missing_tip_id", "message": "tip_payment_id is required to reverse a tip."})

    # Idempotency short-circuit: already reversed -> return the stored receipt.
    prior = _load_reversal_receipt(tipper_id, tip_payment_id)
    if prior is not None:
        return prior

    ts = now_ts()
    reversal_id = uuid.uuid4().hex
    refund_id = uuid.uuid4().hex
    reason_str = _reason_for_content_type(content_type)
    base_meta: Dict[str, Any] = {
        "content_type": content_type,
        "content_id": content_id,
        "tipper_user_id": tipper_id,
        "recipient_user_id": recipient_id,
        "tip_payment_id": tip_payment_id,
        "reversal_of": tip_payment_id,
        "reversal_reason": reason,
    }
    if actor:
        base_meta["reversal_actor"] = actor
    if meta:
        base_meta.update(meta)

    # Recipient clawback (entry_type != "credit" -> earnings not inflated).
    clawback_item = {
        "pk": user_pk(recipient_id),
        "sk": f"LEDGER#{ts}#{reversal_id}",
        "entry_id": reversal_id,
        "ts": ts,
        "type": "reversal",
        "amount_cents": net_cents,
        "currency": currency,
        "state": "settled",
        "reason": f"Reversal: {reason_str}",
        "meta": base_meta,
    }
    # Tipper refund (entry_type != "credit").
    refund_item = {
        "pk": user_pk(tipper_id),
        "sk": f"LEDGER#{ts}#{refund_id}",
        "entry_id": refund_id,
        "ts": ts,
        "type": "refund",
        "amount_cents": gross_cents,
        "currency": currency,
        "state": "settled",
        "reason": f"Refund: {reason_str}",
        "meta": base_meta,
    }
    receipt = ReversalResult(
        tip_payment_id=tip_payment_id,
        refunded_cents=gross_cents,
        clawback_cents=net_cents,
        reversal_entry_id=reversal_id,
        refund_entry_id=refund_id,
        idempotent_replay=False,
    )
    marker_item = {
        "pk": user_pk(tipper_id),
        "sk": _reversal_sk(tip_payment_id),
        "ts": ts,
        **asdict(receipt),
    }
    marker_item["idempotent_replay"] = False

    table_name = S.billing_table_name
    tx_items = [
        {"Put": {"TableName": table_name, "Item": _av(clawback_item)}},
        {"Put": {"TableName": table_name, "Item": _av(refund_item)}},
        {
            "Put": {
                "TableName": table_name,
                "Item": _av(marker_item),
                "ConditionExpression": "attribute_not_exists(sk)",
            }
        },
    ]
    client = T.billing.meta.client
    try:
        client.transact_write_items(TransactItems=tx_items)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "TransactionCanceledException":
            # Lost the race / already reversed -> return the stored receipt.
            winner = _load_reversal_receipt(tipper_id, tip_payment_id)
            if winner is not None:
                return winner
            receipt.idempotent_replay = True
            return receipt
        raise

    # --- best-effort adjuncts, first reversal only ---
    # Flip the original credit out of the recipient's spendable balance.
    if credit_entry_id and credit_ts is not None:
        try:
            T.billing.update_item(
                Key={"pk": user_pk(recipient_id), "sk": f"LEDGER#{int(credit_ts)}#{credit_entry_id}"},
                UpdateExpression="SET #s = :r",
                ConditionExpression="attribute_exists(sk)",
                ExpressionAttributeNames={"#s": "state"},
                ExpressionAttributeValues={":r": "reversed"},
            )
        except Exception:
            logger.warning("original credit state flip skipped for tip=%s", tip_payment_id, exc_info=True)

    # Refund the processor charge when a real PaymentIntent backed it.
    if payment_intent_id:
        try:
            from app.routers.billing import ensure_stripe_configured
            import stripe

            ensure_stripe_configured()
            stripe.Refund.create(
                payment_intent=payment_intent_id,
                idempotency_key=f"tiprev:{tip_payment_id}",
            )
        except Exception:
            logger.warning("stripe refund skipped for tip=%s", tip_payment_id, exc_info=True)

    return receipt

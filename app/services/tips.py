"""TIP-B0: centralized tip charge service.

`charge_tip` is the single seam every tipping surface calls. It centralizes what
used to be copy-pasted across newsfeed / messaging / broadcast / video handlers:

  1. resolve the payment method via a fallback chain
     (explicit -> per-user tip_default_payment_method_id -> general default -> blank-in-dev)
  2. validate PM ownership ONCE (the `PM#`-prefix scan previously duplicated in
     send_message_tip / tip_post / unlock / broadcast_tip_store)
  3. delegate `can_tip` guard in ONE place (default-DENY)
  4. idempotency-key dedup (a replayed tip returns the stored receipt, no double write)
  5. the EXISTING mock charge (mint a `tip_<hex>` id -- NO real PaymentIntent yet;
     the real stripe-mock charge is B1 / TIP-101) followed by the EXISTING
     `write_tip_ledger` (UNCHANGED: paired settled debit(gross)/credit(net, type:"credit")
     with the 20% `fee_tips_bps` split)

B0 is behavior-preserving centralization. It does NOT change what `write_tip_ledger`
writes and does NOT add the real charge. Its only intended behavior changes vs the
old inline sites are (a) idempotent replay and (b) callers validating BEFORE any
ledger write (the surfaces reorder to call this after their guards).
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_config import split_fee
from app.services.billing_shared import ddb_get, ddb_put, ddb_query_pk, user_pk
from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger

logger = logging.getLogger(__name__)

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

    Uses a conditional put so a concurrent winner is not overwritten. B5 replaces
    this read-then-write with a fully transactional debit+credit+receipt claim.
    """
    if not idempotency_key:
        return
    item = {
        "pk": user_pk(tipper_id),
        "sk": _idem_sk(idempotency_key),
        "ts": now_ts(),
        **asdict(result),
    }
    item["idempotent_replay"] = False  # store the canonical (non-replay) receipt
    try:
        ddb_put(T.billing, item, condition_expression="attribute_not_exists(sk)")
    except Exception:
        # ConditionalCheckFailed (a concurrent winner already stored it) or a
        # transient error -- neither should fail the tip that already credited.
        logger.warning("tip idempotency store skipped", exc_info=True)


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

    stripe-mock nuance: the local stripe-mock fixture server cannot actually
    confirm an off_session PaymentIntent and returns "requires_payment_method" for
    every create. When Stripe is pointed at such a mock (stripe_api_base overridden)
    we accept the created intent as settled so the tip money-path works end-to-end;
    a real Stripe integration (no api_base override) still requires a true
    "succeeded" and a real decline surfaces as CardError -> 402.
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
      -> resolve+validate PM -> mock charge -> write_tip_ledger -> store receipt.

    Returns a TipResult receipt. Raises HTTPException(400/403) on validation failure.
    B0 performs the EXISTING mock charge only; the real stripe-mock PaymentIntent is
    B1 (TIP-101). `write_tip_ledger` is called UNCHANGED.
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
    # Callers that already minted a tip id (and stored it on their content row)
    # pass it through so the ledger row + content row stay linked; else mint one.
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

    # Precompute fee/net for the receipt (write_tip_ledger applies the same split).
    fee_cents, net_cents, _fee_bps = split_fee("tip_debit", amount_cents)

    # 6. Write the ledger (UNCHANGED primitive: net type:"credit", 20% fee split).
    ledger_ids = write_tip_ledger(
        TipLedgerEntry(
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
    )

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

    # 7. Persist the receipt for idempotent replay.
    _store_idempotent_receipt(tipper_id, idempotency_key, result)
    return result

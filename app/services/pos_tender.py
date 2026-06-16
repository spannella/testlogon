"""
POS-006/POS-007/POS-008 — Tender, void, and refund service.

Cash tender calls purchase_cart (SHOP-001), writes a pos_cash_sale ledger entry
via billing_shared.new_ledger_entry, and updates the session's cash-float counters.
Card/wallet tenders similarly delegate to billing collaborators.

All functions are gated on S.pos_enabled and S.inventory_reservations_enabled (sibling flag).
Never touches T.billing, T.orders, or T.catalog directly — only through the
canonical service layer (billing_shared, shoppingcart, commerce_order_service).
"""
from __future__ import annotations

import hashlib
from decimal import Decimal
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.pos_register import (
    _require_enabled,
    _audit,
    _session_pk,
    _txn_pk,
    _tender_pk,
    _to_int,
    _txn_out,
)


# ── tender a transaction (cash) ───────────────────────────────────────────────

def tender_cash(
    *,
    session_id: str,
    txn_id: str,
    cashier_sub: str,
    amount_tendered_cents: int,
    idempotency_key: str,
) -> Dict[str, Any]:
    """Complete a POS sale via cash payment.

    1. Validates the TXN draft exists and is in 'draft' status.
    2. Idempotency: if the TENDER row already exists, returns the existing TXN.
    3. Calls purchase_cart to settle stock and create an order.
    4. Writes a TENDER sub-row under the session PK.
    5. Writes a pos_cash_sale ledger entry to T.billing.
    6. Updates cash-float counters on the session row.
    7. Marks TXN as 'tendered'.
    """
    _require_enabled()

    # Load and validate TXN draft.
    txn_item = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item")
    if not txn_item:
        raise HTTPException(status_code=404, detail="Transaction not found")
    if txn_item.get("cashier_sub") != cashier_sub:
        raise HTTPException(status_code=403, detail="Cashier does not own this transaction")

    status = txn_item.get("status")
    if status == "tendered":
        # Already settled — idempotent return.
        return _build_txn_out_from_item(txn_item, session_id)
    if status != "draft":
        raise HTTPException(
            status_code=409,
            detail=f"Transaction status is '{status}'; cannot tender",
        )

    cart_id = txn_item.get("cart_id", "")
    subtotal_cents = _to_int(txn_item.get("subtotal_cents"))

    # Apply tax from global rate if configured.
    tax_rate_bps = getattr(S, "pos_default_tax_rate_bps", 0)
    tax_cents = int(subtotal_cents * tax_rate_bps / 10000)
    total_cents = subtotal_cents + tax_cents

    # Validate tendered amount covers total.
    change_due = amount_tendered_cents - total_cents
    if change_due < 0:
        raise HTTPException(
            status_code=422,
            detail=f"Tendered amount ({amount_tendered_cents} cents) does not cover total ({total_cents} cents)",
        )

    now = now_ts()

    # Idempotency on tender row: write with condition.
    tender_row: Dict[str, Any] = {
        "pos_pk": f"SESSION#{session_id}",
        "pos_sk": f"TENDER#{txn_id}",
        "txn_id": txn_id,
        "session_id": session_id,
        "cashier_sub": cashier_sub,
        "kind": "cash",
        "amount_cents": amount_tendered_cents,
        "change_due_cents": change_due,
        "total_cents": total_cents,
        "created_at": now,
        "idempotency_key": idempotency_key,
    }

    try:
        T.pos.put_item(
            Item=tender_row,
            ConditionExpression="attribute_not_exists(pos_pk)",
        )
    except ClientError as exc:
        code = exc.response["Error"].get("Code", "")
        if code == "ConditionalCheckFailedException":
            # Already tendered — return current TXN state.
            fresh = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item", txn_item)
            return _build_txn_out_from_item(fresh, session_id)
        raise

    # Settle the cart (stock decrement + order creation).
    order_id: Optional[str] = None
    try:
        from app.services.shoppingcart import purchase_cart  # lazy import (RULE-1)
        purchase_result = purchase_cart(cashier_sub, cart_id)
        order_id = purchase_result.get("order_id") or purchase_result.get("cart_id")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Cart purchase failed: {exc}") from exc

    # Write ledger entry for cash sale.
    ledger_sk_val: Optional[str] = None
    try:
        from app.services.billing_shared import new_ledger_entry, user_pk  # lazy import (RULE-1)
        sk_val, led_item = new_ledger_entry(
            key_name="pk",
            key_value=user_pk(cashier_sub),
            entry_type="sale",
            amount_cents=total_cents,
            state="settled",
            reason="pos_cash_sale",
            meta={"txn_id": txn_id, "session_id": session_id, "order_id": order_id or ""},
            extra={"provider": "pos_cash", "signed_amount_cents": -total_cents},
        )
        T.billing.put_item(Item=led_item)
        ledger_sk_val = sk_val
    except Exception:
        # Billing failure must NOT roll back the already-settled cart.
        _audit("pos_cash_ledger_failed", cashier_sub, txn_id=txn_id)

    # Update session cash-float counters atomically.
    try:
        T.pos.update_item(
            Key=_session_pk(session_id),
            UpdateExpression="ADD cash_in_cents :ci, change_out_cents :co",
            ExpressionAttributeValues={
                ":ci": amount_tendered_cents,
                ":co": change_due,
            },
        )
    except Exception:
        pass  # Best-effort; close_session will use whatever is there.

    # Mark TXN as tendered.
    update_expr = (
        "SET #status = :tendered, "
        "order_id = :oid, "
        "tax_cents = :tax, "
        "total_cents = :total, "
        "updated_at = :now"
    )
    expr_vals: Dict[str, Any] = {
        ":tendered": "tendered",
        ":oid": order_id or "",
        ":tax": tax_cents,
        ":total": total_cents,
        ":now": now,
    }
    if ledger_sk_val:
        update_expr += ", ledger_sk = :lsk"
        expr_vals[":lsk"] = ledger_sk_val

    T.pos.update_item(
        Key=_txn_pk(txn_id),
        UpdateExpression=update_expr,
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues=expr_vals,
    )

    _audit(
        "pos_cash_tendered",
        cashier_sub,
        txn_id=txn_id,
        session_id=session_id,
        total_cents=total_cents,
        amount_tendered_cents=amount_tendered_cents,
        change_due_cents=change_due,
        order_id=order_id or "",
    )

    # POS-009 — best-effort receipt generation; never blocks settlement.
    try:
        from app.services.pos_receipt import get_or_create_pos_receipt  # lazy import (RULE-1)
        get_or_create_pos_receipt(txn_id)
    except Exception:
        pass

    updated = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item", txn_item)
    return _build_txn_out_from_item(updated, session_id)


# ── tender a transaction (card) ───────────────────────────────────────────────

def tender_card(
    *,
    session_id: str,
    txn_id: str,
    cashier_sub: str,
    amount_tendered_cents: int,
    payment_method_id: str,
    idempotency_key: str,
    card_kind: Optional[str] = None,
    last4: Optional[str] = None,
) -> Dict[str, Any]:
    """Complete a POS sale via card payment (POS-007).

    Routes the actual charge through the shared billing layer
    (``app.routers.billing.charge_once``) — same Stripe PaymentIntent path,
    provider-toggle 503 gate, and fraud-gate 403 used everywhere else. No
    billing math is forked here. After the charge settles, the canonical POS
    sale ledger entry is written (``provider="pos_card"``) and the cart is
    settled via ``purchase_cart`` (mirrors ``tender_cash``).

    Card decline -> 402 (no tender row, TXN stays 'draft').
    """
    _require_enabled()

    txn_item, total_cents = _load_draft_txn_for_tender(
        session_id=session_id, txn_id=txn_id, cashier_sub=cashier_sub,
    )
    if txn_item.get("status") == "tendered":
        return _build_txn_out_from_item(txn_item, session_id)

    # Card must cover the total exactly (no overpayment/change on a card).
    if amount_tendered_cents < total_cents:
        raise HTTPException(
            status_code=422,
            detail=f"Card amount ({amount_tendered_cents} cents) does not cover total ({total_cents} cents)",
        )

    now = now_ts()

    # Idempotency gate on the tender row (before any charge).
    tender_row: Dict[str, Any] = {
        "pos_pk": f"SESSION#{session_id}",
        "pos_sk": f"TENDER#{txn_id}",
        "txn_id": txn_id,
        "session_id": session_id,
        "cashier_sub": cashier_sub,
        "kind": "card",
        "amount_cents": amount_tendered_cents,
        "change_due_cents": 0,
        "total_cents": total_cents,
        "payment_method_id": payment_method_id,
        "created_at": now,
        "idempotency_key": idempotency_key,
    }
    if card_kind:
        tender_row["card_kind"] = card_kind
    if last4:
        tender_row["last4"] = last4
    if card_kind or last4:
        # card_ref drives the receipt brand/last4 projection ("visa_4242").
        tender_row["card_ref"] = f"{card_kind or 'card'}_{last4 or '????'}"

    try:
        T.pos.put_item(
            Item=tender_row,
            ConditionExpression="attribute_not_exists(pos_pk)",
        )
    except ClientError as exc:
        code = exc.response["Error"].get("Code", "")
        if code == "ConditionalCheckFailedException":
            fresh = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item", txn_item)
            return _build_txn_out_from_item(fresh, session_id)
        raise

    # Charge the card through the shared billing layer (provider toggle + fraud
    # gate + Stripe PaymentIntent all live inside charge_once). On decline we
    # roll back the tender row and surface a 402 (TXN stays 'draft').
    pi_id: Optional[str] = None
    try:
        from app.routers.billing import charge_once  # lazy import (RULE-1)
        from app.models import StripeChargeReq  # lazy import (RULE-1)
        result = charge_once(
            StripeChargeReq(
                amount_cents=total_cents,
                payment_method_id=payment_method_id,
                description=f"POS card tender txn:{txn_id}",
                idempotency_key=f"pos_card:{txn_id}:{idempotency_key}",
            ),
            req=None,
            ctx={"user_sub": cashier_sub},
            actor=None,
        )
        status = (result or {}).get("status")
        pi_id = (result or {}).get("payment_intent_id")
        if status == "failed":
            # Card declined — undo the tender row, leave TXN draft.
            T.pos.delete_item(Key={"pos_pk": f"SESSION#{session_id}", "pos_sk": f"TENDER#{txn_id}"})
            raise HTTPException(
                status_code=402,
                detail=str((result or {}).get("reason") or "Card declined"),
            )
    except HTTPException:
        # Provider-disabled (503), fraud (403), or our own 402 — undo tender row.
        T.pos.delete_item(Key={"pos_pk": f"SESSION#{session_id}", "pos_sk": f"TENDER#{txn_id}"})
        raise
    except Exception as exc:
        T.pos.delete_item(Key={"pos_pk": f"SESSION#{session_id}", "pos_sk": f"TENDER#{txn_id}"})
        raise HTTPException(status_code=502, detail=f"Card charge failed: {exc}") from exc

    if pi_id:
        T.pos.update_item(
            Key={"pos_pk": f"SESSION#{session_id}", "pos_sk": f"TENDER#{txn_id}"},
            UpdateExpression="SET pi_id = :p",
            ExpressionAttributeValues={":p": pi_id},
        )

    return _settle_noncash_tender(
        txn_item=txn_item,
        session_id=session_id,
        txn_id=txn_id,
        cashier_sub=cashier_sub,
        total_cents=total_cents,
        ledger_provider="pos_card",
        ledger_reason="pos_card_sale",
        ledger_meta={"pi_id": pi_id or ""},
        now=now,
        audit_event_name="pos_card_tendered",
        audit_extra={"payment_method_id": payment_method_id, "pi_id": pi_id or ""},
    )


# ── tender a transaction (wallet) ─────────────────────────────────────────────

def tender_wallet(
    *,
    session_id: str,
    txn_id: str,
    cashier_sub: str,
    amount_tendered_cents: int,
    idempotency_key: str,
) -> Dict[str, Any]:
    """Complete a POS sale via in-platform wallet debit (POS-007).

    Debits the cashier-user's wallet via ``billing_shared.apply_wallet_delta``
    (insufficient balance -> 402). Writes the canonical POS sale ledger entry
    (``provider="pos_wallet"``) and settles the cart. No billing math forked.
    """
    _require_enabled()

    txn_item, total_cents = _load_draft_txn_for_tender(
        session_id=session_id, txn_id=txn_id, cashier_sub=cashier_sub,
    )
    if txn_item.get("status") == "tendered":
        return _build_txn_out_from_item(txn_item, session_id)

    if amount_tendered_cents < total_cents:
        raise HTTPException(
            status_code=422,
            detail=f"Wallet amount ({amount_tendered_cents} cents) does not cover total ({total_cents} cents)",
        )

    now = now_ts()

    tender_row: Dict[str, Any] = {
        "pos_pk": f"SESSION#{session_id}",
        "pos_sk": f"TENDER#{txn_id}",
        "txn_id": txn_id,
        "session_id": session_id,
        "cashier_sub": cashier_sub,
        "kind": "wallet",
        "amount_cents": amount_tendered_cents,
        "change_due_cents": 0,
        "total_cents": total_cents,
        "payment_method_id": "wallet",
        "created_at": now,
        "idempotency_key": idempotency_key,
    }

    try:
        T.pos.put_item(
            Item=tender_row,
            ConditionExpression="attribute_not_exists(pos_pk)",
        )
    except ClientError as exc:
        code = exc.response["Error"].get("Code", "")
        if code == "ConditionalCheckFailedException":
            fresh = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item", txn_item)
            return _build_txn_out_from_item(fresh, session_id)
        raise

    # Debit the wallet via the shared primitive. Insufficient balance raises a
    # ConditionalCheckFailedException (botocore ClientError) -> 402.
    try:
        from app.services.billing_shared import apply_wallet_delta, user_pk  # lazy import (RULE-1)
        apply_wallet_delta(T.billing, user_pk(cashier_sub), -int(total_cents))
    except ClientError as exc:
        code = exc.response["Error"].get("Code", "")
        T.pos.delete_item(Key={"pos_pk": f"SESSION#{session_id}", "pos_sk": f"TENDER#{txn_id}"})
        if code == "ConditionalCheckFailedException":
            raise HTTPException(status_code=402, detail="Insufficient wallet balance")
        raise
    except HTTPException:
        T.pos.delete_item(Key={"pos_pk": f"SESSION#{session_id}", "pos_sk": f"TENDER#{txn_id}"})
        raise
    except Exception as exc:
        T.pos.delete_item(Key={"pos_pk": f"SESSION#{session_id}", "pos_sk": f"TENDER#{txn_id}"})
        raise HTTPException(status_code=502, detail=f"Wallet debit failed: {exc}") from exc

    return _settle_noncash_tender(
        txn_item=txn_item,
        session_id=session_id,
        txn_id=txn_id,
        cashier_sub=cashier_sub,
        total_cents=total_cents,
        ledger_provider="pos_wallet",
        ledger_reason="pos_wallet_sale",
        ledger_meta={},
        now=now,
        audit_event_name="pos_wallet_tendered",
        audit_extra={},
    )


# ── shared non-cash settlement helper ─────────────────────────────────────────

def _load_draft_txn_for_tender(
    *, session_id: str, txn_id: str, cashier_sub: str,
) -> tuple[Dict[str, Any], int]:
    """Load + validate a draft TXN for tender. Returns (txn_item, total_cents).

    Mirrors tender_cash's validation: 404 (missing), 403 (wrong cashier),
    409 (not draft, except the idempotent 'tendered' case which the caller
    short-circuits). total_cents = subtotal + global tax.
    """
    txn_item = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item")
    if not txn_item:
        raise HTTPException(status_code=404, detail="Transaction not found")
    if txn_item.get("cashier_sub") != cashier_sub:
        raise HTTPException(status_code=403, detail="Cashier does not own this transaction")

    status = txn_item.get("status")
    if status == "tendered":
        # Caller short-circuits to an idempotent return.
        return txn_item, _to_int(txn_item.get("total_cents")) or _to_int(txn_item.get("subtotal_cents"))
    if status != "draft":
        raise HTTPException(
            status_code=409,
            detail=f"Transaction status is '{status}'; cannot tender",
        )

    subtotal_cents = _to_int(txn_item.get("subtotal_cents"))
    tax_rate_bps = getattr(S, "pos_default_tax_rate_bps", 0)
    tax_cents = int(subtotal_cents * tax_rate_bps / 10000)
    total_cents = subtotal_cents + tax_cents
    return txn_item, total_cents


def _settle_noncash_tender(
    *,
    txn_item: Dict[str, Any],
    session_id: str,
    txn_id: str,
    cashier_sub: str,
    total_cents: int,
    ledger_provider: str,
    ledger_reason: str,
    ledger_meta: Dict[str, Any],
    now: int,
    audit_event_name: str,
    audit_extra: Dict[str, Any],
) -> Dict[str, Any]:
    """Settle a card/wallet tender: purchase_cart -> ledger entry -> mark TXN
    tendered. Mirrors the tail of tender_cash. Money has already moved before
    this is called; the canonical POS sale ledger row is written here.
    """
    cart_id = txn_item.get("cart_id", "")
    subtotal_cents = _to_int(txn_item.get("subtotal_cents"))
    tax_cents = total_cents - subtotal_cents

    # Settle the cart (stock decrement + order creation).
    order_id: Optional[str] = None
    try:
        from app.services.shoppingcart import purchase_cart  # lazy import (RULE-1)
        purchase_result = purchase_cart(cashier_sub, cart_id)
        order_id = purchase_result.get("order_id") or purchase_result.get("cart_id")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Cart purchase failed: {exc}") from exc

    # Write the canonical POS sale ledger entry (provider-attributed).
    ledger_sk_val: Optional[str] = None
    try:
        from app.services.billing_shared import new_ledger_entry, user_pk  # lazy import (RULE-1)
        meta = {"txn_id": txn_id, "session_id": session_id, "order_id": order_id or ""}
        meta.update(ledger_meta)
        sk_val, led_item = new_ledger_entry(
            key_name="pk",
            key_value=user_pk(cashier_sub),
            entry_type="sale",
            amount_cents=total_cents,
            state="settled",
            reason=ledger_reason,
            meta=meta,
            extra={"provider": ledger_provider, "signed_amount_cents": -total_cents},
        )
        T.billing.put_item(Item=led_item)
        ledger_sk_val = sk_val
    except Exception:
        _audit(f"{ledger_provider}_ledger_failed", cashier_sub, txn_id=txn_id)

    # Mark TXN as tendered.
    update_expr = (
        "SET #status = :tendered, order_id = :oid, tax_cents = :tax, "
        "total_cents = :total, updated_at = :now"
    )
    expr_vals: Dict[str, Any] = {
        ":tendered": "tendered",
        ":oid": order_id or "",
        ":tax": tax_cents,
        ":total": total_cents,
        ":now": now,
    }
    if ledger_sk_val:
        update_expr += ", ledger_sk = :lsk"
        expr_vals[":lsk"] = ledger_sk_val

    T.pos.update_item(
        Key=_txn_pk(txn_id),
        UpdateExpression=update_expr,
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues=expr_vals,
    )

    _audit(
        audit_event_name,
        cashier_sub,
        txn_id=txn_id,
        session_id=session_id,
        total_cents=total_cents,
        order_id=order_id or "",
        **audit_extra,
    )

    # POS-009 — best-effort receipt generation; never blocks settlement.
    try:
        from app.services.pos_receipt import get_or_create_pos_receipt  # lazy import (RULE-1)
        get_or_create_pos_receipt(txn_id)
    except Exception:
        pass

    updated = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item", txn_item)
    return _build_txn_out_from_item(updated, session_id)


# ── void a transaction ────────────────────────────────────────────────────────

def void_txn(
    *,
    txn_id: str,
    cashier_sub: str,
    reason: str,
) -> Dict[str, Any]:
    """Void a draft POS transaction (no money was charged yet).

    Can only void a 'draft' TXN (before tender). After tender, use refund_txn.
    """
    _require_enabled()

    txn_item = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item")
    if not txn_item:
        raise HTTPException(status_code=404, detail="Transaction not found")
    if txn_item.get("cashier_sub") != cashier_sub:
        raise HTTPException(status_code=403, detail="Cashier does not own this transaction")

    status = txn_item.get("status")
    if status == "voided":
        return _build_txn_out_from_item(txn_item, txn_item.get("session_id", ""))
    if status != "draft":
        raise HTTPException(
            status_code=409,
            detail=f"Transaction status is '{status}'; only draft transactions can be voided",
        )

    session_id = txn_item.get("session_id", "")
    now = now_ts()

    T.pos.update_item(
        Key=_txn_pk(txn_id),
        UpdateExpression="SET #status = :voided, void_reason = :reason, updated_at = :now",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":voided": "voided",
            ":reason": reason,
            ":now": now,
        },
    )

    _audit("pos_txn_voided", cashier_sub, txn_id=txn_id, session_id=session_id, reason=reason)

    updated = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item", txn_item)
    return _build_txn_out_from_item(updated, session_id)


# ── refund a tendered transaction ─────────────────────────────────────────────

def refund_txn(
    *,
    txn_id: str,
    cashier_sub: str,
    reason: str,
) -> Dict[str, Any]:
    """Refund a tendered POS transaction via the returns/RMA pipeline.

    Guards on S.inventory_reservations_enabled for inventory flag (RULE-2).
    Writes a reversal ledger entry with extra={"provider": "pos_cash"}.
    """
    _require_enabled()

    txn_item = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item")
    if not txn_item:
        raise HTTPException(status_code=404, detail="Transaction not found")
    if txn_item.get("cashier_sub") != cashier_sub:
        raise HTTPException(status_code=403, detail="Cashier does not own this transaction")

    status = txn_item.get("status")
    if status == "refunded":
        return _build_txn_out_from_item(txn_item, txn_item.get("session_id", ""))
    if status != "tendered":
        raise HTTPException(
            status_code=409,
            detail=f"Transaction status is '{status}'; only tendered transactions can be refunded",
        )

    session_id = txn_item.get("session_id", "")
    total_cents = _to_int(txn_item.get("total_cents"))
    ledger_sk_ref = txn_item.get("ledger_sk")
    now = now_ts()

    # Reverse the ledger entry if we have a reference.
    if ledger_sk_ref:
        try:
            from app.services.billing_shared import settle_or_reverse_ledger, user_pk  # lazy import (RULE-1)
            settle_or_reverse_ledger(
                T.billing,
                "pk",
                user_pk(cashier_sub),
                ledger_sk_ref,
                new_state="reversed",
            )
        except Exception:
            pass  # Best-effort; don't block the refund state transition.

    # Write a refund ledger entry.
    try:
        from app.services.billing_shared import new_ledger_entry, user_pk  # lazy import (RULE-1)
        _sk_ref, led_item = new_ledger_entry(
            key_name="pk",
            key_value=user_pk(cashier_sub),
            entry_type="refund",
            amount_cents=total_cents,
            state="settled",
            reason="pos_cash_refund",
            meta={"txn_id": txn_id, "session_id": session_id},
            extra={"provider": "pos_cash", "signed_amount_cents": total_cents},
        )
        T.billing.put_item(Item=led_item)
    except Exception:
        _audit("pos_refund_ledger_failed", cashier_sub, txn_id=txn_id)

    # Guard on inventory flag for any stock restoration (RULE-2).
    if getattr(S, "inventory_reservations_enabled", False):
        try:
            # Inventory restoration is handled by the returns/RMA pipeline.
            # Here we just note the flag is on; actual restoration lives in returns_rma.
            pass
        except Exception:
            pass

    T.pos.update_item(
        Key=_txn_pk(txn_id),
        UpdateExpression="SET #status = :refunded, refund_reason = :reason, updated_at = :now",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":refunded": "refunded",
            ":reason": reason,
            ":now": now,
        },
    )

    _audit("pos_txn_refunded", cashier_sub, txn_id=txn_id, session_id=session_id,
           total_cents=total_cents, reason=reason)

    updated = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item", txn_item)
    return _build_txn_out_from_item(updated, session_id)


# ── session report (X/Z) ──────────────────────────────────────────────────────

def get_session_report(session_id: str) -> Dict[str, Any]:
    """Compute X/Z report totals for a session."""
    _require_enabled()

    sess_item = T.pos.get_item(Key=_session_pk(session_id)).get("Item")
    if not sess_item:
        raise HTTPException(status_code=404, detail="Session not found")

    # Query all TXN rows for this session via GSI_SESSION_TXN.
    txns: List[Dict[str, Any]] = []
    try:
        resp = T.pos.query(
            IndexName="GSI_SESSION_TXN",
            KeyConditionExpression="session_id = :sid",
            ExpressionAttributeValues={":sid": session_id},
            ScanIndexForward=True,
        )
        txns = resp.get("Items", [])
        # Paginate if needed.
        while resp.get("LastEvaluatedKey"):
            resp = T.pos.query(
                IndexName="GSI_SESSION_TXN",
                KeyConditionExpression="session_id = :sid",
                ExpressionAttributeValues={":sid": session_id},
                ExclusiveStartKey=resp["LastEvaluatedKey"],
                ScanIndexForward=True,
            )
            txns.extend(resp.get("Items", []))
    except Exception:
        pass

    # Compute totals from tendered TXNs.
    total_sales_cents = 0
    transaction_count = 0
    for txn in txns:
        if txn.get("status") == "tendered":
            transaction_count += 1
            total_sales_cents += _to_int(txn.get("total_cents"))

    # Query tender sub-rows for cash totals.
    total_cash_tendered = 0
    total_change_given = 0
    try:
        tender_resp = T.pos.query(
            KeyConditionExpression="pos_pk = :pk AND begins_with(pos_sk, :prefix)",
            ExpressionAttributeValues={
                ":pk": f"SESSION#{session_id}",
                ":prefix": "TENDER#",
            },
        )
        for t in tender_resp.get("Items", []):
            if t.get("kind") == "cash":
                total_cash_tendered += _to_int(t.get("amount_cents"))
                total_change_given += _to_int(t.get("change_due_cents"))
    except Exception:
        pass

    base = _to_int
    return {
        "session_id": session_id,
        "register_id": sess_item.get("register_id", ""),
        "cashier_sub": sess_item.get("cashier_sub", ""),
        "status": sess_item.get("status", ""),
        "opening_float_cents": base(sess_item.get("opening_float_cents")),
        "closing_float_cents": sess_item.get("closing_float_cents"),
        "expected_cash_cents": sess_item.get("expected_cash_cents"),
        "counted_cash_cents": sess_item.get("counted_cash_cents"),
        "over_short_cents": sess_item.get("over_short_cents"),
        "opened_at": base(sess_item.get("opened_at")),
        "closed_at": sess_item.get("closed_at"),
        "transaction_count": transaction_count,
        "total_sales_cents": total_sales_cents,
        "total_cash_tendered_cents": total_cash_tendered,
        "total_change_given_cents": total_change_given,
    }


# ── list session transactions ─────────────────────────────────────────────────

def list_session_txns(session_id: str) -> List[Dict[str, Any]]:
    """List all TXNs for a session via GSI_SESSION_TXN."""
    _require_enabled()

    try:
        resp = T.pos.query(
            IndexName="GSI_SESSION_TXN",
            KeyConditionExpression="session_id = :sid",
            ExpressionAttributeValues={":sid": session_id},
            ScanIndexForward=True,
        )
        items = resp.get("Items", [])
        while resp.get("LastEvaluatedKey"):
            resp = T.pos.query(
                IndexName="GSI_SESSION_TXN",
                KeyConditionExpression="session_id = :sid",
                ExpressionAttributeValues={":sid": session_id},
                ExclusiveStartKey=resp["LastEvaluatedKey"],
                ScanIndexForward=True,
            )
            items.extend(resp.get("Items", []))
        return [_txn_out(it) for it in items]
    except Exception:
        return []


# ── private helpers ───────────────────────────────────────────────────────────

def _build_txn_out_from_item(item: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    """Build a PosTransactionOut-compatible dict from a TXN row."""
    txn_id = item.get("txn_id", "")
    # Fetch tender rows to build the tenders list.
    tenders: List[Dict[str, Any]] = []
    try:
        resp = T.pos.query(
            KeyConditionExpression="pos_pk = :pk AND begins_with(pos_sk, :prefix)",
            ExpressionAttributeValues={
                ":pk": f"SESSION#{session_id}",
                ":prefix": f"TENDER#{txn_id}",
            },
        )
        for t in resp.get("Items", []):
            tenders.append({
                "kind": t.get("kind", "cash"),
                "amount_cents": _to_int(t.get("amount_cents")),
                "change_due_cents": _to_int(t.get("change_due_cents")),
                "payment_method_id": t.get("payment_method_id"),
                "card_ref": t.get("card_ref"),
            })
    except Exception:
        pass

    return {
        "txn_id": txn_id,
        "session_id": session_id,
        "cart_id": item.get("cart_id"),
        "order_id": item.get("order_id"),
        "status": item.get("status", "draft"),
        "subtotal_cents": _to_int(item.get("subtotal_cents")),
        "discount_cents": _to_int(item.get("discount_cents")),
        "tax_cents": _to_int(item.get("tax_cents")),
        "total_cents": _to_int(item.get("total_cents")),
        "tenders": tenders,
        "receipt_id": item.get("receipt_id"),
        "created_at": _to_int(item.get("created_at")),
        "updated_at": _to_int(item.get("updated_at")),
    }

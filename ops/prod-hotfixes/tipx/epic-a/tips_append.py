

# ---------------------------------------------------------------------------
# TIPX-A2 — reachable reversal: look up a tip by tip_payment_id and reverse it.
# ---------------------------------------------------------------------------
def _find_tip_debit_row(tipper_id: str, tip_payment_id: str) -> Optional[Dict[str, Any]]:
    """Return the tipper's DEBIT ledger row for ``tip_payment_id`` (or None).

    Scans the tipper's billing partition for a ``type=="debit"`` tip row whose
    ``meta.tip_payment_id`` matches. Cheap: one partition, tip debits are sparse.
    """
    for row in ddb_query_pk(T.billing, user_pk(tipper_id)):
        if row.get("type") != "debit":
            continue
        meta = row.get("meta") or {}
        if meta.get("tip_payment_id") == tip_payment_id:
            return row
    return None


def _find_tip_credit_row(recipient_id: str, tip_payment_id: str) -> Optional[Dict[str, Any]]:
    """Return the recipient's CREDIT ledger row for ``tip_payment_id`` (or None)."""
    for row in ddb_query_pk(T.billing, user_pk(recipient_id)):
        if row.get("type") != "credit":
            continue
        meta = row.get("meta") or {}
        if meta.get("tip_payment_id") == tip_payment_id:
            return row
    return None


def reverse_tip_by_payment_id(
    *,
    tip_payment_id: str,
    tipper_id: str,
    recipient_id: Optional[str] = None,
    reason: str = "admin_reversal",
    actor: Optional[str] = None,
) -> ReversalResult:
    """TIPX-A2: reverse a tip identified only by its ``tip_payment_id``.

    Resolves the original debit (and, where possible, the recipient credit) from
    the ledger so callers -- an admin refund route or a charged-but-not-delivered
    reconcile hook -- can undo a tip without threading every ledger field. Then
    delegates to the idempotent ``reverse_tip`` (type != "credit", flips the
    original credit to state="reversed", best-effort Stripe refund).

    ``tipper_id`` is required (the ledger is partitioned by user). ``recipient_id``
    is derived from the debit row's meta when omitted.

    Idempotency short-circuits BEFORE the (possibly slow) ledger scan: a
    tip that was already reversed returns its stored receipt with no re-scan.
    """
    if not tip_payment_id:
        raise HTTPException(400, {"code": "missing_tip_id", "message": "tip_payment_id is required."})
    if not tipper_id:
        raise HTTPException(400, {"code": "missing_tipper", "message": "tipper_id is required to locate the tip."})

    # Already reversed -> return the stored receipt (idempotent, no scan needed).
    prior = _load_reversal_receipt(tipper_id, tip_payment_id)
    if prior is not None:
        return prior

    debit = _find_tip_debit_row(tipper_id, tip_payment_id)
    if not debit:
        raise HTTPException(404, {"code": "tip_not_found", "message": f"No tip debit found for {tip_payment_id}."})
    meta = debit.get("meta") or {}

    gross_cents = int(debit.get("amount_cents", 0))
    fee_cents = int(meta.get("platform_fee_cents", 0))
    net_cents = max(0, gross_cents - fee_cents)
    content_type = meta.get("content_type", "post")
    content_id = meta.get("content_id", "")
    currency = debit.get("currency", "USD")
    payment_intent_id = meta.get("payment_intent_id") or debit.get("payment_intent_id")
    recipient = recipient_id or meta.get("recipient_user_id", "")
    if not recipient:
        raise HTTPException(400, {"code": "missing_recipient", "message": "Could not resolve tip recipient."})

    # Locate the recipient credit row so reverse_tip can flip it to state=reversed
    # (clawing the net out of the recipient's spendable balance + leaderboard).
    credit_entry_id = None
    credit_ts = None
    credit = _find_tip_credit_row(recipient, tip_payment_id)
    if credit:
        credit_entry_id = credit.get("entry_id")
        credit_ts = int(credit.get("ts", 0)) or None

    return reverse_tip(
        tipper_id=tipper_id,
        recipient_id=recipient,
        gross_cents=gross_cents,
        net_cents=net_cents,
        tip_payment_id=tip_payment_id,
        content_type=content_type,
        content_id=content_id,
        currency=currency,
        payment_intent_id=payment_intent_id,
        credit_entry_id=credit_entry_id,
        credit_ts=credit_ts,
        reason=reason,
        actor=actor,
    )

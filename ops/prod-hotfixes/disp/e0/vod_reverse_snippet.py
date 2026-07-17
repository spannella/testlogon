

# ─── DISP-004 (N1): reverse a VOD pay-to-unlock purchase ─────────────────────
#
# The ONE true code gap in the payment-disputes program: VOD pay-to-unlock
# (purchase_video above) writes a buyer debit + a seller credit + the
# T.vod_entitlements access row, but has NO reverse function — refunding a VOD
# purchase today would leave the buyer with BOTH the money back AND continued
# access. reverse_vod_purchase mirrors the tips.reverse_tip / _reverse_subscription_charge
# shape and, crucially, DELETES the entitlement row so a refunded buyer LOSES
# access (playback re-locks).
#
# Money-safety invariants (identical to reverse_tip):
#   * the seller CLAWBACK entry (type="reversal") and the buyer REFUND entry
#     (type="refund") are NOT type="credit", so a reversal can never inflate
#     seller earnings (get_available_balance sums only type=="credit").
#   * the ORIGINAL seller credit row is flipped to state="reversed" so it drops
#     out of get_available_balance. NOTE: the seller-credit entry_type differs by
#     environment — prod writes type="credit" (counts toward balance), the dev
#     clone writes type="vod_purchase_credit" (does not) — so the original credit
#     is located by meta.purchase_id (type-agnostic), and the flip is correct in
#     both. On prod this genuinely claws spendable balance back; on dev the flip
#     is still recorded for audit/reconciliation honesty.
#   * a VODREVERSAL#{purchase_id} marker (conditional put) makes it idempotent +
#     guards double-reversal; a second call returns the stored receipt as a no-op.
#   * clawback_only=True suppresses the buyer refund leg (for the chargeback path
#     in E3: the processor already pulled the buyer's money, so we only claw the
#     seller credit and revoke access — no double buyer credit).
#
# Access revocation (delete_item) is a best-effort adjunct AFTER the atomic
# ledger transact, on the FIRST reversal only, exactly like reverse_tip flips the
# original credit only on the first (winning) call.

def _vod_reversal_sk(purchase_id: str) -> str:
    return f"VODREVERSAL#{purchase_id}"


def _find_vod_purchase_debit_row(buyer_id: str, purchase_id: str) -> Optional[Dict[str, Any]]:
    """Return the buyer's DEBIT ledger row for ``purchase_id`` (or None)."""
    pk = user_pk(buyer_id)
    for row in T.billing.query(
        KeyConditionExpression=Key("pk").eq(pk),
    ).get("Items", []):
        if not str(row.get("sk", "")).startswith("LEDGER#"):
            continue
        if str(row.get("type", "")) != "vod_purchase_debit":
            continue
        meta = row.get("meta") or {}
        if meta.get("purchase_id") == purchase_id:
            return row
    return None


def _find_vod_credit_row(seller_id: str, purchase_id: str) -> Optional[Dict[str, Any]]:
    """Return the seller's original CREDIT ledger row for ``purchase_id`` (or None).

    Located by ``meta.purchase_id`` and NOT by a fixed ``type`` value: prod writes
    the seller credit as type="credit" while the dev clone writes
    type="vod_purchase_credit". We accept either credit-direction type so the
    state="reversed" flip is correct in both environments; refund/reversal/debit
    rows (which also carry the purchase_id) are excluded so a replay never
    re-flips a reversal entry.
    """
    _CREDIT_TYPES = {"credit", "vod_purchase_credit", "vod_rental_credit"}
    pk = user_pk(seller_id)
    for row in T.billing.query(
        KeyConditionExpression=Key("pk").eq(pk),
    ).get("Items", []):
        if not str(row.get("sk", "")).startswith("LEDGER#"):
            continue
        if str(row.get("type", "")) not in _CREDIT_TYPES:
            continue
        meta = row.get("meta") or {}
        if meta.get("purchase_id") == purchase_id:
            return row
    return None


def reverse_vod_purchase(
    *,
    purchase_id: str,
    buyer_id: str,
    seller_id: Optional[str] = None,
    video_id: Optional[str] = None,
    gross_cents: Optional[int] = None,
    currency: str = "USD",
    reason: str = "admin_reversal",
    actor: Optional[str] = None,
    clawback_only: bool = False,
) -> Dict[str, Any]:
    """DISP-004 (N1): idempotently reverse a VOD pay-to-unlock purchase.

    Writes, in a single TransactWriteItems on T.billing:
      * a seller CLAWBACK ledger entry (type="reversal", amount = gross) —
      * a buyer REFUND ledger entry (type="refund", amount = gross) — UNLESS
        ``clawback_only`` (chargeback path: buyer already got their money) —
      * a ``VODREVERSAL#{purchase_id}`` marker claimed with attribute_not_exists.

    NEITHER money entry uses type "credit", so a reversal can never inflate seller
    earnings. The marker makes it idempotent + guards double-reversal.

    Best-effort adjuncts (FIRST reversal only): flip the original seller credit to
    state="reversed" (drops it out of get_available_balance) and — the code gap
    this ticket exists to close — DELETE the T.vod_entitlements row so the
    refunded buyer LOSES access (check_entitlement -> not_purchased, playback 403).

    Charge fields (seller_id/video_id/gross_cents) are resolved from the ledger
    when omitted, so an admin/dispatch caller can reverse a purchase knowing only
    (purchase_id, buyer_id).
    """
    if not purchase_id:
        raise HTTPException(400, {"code": "missing_purchase_id", "message": "purchase_id is required to reverse a VOD purchase."})
    if not buyer_id:
        raise HTTPException(400, {"code": "missing_buyer", "message": "buyer_id is required to locate the purchase."})

    marker_key = _vod_reversal_sk(purchase_id)

    # Idempotency short-circuit BEFORE the ledger scan: already reversed -> receipt.
    prior = T.billing.get_item(Key={"pk": user_pk(buyer_id), "sk": marker_key}).get("Item")
    if prior and prior.get("purchase_id"):
        return {**{k: v for k, v in prior.items() if k not in ("pk", "sk")}, "idempotent_replay": True}

    # Resolve missing charge fields from the buyer debit row.
    debit = _find_vod_purchase_debit_row(buyer_id, purchase_id)
    dmeta = (debit or {}).get("meta") or {}
    seller = seller_id or str(dmeta.get("seller_id") or "")
    vid = video_id or str(dmeta.get("video_id") or "")
    if gross_cents is None:
        gross_cents = abs(int((debit or {}).get("amount_cents", 0) or 0))
    if debit is not None:
        currency = str(debit.get("currency") or currency)
    if not seller:
        raise HTTPException(400, {"code": "missing_seller", "message": "Could not resolve VOD seller."})
    if gross_cents <= 0:
        raise HTTPException(400, {"code": "invalid_amount", "message": "VOD reversal amount must be positive."})

    ts = now_ts()
    reversal_id = uuid.uuid4().hex
    refund_id = uuid.uuid4().hex

    # Locate the original seller credit so we can flip it to state="reversed".
    credit = _find_vod_credit_row(seller, purchase_id)

    base_meta: Dict[str, Any] = {
        "content_type": "vod",
        "content_id": vid,
        "video_id": vid,
        "buyer_id": buyer_id,
        "buyer_user_id": buyer_id,
        "seller_id": seller,
        "recipient_user_id": seller,
        "purchase_id": purchase_id,
        "reversal_of": purchase_id,
        "reversal_reason": reason,
        "clawback_only": bool(clawback_only),
    }
    if actor:
        base_meta["reversal_actor"] = actor

    # Seller clawback (type != "credit" -> earnings not inflated).
    clawback_item = {
        "pk": user_pk(seller),
        "sk": f"LEDGER#{ts}#{reversal_id}",
        "entry_id": reversal_id,
        "ts": ts,
        "type": "reversal",
        "amount_cents": int(gross_cents),
        "currency": currency,
        "state": "settled",
        "reason": "Reversal: VOD purchase refund",
        "meta": base_meta,
    }
    # Buyer refund (type != "credit"). Suppressed on the chargeback (clawback_only) path.
    refund_item = {
        "pk": user_pk(buyer_id),
        "sk": f"LEDGER#{ts}#{refund_id}",
        "entry_id": refund_id,
        "ts": ts,
        "type": "refund",
        "amount_cents": int(gross_cents),
        "currency": currency,
        "state": "settled",
        "reason": "Refund: VOD purchase",
        "meta": base_meta,
    }

    receipt: Dict[str, Any] = {
        "purchase_id": purchase_id,
        "video_id": vid,
        "buyer_id": buyer_id,
        "seller_id": seller,
        "refunded_cents": 0 if clawback_only else int(gross_cents),
        "clawback_cents": int(gross_cents),
        "reversal_entry_id": reversal_id,
        "refund_entry_id": "" if clawback_only else refund_id,
        "clawback_only": bool(clawback_only),
        "reason": reason,
        "created_at": ts,
        "idempotent_replay": False,
    }
    marker_item = {
        "pk": user_pk(buyer_id),
        "sk": marker_key,
        **receipt,
    }

    table_name = S.billing_table_name
    tx_items = [
        {"Put": {"TableName": table_name, "Item": _vod_av(clawback_item)}},
    ]
    if not clawback_only:
        tx_items.append({"Put": {"TableName": table_name, "Item": _vod_av(refund_item)}})
    tx_items.append({
        "Put": {
            "TableName": table_name,
            "Item": _vod_av(marker_item),
            "ConditionExpression": "attribute_not_exists(sk)",
        }
    })

    client = ddb_transact_client()
    try:
        client.transact_write_items(TransactItems=tx_items)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "TransactionCanceledException":
            # Lost the race / already reversed -> return the stored receipt.
            winner = T.billing.get_item(Key={"pk": user_pk(buyer_id), "sk": marker_key}).get("Item")
            if winner and winner.get("purchase_id"):
                return {**{k: v for k, v in winner.items() if k not in ("pk", "sk")}, "idempotent_replay": True}
            receipt["idempotent_replay"] = True
            return receipt
        raise

    # --- best-effort adjuncts, FIRST reversal only ---
    # 1. Flip the original seller credit out of spendable balance.
    if credit is not None:
        try:
            T.billing.update_item(
                Key={"pk": user_pk(seller), "sk": credit.get("sk")},
                UpdateExpression="SET #s = :r",
                ConditionExpression="attribute_exists(sk)",
                ExpressionAttributeNames={"#s": "state"},
                ExpressionAttributeValues={":r": "reversed"},
            )
        except Exception:
            logger.warning("original VOD credit state flip skipped for purchase=%s", purchase_id, exc_info=True)

    # 2. THE CODE GAP: delete the entitlement row so the buyer LOSES access.
    if vid:
        try:
            T.vod_entitlements.delete_item(Key={"pk": f"USER#{buyer_id}", "sk": f"VIDEO#{vid}"})
        except Exception:
            logger.warning("VOD entitlement delete skipped for buyer=%s video=%s", buyer_id, vid, exc_info=True)

    # 3. Back the revenue stats out of the video metadata (best-effort).
    if vid:
        try:
            T.video_metadata.update_item(
                Key={"video_id": vid},
                UpdateExpression="SET purchase_count = if_not_exists(purchase_count, :z) - :one, "
                "revenue_cents = if_not_exists(revenue_cents, :z) - :price",
                ConditionExpression="attribute_exists(video_id)",
                ExpressionAttributeValues={":z": 0, ":one": 1, ":price": int(gross_cents)},
            )
        except Exception:
            logger.warning("VOD revenue stat back-out skipped for video=%s", vid, exc_info=True)

    return receipt

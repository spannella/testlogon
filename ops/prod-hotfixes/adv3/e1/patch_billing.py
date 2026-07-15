import sys
p = "app/services/ad_billing.py"
s = open(p, encoding="utf-8").read()
orig = s

# ---- EDIT 1: deposit_funds signature ----
s = s.replace(
    'def deposit_funds(account_id: str, amount_cents: int, payment_method_id: str = "") -> dict:',
    'def deposit_funds(account_id: str, amount_cents: int, payment_method_id: str = "",\n                  *, internal: bool = False) -> dict:',
    1,
)

# ---- EDIT 2: honest-charge guard + idempotent credit in deposit_funds ----
old_block = '''    payment_intent_id = _charge_deposit(
        owner_sub=owner_sub, account_id=account_id,
        amount_cents=amount_cents, payment_method_id=payment_method_id,
    )

    ts = now_ts()
    entry_id = f"dep_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")
'''
new_block = '''    payment_intent_id = _charge_deposit(
        owner_sub=owner_sub, account_id=account_id,
        amount_cents=amount_cents, payment_method_id=payment_method_id,
    )

    # ADV3-1 (A1/A2/B9): the PUBLIC /deposit path must be backed by a REAL charge
    # -- never credit free budget. A missing payment method is a hard 400 (no
    # ledger, no credit); a supplied card that could not be charged because the
    # processor rail is unconfigured (dev stub -> payment_intent_id is None) is
    # recorded LOUDLY as an uncharged simulation + alert and still NOT credited.
    # The internal-seed caller (internal=True) keeps the legacy ledger-only
    # behavior so seeding/back-office top-ups without a card still work.
    from fastapi import HTTPException
    if not internal:
        if not payment_method_id:
            raise HTTPException(400, {
                "code": "payment_method_required",
                "message": "A payment method is required to fund an ad account.",
            })
        if not payment_intent_id:
            _record_uncharged_deposit(account_id, amount_cents, payment_method_id)
            raise HTTPException(402, {
                "code": "charge_unavailable",
                "message": "Deposit could not be charged (payment processor unavailable).",
            })

    ts = now_ts()
    entry_id = f"dep_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")

    # ADV3-1: idempotent credit. A double-fired deposit reuses the same processor
    # idempotency_key -> the same PaymentIntent -> credit the balance EXACTLY once.
    if payment_intent_id:
        try:
            T.ad_billing.put_item(
                Item={
                    "pk": f"ACCT#{account_id}",
                    "sk": f"DEPIDEMP#{payment_intent_id}",
                    "entry_type": "deposit_idempotency",
                    "created_at": ts,
                },
                ConditionExpression="attribute_not_exists(sk)",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                logger.info("ad_deposit_duplicate account=%s pi=%s", account_id, payment_intent_id)
                return {"ok": True, "reason": "duplicate",
                        "new_balance_cents": _get_balance(account_id)}
            raise
'''
assert old_block in s, "deposit block not found"
s = s.replace(old_block, new_block, 1)

# ---- EDIT 3: add _record_uncharged_deposit helper right after _charge_deposit ----
anchor = '''    if not charged_ok:
        raise HTTPException(
            402,
            {"code": "payment_failed",
             "message": f"Deposit charge did not succeed (status={status})."},
        )
    return pi.get("id")
'''
helper = anchor + '''

def _record_uncharged_deposit(account_id: str, amount_cents: int, payment_method_id: str) -> None:
    """ADV3-1: LOUD degrade for a public deposit that could not be charged because
    the processor rail is unconfigured (dev stub). Writes an ``uncharged_simulation``
    ledger row (NOT a ``budget_deposit`` -- no balance is credited) and emits a
    critical alert so a silent free-credit can never masquerade as a real deposit.
    """
    ts = now_ts()
    entry_id = f"depsim_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")
    try:
        T.ad_billing.put_item(Item={
            "pk": f"ACCT#{account_id}",
            "sk": f"LEDGER#{ts}#{entry_id}",
            "entry_id": entry_id,
            "account_id": account_id,
            "entry_type": "budget_deposit_uncharged",
            "amount_cents": amount_cents,
            "state": "uncharged_simulation",
            "reason": "Deposit not charged (payment processor unavailable)",
            "meta": {"payment_method_id": payment_method_id, "stripe_payment_intent_id": ""},
            "month_key": month_key,
            "created_at": ts,
        })
    except Exception:
        logger.warning("ad_deposit_uncharged_ledger_failed account=%s", account_id)
    try:
        from app.services.ad_accounts import get_ad_account
        from app.services.alerts import write_alert
        owner_sub = (get_ad_account(account_id) or {}).get("owner_sub", "")
        write_alert(
            owner_sub or account_id,
            event="ad_deposit_uncharged",
            outcome="critical",
            title="Ad deposit could not be charged",
            details={"account_id": account_id, "amount_cents": amount_cents,
                     "reason": "payment_processor_unconfigured"},
        )
    except Exception:
        logger.warning("ad_deposit_uncharged_alert_failed account=%s", account_id)
'''
assert anchor in s, "charge_deposit anchor not found"
s = s.replace(anchor, helper, 1)

# ---- EDIT 4: hard campaign-budget guard in _process_charge step 2 ----
old_step2 = '''    # 2. Increment campaign spend
    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        UpdateExpression="SET spent_today_cents = if_not_exists(spent_today_cents, :z) + :amt, "
                         "lifetime_spent_cents = if_not_exists(lifetime_spent_cents, :z) + :amt",
        ExpressionAttributeValues={":z": 0, ":amt": charge_cents},
    )
'''
new_step2 = '''    # 2. Increment campaign spend -- HARD budget guard (ADV3-2/A4). When the
    #    campaign has a positive budget_cents the spend bump is a CONDITIONAL write
    #    that rejects the charge when it would push lifetime_spent_cents past
    #    budget_cents, so concurrent charges can NEVER overshoot the advertiser's
    #    budget. On rejection we roll the account debit back (refund balance +
    #    back out lifetime_spend), release any idempotency marker, and report
    #    budget_exceeded -- nothing else is written.
    campaign_budget_cents = 0
    try:
        from app.services.ad_campaigns import get_campaign as _gc_budget
        campaign_budget_cents = int((_gc_budget(account_id, campaign_id) or {}).get("budget_cents", 0) or 0)
    except Exception:
        campaign_budget_cents = 0

    _spend_kwargs = {
        "Key": {"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        "UpdateExpression": "SET spent_today_cents = if_not_exists(spent_today_cents, :z) + :amt, "
                            "lifetime_spent_cents = if_not_exists(lifetime_spent_cents, :z) + :amt",
        "ExpressionAttributeValues": {":z": 0, ":amt": charge_cents},
    }
    if campaign_budget_cents > 0:
        # prior lifetime_spent must leave room for this charge (budget - amt).
        _spend_kwargs["ConditionExpression"] = (
            "attribute_not_exists(lifetime_spent_cents) OR lifetime_spent_cents <= :budget_room"
        )
        _spend_kwargs["ExpressionAttributeValues"][":budget_room"] = campaign_budget_cents - charge_cents

    try:
        T.ad_campaigns.update_item(**_spend_kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            # Roll back the account debit performed in step 1.
            try:
                T.ad_accounts.update_item(
                    Key={"pk": f"ACCT#{account_id}", "sk": "META"},
                    UpdateExpression="SET balance_cents = if_not_exists(balance_cents, :z) + :amt, "
                                     "lifetime_spend_cents = if_not_exists(lifetime_spend_cents, :z) - :amt",
                    ExpressionAttributeValues={":z": 0, ":amt": charge_cents},
                )
            except Exception:
                logger.warning("ad_budget_guard_rollback_failed account=%s campaign=%s",
                               account_id, campaign_id)
            if idempotency_key:
                try:
                    T.ad_billing.delete_item(
                        Key={"pk": f"ACCT#{account_id}", "sk": f"IDEMP#{idempotency_key}"}
                    )
                except Exception:
                    pass
            logger.info("ad_charge_budget_exceeded account=%s campaign=%s amount=%s budget=%s",
                        account_id, campaign_id, charge_cents, campaign_budget_cents)
            return {"ok": False, "reason": "budget_exceeded", "charge_cents": charge_cents}
        raise
'''
assert old_step2 in s, "step2 not found"
s = s.replace(old_step2, new_step2, 1)

# ---- EDIT 5: reversal ledger meta A6 label fix ----
old_meta = '''        "reason": f"Charge reversal ({reason})",
        "meta": {
            "reversal_of": entry_id, "reversal_reason": reason, "reversal_actor": actor,
            "original_entry_type": etype, "creator_id": creator_id,
            "creator_clawback_cents": creator_share if creator_id else 0,
            "platform_reversal_cents": platform_share,
        },'''
new_meta = '''        "reason": f"Charge reversal ({reason})",
        "meta": {
            "reversal_of": entry_id, "reversal_reason": reason, "reversal_actor": actor,
            "original_entry_type": etype, "creator_id": creator_id,
            # ADV3-2/A6: the real clawback is the MEMBER share in a syndicate split
            # (the treasury took the remainder); a non-syndicate reversal claws the
            # full creator_share. member_clawback already encodes both cases.
            "creator_clawback_cents": member_clawback if creator_id else 0,
            "member_clawback_cents": member_clawback if creator_id else 0,
            "treasury_debit_cents": treasury_debit_planned,
            "is_syndicate_split": is_syndicate_split,
            "platform_reversal_cents": platform_share,
        },'''
assert old_meta in s, "reversal meta not found"
s = s.replace(old_meta, new_meta, 1)

assert s != orig
open(p, "w", encoding="utf-8").write(s)
print("ad_billing.py patched OK; delta bytes:", len(s) - len(orig))

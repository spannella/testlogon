p = "app/services/ad_billing.py"
s = open(p, encoding="utf-8").read()
orig = s

old = '''    payment_intent_id = _charge_deposit(
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

new = '''    from fastapi import HTTPException
    # ADV3-1 (A1/A2/B9): a PUBLIC deposit MUST be backed by a real charge -- never
    # credit free budget. A missing payment method is a hard 400 (no ledger, no
    # credit). The internal-seed caller (internal=True) keeps the legacy
    # ledger-only path so seeding/back-office top-ups without a card still work.
    if not internal and not payment_method_id:
        raise HTTPException(400, {
            "code": "payment_method_required",
            "message": "A payment method is required to fund an ad account.",
        })

    # ADV3-1: application-level deposit idempotency, claimed BEFORE the charge so a
    # double-fired deposit can neither double-charge nor double-credit -- this holds
    # even against a stripe-mock that does not itself honor the processor
    # idempotency_key (a real Stripe returns the same PaymentIntent for the same
    # key; the mock returns a fresh one). Keyed on the SAME
    # (account, amount, payment_method) tuple the PaymentIntent idempotency_key uses
    # so the app-level guard and the processor guard agree. Released on a failed /
    # again-uncharged charge so a genuine retry (e.g. a different card) can fund.
    idem_key = ""
    if not internal and payment_method_id:
        idem_key = "addep:%s:%s:%s" % (account_id, amount_cents, payment_method_id)
        try:
            T.ad_billing.put_item(
                Item={"pk": f"ACCT#{account_id}", "sk": f"DEPIDEMP#{idem_key}",
                      "entry_type": "deposit_idempotency", "created_at": now_ts()},
                ConditionExpression="attribute_not_exists(sk)",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                logger.info("ad_deposit_duplicate account=%s key=%s", account_id, idem_key)
                return {"ok": True, "reason": "duplicate",
                        "new_balance_cents": _get_balance(account_id)}
            raise

    def _release_idem():
        if idem_key:
            try:
                T.ad_billing.delete_item(
                    Key={"pk": f"ACCT#{account_id}", "sk": f"DEPIDEMP#{idem_key}"}
                )
            except Exception:
                pass

    # Charge the payment method. A decline / processor error raises 402 (below,
    # inside _charge_deposit) -- release the idem claim first so a retry can fund.
    try:
        payment_intent_id = _charge_deposit(
            owner_sub=owner_sub, account_id=account_id,
            amount_cents=amount_cents, payment_method_id=payment_method_id,
        )
    except Exception:
        _release_idem()
        raise

    if not internal and not payment_intent_id:
        # Stripe unconfigured (dev stub) despite a supplied card: LOUD simulation
        # (uncharged_simulation ledger row + critical alert), never a silent free
        # credit; release the idem claim so a retry can fund once configured.
        _release_idem()
        _record_uncharged_deposit(account_id, amount_cents, payment_method_id)
        raise HTTPException(402, {
            "code": "charge_unavailable",
            "message": "Deposit could not be charged (payment processor unavailable).",
        })

    ts = now_ts()
    entry_id = f"dep_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")
'''

assert old in s, "v2 deposit region not found"
s = s.replace(old, new, 1)
assert s != orig
open(p, "w", encoding="utf-8").write(s)
print("ad_billing.py v2 patched OK; delta bytes:", len(s) - len(orig))

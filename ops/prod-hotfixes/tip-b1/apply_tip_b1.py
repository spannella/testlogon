#!/usr/bin/env python3
"""TIP-B1 patch: TIP-101 real stripe-mock charge in charge_tip + TIP-102
tip_default_payment_method_id endpoints + TIP-105 group attached-tip rejection.

Idempotent-ish: refuses to double-apply (asserts each anchor's occurrence count).
Usage: apply_tip_b1.py <repo_root>
"""
import io, sys, py_compile

ROOT = sys.argv[1].rstrip('/')

def patch(path, edits):
    full = ROOT + '/' + path
    with io.open(full, 'r', encoding='utf-8') as f:
        src = f.read()
    for label, old, new, count in edits:
        n = src.count(old)
        assert n == count, f'{path}: anchor [{label}] found {n} times, expected {count}'
        src = src.replace(old, new)
    with io.open(full, 'w', encoding='utf-8') as f:
        f.write(src)
    py_compile.compile(full, doraise=True)
    print('PATCHED+COMPILED', path)

# ---------------- FILE 1: app/services/tips.py (TIP-101) ----------------
TIPS_HELPER = '''def _charge_tip_payment_intent(
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


'''

TIPS_OLD_A = '''    if pm not in pm_ids:
        raise HTTPException(400, "Payment method not found")
    return pm


def charge_tip(
'''
TIPS_NEW_A = '''    if pm not in pm_ids:
        raise HTTPException(400, "Payment method not found")
    return pm


''' + TIPS_HELPER + '''def charge_tip(
'''

TIPS_OLD_B = '''    # 5. Mock charge (B0). The real stripe-mock PaymentIntent is B1/TIP-101.
    # Callers that already minted a tip id (and stored it on their content row)
    # pass it through so the ledger row + content row stay linked; else mint one.
    tip_payment_id = tip_payment_id or ("tip_" + uuid.uuid4().hex)
    payment_intent_id: Optional[str] = None
'''
TIPS_NEW_B = '''    # 5. Real charge via stripe-mock PaymentIntent (TIP-101), mirroring
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
'''

patch('app/services/tips.py', [
    ('tips.helper', TIPS_OLD_A, TIPS_NEW_A, 1),
    ('tips.charge_step', TIPS_OLD_B, TIPS_NEW_B, 1),
])
print('done tips')

# ---------------- FILE 2: app/routers/billing.py (TIP-102) ----------------
BILLING_BLOCK = '''

def set_tip_default_pm(user_id: str, pm_id: Optional[str]) -> None:
    """TIP-102: per-user tip-routing default PM, distinct from the subscription
    default_payment_method_id. charge_tip.resolve_tip_payment_method falls back to
    this BEFORE the general default. App-side routing preference only -- it does NOT
    change the Stripe customer's invoice default."""
    pk = user_pk(user_id)
    if not ddb_get(T.billing, pk, "BILLING"):
        ddb_put(T.billing, {"pk": pk, "sk": "BILLING", "autopay_enabled": False, "currency": "usd", "default_payment_method_id": None, "tip_default_payment_method_id": pm_id})
    else:
        ddb_update(T.billing, pk, "BILLING", "SET tip_default_payment_method_id = :pm", {":pm": pm_id})


@dual_route("GET", "/billing/payment-methods/tip-default")
def get_tip_default(ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), user_sub: Optional[str] = None) -> Dict[str, Optional[str]]:
    user_id = _billing_read_user_sub(ctx, user_sub, actor)
    billing = ddb_get(T.billing, user_pk(user_id), "BILLING") or {}
    return {"tip_default_payment_method_id": billing.get("tip_default_payment_method_id")}


@dual_route("POST", "/billing/payment-methods/tip-default")
def set_tip_default(body: SetDefaultReq, req: Request = None, ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), user_sub: Optional[str] = None) -> Dict[str, bool]:
    user_id, admin_tags = _billing_write_user_context(ctx, user_sub, actor)
    pk = user_pk(user_id)
    if not ddb_get(T.billing, pk, pm_sk(body.payment_method_id)):
        raise HTTPException(404, "Payment method not found")
    set_tip_default_pm(user_id, body.payment_method_id)
    audit_event("billing_tip_default_set", user_id, req, outcome="success", payment_method_id=body.payment_method_id, **admin_tags)
    return {"ok": True}
'''

BILLING_OLD = '''    bump_dunning_after_payment_method_update(user_id, "stripe")
    return {"ok": True}


@dual_route("DELETE", "/billing/payment-methods/{payment_method_id}")'''
BILLING_NEW = '''    bump_dunning_after_payment_method_update(user_id, "stripe")
    return {"ok": True}

''' + BILLING_BLOCK + '''

@dual_route("DELETE", "/billing/payment-methods/{payment_method_id}")'''

patch('app/routers/billing.py', [
    ('billing.tip_default', BILLING_OLD, BILLING_NEW, 1),
])
print('done billing')

# ---------------- FILE 3: app/routers/messaging.py (TIP-105) ----------------
MSG_DTO_OLD = '    tip_payment_method_id: Optional[str] = Field(default=None, max_length=200)'
MSG_DTO_NEW = MSG_DTO_OLD + '\n    tip_recipient_id: Optional[str] = Field(default=None, max_length=200)  # TIP-105: required recipient for a group attached tip'

MSG_HELPER = '''

def _resolve_attached_tip_recipient(
    conversation_id: str, sender_id: str, explicit_recipient_id: Optional[str] = None
) -> str:
    """TIP-105: resolve the recipient for an attached-on-SEND tip.

    DM    -> the other participant (unchanged behavior).
    Group -> REJECT with 400 tip_not_allowed_in_group UNLESS an explicit
             tip_recipient_id names a DISTINCT group participant, then credit them.

    Never returns None: it returns a valid non-self recipient or raises. An
    attached-on-send tip that credited the sender would be a self-tip, so a group
    tip with no (valid) explicit recipient is rejected rather than silently dropped
    (the pre-TIP-105 behavior stored the tip but never charged/credited). Post-hoc
    tipping of someone else's group message is unaffected (it credits the message
    author directly and does not use this helper).
    """
    try:
        resp = tbl_parts.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq(conversation_id),
            Limit=50,
        )
        participants = resp.get("Items", [])
    except Exception:
        participants = []
    other_ids = [
        p.get("user_id")
        for p in participants
        if p.get("user_id") and p.get("user_id") != sender_id
    ]
    if explicit_recipient_id:
        if explicit_recipient_id == sender_id:
            raise HTTPException(400, {"code": "cannot_tip_self", "message": "Cannot tip yourself."})
        if explicit_recipient_id not in other_ids:
            raise HTTPException(
                400,
                {"code": "tip_recipient_not_in_conversation",
                 "message": "tip_recipient_id must name a participant of this conversation."},
            )
        return explicit_recipient_id
    if len(other_ids) == 1:
        return other_ids[0]  # DM: the unambiguous other participant
    raise HTTPException(
        400,
        {"code": "tip_not_allowed_in_group",
         "message": "Attached tips in a group require an explicit tip_recipient_id naming a participant."},
    )
'''

MSG_HELPER_OLD = '''    other_ids = [p.get("user_id") for p in participants if p.get("user_id") != sender_id]
    if len(other_ids) == 1:
        return other_ids[0]
    return None  # Group chat or error
'''
MSG_HELPER_NEW = MSG_HELPER_OLD + MSG_HELPER

MSG_SITE_OLD = '''            recipient_id = _resolve_tip_recipient(conversation_id, user_id)
            if recipient_id:
'''
MSG_SITE_NEW = '''            recipient_id = _resolve_attached_tip_recipient(conversation_id, user_id, inp.tip_recipient_id)
            item["tip_recipient_id"] = recipient_id
            if recipient_id:
'''

patch('app/routers/messaging.py', [
    ('msg.dto_field', MSG_DTO_OLD, MSG_DTO_NEW, 3),
    ('msg.helper', MSG_HELPER_OLD, MSG_HELPER_NEW, 1),
    ('msg.immediate_sites', MSG_SITE_OLD, MSG_SITE_NEW, 3),
])
print('done messaging')
print('ALL PATCHES APPLIED')

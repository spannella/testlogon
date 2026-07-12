# TIP-B1 prod hotfix (TIP-101 real charge + TIP-102 tip-default PM + TIP-105 group-send rejection)

Applied LIVE to prod (/home/ubuntu/testlogon) and mirrored to the dev clone
(~/dev/testlogon, branch android-impl, base HEAD 53748a5b). Backend-only slice of
epic B1. App tickets (TIP-103/104/106) are separate.

## What changed (3 files, all via ops/prod-hotfixes/tip-b1/apply_tip_b1.py)

### TIP-101 -- real stripe-mock PaymentIntent inside charge_tip  (app/services/tips.py)
- New `_charge_tip_payment_intent(...)` mirrors billing.charge_once:
  `stripe.PaymentIntent.create(amount, currency, customer=get_or_create_customer(tipper),
  payment_method, off_session=True, confirm=True, idempotency_key=<charge_tip idempotency_key>,
  metadata=...)` reusing the billing.py rail (ensure_stripe_configured + get_or_create_customer).
- charge_tip step 5 now sets payment_intent_id from it (was hard-None mock).
- Failure semantics: CardError / any StripeError / non-succeeded terminal status ->
  HTTPException(402, payment_failed) raised BEFORE write_tip_ledger, so NO debit/credit
  ledger row is written on a failed charge. write_tip_ledger + the 20% fee split are UNCHANGED.
- Dev-stub path preserved: returns None (no processor call) when stripe_secret_key is
  unset OR the resolved PM is blank (the blank-PM dev tolerance billing.py already allows).
- stripe-mock nuance: the local stripe-mock fixture server (STRIPE_API_BASE=localhost:12111)
  cannot confirm off_session intents and returns "requires_payment_method" for every create.
  When stripe_api_base is overridden (a mock that cannot truly confirm) a created intent is
  accepted as settled UNLESS status in {canceled, payment_failed}; a real Stripe integration
  (no api_base override) still requires a true "succeeded". This keeps the money-path working
  in the mock env while a real decline (CardError) / hard-fail status still -> 402.

### TIP-102 -- tip_default_payment_method_id + endpoints  (app/routers/billing.py)
- set_tip_default_pm(user_id, pm_id) writes tip_default_payment_method_id on the USER#..#BILLING row.
- GET  /ui/billing/payment-methods/tip-default -> {tip_default_payment_method_id}
- POST /ui/billing/payment-methods/tip-default (SetDefaultReq) -> validates PM ownership (404 if
  missing), sets tip-default, audits billing_tip_default_set. Does NOT touch the Stripe invoice default.
- charge_tip.resolve_tip_payment_method already reads tip_default_payment_method_id before the
  general default (from B0) -> the fallback chain is now fully wired: explicit -> tip-default -> general.

### TIP-105 -- reject attached tip on a GROUP send unless explicit valid recipient  (app/routers/messaging.py)
- New tip_recipient_id field on the 3 send DTOs (SendTextMessageIn / CreateImageMessageIn /
  CreateGalleryMessageIn).
- New _resolve_attached_tip_recipient(conversation_id, sender_id, explicit_recipient_id): DM ->
  the other participant (unchanged); GROUP -> 400 tip_not_allowed_in_group UNLESS an explicit
  tip_recipient_id names a DISTINCT participant (then credit them). Self -> 400 cannot_tip_self;
  non-participant -> 400 tip_recipient_not_in_conversation. Never returns None (no silent self-tip).
- The 3 immediate attached-tip send paths (text/image/gallery) now call it (was _resolve_tip_recipient
  which silently returned None for groups -> uncredited). The scheduled-delivery site keeps the old
  graceful _resolve_tip_recipient (no delivery-time 400). Post-hoc send_message_tip unchanged (already
  credits the message author for DMs + groups).

## Backups (prod)
app/services/tips.py.bak_tipb1_1783460491
app/routers/billing.py.bak_tipb1_1783460491
app/routers/messaging.py.bak_tipb1_1783460491

## Re-apply / mirror
    python3 ops/prod-hotfixes/tip-b1/apply_tip_b1.py <repo_root>
(idempotent-guarded: asserts each anchor's occurrence count; py_compiles each file)

## Verification (prod, live backend env, 2026-07-07) -- ALL PASS
- S1 real charge: PaymentIntent pi_Qzx5RbmkWo5T68v created; charged 500, fee 100, net 400;
  credit row type=credit amount=400; debit row 500.
- S2 forced non-succeeded (status=canceled): 402 payment_failed, 0 credit + 0 debit rows (NO ledger).
- S2b real CardError decline: 402, 0 credit rows.
- S3 tip-default: set tip-default then tip with no PM -> resolves to tip-default; charge ok, net 800.
- S3b idempotent replay (same key x2): replay flag true, exactly 1 credit row.
- S4 TIP-105: group+no-recipient -> 400 tip_not_allowed_in_group; group+valid -> credits it;
  group+self -> 400 cannot_tip_self; group+non-participant -> 400 tip_recipient_not_in_conversation;
  DM+no-recipient -> credits the other participant (unchanged).

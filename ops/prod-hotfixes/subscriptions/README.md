# SUB-E0 — Real subscribe charge + subscription record + tier benefits

**LIVE PROD HOTFIX** (SSM, no SSH). Prod EC2 `i-08f937fc705ebea75`.
File: `app/routers/subscription_server.py` (byte-identical prod==dev before change).

## Prod backups (.bak)
- `app/routers/subscription_server.py.bak_sube0_1783737534` (pre-change original)

## What changed (money-path)
Replaced the FAKE unconditional `invoice status="paid"` stamp in `POST /api/plans/{plan_id}/subscribe`
with a REAL, funds-guarded stripe-mock charge reusing the tips PaymentIntent pattern:
- `resolve_subscription_payment_method` (explicit -> subscriber `default_payment_method_id`; STRICT: no/unowned PM -> 402).
- `_charge_subscription_payment_intent` (off_session=True, confirm=True, idempotency_key; real `CardError`/StripeError -> 402;
  accept under the mock unless status in {canceled,payment_failed} — same convention as tips/ads).
- Charge runs BEFORE any write. On decline/no-PM -> 402 and NOTHING is written (no subscription, no invoice, no creator credit).
- On success: invoice `paid` with `provider="stripe"` + `provider_invoice_id`=real PaymentIntent id; creator credited NET
  (price - 10% SUBSCRIPTION_FEE_BPS fee) via existing `_mirror_creator_credit_to_billing` (`type:"credit"`); subscription active.
- `next_billing_date` (= `current_period_end` at create) + `payment_method_id` + `payment_intent_id` added to the subscription record (for the E1 renewal engine).
- Idempotency: `SubscribeIn.client_request_id` -> `SUBIDEMP#` marker in `T.billing`; retry returns the same subscription, no double charge/subscribe.
- Trials and fully-discounted ($0) subscribes collect no funds now and skip the charge (unchanged behavior; E2 handles trial-card-up-front).

## Tier benefits model
- New `PlanBenefit{label, detail?}`; `PlanCreateIn.benefits` / `PlanUpdateIn.benefits` (settable) and `PlanOut.benefits` (returned).
- Persisted on `create_plan` / `update_plan`; existing/seeded plans default to `[]`.

## Grandfather
Only NEW subscribes go through the real charge. No migration/backfill; existing phantom subscription credits/records untouched.

## Prod in-process verify (SSM) — LEDGER EVIDENCE
- Benefits round-trip on create/get/patch (structured [{label, detail}]).
- A (PM + card): status active, provider=stripe, price 799, pi_id=pi_R13rAb0VInTOpKz, creator credited NET 720 (799 - 79 fee, type:"credit"),
  next_billing_date=1786329655==current_period_end, invoice paid w/ provider_invoice_id=pi_id, subscriber PAY# row written.
- B (retry same client_request_id): SAME subscription_id, creator credit count stays 1, subscriber sub-index count 1 (no double charge/subscribe).
- C (no PM): HTTP 402 no_payment_method; 0 subscription, 0 pay rows, 0 credit.
- D (forced CardError decline): HTTP 402 payment_failed; 0 subscription, 0 credit delta, 0 pay rows.

Fee unchanged: SUBSCRIPTION_FEE_BPS=1000 (10%).

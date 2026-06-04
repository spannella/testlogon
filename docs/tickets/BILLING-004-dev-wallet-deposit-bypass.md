# BILLING-004: Dev-Mode Wallet Deposit Direct-Credit Bypass

**Ticket**: BILLING-004
**Author**: Engineering
**Status**: Open
**Date**: 2026-06-04
**Priority**: Medium
**Estimated effort**: 1 day
**Dependencies**: ADS-007 (billing engine), BILLING-002 (payout dashboard)

---

## 1. Overview & Motivation

### 1.1 Problem Statement

Depositing money into the wallet does not work in the local/dev environment. The
deposit endpoint (`app/routers/billing.py`, `POST /billing/wallet/deposit`,
~line 2331) creates a Stripe **off-session** PaymentIntent with `confirm=True`
and only credits the wallet when the intent returns `status == "succeeded"`:

```python
pi = stripe.PaymentIntent.create(..., off_session=True, confirm=True, ...)
wallet_balance_cents = 0
if pi.get("status") == "succeeded":
    wallet_balance_cents = apply_wallet_delta(T.billing, pk, int(body.amount_cents), ...)
```

The local `stripe-mock` service (port 12111) **always returns
`requires_payment_method` for off-session PaymentIntents** (documented in
CLAUDE.md). So in dev:

- The ledger entry is written as `pending` and the wallet is **never credited**.
- The API still returns HTTP 200 with `wallet_balance_cents: 0`.
- The frontend (`frontend/src/pages/billing/Wallet.tsx`) shows a success toast
  ("Deposited $X") while the actual balance stays at $0 — **misleading UX**.

This blocks any manual dev/QA flow that needs a funded wallet (tips, unlocks,
paid calls, subscriptions), and E2E tests currently work around it by seeding
`wallet_balance_cents` directly into DynamoDB
(`frontend/e2e/billing-wallet.spec.ts` `injectWalletBalance`).

This is **not a production bug** — real Stripe approves off-session intents and
returns `succeeded`. It is purely a dev-environment gap.

### 1.2 How It Works (proposed)

When `S.dev_mode` is true (and only then), the deposit endpoint bypasses the
Stripe off-session confirmation and credits the wallet directly:

1. Validate the request (amount within min/max, payment method present as today).
2. Skip the `stripe.PaymentIntent.create(off_session=True, confirm=True)` call.
3. Write a `settled` ledger entry with `reason="wallet_deposit"` and a synthetic
   `payment_intent_id` (e.g. `pi_dev_{uuid4().hex}`).
4. Call `apply_wallet_delta(T.billing, pk, amount_cents, currency=...)`.
5. Return `{ status: "succeeded", payment_intent_id, wallet_balance_cents }` so
   the existing frontend success path and toast are accurate.

Production behaviour is unchanged: the real Stripe path runs whenever
`S.dev_mode` is false.

### 1.3 Design Principles

- **Dev-only**: Guarded strictly by `S.dev_mode`; the production Stripe code path
  is untouched.
- **Same response contract**: Returns the same shape so no frontend change is
  required (the toast/`wallet_balance_cents` already exist).
- **Auditable**: Still writes a ledger entry + `audit_event("billing_wallet_deposit", ...)`
  so dev deposits are traceable like real ones.

---

## 2. Implementation

### 2.1 Backend (`app/routers/billing.py`)

In the `wallet_deposit` handler, before the Stripe call, add:

```python
if S.dev_mode:
    led_sk, led_item = new_ledger_entry(pk=pk, amount_cents=int(body.amount_cents),
                                        currency=currency, state="settled",
                                        reason="wallet_deposit")
    ddb_put(T.billing, led_item)
    wallet_balance_cents = apply_wallet_delta(T.billing, pk, int(body.amount_cents),
                                              currency=currency)
    audit_event("billing_wallet_deposit", user_id, req, outcome="success",
                amount_cents=int(body.amount_cents), dev_bypass=True)
    return {"status": "succeeded",
            "payment_intent_id": f"pi_dev_{uuid4().hex}",
            "wallet_balance_cents": wallet_balance_cents}
# ... existing real-Stripe path unchanged ...
```

(Reuse the exact ledger/`apply_wallet_delta` helpers already used by the
succeeded branch so the settled ledger + balance stay consistent.)

### 2.2 Frontend

No change required — `Wallet.tsx` already renders `data.wallet_balance_cents`
and the success toast. After this fix the toast/value will be correct in dev.

---

## 3. Testing

- **E2E**: Add a `billing-wallet.spec.ts` test that POSTs `/billing/wallet/deposit`
  in dev mode and asserts `wallet_balance_cents` increased by the deposited
  amount (no longer needs `injectWalletBalance` for the happy path). Keep the
  DDB-seed helper for tests that need a precise starting balance.
- **Unit/pytest**: Assert the dev branch writes a `settled` ledger row and that
  the wallet delta is applied; assert the production branch is unchanged when
  `dev_mode` is false (mock Stripe).

## 4. Out of Scope

- Real Stripe SCA/3DS handling (already works in production).
- Withdrawals / payouts (covered by BILLING-002).

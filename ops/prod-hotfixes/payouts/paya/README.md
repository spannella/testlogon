# PAY-A — Payout balance-debit foundation + honest transfer seam (LIVE PROD HOTFIX)

Fixes the P0 double-spend in the money-OUT path. Single-file change:
`app/services/creator_payouts.py`.

## Root cause (the P0 double-spend)
`get_available_balance` computed `available = sum(billing credits past the 7-day
hold) - _get_active_payout_total()`, where `_get_active_payout_total` only sums
payouts still in `ACTIVE_PAYOUT_STATES = {requested, approved, processing}`. The
old `complete_payout` merely stamped `status -> completed` + `completed_at` and
released the single-active sentinel — it wrote NO `type="debit"` ledger row and
did NO transfer. So the moment a payout left the active set (completed), it was no
longer subtracted by `_get_active_payout_total` AND no debit row existed to
subtract it instead, so `get_available_balance` REVERTED to the full pre-payout
amount and the SAME earnings became re-withdrawable without bound (the sentinel
only serializes concurrent requests, not sequential re-withdrawal). The platform
liability ledger was never reduced.

## What changed (PAY-01..03)
- **PAY-01 (P0 fix):** `complete_payout` -> `_finalize_paid` now writes a REAL
  idempotent `type="debit", reason="payout"` row to `T.billing` (pk=USER#{creator},
  sk=LEDGER#..., state="settled", meta.payout_id) on terminal PAID, guarded by a
  conditional `PAYOUTDEBIT#{payout_id}` marker row (exactly one debit per payout).
  `get_available_balance` subtracts payout-debit rows (`_sum_payout_debits`) so a
  completed payout PERMANENTLY reduces the balance. CONTINUITY: debit is written
  BEFORE the status leaves the active set, so the amount is always subtracted by
  exactly one of {reservation, debit} — no revert window, no double-count.
- **PAY-02:** over-withdraw rejected (post-claim balance re-check, now ledger-true);
  `fail_payout(returned=)` reverses a paid payout's debit (flips state->reversed,
  idempotent) so funds return; an active/never-debited payout just releases the
  reservation (cancel/fail).
- **PAY-03:** `payout_transfer` honest seam — mock now (transfer_provider="mock",
  no real money, real debit still written); real Stripe Connect / PayPal when
  explicitly keyed. transfer_provider + transfer_ref stored on the payout record.

## How to enable the REAL transfer rail (currently mock)
- **Stripe Connect:** set env `STRIPE_CONNECT_ENABLED=1` AND have `S.stripe_secret_key`
  set -> `payout_transfer` performs `stripe.Transfer.create(amount, currency="usd",
  destination=<connect_account_id|method_id|method>, idempotency_key=payout_{id})`.
- **PayPal Payouts:** set env `PAYOUT_USE_REAL_PROVIDER=1` AND PayPal creds
  (`paypal_client_id`/`paypal_client_secret`) -> `paypal_payouts.create_payout`.
- The gate is a DEDICATED flag, NOT mere presence of `stripe_secret_key`/`paypal_client_id`
  (those are already set for the money-IN mock rail), so turning ON real money-OUT is
  an explicit, separate opt-in. When neither flag is set -> mock (no external money),
  but the real `type="debit"` still lands so the platform balance honestly drops.

## Deploy
- Prod EC2 i-08f937fc705ebea75 via SSM. Backup: `app/services/creator_payouts.py.bak_paya_1783829511` (md5 067540e11f7a7a1ddde9d3483ba2d9db = pre-change original, preserved on prod for rollback).
- Live file md5: be88b9eead9ac89816bb3757fddf13f6 (== this fold copy == dev clone). Restart via restart_backend.sh; openapi 200.

## Verify (in-process on PROD DDB, synthetic user, auto-cleaned): 16/16 PASS
seed 5000 -> available 5000; request 3000 -> available 2000 (reservation); approve+
complete -> 1 debit(3000) + transfer_provider=mock + available STAYS 2000 (no revert
to 5000); re-request 3000 -> rejected (no double-spend / P0 CLOSED); complete x2 ->
still 1 debit (idempotent); request 50000 -> rejected (over-withdraw); returned-after-
paid -> debit state=reversed + available back to 5000; re-reverse -> False (idempotent);
cancel active -> reservation released, no debit/marker; fail active never-completed ->
no reverse; money-IN credit path unchanged; seam WOULD call
`stripe.Transfer.create(amount=2500, idempotency_key=payout_px_seam)` (real=True) when
`STRIPE_CONNECT_ENABLED` keyed. Cleanup left zero residue.

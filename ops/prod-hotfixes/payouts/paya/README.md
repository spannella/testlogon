# PAY-A — Payout balance-debit foundation + honest transfer seam (LIVE PROD HOTFIX)

Fixes the P0 double-spend in the money-OUT path. Single-file change:
`app/services/creator_payouts.py`.

## What changed (PAY-01..03)
- **PAY-01 (P0 fix):** `complete_payout` now writes a REAL idempotent
  `type="debit", reason="payout"` row to `T.billing` (pk=USER#{creator},
  sk=LEDGER#..., state="settled", meta.payout_id) on terminal PAID, guarded by a
  conditional `PAYOUTDEBIT#{payout_id}` marker row (exactly one debit per payout).
  `get_available_balance` subtracts payout-debit rows (`_sum_payout_debits`) so a
  completed payout PERMANENTLY reduces the balance. CONTINUITY: debit is written
  BEFORE the status leaves the active set, so the amount is always subtracted by
  exactly one of {reservation, debit} — no revert window.
- **PAY-02:** over-withdraw rejected (post-claim balance re-check, now ledger-true);
  `fail_payout(returned=)` reverses a paid payout's debit (flips state->reversed,
  idempotent) so funds return; an active/never-debited payout just releases the
  reservation (cancel/fail).
- **PAY-03:** `payout_transfer` honest seam — mock now (transfer_provider="mock",
  no real money, real debit still written); real Stripe Connect / PayPal when
  explicitly keyed (STRIPE_CONNECT_ENABLED=1 / PAYOUT_USE_REAL_PROVIDER=1). Gate is
  a DEDICATED flag, NOT mere presence of stripe_secret_key (already set for the
  money-IN mock rail). transfer_provider + transfer_ref stored on the payout record.

## Deploy
- Prod EC2 i-08f937fc705ebea75 via SSM. Backup: `app/services/creator_payouts.py.bak_paya_1783829511` (md5 067540e11f7a7a1ddde9d3483ba2d9db = pre-change original).
- Live file md5: be88b9eead9ac89816bb3757fddf13f6. Restart via restart_backend.sh; openapi 200.

## Verify (in-process on PROD DDB, synthetic user, cleaned up): 14/14 PASS
seed 5000; request 3000 -> available 2000 (reservation); complete -> 1 debit(3000)
+ transfer_provider=mock + available STAYS 2000 (no revert); re-request 3000 ->
rejected (no double-spend); complete x2 -> still 1 debit (idempotent); request
50000 -> rejected (over-withdraw); returned-after-paid -> debit state=reversed,
available back to 5000 (idempotent); cancel/fail active -> reservation released, no
debit; seam WOULD call Stripe Transfer.create(amount, idempotency_key=payout_{id})
when STRIPE_CONNECT_ENABLED keyed.

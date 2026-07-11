# SUB-E2 — proration/upgrade-downgrade + trials (card up front) + sweeper auto-convert

Money-path slice on top of E0 (real subscribe charge) + E1 (renewal/dunning sweeper).
LIVE PROD HOTFIX applied via SSM; mirrored on the dev clone; folded here.

## What changed (2 files, anchored idempotent patch)

`app/routers/subscription_server.py`
- **`SubscriptionChangePlanIn`** gains optional `payment_method_id` (explicit PM for the
  upgrade delta charge; falls back to the subscription's stored PM).
- **`subscribe()` — TRIAL card-up-front.** A `trialing` subscribe now CAPTURES + VALIDATES a
  real owned PM (`resolve_subscription_payment_method`) at trial start with **NO charge**, and
  stores it on the record so the sweeper can auto-convert. A trial with no resolvable PM is
  rejected `402` (no phantom trialing sub).
- **`change_subscription_plan()` — routed by price (locked decision).**
  - **UPGRADE** (target price strictly higher, or `effective!=period_end`): applies IMMEDIATELY,
    charges the **prorated DELTA** for the remaining period via the E0 rail
    (`_charge_subscription_payment_intent`, funds-guarded, real PI), switches the plan NOW
    (period end unchanged), and credits the creator the **DELTA NET** (10% fee) via
    `save_ledger_entry(charge/fee)` + `_mirror_creator_credit_to_billing` (withdrawable).
  - **DOWNGRADE** (target price <= current, or `effective=period_end`): SCHEDULES a
    `pending_change {plan_id, interval, price_cents, apply_at, direction}` (+ legacy
    `pending_*` mirror fields). **No immediate money.**

`app/services/subscription_renewal.py`
- **`_process()`** now handles `trialing`: at `trial_end <= now` it AUTO-CONVERTS via
  `_attempt_renewal(..., trial_conversion=True)` (charge the captured card -> active + creator
  credit; decline / no-PM -> dunning `past_due`).
- **`_apply_pending_change()`** (new): applies a due scheduled plan change (mutates
  plan_id/interval/price_cents, clears `pending_*`) so the following renewal charges the NEW
  plan for the NEW period. Called from `_attempt_renewal` before amount computation.
- **`_renewal_success()` / `_attempt_renewal()`** gain a `trial_conversion` flag
  (billing_reason `trial_conversion`, `trial_converted_at`, distinct `trial_converted` summary
  bucket, `:convert` processor idempotency suffix).
- Sweep summary gains `trial_converted` + `plan_changed` buckets.

Idempotency unchanged from E1: per-cycle `RENEWCYCLE#{period_end}` claim (one credit/invoice/
advance per cycle) + processor `idempotency_key`.

## Apply (idempotent, anchored — runs on dev clone AND divergent prod)
```
ROOT=<repo-root> python3 apply_sube2.py     # all APPLIED first run, SKIP_ALREADY thereafter
```
Prod live hotfix: `.bak_sube2_1783742580` on both files; restart `restart_backend.sh`; openapi 200.

## Verify (in-process on real DDB + stripe-mock rail)
```
su - ubuntu -c 'cd /home/ubuntu/testlogon && set -a && . ./.env.local && export DEV_MODE=1 \
  PYTHONPATH=/home/ubuntu/testlogon && set +a && .venv/bin/python verify_sube2.py'
```
**PROD DDB result: 30/30 OVERALL ALL_PASS.**
- U upgrade: delta 1000 charged (real PI), plan switched, period unchanged, creator net +900.
- D downgrade: pending_change scheduled, no immediate money; sweep applies at period end +
  renews at new price + creator net +900.
- T trial: card captured up front, no charge; sweep auto-converts (real PI) + creator net +900.
- X trial-convert decline: past_due dunning, zero creator credit.

## Residual (pre-existing, NOT E2)
`emit_subscription_cycle_order_and_reconcile` logs `subscription_cycle_reconciliation_invariant_
failed reason=missing_order -> dead_lettered` (also on E0 subscribe / E1 renewal). Money path is
correct; only the downstream recurring-grant reconciler dead-letters.

# SUB-E1 — Recurring RENEWAL + DUNNING engine + expiry enforcement

**LIVE PROD HOTFIX** (SSM, no SSH). Prod EC2 `i-08f937fc705ebea75`. Backend-only (no app change).
Builds on SUB-E0 (`adcb823f`): real funds-guarded subscribe charge + `next_billing_date`/`payment_method_id`/`payment_intent_id` on the record.

## Prod backups (.bak_sube1_1783741467)
- `app/services/subscription_access.py.bak_sube1_1783741467`
- `app/core/settings.py.bak_sube1_1783741467`
- `app/services/alerts.py.bak_sube1_1783741467`
- `app/main.py.bak_sube1_1783741467`
- `app/routers/subscription_server.py.bak_sube1_1783741467`
(`app/services/subscription_renewal.py` is NEW — no .bak.)

## What shipped
1. **NEW `app/services/subscription_renewal.py`** — periodic sweep (pattern:
   `moderation_lifecycle.start_hold_sweep_task` / `billing_dunning`). `run_renewal_sweep(now, limit)`
   scans `T.subscriptions` base META rows (`entity=="subscription"`, `sk=="META"`) and drives:
   - **RENEWAL** (active, auto_renew, not cancel_at_period_end, `next_billing_date<=now`): REAL charge via
     `subscription_server._charge_subscription_payment_intent` with the stored `payment_method_id`,
     `idempotency_key = "{sub_id}:{current_period_end}"` (ONE processor charge per cycle). On success:
     advance `current_period_end += interval` + `next_billing_date`, credit the creator NET (10%
     `SUBSCRIPTION_FEE_BPS`) via the exact E0 `save_ledger_entry`+`_mirror_creator_credit_to_billing`
     path, write a `paid` invoice, clear dunning, emit `subscription_renewed`. A per-cycle conditional
     `RENEWCYCLE#{period_end}` marker guarantees credit/invoice/advance run at most once per cycle even
     under overlapping ticks (charge itself is idempotent at the processor).
   - **DUNNING** (declined charge OR no stored PM): `status=past_due`, `dunning_attempts++`, retry at day
     **1/3/5/7** (`SUBSCRIPTION_DUNNING_RETRY_DAYS`), emit `subscription_renewal_failed`, write NO credit.
     On the FIRST decline an ACCESS horizon `grace_until = now + (last_retry_day + grace_days)` is set so
     content access CONTINUES through the whole dunning window. After the last retry -> `dunning_state=grace`
     (+`subscription_expiring`); when `grace_until<=now` -> `status=expired` + `subscription_expired`.
   - **Terminal at period end**: cancel_at_period_end -> `canceled`; auto_renew off -> `expired` (no charge).
   - `start_subscription_renewal_task()` registered in `app/main.py` (interval `SUBSCRIPTION_RENEWAL_INTERVAL_SECONDS=900`).
2. **`subscription_access.has_active_subscription`** — EXPIRY ENFORCEMENT: still requires
   status in {active, past_due, trialing}, PLUS the grace-extended end
   (`max(current_period_end, grace_until)`) must be in the FUTURE. A lapsed sub (period elapsed, no
   successful renewal) or an `expired`/`canceled` sub now LOSES access. A record with no period info
   (legacy/grandfathered) is left un-enforced.
3. **`alerts.DEFAULT_PUSH_EVENT_TYPES`** += `subscription_renewed`, `subscription_renewal_failed`,
   `subscription_expiring`, `subscription_expired` (default-ON transactional push; E5 completes the set).
4. **`app/core/settings.py`** — `subscription_renewal_enabled` (true), `subscription_renewal_interval_seconds`
   (900), `subscription_dunning_retry_days` ("1,3,5,7"), `subscription_grace_days` (7).
5. **`subscription_server.py`** — admin/root-gated manual trigger `POST /ui/admin/subscriptions/run-renewals`
   (`?limit=&now_override=`) so the sweep is drivable for verification (like the moderation/shipment simulate drivers).

## Grandfather / money safety
- Grandfathered active subs with no `next_billing_date` AND no `payment_method_id` are SKIPPED by the sweep
  (never charged). A sub with no stored PM is routed to dunning, not charged.
- Renewals charge REALLY (funds-guarded, idempotent per cycle) + credit the creator NET each cycle. A declined
  renewal writes NO credit. E0 subscribe + the tip/ad rails are untouched.

## Apply (anchored, idempotent — dev clone AND prod)
`python3 apply_sube1.py <repo_root>` patches the 5 existing files (skips if the SUB-E1 marker is present);
the NEW `subscription_renewal.py` is deployed alongside. `probe_sube1.py` confirms anchors before apply.

## Prod in-process verify (SSM) — 27/27 OVERALL ALL_PASS (`verify_sube1.py`, real prod DDB + stripe-mock)
- **A renewal**: real PI `pi_R14pd49vToBrExG`, creator credited NET **720** (799-79) a SECOND cycle,
  `current_period_end`+`next_billing_date` advanced by exactly one interval (+2592000s), natural re-run
  not-due (no 2nd credit), forced same-cycle overlap -> `idempotent_skips` (RENEWCYCLE claim), credit count unchanged.
- **B dunning**: decline -> past_due, attempt #1, day-1 retry, NO creator credit; access CONTINUES through
  past_due/grace; drove all retries -> grace (attempts=5) -> `expired`; expired sub LOSES access; zero credit total.
- **C**: a lapsed active sub (period elapsed, unswept) returns `has_active_subscription` False.
- **D**: cancel-at-period-end keeps access until period end, then loses access + sweep flips to `canceled` (no charge).

## Residual (pre-existing, NOT an E1 regression)
`emit_subscription_cycle_order_and_reconcile` logs `subscription_cycle_reconciliation_invariant_failed
reason=missing_order` then `reconciliation_status=dead_lettered` (also fires on the E0 subscribe/convert
paths — same helper). Money path (charge/credit/invoice) is correct; only the downstream recurring-grant
reconciler dead-letters.

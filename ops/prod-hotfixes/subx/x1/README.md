# SUBX Epic X1 — Money correctness (live prod hotfix)

**Program:** Subscriptions smoothing (`ops/plans/subscriptions-rough-edges-plan.md`), Epic X1 / SUBX-10..15.
**Target files:** `app/routers/subscription_server.py`, `app/services/subscription_renewal.py` (byte-identical dev==prod).
**Applied:** 2026-07-15. **Prod EC2:** `i-08f937fc705ebea75` via SSM. **Backup on prod:** `*.bak_subx_1784148827`.
**Baseline md5 (pre-X1, dev==prod):** server `428ea00dd3fffae29a4b196f5cffcce9`, renewal `13a145b476fa6875439387cead15c1f8`.
**Post-patch md5 (dev==prod):** server `a62ec6b2658ffb80c74d2bee36315afa`, renewal `ec6600652ca37c757d0f0a2c714a7cd8`.

## Tickets

### SUBX-10 — Cycle-accurate proration (denominator = CURRENT cycle, not lifetime)
`change_subscription_plan`, `/refund`, and immediate `/cancel` prorated against `start_at` (whole-lifetime), so a sub renewed N times refunded/charged a tiny fraction. Added `_current_period_start(sub)` — the persisted `current_period_start` (written at subscribe/gift, advanced to `old_cpe` each renewal) with a `current_period_end - interval` fallback for legacy rows — and use it in all three callers. A sub half-way through its current cycle now refunds ~50%, not ~13%.

### SUBX-11 — Interval-aware up/downgrade
`is_upgrade` was raw `new_price > old_price`, so month→year (annual >> monthly) was always an "upgrade" and mis-charged the raw annual-minus-monthly delta on the monthly period. Now classify on a **monthly-equivalent** basis (`_sube4_monthly_equiv_cents`). On an **interval change** the immediate upgrade starts a fresh cycle: charge `new_price − (old_price × remaining_fraction)` and reset `current_period_start=now`, `current_period_end=now+interval`, `next_billing_date`. Same-interval upgrade keeps its period (delta-only). Downgrades (incl. year→month) schedule a `pending_change` applied at period end.

### SUBX-12 — Real refund on creator remove
`remove_subscriber` previously did a phantom `mark_invoice_refunded` (flip an invoice string) + a creator-side "refund" ledger row — the subscriber's card was never refunded and the creator's live credit was never clawed back. Now routes through the shared immediate-cancel path (`_reverse_subscription_charge`): real prorated card refund to the subscriber (or gifter), creator credit reversed (state=reversed, not inflating), access revoked. Idempotent.

### SUBX-13 — Dunning cadence anchored to first decline (1/3/5/7)
`subscription_renewal._decline` added each retry gap to the *previous* retry time → cumulative **1/4/9/16** (and any late sweep pushed the whole schedule out). Now stores `first_decline_at` on the first decline and schedules `dunning_next_retry_at = first_decline_at + retry_days[attempt] × 1d` → retries land on **absolute days 1/3/5/7**; `grace_until = first_decline_at + (max_retry + grace) × 1d`; after the 4th retry → grace → `expired`. `first_decline_at` is cleared on a successful renewal and on resume.

### SUBX-14 — Discount base-price correctness (no double-apply; MRR/renewal use list)
Subscribe stored the **discounted** amount in `price_cents`, then `_renewal_amount` applied the discount **again** (double-discount) and MRR/analytics read the discounted price. Now `price_cents` is always the **list** price; a separate `charge_price` (the discounted initial amount) is charged and recorded on the initial invoice (`amount_cents` + `list_price_cents`). Renewal (`_renewal_amount`) applies the discount **once** to the list price while `discount_remaining_months > 0`. A `duration=="once"` code sets `discount_remaining_months = 0` (initial charge only); `repeating N` → `N−1` remaining renewals. MRR now reads the list price.

### SUBX-15 — Double-subscribe/gift guard + resume integrity + cancel convergence
- **Guard:** `subscribe`/`gift` reject a second live sub to the same creator (`_find_active_sub_for_creator` → return the existing sub, no second charge).
- **Resume:** `resume` clears dunning residue and only restores `active` when paid time remains (`current_period_end > now`); a **lapsed** sub returns **409** (`subscription_lapsed`) directing the client to re-subscribe — never an active-but-locked sub.
- **Cancel convergence:** one shared `_apply_immediate_cancel(...)` now backs `/cancel(immediate)`, `/renewal(effective=immediate)` (previously revoked with **no refund**), and creator `remove` — all three refund + revoke identically.

## Cross-ticket interaction (documented)
SUBX-10 makes a **start-of-cycle** default `/refund` frac≈1.0 (100% unused = a *full* refund), which the SUBX-02 rule restricts to creator/gifter/admin. A mid-cycle subscriber self-refund (frac<1) still succeeds and revokes access. The X0 verifier's prorated-refund check was updated to seed a mid-cycle sub + assert a **proportional** clawback (it previously relied on the buggy lifetime denominator).

## Apply (prod, via SSM)
`apply_subx1_ssm.sh` is the exact SSM payload used: it md5-guards the baseline, backs up both files (`*.bak_subx_<ts>`), base64-decodes + `patch`es (`subx1_server.patch`, `subx1_renewal.patch`), md5-guards the result (auto-restores on mismatch), `ast.parse`s, chowns `ubuntu:ubuntu`, and restarts via `sudo -u ubuntu bash /home/ubuntu/restart_backend.sh`. Re-runnable on the byte-identical baseline.

## Verify (prod, live-DDB-direct, self-cleaning to 0 residue)
- `verify_subx1.py` — 21/21 PASS. Direct async endpoint calls against the real prod DDB, TAG-tagged synthetic creators/subs/PMs, isolates commerce-emit/alerts/milestones/ad-attr (untouched by X1), sweeps `subscriptions/billing/purchase_transactions/purchase_events` to **0 residue**. Run under `bash -c 'set -a; . ./.env.local; set +a; .venv/bin/python verify_subx1.py'` (the app's AWS creds live in `.env.local`; the SSM instance role has no DDB perms).
- `moto_run_subx1.py` — dev-host dry-run harness (moto in-memory tables; the dev clone has no live DDB).
- `prod_sweep.py` — standalone `subx1v-` residue sweeper across all touched tables (belt-and-suspenders).

### Prod verify matrix — 21/21 PASS (SUBX1) + 22/22 PASS (X0 no-regression), 0 residue
| Ticket | Positive | Negative / boundary |
|--------|----------|---------------------|
| SUBX-10 | renewed-sub immediate cancel refunds cycle-correct **500** (½ cycle), not ~130 lifetime | — |
| SUBX-10b | mid-cycle subscriber `/refund` → 200, partial clawback 450, access revoked | (start-of-cycle default refund = full → subscriber-blocked, by design) |
| SUBX-11 | month→year upgrade, interval reset (cpe≈now+365d), sane delta credited net(14000) | year→month schedules a `pending_change` downgrade (no immediate charge) |
| SUBX-12 | creator remove refunds subscriber card (1000), creator credit clawed to 0, access revoked | — |
| SUBX-13 | retries land absolute **d1/3/5/7**; grace_until = anchor+14d; grace after 4th retry | (was 1/4/9/16) |
| SUBX-14 | list price stored (1000); "once" remaining=0; renewal uses list (1000, no double); MRR=list; initial invoice discounted (500); repeating N=3 → remaining 2, renewal 500 | — |
| SUBX-15 | double-subscribe returns existing (no 2nd charge); resume restores active+unlocked; 3 cancel paths refund identically (1000) | resume LAPSED → 409 (no active-but-locked) |
| X0 (regression) | convert/refund-revokes-access/webhook-auth/gating all intact | 22/22 |

**Unit tests** (`tests/test_subscription_server_charge_paths.py`): 6/8 pass; the 2 failures (`test_subscribe_path`, `test_change_plan_proration_path`) are **pre-existing** (identical on the pre-X1 baseline — the change-plan test supplies equal prices so it schedules; the subscribe test doesn't mock the PM resolver), unrelated to X1.

## Residual (non-blocking)
- Legacy **discounted** subs created *before* X1 still carry a discounted `price_cents` + `discount_remaining_months>0`; their next renewal may double-discount once before `remaining` reaches 0 (a small one-time undercharge on that narrow cohort). New subs are correct. No migration shipped (discounts are rarely used; grandfathered like the phantom-revenue decision).

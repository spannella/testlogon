# SUBX Epic X0 — Stop the P0 subscription money leaks (live prod hotfix)

**Program:** Subscriptions smoothing (`ops/plans/subscriptions-rough-edges-plan.md`), Epic X0 / SUBX-01..03.
**Target file:** `app/routers/subscription_server.py` (byte-identical dev==prod).
**Applied:** 2026-07-15. **Prod EC2:** `i-08f937fc705ebea75` via SSM. **Backup on prod:** `app/routers/subscription_server.py.bak_subx_1784146663`.
**Post-patch md5 (dev==prod):** `428ea00dd3fffae29a4b196f5cffcce9`.

## Tickets

### SUBX-01 — Kill the phantom `/trial/convert` (M1, P0)
`convert_trial` previously minted a `stub_inv` invoice and credited the creator NET with **zero dollars collected** (no PM resolve, no charge, no funds guard). It now routes the manual conversion through the **same funds-guarded rail the sweeper uses** — `subscription_renewal._attempt_renewal(sub, ts, summary, trial_conversion=True)`:
- missing / declined payment method → the rail declines → endpoint returns **402** and credits **nothing** (sub goes `past_due`, consistent with sweeper auto-convert dunning);
- success only after a real captured PaymentIntent (accept-under-mock honest rail) → creator credited **NET** exactly once; per-cycle idempotent (`{sub}:convert` PI key + `RENEWCYCLE#` claim). A repeat call hits the `status != trialing` guard → 400, no double charge.

### SUBX-02 — Refund revokes access + restricts full refunds (M2, P0)
Standalone `/refund` previously reversed the charge but never touched `status`/`current_period_end` → a subscriber could refund their own cycle and **keep access**. Now:
- only the **creator / gifter / platform-admin** may issue a FULL (`fraction >= 1.0`) refund; a subscriber may only self-refund the unused prorated remainder (else 403);
- on any refund the cycle is revoked: `status=canceled`, `current_period_end=now`, `auto_renew=False` (mirrors the immediate-cancel path) → `has_active_subscription` flips **False** and gated content re-locks. Idempotent (an idempotent-replay reversal does not re-revoke).

### SUBX-03 — Authenticate the billing webhook (M3, P0)
`POST /api/billing/webhooks/{provider}` was **unauthenticated** — anyone knowing a `subscription_id` could `invoice.paid` a sub back to `active`, advance the period, and re-enable `auto_renew`, bypassing dunning. Now (seam mirrors `admin_payouts.payout_provider_webhook`):
- a shared secret `SUBSCRIPTION_WEBHOOK_SECRET` (env, or `S.subscription_webhook_secret`) is required via header **`X-Subscription-Webhook-Secret`**; an unsigned / forged caller → **401** and mutates nothing;
- **defense-in-depth (unconditional):** `invoice.paid` is now **bookkeeping-only** — it records the invoice but **no longer** extends `current_period_end` / flips `status=active` / re-enables `auto_renew`. Only the real funds-guarded renewal sweeper advances the lifecycle. So even a validly-signed `invoice.paid` without a real capture cannot free-extend an expired/banned sub.

**Prod config:** `SUBSCRIPTION_WEBHOOK_SECRET` was appended to prod `/home/ubuntu/testlogon/.env.local` (gitignored; a fresh 32-byte hex) so the gate is active. Rotate as needed; the `invoice.paid` neutering holds even if the secret is unset.

## Files
- `apply_subx0.py` — idempotent, single-match-asserted patch applied to `app/routers/subscription_server.py` (6 replacements). Re-runnable on a byte-identical baseline.
- `verify_subx0.py` — live-DDB-direct prod verifier: synthetic creators/subs/PMs, drives the real localhost:8000 endpoints, asserts money + gating + lifecycle, then TAG-sweeps `subscriptions/billing/orders/order_items/entitlements` to **0 residue**.

## Apply (prod, via SSM)
```
cp app/routers/subscription_server.py app/routers/subscription_server.py.bak_subx_$(date +%s)
python3 apply_subx0.py app/routers/subscription_server.py
python3 -c "import ast; ast.parse(open('app/routers/subscription_server.py').read())"
grep -q '^SUBSCRIPTION_WEBHOOK_SECRET=' .env.local || echo "SUBSCRIPTION_WEBHOOK_SECRET=<hex>" >> .env.local
chown ubuntu:ubuntu app/routers/subscription_server.py .env.local
sudo -u ubuntu bash /home/ubuntu/restart_backend.sh
```

## Verify matrix (prod live-DDB, 2026-07-15) — 22/22 PASS, 0 residue
| Ticket | Positive | Negative |
|--------|----------|----------|
| SUBX-01 | with-PM convert → 200 active, creator +NET(900) once, repeat → 400 no double credit | no-PM convert → 402, `past_due`, **no credit** |
| SUBX-02 | subscriber prorated refund → 200, access **revoked** (`canceled`), `has_active`→False, content re-locks, credit clawed back to baseline (not inflating) | subscriber full-refund (`fraction=1.0`) → **403**, sub stays active |
| SUBX-03 | authed `invoice.paid` → 200 **but** expired sub NOT extended/activated (bookkeeping-only) | unauth webhook → **401**, no un-expire/extend |
| CORE (regression) | subscriber unlocked after convert; renewal-rail charge/credit/idempotency intact | stranger locked pre-subscribe |

Backend unit tests (`tests/test_subscription_server_charge_paths.py`): the trial-convert test was updated to the SUBX-01 contract (with-PM charges+reconciles; no-PM declines 402 + credits nothing). Pre-existing unrelated failures (`test_subscribe_path`, `test_change_plan_proration_path`, e2e table-not-found) are unchanged by this epic.

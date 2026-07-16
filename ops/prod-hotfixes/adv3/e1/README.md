# ADV3 EPIC E1 — Money-correctness (ADV3-1 + ADV3-2)

Live prod hotfix folded here. Backend-only. Makes the ad **cash-in rail honest**
and hardens the **charge path**. Prod EC2 `i-08f937fc705ebea75` (SSM, no SSH);
dev reference clone `~/dev/testlogon` @ `android-impl`.

## What changed (3 service files)

### `app/services/ad_billing.py`
- **ADV3-1 (A1/A2/B9) — honest deposit charge.** `deposit_funds()` gains an
  `internal: bool` seam. The **public** path now:
  - **rejects a deposit with no `payment_method_id` → HTTP 400** (no ledger row,
    no balance credit) — closes the "optional PM = free budget" hole.
  - charges the card via `_charge_deposit` (existing stripe-mock PaymentIntent
    rail, accept-under-mock; real `CardError` → **402**) and **credits balance
    ONLY on a successful charge**.
  - if the processor rail is unconfigured (dev stub → `payment_intent_id` is
    `None`) records a **LOUD** `state="uncharged_simulation"` ledger row +
    critical alert and raises **402** — never a silent free credit
    (`_record_uncharged_deposit`).
  - **application-level idempotency** claimed BEFORE the charge, keyed on the
    same `addep:{account}:{amount}:{pm}` tuple as the PaymentIntent
    idempotency_key (marker `DEPIDEMP#…`, released on a failed charge). A
    double-fired deposit neither double-charges nor double-credits — **holds even
    against a stripe-mock that does not honor processor idempotency keys** (the
    mock returns a fresh PI each call; a real Stripe returns the same one).
  - `internal=True` preserves the legacy ledger-only path so seed/back-office
    top-ups without a card still credit.
- **ADV3-2/A4 — hard campaign-budget guard.** `_process_charge` step 2 makes the
  campaign-spend bump a **conditional write** (`lifetime_spent_cents <=
  budget_cents - amt`) when the campaign has a positive budget. On rejection it
  **rolls back the account debit**, releases the idempotency marker, and returns
  `{"ok": False, "reason": "budget_exceeded"}`. Concurrent charges can no longer
  overshoot `budget_cents`.
- **ADV3-2/A6 — reversal clawback label.** The `charge_reversal` ledger-row meta
  now records `member_clawback` (the real clawback in a syndicate 3-way split;
  the treasury took the remainder) instead of the full `creator_share`, plus
  `member_clawback_cents` / `treasury_debit_cents` / `is_syndicate_split`. DDB
  debits were already correct — this fixes the audit meta only.

### `app/services/ad_serving.py`
- **ADV3-2/A3 — click double-charge.** `record_cta_click` now uses the
  **canonical `{ad_click_id}#click`** idempotency key (was
  `{id}#cta#{type}`), so a creative with BOTH a click-through and an in-player
  CTA bills CPC **exactly once** per `ad_click_id` (first-of-either charges, the
  second no-ops).
- **ADV3-2/E4 — CTA fraud gate.** `record_cta_click` now runs
  `ad_fraud_prevention.check_fraud(event_type="click", …)` before the CPC charge
  (it previously skipped IVT/velocity/bot filtering entirely). A flagged tap is
  recorded (`record_fraud_event`), feeds `maybe_auto_suspend`, and is **not
  charged**; a legitimate tap records account activity and charges as before.

### `app/services/ad_attribution.py`
- **ADV3-2/A5 — don't consume the click on underfunded conversion.** After the
  atomic last-click claim, if `charge_conversion` returns
  `insufficient_funds` / `budget_exceeded` the claim is **reverted** (status
  restored, `converted_at`/conversion fields removed) and the call returns
  `charge_deferred`. Because `_process_charge` releases its idempotency marker on
  insufficient funds, a later retry (after the advertiser refills) re-attributes
  and charges **exactly once**.

## Apply (already applied to prod)

Run each patcher from the repo root (`cd /home/ubuntu/testlogon`). They are
idempotent string-replace scripts that `assert` their target blocks then
rewrite in place:

```
python3 patch_billing.py       # ADV3-1 v1 + ADV3-2 A4/A6
python3 patch_serving.py       # ADV3-2 A3 + E4
python3 patch_attribution.py   # ADV3-2 A5
python3 patch_billing_v2.py    # ADV3-1 deposit idempotency hardening (pre-charge marker)
python3 -m py_compile app/services/ad_billing.py app/services/ad_serving.py app/services/ad_attribution.py
sudo chown ubuntu:ubuntu app/services/ad_*.py
sudo -u ubuntu bash /home/ubuntu/restart_backend.sh   # then curl openapi.json == 200
```

Prod backups written (restore = copy back + restart):
- `app/services/ad_billing.py.bak_adv3_1784128523`   (pre-E1)
- `app/services/ad_serving.py.bak_adv3_1784128523`
- `app/services/ad_attribution.py.bak_adv3_1784128523`
- `app/services/ad_billing.py.bak_adv3v2_1784129263` (pre deposit-idempotency v2)

## Verify

`adv3_verify.py` is a service-level harness: it boots its **own in-process moto
DynamoDB** with the real ad-table schemas, imports the patched services, and
drives every AC against a real DDB engine + the real stripe-mock rail
(`localhost:12111`). **Zero prod-DDB residue** — the moto store is created and
destroyed inside the harness process; the live prod DDB is never written.

Run (prod, env sourced):
```
cd /home/ubuntu/testlogon && set -a && source .env.local && set +a
export PYTHONPATH=/home/ubuntu/testlogon
.venv/bin/python ops/prod-hotfixes/adv3/e1/adv3_verify.py
```

### Result: 15/15 PASS

| Ticket | Case | Result |
|---|---|---|
| ADV3-1 | deposit no-PM → 400, no credit/ledger | PASS |
| ADV3-1 | deposit w/ PM → charges + credits (PI recorded) | PASS |
| ADV3-1 | double-fire → idempotent (credit once) | PASS |
| ADV3-1 | card decline → 402, no credit | PASS |
| ADV3-1 | internal seed path still credits w/o PM | PASS |
| ADV3-2/A3 | click + CTA bill CPC once (canonical key) | PASS |
| ADV3-2/A3 | control: fresh CTA still bills | PASS |
| ADV3-2/A4 | sequential 20 charges vs budget 300 → spent==300 | PASS |
| ADV3-2/A4 | concurrent 20 charges → spend never > budget | PASS |
| ADV3-2/A5 | underfunded conversion does NOT consume click | PASS |
| ADV3-2/A5 | fund + retry settles exactly once | PASS |
| ADV3-2/A6 | syndicate reversal meta = member clawback (70) | PASS |
| ADV3-2/A6 | control: non-syndicate claws full creator_share (100) | PASS |
| ADV3-2/E4 | flagged CTA → not charged, fraud recorded | PASS |
| ADV3-2/E4 | legit CTA → passes gate + charges | PASS |

## Notes / residuals
- Prod runtime already has the stripe-mock rail configured
  (`STRIPE_SECRET_KEY=sk_test_…`, `STRIPE_API_BASE=http://localhost:12111`), so
  A1 ("key empty → all free") was already closed at runtime; the live remaining
  hole was A2 (omit PM → free credit), now closed.
- No regression to serve/attribution or tips/subs/payouts: only the three ad
  service files changed; the main billing rail is untouched; app boots (openapi
  200).
- App-side follow-ups (force PM selection in the deposit sheet, "Add card"
  affordance, no double-tap) are ADV3-3 (separate epic).

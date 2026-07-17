# DISP E0 — Payment-Disputes FOUNDATION (unified record + charge resolver + reversal-rail dispatcher + reverse_vod_purchase + mutex)

Epic **E0 / DISP-001..005** of the payment-disputes program
(`ops/plans/payment-disputes-plan.md`). Backend, **real-now**, **no user money
moves for real users yet** — this lands the money-correctness core that both
dispute tracks (user `billing_disputes` + processor `PaymentIncident`) will
converge on in E1/E3. Every rail is now callable, honest, and idempotent.

## What it does

The single central defect of the two shipped dispute stacks was that **neither
touched the shared `T.billing` ledger** — they moved dispute *state* only. E0
wires a resolution to the CORRECT EXISTING reversal rail per charge type.

| Ticket | Deliverable |
|---|---|
| DISP-001 | Unified dispute record: `file_dispute` gains `source ∈ {user, processor}` + `charge_type` + `charge_ref` + `linked_dispute_id` + `rail_marker`, persisted on the `T.billing_disputes` META row. Legacy rows default `source=user` (no behavior change). |
| DISP-002 | `dispute_dispatch.resolve_charge(charge_ref, charge_type)` — normalizes any of the six charge refs into the params each rail needs (ledger rows, counterpart parties, sub id / period_end / ad account / purchase_id). |
| DISP-003 | `dispute_dispatch.dispatch_reversal(...)` — one function, `_RAIL` map `charge_type → rail`: tip/message → `reverse_tip_by_payment_id`; subscription → `_reverse_subscription_charge`; ad → `reverse_ad_charge`; ecom → `refund_requests.create_refund_request`+`approve_request`; vod → `reverse_vod_purchase`. Full/partial (partial: ecom via `override_amount_cents`, sub via `refund_fraction`; rejected for tip/ad/vod in v1). Idempotent. |
| DISP-004 (N1) | `vod_purchase.reverse_vod_purchase(...)` — THE code gap. Clawback seller + buyer refund (both `type != credit`) + flip original seller credit `state=reversed` + **`T.vod_entitlements.delete_item`** so a refunded buyer LOSES access + `VODREVERSAL#{purchase_id}` marker (idempotent). `clawback_only=True` suppresses the buyer refund for the E3 chargeback path. |
| DISP-005 | `claim_charge_reversal_mutex` (the cross-track credit-flip mutex: a user refund and a processor chargeback on the same charge can never double-debit) + `guarded_dispute_transition` (act-after-guard conditional status write; the rail fires ONLY when `changed=True`). |

## Honesty invariants (all upheld, live-verified)

- Every reversal leg writes `type ∈ {reversal, refund, refund_credit,
  refund_debit}` — **never `credit`** — so a reversal can never inflate earnings
  (`get_available_balance` / `total_earned_cents` sum only `type=="credit" &
  state!="reversed" & amount>0`).
- tip/sub/ad/vod flip the **original credit** to `state="reversed"` (drops it out
  of earnings). ecom uses the **offsetting-debit** model of `refund_requests`
  (seller `refund_debit` nets the credit + balance-summary delta) — its native,
  shipped honesty model; E0 does not change it.
- **VOD env split (important):** on **prod** the seller credit is written
  `entry_type="credit"` (counts toward balance), on the **dev clone** it is
  `entry_type="vod_purchase_credit"` (does not). `reverse_vod_purchase` locates
  the original credit by `meta.purchase_id` (type-agnostic) and flips it in both,
  so the clawback is correct on prod (real balance drop) and honest on dev.

## Files

- **NEW** `app/services/dispute_dispatch.py`
- `app/services/vod_purchase.py` — +imports, `_vod_av` transact serializer,
  `reverse_vod_purchase` + `_vod_reversal_sk` + `_find_vod_purchase_debit_row` +
  `_find_vod_credit_row`.
- `app/services/billing_disputes.py` — `file_dispute` DISP-001 fields.

No new HTTP routes in E0 (the user/admin dispute surfaces land in E1/E2), so no
`#118` api-key route registration is required here.

## Apply

```
python3 apply_dispe0.py <REPO_ROOT> <THIS_DIR>
```

Idempotent (sentinel-guarded: `def reverse_vod_purchase(` /
`"source": source or "user"`). Backs up each edited file to
`<file>.bak_disp_<ts>` before touching it. Places `dispute_dispatch.py`, patches
the two files, AST-checks all three.

## Verify (LIVE, real HTTP)

```
set -a; . .env.local; set +a
PYTHONPATH=<REPO_ROOT> .venv/bin/python verify_e0.py          # 24/24, 0 residue
PYTHONPATH=<REPO_ROOT> .venv/bin/python verify_transition.py  # 5/5
```

`verify_e0.py` seeds a REAL charge of each of the six types against the same live
DynamoDB the running uvicorn uses, drives `dispatch_reversal`, and asserts every
money/access effect via **real HTTP** against the running server (minted
`ui_access_token` cookie: `/ui/payouts/balance` total_earned drop,
`/ui/videos/purchases/list` entitlement gone) + live-DDB credit-state reads, then
prefix-scan purges all synthetic rows (0 residue). Balance assertions use
`total_earned_cents` (hold-independent) because a fresh credit sits in
`hold_cents` for the 7-day payout hold.

### LIVE matrix (dev prod-mock, 2026-07-17) — 24 PASS / 0 FAIL

tip (credit + reverse + flip + drop + idempotent), message (tip rail), vod
(entitlement granted → **DELETED** → buyer loses access; credit flipped; no
inflation; idempotent), subscription (full clawback + drop + idempotent), ad
(revenue-split credit + clawback + drop + idempotent), ecom (seller `refund_debit`
clawback == net + buyer `refund_credit`, no double-credit), mutex (first claimant
wins, second blocked). Plus DISP-001/005: unified record fields, legacy
`source=user` default, guarded transition one-winner, illegal-skip rejected.

# DISP E1 — user-level dispute flow (first real money movement)

Wires the pre-existing user-track dispute stub (`billing_disputes`) to the E0
reversal-rail dispatcher (`dispute_dispatch`) so a **resolved dispute actually
moves money** on the correct existing rail — the core fix of the payment-disputes
program's user track. Ledger reconciliation is real-now; the rails' own Stripe
refund legs stay real-when-keyed.

## Tickets

| Ticket | Deliverable |
|---|---|
| **DISP-010** | Reason enum `not_received/not_as_described/unauthorized/duplicate/quality` + per-charge-type gating (`dispute_lifecycle.reasons_for_charge_type` / `validate_reason`). tip/message/subscription: no not_received/not_as_described; ad: only unauthorized/duplicate; ecom/vod: full set. `reason_detail` free-text carried separately. |
| **DISP-011** | User state machine (`dispute_lifecycle._ALLOWED`): `open -> needs_response -> under_review -> resolved{refunded,partial,denied}` + `withdrawn`/`escalated`. Forward-only; illegal skips 409; withdraw vs resolve mutually exclusive via the E0 guarded transition (DISP-005). |
| **DISP-012** | Creator/seller response window: `open -> needs_response` sets `respond_by = now + dispute_response_window_days` (7d) + notifies the creator. `sweep_expired_dispute_responses` mirrors `moderation_lifecycle.sweep_expired_holds` -> a no-response window auto-advances to `under_review` (NOT auto-loss; admin decides). Auto-skip policy: `unauthorized` OR `amount < dispute_auto_refund_threshold_cents` skips the window straight to the admin queue. Late response after the sweep attaches as a comment (no illegal transition). |
| **DISP-013** | `billing_disputes.resolve_dispute` rewritten to drive `dispute_dispatch.dispatch_reversal`: `refunded -> full`, `partial -> override_amount_cents` (ecom/subscription only), `denied -> state-only (zero ledger)`. Guarded flip: the rail fires ONLY when this call is the winning `-> resolved` transition (concurrent double-resolve / withdraw-vs-resolve = exactly one money move). Rail rejection rolls the status back to `under_review` (never a phantom "resolved" with no money moved). |
| **DISP-014** | Pre-open guards: (a) **refund-then-dispute** blocked — the charge's E0 credit-flip mutex (`CHARGEMUTEX#{type}#{ref}`) already claimed => `409 already_reversed`; (b) **dedup** — one non-terminal dispute per `charge_ref` per user => `409 duplicate_open_dispute`; plus DISP-010 reason gating + charge auto-detection from a `transaction_entry_id`. |

## Files

* **NEW** `app/services/dispute_lifecycle.py` — reasons/gating (010), state machine (011), response window + SLA sweep (012), `detect_charge_from_entry`.
* `app/services/billing_disputes.py` — `file_dispute` gains reason gating + pre-open guards + auto-open window + `recipient_id`/`reason_detail`/`respond_by`/`responses` fields; `resolve_dispute` wired to the dispatcher; NEW `withdraw_dispute`; `_to_out` surfaces the new fields.
* `app/routers/billing_disputes.py` — file passes the new fields; NEW `POST /ui/billing/disputes/{id}/withdraw`; resolve takes `override_amount_cents`; NEW admin `POST /ui/admin/disputes/sweep`.
* `app/models.py` — `DisputeFileIn` (+reason_detail/charge_type/charge_ref/recipient_id; reason min_length 10->1); `DisputeResolveIn` (+refunded|partial|denied + override_amount_cents).
* `app/core/settings.py` — `dispute_response_window_days` (7), `dispute_auto_refund_threshold_cents` (0).

## Apply (prod, via SSM as ubuntu)

```
python3 apply_dispe1.py /home/ubuntu/testlogon /home/ubuntu/testlogon/ops/prod-hotfixes/disp/e1
# restart: pkill -f "uvicorn app.main" (root) FIRST, then restart_backend.sh as ubuntu; openapi 200
```

Idempotent (sentinel-guarded). Backs up each edited file to `<file>.bak_disp_<ts>`.
`billing_disputes.py` + `router` are whole-file overwrites (prod == dev HEAD,
md5 `753595...` / `871f72...`); `models.py` + `settings.py` are targeted
string-replace patches (huge prod-divergent shared files — anchor blocks are
byte-identical to dev HEAD).

## Verify (LIVE HTTP against the running server)

```
set -a; . .env.local; set +a; PYTHONPATH=$PWD .venv/bin/python verify_e1.py
```

Seeds real tip/subscription/ecom/vod charges, drives the whole flow over real
HTTP (minted cookies), asserts money moved + access revoked + guards + SLA sweep
+ idempotency, auto-cleans (0 residue). **20/20 PASS on dev + prod.**

Key semantic notes carried from E0:
* tip/subscription/vod reversal = **credit-flip** -> assert on `total_earned_cents`.
* ecom reversal = **offsetting refund_debit** (does NOT flip the original credit) -> assert the seller `refund_debit` row exists (its amount = the seller's net for the order; the buyer `refund_credit` = the override/partial amount).
* balance is held 7d, so a fresh seed credit has `available_cents=0` — the hold-independent signal is `total_earned` (credit-flip) or the refund_debit row (ecom).

# DISP E3 — Processor chargeback track (DISP-030..035)

Wires the half-built **PaymentIncident** processor stack to the shared ledger +
the six reversal rails, so a real Stripe/card-network chargeback actually moves
money (hold-on-open, clawback-only rail, chargeback fee, LOST/WON/ACCEPTED
reconcile) — the same money layer the user track already uses (E1), but driven
by the processor webhook instead of a human admin.

Ledger reconciliation is **real-now** (mock-testable). Processor I/O (signature
verify, Dispute.retrieve, evidence submit, real fee amount) stays
**real-when-keyed** behind the existing rollout flags (disabled -> shadow ->
live per provider). Ships in **shadow** first.

## Tickets

- **DISP-030 — map missing dispute events.** `payment_incident_stripe_adapter.py`
  now parses `charge.dispute.funds_withdrawn` / `funds_reinstated`
  (funds_withdrawn -> `opened`; funds_reinstated -> `opened` + `funds_restored`
  audit flag) and carries `funds_moved` / `due_by` / `charge_meta` on the
  canonical event payload. Mirrored on PayPal (`CUSTOMER.DISPUTE.*`) + CCBill
  (`Chargeback`). Existing created/updated/closed mapping unchanged.
- **DISP-031 — hold on open.** `dispute_chargeback.hold_charge_on_open` flips the
  original creator/seller credit row(s) `state="held"` (settled -> held) so the
  contested funds drop out of `get_available_balance` **immediately**
  (`creator_payouts.py` filter now also excludes `state="held"`). Idempotent via
  a `CHARGEBACK_HOLD#{incident}` marker; the per-row *prior* state is recorded so
  a WON can restore it exactly.
- **DISP-032 — evidence assembler + response window.**
  `build_dispute_evidence(incident, creator_rebuttal=...)` builds a Stripe
  `dispute.evidence`-shaped packet from the charge meta + the creator rebuttal;
  `response_due_at` prefers Stripe `evidence_details.due_by`, else the configured
  window. Submit is the real-when-keyed `submit_dispute_response` adapter seam
  (mock-records now, `Dispute.modify(evidence=)` when keyed).
- **DISP-033 — clawback-only rail forks.** Each of the four remaining rails
  (`reverse_tip` / `_reverse_subscription_charge` / `reverse_ad_charge` /
  `refund_requests.approve_request`) gained a `clawback_only` param; VOD already
  had one. On a chargeback the buyer/advertiser refund leg + any Stripe refund
  are **suppressed** (the processor already refunded the cardholder) while the
  creator/seller clawback + original-credit flip still fire. `dispute_dispatch`'s
  four rail forks now pass `clawback_only` through (the E0 501 stubs are gone).
- **DISP-034 — `chargeback_fee` ledger type.** `build_chargeback_fee_item` writes
  a `type="chargeback_fee"` (NON-credit -> excluded from earnings by the existing
  credit filter, no new counter) row on LOST/ACCEPTED. Amount = Stripe
  balance_transactions fee (`charge_meta.fee_cents`, keyed) or the configured flat
  default (`S.dispute_chargeback_fee_cents`, $15). Policy flag
  `S.dispute_chargeback_fee_policy` = `creator_eats` (creator ledger) vs
  `platform_eats` (`PLATFORM#revenue`). Idempotent via the LOST marker.
- **DISP-035 — LOST/WON/ACCEPTED reconciler.** `reconcile_terminal`:
  - LOST / ACCEPTED -> drive the correct rail `clawback_only=True` (creator
    clawed, NO buyer refund, NO Stripe refund), flip any still-held credit
    `held -> reversed`, record the fee. `CHARGEBACK_LOST#{incident}` marker.
  - WON -> restore each held credit to its ORIGINAL state (`held -> settled`),
    clear the hold. `CHARGEBACK_RELEASE#{incident}` marker. No ledger money move.
  - Gated by `S.dispute_chargeback_reconcile_enabled` (belt on top of shadow).

The reconciler is hooked into the LIVE (non-shadow) stripe webhook branch in
`billing.py` (`_disp_cb.on_incident_transition` after each processed transition),
which also now persists `charge_meta` / `due_by` on the incident row. The dispute
transition table (`payment_incidents_domain.py`) was widened so a real
`charge.dispute.closed` can move a live state directly to a terminal outcome
(Stripe does not require our intermediate `under_review`); still forward-only.

## Cross-track safety

The LOST clawback rides `dispatch_reversal(..., use_mutex=True)`, so it shares the
E0 credit-flip mutex with the user track — a user refund + a processor chargeback
on the SAME charge can never double-debit (the loser is a no-op). Full E4 link is
its own ticket, but the mutex guard is already in force here.

## Files changed (mirror byte-for-byte into prod)

```
app/services/dispute_chargeback.py                 (NEW — reconciler)
app/services/payment_incident_stripe_adapter.py    (DISP-030)
app/services/payment_incident_paypal_adapter.py    (DISP-030 mirror)
app/services/payment_incident_ccbill_adapter.py    (DISP-030 mirror)
app/services/creator_payouts.py                    (DISP-031 balance filter += state!=held)
app/services/tips.py                               (DISP-033 clawback_only)
app/routers/subscription_server.py                 (DISP-033 clawback_only)
app/services/ad_billing.py                         (DISP-033 clawback_only)
app/services/refund_requests.py                    (DISP-033 clawback_only)
app/services/dispute_dispatch.py                   (DISP-033 wire forks through)
app/services/payment_incidents_domain.py           (DISP-035 widen closed-from-live)
app/routers/billing.py                             (webhook reconciler hook + charge_meta persist)
app/core/settings.py                               (DISP-034 fee flags + reconcile flag)
scripts/local-ddb-init.py                          (payment_incidents GSIs for parity)
tests/test_payment_incidents_domain.py             (transition-widen tests)
tests/test_payment_incident_transitions.py         (transition-widen tests)
```

## Apply (prod)

The **code** is mirrored byte-for-byte (see the copies in this dir). Data-plane:
the dev clone's `payment_incidents` table + its child tables were half-built
(missing GSIs / missing tables). Run once against the target DDB:

```
PYTHONPATH=. python ops/prod-hotfixes/disp/e3/provision_incident_tables.py   # events/evidence/retries/ticket_links
PYTHONPATH=. python ops/prod-hotfixes/disp/e3/provision_incident_gsis.py     # incidents GSIs
```

(Both idempotent; on prod the canonical
`scripts/migrations/20260324_payment_incidents_schema.py` is authoritative.)

Ship in **shadow** (`PAYMENT_INCIDENTS_SHADOW_MODE=1` or per-provider) first;
promote to **live** per provider after a clean shadow window. Real Stripe I/O
goes live only when `STRIPE_WEBHOOK_SECRET` is set + the `stripe` SDK is present.

## LIVE verification (real HTTP against the running server)

Signs a mock Stripe webhook with the local `whsec` (real signature verify passes)
and POSTs to `/api/billing/webhooks/stripe`; asserts every money/access effect
via live DDB + HTTP balance; 0 residue.

```
set -a; . .env.local; set +a
PYTHONPATH=. python ops/prod-hotfixes/disp/e3/verify_e3.py          # 25/25 PASS
PYTHONPATH=. python ops/prod-hotfixes/disp/e3/check_ad_clawback.py  # 5/5 PASS
PYTHONPATH=. python ops/prod-hotfixes/disp/e3/check_ecom_clawback.py# 3/3 PASS
```

### LIVE pos/neg matrix (25/25 + 5/5 + 3/3)

POSITIVE (money really moves the right way):
- tip/sub/vod `dispute.created` -> original credit flips `held`, drops out of the
  earned/available balance immediately.
- `funds_withdrawn` maps -> `opened`, hold idempotent (no double-hold).
- evidence assembled from charge meta + rebuttal, `due_by` deadline stamped.
- LOST (tip/vod/sub-ACCEPTED): creator clawed (`type=reversal`, net), held credit
  -> `reversed`, `chargeback_fee` recorded ($15 creator_eats), earnings stay
  dropped; VOD LOST also revokes the buyer entitlement (access lost).
- WON (vod): held credit restored to `settled`, exact balance back, no ledger move.
- ad/ecom clawback-only: seller/creator clawed, advertiser/buyer NOT re-credited,
  ad lifetime-spend still backed out.

NEGATIVE (no double-debit / safe no-op):
- NO buyer/payer/advertiser refund on any chargeback (processor already refunded).
- LOST redelivery deduped -> no 2nd clawback, no 2nd fee.
- WON redelivery -> state stays settled.
- unmapped external charge -> webhook still 200, records a non-resolvable hold
  marker; LOST on it is a safe no-op (no crash, no ledger write).
- full (non-chargeback) refund path unchanged (E1 20/20 still green).

No regression: E1 20/20, payment_incident domain/transition/adapter unit tests
35/35, ad/ecom rail full-vs-clawback both correct.

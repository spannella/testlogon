# SUB-E2 PART 2 — gifting + cancel/refund (prod hotfix + fold)

Money-path completion of EPIC E2 (SUB-23 gifting, SUB-25 cancel/refund + the
`canceling` access fix). Live prod hotfix via SSM, mirrored byte-identical into
the dev clone, committed with the 3 source files.

## What shipped (3 files, anchored-idempotent patch `apply_sube2_p2.py`)

`app/routers/subscription_server.py`
- **GIFT** `POST /api/plans/{plan_id}/gift` (`gift_subscription`): the GIFTER pays
  ONE cycle via the real E0 rail (`_charge_subscription_payment_intent`,
  funds-guarded, real PI). The RECIPIENT gets a one-cycle subscription
  `status=active, auto_renew=False, is_gift=True, gifter_id=…`, **no PM** — so it
  LAPSES at period end via the E1 sweeper (never charged). Creator credited NET
  (10% fee) via ledger charge/fee + `_mirror_creator_credit_to_billing`. The PAY
  record is written under the **gifter** (payer), never the recipient. Namespaced
  `gift:` idempotency reuses the subscribe idem markers.
- **CANCEL** (`cancel_subscription`): default `cancel_at_period_end=True` →
  `status=canceling` (keeps access to period end, NO refund). Immediate
  (`cancel_at_period_end=False`) → revoke NOW (`status=canceled`, period_end=now)
  + **refund** the unused prorated portion by default (`refund=False` to suppress),
  claw back the creator credit. A fully-elapsed period yields fraction 0 (no
  refund → repeat immediate-cancel is a no-op).
- **REFUND helper** `_reverse_subscription_charge` (tips.reverse_tip / ADV-502
  pattern): payer REFUND entry (`type=refund`) + creator CLAWBACK entry
  (`type=reversal`) — NEITHER is `type=credit`, so a reversal never inflates
  earnings; the ORIGINAL mirror-credit row is flipped `state=reversed` (drops out
  of `get_available_balance`/`creator_earnings`) and, on a PARTIAL refund, the KEPT
  (used) fraction is re-credited. A `SUBREVERSAL#{sub}#{period_end}` conditional
  marker makes it idempotent; a real Stripe partial `Refund` is issued best-effort
  against the original PaymentIntent.
- **REFUND endpoint** `POST /api/subscriptions/{subscription_id}/refund`
  (`refund_subscription`): general/dispute path (default = remaining prorated
  portion; `fraction=1.0` = full cycle), authorized for the subscriber, creator,
  or (for a gift) the gifter.
- New input models: `SubscriptionCancelIn.refund`, `SubscriptionGiftIn`,
  `SubscriptionRefundIn`.

`app/services/subscription_access.py`
- `has_active_subscription` now grants access for `canceling` (bounded by
  `current_period_end`), fixing the SUB-25 bug where cancel-at-period-end lost
  access immediately.

`app/services/subscription_renewal.py`
- The sweeper `_process` makes a `canceling` sub terminal `canceled` at period end
  (NEVER charged / renewed / dunned), completing the cancel-at-period-end lifecycle.

## Verify (in-process on prod DDB — `verify_sube2_p2.py`) — 29/29 ALL_PASS
- **G** GIFT: gifter charged once (real PI `pi_R15QHxZAUA9f8ph`); recipient sub
  auto_renew False, ZERO PM/PAY under recipient; creator credited NET 1800;
  recipient has access; LAPSES at period end via sweep (expired, no charge/credit).
- **C** cancel-at-period-end: `canceling` keeps access, NO refund; sweep at
  period end → `canceled`, access ends.
- **I** IMMEDIATE cancel (mid-cycle, price 2000): access revoked now; subscriber
  refunded 1000 (`type=refund`); creator clawback 900 (`type=reversal`); original
  credit `state=reversed`; retained credit 900; live credit sum dropped exactly
  900 (earnings not inflated); repeat immediate-cancel = no double refund.
- **R** general /refund: 50% → refund 1000 / clawback 900; same-key replay
  idempotent (no double refund).
- Regression: PART 1 verify re-run on prod = **30/30 ALL_PASS** (no E0/E1/E2-P1 regress).

## Ops
- Prod `.bak` (all 3 files): `.bak_sube2p2_1783743752`.
- dev↔prod byte-IDENTICAL sha256: `039aed08…` (subscription_server.py) /
  `75ff24d8…` (subscription_access.py) / `7a1cbd82…` (subscription_renewal.py).
- Restart via `restart_backend.sh`; openapi=200; `/api/plans/{id}/gift` +
  `/api/subscriptions/{id}/refund` + run-renewals routes registered.
- Apply is idempotent (SKIP when markers present); anchors fail loudly on drift.

## Residual (pre-existing, NOT E2)
`emit_subscription_cycle_order_and_reconcile` logs
`subscription_cycle_reconciliation_invariant_failed reason=missing_order →
dead_lettered`. Money path is correct; only the downstream recurring-grant
reconciler dead-letters.

# TestLogon Payment-Disputes Subsystem — Unified Design & Implementation Plan (DISP-*)

Status: PLAN (for review). Grounded in a 3-pass read (reuse-map, user-track, processor-track) of
`android-impl @ c7e5efa7` on dev host `192.168.0.249` (`~/dev/testlogon`), over the shared
`T.billing` ledger and all six shipped money subsystems (tips, subscriptions, ad-billing,
ecommerce, VOD pay-to-unlock, pay-to-message).

> **Prod-divergence rule.** Every citation is the **dev reference clone**. Some money code is
> prod-divergent (`app/main.py`, `messaging.py`, `sessions.py`, `broadcast_*`, and the
> order-lifecycle / seller-fulfilment tail — see `ecommerce-rough-edges-plan.md`). The dispute
> stacks (`billing_disputes.*`, `payment_incident_*`, `payment_reconciliation.py`) and the six
> reversal rails' DDB tables + the `get_available_balance` credit-filter lines must be
> **re-confirmed against prod via SSM** before landing code. Every backend change lands as an
> `android-impl` commit AND (for anything already live) a re-apply artifact in `ops/prod-hotfixes/`.
> Two-device on-device verification per user-facing ticket (Galaxy A15 / Pixel 7a; admin acct
> `crash1782189692@` role=admin per `android-test-fleet-admin.md`).

---

## 1. HEADLINE

**This is NOT greenfield. Two disjoint, half-built dispute stacks already ship, and the single
central defect is that NEITHER drives any reversal rail — they move dispute *state* and never
reconcile the shared `T.billing` ledger.** The real program is *not* "build a dispute state
machine"; it is **"wire the two existing state machines to the six existing reversal rails +
the shared ledger, merge/deconflict the overlapping stacks, fill the two true code gaps (VOD
revocation + chargeback-fee accounting), and add the missing hold/response-window semantics."**

The two existing stacks:

1. **`billing_disputes` (user-level stub).** `app/services/billing_disputes.py` +
   `app/routers/billing_disputes.py` (`/ui/billing/disputes`, `/ui/admin/disputes/{id}/respond|resolve`),
   gated `S.billing_disputes_enabled` (default ON), table `T.billing_disputes`. `resolve_dispute()`
   (`billing_disputes.py:244-303`, confirmed) only writes `status=resolved` + an alert + an audit
   event — **it never touches `T.billing`**, never claws back, never revokes entitlement.
   `_VALID_RESOLUTIONS=("won","lost","accepted")` but no resolution moves money.

2. **`PaymentIncident` (processor-level).** A full adapter/domain/transition/store/reconciliation
   stack (`payment_incidents_domain.py`, `payment_incident_transitions.py`, `payment_incidents_store.py`,
   `payment_incident_{stripe,paypal,ccbill}_adapter.py`, `payment_reconciliation.py`), mounted in
   `app/routers/billing.py:78-95,320-338,452,483`. It ingests `charge.dispute.created/updated/closed`
   (`stripe_adapter.py:46`), verifies signatures, runs a guarded `DisputeStatus` state machine
   (`payment_incidents_domain.py:51-65,155`), submits evidence to Stripe
   (`stripe.Dispute.modify(evidence=)`, `stripe_adapter.py:139`), and idempotency-claims provider
   events (`transitions.py:198`). **But grep of `T.billing|apply_balance_delta|reverse_tip|
   new_ledger_entry` across all `payment_incident_*` + `payment_reconciliation.py` returns NOTHING** —
   on LOST it does not debit, does not claw back creator credit, does not book the chargeback fee, and
   `_map_dispute_status` (`stripe_adapter.py:165-176`, confirmed) never maps
   `charge.dispute.funds_withdrawn` / `funds_reinstated` (the hold/un-hold triggers).

### 1.1 The unified dispute record + state machine

One dispute record spanning both origins, co-located with the existing `T.billing_disputes` table,
with a `source` in `{user, processor}` discriminator and a shared **charge-resolver -> reversal-rail
dispatcher** at the center. Both origins share: the underlying charge reference, the ledger
credit-flip mutex (idempotency marker), the reversal-rail dispatch, and the admin surface. They
differ only in lifecycle (user = moderation-style response-window; processor = Stripe-driven
`due_by` window) and money direction (user refund vs. chargeback clawback).

```
 DISPUTE RECORD  (T.billing_disputes, pk=DISPUTE#{id}, sk=META)
   source: user | processor
   charge_ref / charge_type (tip|message|subscription|ad|ecom|vod)
   reason / reason_detail / evidence
   status  (per-source machine, below)
   linked_dispute_id  (cross-link user<->processor on same charge)
   resolution  (refunded|partial|denied  |  won|lost|accepted)
   rail_marker  (TIPREVERSAL#|SUBREVERSAL#|REVERSAL#|VODREVERSAL#|CHARGEBACK#|CHARGEBACK_HOLD#)

 USER machine (reuses moderation hold/response-window/SLA):
   open -> needs_response -> under_review -> resolved:{refunded|partial|denied}
     |         |(creator responds / SLA sweep)        ^
     |         +---- SLA lapse (no response) ----------+
     +-> under_review (auto-skip: unauthorized / low-value)
     +-> withdrawn
   resolved -> escalated  (appeal, reuses appeals.py)

 PROCESSOR machine (reuses payment_incidents DisputeStatus, domain.py:51-65):
   opened -> evidence_required -> response_submitted -> under_review -> {won|lost|accepted}
     (opened driven by charge.dispute.created OR funds_withdrawn, idempotent -> HOLD credit)
     (closed -> won: release hold | lost/accepted: clawback + fee + record_chargeback)
```

Both machines drive the **same dispatcher** on the terminal money-moving transition:
`charge_type -> reversal fn`, guarded by the credit-flip mutex so a user-refund and a
processor-chargeback on the same charge can never double-debit.

### 1.2 REUSED vs NEW

**REUSED (do not reinvent):**
- Guarded, act-after-guard transition primitive: `moderation_case.transition_result`
  (`moderation_case.py:346-375`) — the idempotency backbone (double-resolve / webhook-race safe).
- Response-window + SLA sweep: `moderation_lifecycle.admin_confirm_hold|poster_respond|
  sweep_expired_holds` + `AWAITING_FINAL_SLA_SECONDS` (`moderation_lifecycle.py:10-41`).
- Admin board shape + scope gate + dual-approval: `admin_moderation.py:36,69-139,145-171,233`.
- Appeals: `appeals.py` / `admin_appeals.py`.
- Six reversal rails: `reverse_tip_by_payment_id` (`tips.py:720`), `_reverse_subscription_charge`
  (`subscription_server.py:912`), `reverse_ad_charge` (`ad_billing.py:1043`),
  `refund_requests.approve_request` multi-party (`refund_requests.py:234,290-405`);
  pay-to-message rides the tip rail (`content_type="message"`, `tips.py:58`).
- Ledger honesty: `get_available_balance` credit filter
  (`creator_payouts.py:110`, filter `type==credit & state!=reversed & amount_cents>0` at `:130-137`,
  confirmed) — earnings ARE the `type=="credit"` sum, no separate `creator_earnings` fn.
- Idempotency marker pattern: `TIPREVERSAL#`/`SUBREVERSAL#`/`REVERSAL#`/incident replay
  (`transitions.py:198`).
- Authenticated webhook seam: `billing.py` ingest (verify/replay/rollout/shadow/metrics,
  `:320,452,483`) — more hardened than the payouts (`admin_payouts.py:234`) / subs
  (`subscription_server.py:3283`) seams it mirrors.
- Processor adapters: `parse_webhook_events` / `fetch_dispute_details` / `submit_dispute_response`
  (`stripe_adapter.py:46,130,139`).
- Fraud recorder (prebuilt): `fraud_detection.record_chargeback` (`fraud_detection.py:512`) —
  increments `chargeback_count`, recomputes risk (`:221-223`), auto-flags at threshold (`:534-540`);
  `chargeback_check` (`:182`), `freeze_user` (`:435`).
- `refund_requests.py` validators: post-ship window (`:93-108`), monthly cap (`:142-154`), dedup GSI
  `ByTransactionId` (`:129-137`).

**NEW (must build):**
- **N1 — `reverse_vod_purchase(payment_id, buyer_id, clawback_only=False)`** — the one true code
  gap: no reverse fn exists and no rail deletes the `T.vod_entitlements` row (`vod_purchase.py:500`,
  confirmed). Must claw back seller credit + write buyer refund (unless `clawback_only`) + flip
  original credit `state=reversed` + **`T.vod_entitlements.delete_item`** (revoke access) + claim
  `VODREVERSAL#{purchase_id}` marker. Without the delete the buyer keeps money AND access.
- **N2 — charge-type dispatcher** — `charge_type -> reversal fn`, resolving subs/ads which do NOT
  reverse off a `LEDGER#` id (they use `sub_id:period_end` / ad account+entry).
- **N3 — clawback-only forks** of the four rails for the chargeback path (keep creator-clawback leg;
  drop buyer-refund leg + drop `stripe.Refund.create`): `reverse_tip_clawback_only`,
  `_reverse_subscription_charge(clawback_only=True)`, `reverse_ad_charge(clawback_only=True)`,
  `approve_request(chargeback=True)`.
- **N4 — reversible `state="held"`** hold semantics + add `state!="held"` to the balance filter
  (`creator_payouts.py:130-137`); hold on OPEN, restore on WON, convert to `reversed` on LOST.
- **N5 — `chargeback_fee` ledger type** — non-credit LEDGER row (auto-excluded from earnings by the
  existing filter; no new counter). Atomic with the clawback, idempotent `CHARGEBACK_FEE#{incident}`.
- **N6 — map `funds_withdrawn`/`funds_reinstated`** in `parse_webhook_events` + `_map_dispute_status`
  (+ PayPal/CCBill mirrors).
- **N7 — evidence assembler** `build_dispute_evidence(incident)` from charge `meta`.
- **N8 — creator response window on the user track** (open->needs_response, respond_by, SLA sweep)
  + admin dispute-queue scope (`AdminScope.PAYMENT_DISPUTES`) + endpoints + app surfaces.
- **N9 — cross-track link/dedupe** (user<->processor on same charge).

### 1.3 Real-now vs real-when-keyed

- **Real NOW (internal, no external key):** all ledger reconciliation math, credit-flip/hold,
  clawback rails, `chargeback_fee` row, `record_chargeback`, dispute lifecycle/state, admin
  adjudication, notifications, dedupe. Fully testable in mock.
- **Real WHEN KEYED (Stripe/PayPal SDK + `stripe_webhook_secret` present, `settings.py:381`):**
  webhook signature verify, `stripe.Dispute.retrieve/modify(evidence=)`, real fee amount from
  `dispute.balance_transactions`, and the best-effort refund legs (`stripe.Refund.create`,
  `subscription_server.py:1076`). Without a key these return
  `ok=False, code="stripe_not_configured"` and are recorded-not-sent — the same real-when-keyed
  posture as the payout runner and the ad-deposit charge seam. Rollout gated by
  `_payment_incident_rollout_mode` disabled|shadow|live (`billing.py:320-338`).

---

## 2. EPIC + TICKET PLAN (dependency-ordered)

Money-correctness / reconciliation lands FIRST; surfaces last. Each ticket notes
backend/app/web and real-now vs seam.

### E0 — FOUNDATION: unified dispute record + dispatcher + rail plumbing (backend; real-now)

- **DISP-001 — Unified dispute record + `source` discriminator** (backend).
  Extend `T.billing_disputes` META schema with `source`, `charge_type`, `charge_ref`,
  `linked_dispute_id`, `rail_marker`, `resolution`. Add GSIs reused from `refund_requests`
  (`ByTransactionId` dedup, `ByStatus`). AC: a dispute row can represent either origin; existing
  stub rows migrate (default `source=user`); no behavior change yet.
- **DISP-002 — Charge resolver** (backend). `resolve_charge(charge_ref, charge_type) -> {ledger_rows,
  meta, content_type, sub_id?, period_end?, ad_account?, purchase_id?, refund_request_id?}`.
  Reads `meta.content_type` and normalizes across the six subsystems. AC: given any of the six
  charge refs, returns the correct dispatch key + params; unit-tested per type.
- **DISP-003 — Reversal-rail dispatcher** (backend). `_RAIL` map `charge_type -> reversal fn`
  (tip/message->`reverse_tip_by_payment_id`, subscription->`_reverse_subscription_charge`,
  ecom->`approve_request`, ad->`reverse_ad_charge`, vod->`reverse_vod_purchase`). Supports
  `override_amount_cents` for partial (ecom/sub native; reject partial for tip/ad in v1).
  AC: dispatcher moves money via the correct rail; honesty invariant preserved (every leg writes
  non-`credit` type + flips original credit `state=reversed`); idempotent via rail markers.
- **DISP-004 — `reverse_vod_purchase`** (backend; NEW N1). Clawback seller credit + buyer
  `refund_credit`/seller `refund_debit` (mirror `refund_requests.py:290-405`) + flip original credit
  `state=reversed` + **`T.vod_entitlements.delete_item`** + `VODREVERSAL#{purchase_id}` marker.
  `clawback_only` flag suppresses buyer refund (for chargebacks). AC: after reversal the entitlement
  row is gone (playback 403) AND the credit no longer counts in `get_available_balance`; redelivery
  no-ops on the marker.
- **DISP-005 — Guarded dispute transition wrapper** (backend). Wrap every dispute status change in a
  `transition_result`-style conditional write (`moderation_case.py:346`); the rail fires ONLY when
  `changed=True`. AC: concurrent double-resolve / withdraw-vs-resolve produce exactly one money move;
  loser is a no-op returning the stored receipt.

### E1 — USER-LEVEL DISPUTE FLOW (backend; real-now, refund legs seam)

- **DISP-010 — Reasons + per-charge-type gating** (backend). Reason enum
  `not_received|not_as_described|unauthorized|duplicate|quality` gated per charge type (tips: no
  not_received; ad: only unauthorized/duplicate; etc.) + `reason_detail` + evidence attach. AC:
  open-dispute rejects a reason invalid for the charge type.
- **DISP-011 — User dispute state machine** (backend; NEW N8). States
  open/needs_response/under_review/resolved/withdrawn/escalated with forward-only `_ALLOWED` table
  (mirrors `moderation_case.py:36-45`). AC: illegal skips rejected; withdraw vs resolve mutually
  exclusive via DISP-005.
- **DISP-012 — Creator response window + SLA sweep** (backend; NEW N8). `open->needs_response`
  sets `respond_by=now+RESPONSE_WINDOW` (7d) + notifies creator (mirrors
  `moderation_lifecycle.admin_confirm_hold:10`); `sweep_expired_dispute_responses` mirrors
  `sweep_expired_holds:14` -> auto-advance to `under_review` (NOT auto-loss; admin decides).
  Auto-skip policy: `unauthorized` OR `amount<S.dispute_auto_refund_threshold_cents` skips the
  window. AC: no-response by respond_by lands in admin queue; late response after sweep attaches as a
  comment (illegal transition rejected).
- **DISP-013 — Wire `resolve_dispute` to the dispatcher** (backend). Replace the stub body
  (`billing_disputes.py:244-303`) so a winning `resolved` transition calls DISP-003 with
  `{refunded->full, partial->override_amount, denied->state-only}`. AC: resolving a tip/sub/ad/ecom/
  vod dispute actually moves money on the correct rail and revokes VOD access; `get_available_balance`
  reflects the clawback; denied/withdrawn move zero ledger.
- **DISP-014 — Pre-open guards** (backend). Dedup on `charge_ref` (reuse `ByTransactionId` concept,
  409 on second non-terminal dispute); dispute-after-refund reject if the charge's ledger row is
  already `state=reversed` (marker exists). AC: double-dip and refund-then-dispute both blocked.

### E2 — APP + WEB SURFACES (app + web; real-now)

- **DISP-020 — User dispute endpoints** (backend/web). `POST/GET /ui/billing/disputes`,
  `GET /ui/billing/disputes/{id}`, `POST .../withdraw`. AC: payer can open from a receipt, list, track,
  withdraw.
- **DISP-021 — Creator respond endpoints** (backend/web). `POST /ui/creator/disputes/{id}/respond`
  (maps to `poster_respond`), `GET /ui/creator/disputes`. AC: creator rebuts within window; text
  surfaced to admin.
- **DISP-022 — Admin dispute queue** (backend/web). `AdminScope.PAYMENT_DISPUTES` +
  `require_admin_scope`; `GET /ui/admin/disputes` cursor queue (filter status/type/amount, reuse
  `admin_moderation.py:145-171`); decision panel with **rail preview + clawback amount**; high-value
  refund reuses dual-approval/senior gate (`admin_moderation.py:69-139`); `POST .../resolve` wired to
  DISP-013. AC: admin sees charge + reason + creator rebuttal + rail preview; second admin required
  above threshold.
- **DISP-023 — App: My Disputes (payer)** (app). Open-from-receipt CTA on transaction-history rows;
  dispute list w/ status chips; detail timeline. AC: two-device verified.
- **DISP-024 — App: Respond to Dispute (creator)** (app). Inbound queue, rebuttal composer +
  evidence, countdown to respond_by. AC: two-device verified.
- **DISP-025 — App/web: Admin Dispute Queue** (app+web). Reuse the moderation-board component. AC:
  list/filters/decision panel with rail preview.

### E3 — PROCESSOR WEBHOOK + EVIDENCE + LIFECYCLE + LOSS-RECONCILIATION + FEE (backend; reconcile real-now, processor I/O seam)

- **DISP-030 — Map missing dispute events** (backend; NEW N6). Add
  `charge.dispute.funds_withdrawn`/`funds_reinstated` to `parse_webhook_events` set + `_map_dispute_status`
  (`stripe_adapter.py:46,165`); mirror in PayPal/CCBill. `funds_withdrawn->opened(funds_moved)`,
  `funds_reinstated->funds_restored`. AC: both events parse to canonical events; existing
  created/updated/closed unchanged.
- **DISP-031 — Hold on OPEN** (backend; NEW N4). On entering `opened`, resolve charge (DISP-002),
  flip original credit to reversible `state="held"` + add `state!="held"` to
  `creator_payouts.py:130-137` filter + stamp `disputed` header flag + `CHARGEBACK_HOLD#{incident}`
  marker. AC: contested funds drop out of `get_available_balance` immediately; idempotent across
  created/funds_withdrawn redelivery.
- **DISP-032 — Evidence assembler + response window** (backend; NEW N7, processor I/O seam).
  `build_dispute_evidence(incident)` from charge `meta` (receipt/customer/service_date/
  product_description/uncategorized_text=creator rebuttal); reuse the moderation-style response window
  but SLA = Stripe `evidence_details.due_by` -> `response_due_at` GSI (`store.py:145`); sweeper
  auto-submits before deadline. `submit_dispute_response` (`stripe_adapter.py:139`) is real-when-keyed.
  AC: evidence persisted per version (`store.put_dispute_evidence:44`); when keyed, submitted to
  Stripe; deadline never missed.
- **DISP-033 — Clawback-only rail forks** (backend; NEW N3). Fork the four rails to keep the
  creator-clawback leg, drop the buyer-refund leg + drop `stripe.Refund.create`; VOD via
  `reverse_vod_purchase(clawback_only=True)`. AC: on a chargeback no buyer credit and no Stripe refund
  is issued; only creator credit is clawed + flipped.
- **DISP-034 — `chargeback_fee` ledger type** (backend; NEW N5). Non-credit LEDGER row on
  LOST/ACCEPTED, atomic with the clawback (same TransactWrite), idempotent `CHARGEBACK_FEE#{incident}`;
  fee amount = Stripe `balance_transactions` (keyed) or configured flat default (mock); policy flag
  creator-eats vs platform-eats. AC: fee excluded from earnings by the existing credit filter (no new
  counter); atomic with clawback.
- **DISP-035 — LOST/WON/ACCEPTED reconciler** (backend). Hook into the LOST/WON/ACCEPTED transition
  (consume `payment_incident.*` emit at `transitions.py:180`, or inline in winner branch). LOST/ACCEPTED
  -> convert `held->reversed` + write the reversal accounting entry + fee (DISP-033/034). WON ->
  flip `held->credit` (inverse of DISP-031) + clear `disputed` flag + `CHARGEBACK_RELEASE#{incident}`.
  AC: LOST claws creator net without buyer refund/Stripe refund; WON restores exact credit; both
  idempotent.

### E4 — FRAUD / ABUSE + CROSS-TRACK LINK (backend; real-now)

- **DISP-040 — Wire `record_chargeback`** (backend; one-line). On LOST/ACCEPTED call
  `fraud_detection.record_chargeback(user_id=payer, amount_cents, tx_id=incident_id)`
  (`fraud_detection.py:512`); optional `freeze_user` on auto-flag for egregious repeat disputers.
  AC: chargeback increments the risk row + auto-flags at threshold (existing infra).
- **DISP-041 — Serial-disputer guards (user track)** (backend). Per-payer monthly dispute cap
  (reuse `S.max_refund_requests_per_month`, `refund_requests.py:142-154`); serial-disputer flag +
  win-rate on the admin queue; auto-route repeat offenders to admin (skip auto-refund threshold);
  optional strike via `user_enforcement_history`. AC: over-cap disputes rejected; repeat offenders
  never auto-refunded.
- **DISP-042 — Cross-track link/dedupe** (backend; NEW N9). Shared credit-flip mutex is the mutex
  (whoever flips original credit `state` first wins; loser no-ops). `charge.dispute.created` while a
  user dispute is open on the same charge -> auto-moot the user dispute ("processor chargeback opened")
  + link `linked_dispute_id` both ways. User-refund already executed then chargeback arrives ->
  clawback no-ops on the `reversed` marker + evidence assembler submits the refund receipt to win the
  chargeback (avoid paying twice). AC: no charge is ever double-debited across tracks; admin board
  shows both under one charge.

### E5 — NOTIFICATIONS + RECONCILIATION + HARDENING (backend/app; real-now)

- **DISP-050 — Notifications** (backend/app). Reuse the alert+push rail (`refund_requests.py:426-439`,
  tappable push) + `moderation_lifecycle._notify` (`:67-103`): payer on open-ack/creator-responded/
  resolved; creator on opened/respond-invite/SLA-warning/resolved; both on every terminal. AC:
  every state change notifies the right parties; pushes tappable.
- **DISP-051 — Reconciliation report + audit** (backend). Per-dispute audit trail; a reconciliation
  view proving each terminal dispute wrote the expected non-credit entries + flipped the original
  credit; `get_available_balance` spot-check. AC: no dispute leaves a `credit` inflating a balance;
  audit event per transition.
- **DISP-052 — Deconflict the two Stripe webhook seams** (backend). Decide `charge.dispute.*` is owned
  by the `billing.py` PaymentIncident endpoint (NOT `subscription_server.billing_webhook`); document
  secret split (`STRIPE_WEBHOOK_SECRET` vs `SUBSCRIPTION_WEBHOOK_SECRET`) or unify. AC: dispute events
  land on exactly one endpoint; subs webhook ignores `charge.dispute.*`.
- **DISP-053 — Rollout/shadow hardening + go-live checklist** (backend). Verify shadow mode
  parse+validate+audit with no state change (`billing.py:340`); replay-cache + idempotency markers
  end-to-end; prod re-confirm of all anchors via SSM; `ops/prod-hotfixes/` folds for any live file.
  AC: shadow run on prod-sampled events produces zero ledger writes; live mode gated by rollout flag.
- **DISP-054 — Scope decisions (product-owner sign-off)** (doc). (i) pay-to-message access revoke on
  refund; (ii) partial-tip disallowed in v1; (iii) chargeback-fee creator-eats vs platform-eats;
  (iv) auto-refund threshold + response-window length; (v) whether a chargeback also cancels sub
  access. AC: decisions recorded before the dependent tickets land.

---

## 3. RECOMMENDED BUILD SEQUENCE + GO-LIVE FLAGS

**Money-correctness / reconciliation FIRST, surfaces LAST.** Both tracks converge on the same
dispatcher, so E0 unblocks everything.

1. **E0 (DISP-001..005)** — unified record, resolver, dispatcher, `reverse_vod_purchase` (unblocks
   the one true code gap), guarded transition. Nothing moves money for real users yet, but every rail
   is now callable + idempotent. *Real-now.*
2. **E1 (DISP-010..014)** — user dispute flow end-to-end wired to the dispatcher; this is the first
   time a resolution actually moves money. Refund legs real-when-keyed. *Real-now (mock refunds).*
3. **E3 (DISP-030..035)** — processor track: map the missing events, hold on open, clawback-only
   forks, `chargeback_fee`, LOST/WON reconciler. Ledger reconciliation is real-now; processor I/O
   (verify/evidence/fee-amount) is seam. Build behind **shadow mode** first.
4. **E4 (DISP-040..042)** — fraud wire + serial-disputer + the cross-track link/dedupe mutex (must
   land before both tracks are live to prevent double-debit).
5. **E2 (DISP-020..025)** — app/web surfaces once the backend is correct and reconciling.
6. **E5 (DISP-050..054)** — notifications, reconciliation audit, seam deconfliction, rollout
   hardening + product decisions.

**Go-live flags for the real processor rail:**
- `S.billing_disputes_enabled` — user-track master (default ON).
- `payment_incidents_rollout_enabled` + `payment_incidents_rollout_providers` (`settings.py:394`) —
  processor-track disabled|shadow|**live** per provider (`billing.py:320-338`). Ship in **shadow**
  (parse+validate+audit, zero state change) -> promote to **live** per provider after a clean shadow
  window.
- `stripe_webhook_secret` (`settings.py:381`) present + `stripe` SDK installed -> verify +
  `stripe.Dispute.retrieve/modify(evidence=)` + real fee amount go live; absent -> recorded-not-sent.
- `S.dispute_auto_refund_threshold_cents` — user auto-refund vs response-window threshold.
- Chargeback-fee policy flag (creator-eats vs platform-eats) — DISP-054.
- `RESPONSE_WINDOW` (7d) + `response_due_at` (processor `due_by`) — the two response windows.

**Ledger-reconciliation is fully testable in mock now**; only processor I/O (signature verify,
evidence-to-Stripe, real fee lookup) goes live when keyed — identical posture to the payout runner
and the ad-deposit charge seam.

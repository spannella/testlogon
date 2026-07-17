# DISP E4 — fraud/abuse wire + serial-disputer guards + cross-track link/dedupe

Money-correctness abuse layer that MUST land before either dispute track goes
live. Adds NOTHING that moves money on its own — it wires the fraud engine, adds
serial-disputer rate-limits, and makes the two dispute tracks converge on ONE
record so the same charge can never be double-debited.

## Tickets

- **DISP-040 — fraud wire.** `dispute_fraud.record_dispute_fraud_signal` feeds the
  existing fraud engine (`fraud_detection.record_chargeback` → risk row +
  auto-flag at `chargeback_threshold`) on a LOST/ACCEPTED processor chargeback
  (`kind="chargeback"`) AND on a user dispute resolved refunded/partial
  (`kind="user_refund"` — same "money came back off this charge" abuse signal).
  Idempotent per `signal_ref` via a `DISPUTE_FRAUDSIG#{kind}#{ref}` marker so a
  webhook redelivery never double-counts. Auto-freezes an egregious repeat
  disputer at `S.dispute_fraud_autofreeze_chargebacks` (`fraud_detection.freeze_user`).
  Wired in `dispute_chargeback._reconcile_lost` (processor) and
  `billing_disputes.resolve_dispute` (user).

- **DISP-041 — serial-disputer guards (user track).** `dispute_fraud.guard_new_dispute`
  is called at open time from `billing_disputes.file_dispute`:
  - per-payer rolling-30d cap (`S.dispute_max_disputes_per_month`, default 5) →
    over-cap open rejected **HTTP 429** `dispute_rate_limited`.
  - a payer with ≥ `S.dispute_serial_disputer_threshold` (default 3) disputes in
    30d is classified `serial_disputer`; the record is stamped `serial_disputer:true`
    and the auto-refund fast-path is **suppressed** — `open_response_window(...,
    force_manual_review=True)` forces `needs_response` (a human reviews) even for
    an `unauthorized`/under-threshold claim that would otherwise auto-skip.
  - `dispute_stats(user_id)` exposes 30d totals + win-rate for the admin queue.

- **DISP-042 (LOAD-BEARING) — cross-track link/dedupe.**
  `dispute_fraud.link_and_moot_on_processor_open` is called the instant a
  processor `charge.dispute.created` lands (from
  `dispute_chargeback.on_incident_transition` on `opened`, right after the hold):
  if a USER dispute is open on the SAME charge it is **auto-mooted** (guarded
  transition → `withdrawn`, `mooted_by_chargeback=true`, `mooted_incident_id`),
  the user record is cross-linked (`linked_dispute_id=incident:{id}`), and a
  `DISPUTE_LINK#{ct}#{ref}` marker is written on the payer partition listing the
  linked user disputes. The mooted user dispute can no longer resolve
  independently (terminal → 409), so only the processor track drives the rail.
  The **credit-flip mutex (E0)** remains the actual no-double-debit enforcement:
  whoever flips the original credit `state` first wins; the loser rail no-ops.
  Symmetric ordering (user refund first) already no-ops the later processor LOST
  clawback on the claimed mutex.

## Flags (settings.py)

- `dispute_max_disputes_per_month` (5) — per-payer rolling-30d cap.
- `dispute_serial_disputer_threshold` (3) — serial-disputer classification.
- `dispute_fraud_autofreeze_chargebacks` (5, 0=off) — auto-freeze threshold.
- `dispute_fraud_signal_enabled` (on) — master flag for the DISP-040 wire.

## Files

- NEW `app/services/dispute_fraud.py` (DISP-040/041/042).
- `app/services/dispute_chargeback.py` — DISP-040 fraud signal in `_reconcile_lost`;
  DISP-042 `link_and_moot_on_processor_open` call in `on_incident_transition`.
- `app/services/billing_disputes.py` — DISP-041 `guard_new_dispute` + `serial_disputer`
  stamp + `force_manual_review` pass-through in `file_dispute`; DISP-040 fraud
  signal in `resolve_dispute`.
- `app/services/dispute_lifecycle.py` — `open_response_window(force_manual_review=...)`.
- `app/core/settings.py` — the four E4 flags (see `settings.py.e4.patch`).

## Verify (LIVE HTTP, prod-mock)

`ops/prod-hotfixes/disp/e4/verify_e4.py` — real HTTP to `/ui/billing/disputes`,
`/ui/admin/disputes/{id}/resolve`, and signed Stripe webhooks to
`/api/billing/webhooks/stripe`. Proves no-double-debit BOTH orderings, auto-moot
+ link, serial-disputer flag/suppress/429, fraud increment + idempotency. 0
residue.

```
set -a; . .env.local; set +a; PYTHONPATH=$PWD .venv/bin/python ops/prod-hotfixes/disp/e4/verify_e4.py
```

Result: **E4 31/31 PASS**; regression E3 25/25, E1 20/20; payment-incident pytest 17/17.

# Entitlement and Billing Reconciliation Jobs (CCE-050)

`app/services/entitlement_billing_reconciliation.py` adds deterministic reconciliation and repair workflows for commercialization entitlement usage.

## Job surfaces

- `reconcile_usage_events_with_service_logs(...)`
  - Reconciles service/request logs with `entitlement_usage_events` ledger rows.
  - Emits actionable drift rows with ownership metadata (`owner_team`, `owner_contact`) and suggested action.
- `build_billing_drift_report(...)`
  - Reconciles consumed entitlement units against billed units.
  - Produces per-entitlement/meter variance rows for billing adjustment workflows.
- `replay_missing_usage_events(...)`
  - Repair tool for replaying missing ledger events from source service logs.
  - Supports dry-run and apply mode.
- `recompute_entitlement_usage(...)`
  - Recomputes `entitlements.usage_consumed` from usage-event source-of-truth.
  - Supports dry-run and apply mode.
- `run_entitlement_billing_reconciliation_job(...)`
  - Composite job entry point returning all reconciliation/repair sections in one report.

## Actionable diff contract

Each drift row contains:

- `entitlement_id`
- `meter`
- expected/actual (or consumed/billed) units
- signed variance/delta
- severity
- recommended action
- owner metadata (`owner_team`, `owner_contact`, `entitlement_ref`)

## Replay/repair workflow

1. Run composite job in dry-run mode (`apply_repairs=False`).
2. Review `usage_vs_logs.diffs` and `billing_drift.diffs` with owning teams.
3. Run `replay_missing_usage_events(..., apply=True)` after approval.
4. Run `recompute_entitlement_usage(..., apply=True)` to align usage counters.
5. Re-run dry-run reconciliation and confirm drift is reduced/zero.

## Staging validation checklist

- Seed entitlements and source service logs with at least one intentional missing usage event.
- Execute dry-run job and confirm actionable drift row ownership metadata is present.
- Execute apply mode and verify replayed event count increments and entitlement usage counters are repaired.
- Re-run dry-run and verify deterministic final state (no new replay for same source idempotency key).
- Attach output reports to rollout evidence for billing/API/Messaging/File Manager owners.


## Cross-system reconciliation invariants (CCE-069)

`run_cross_system_reconciliation_invariants(...)` adds invariant checks for commercialization cutover:

- billed units == canonical order items (`reconcile_billed_units_with_order_items`)
- canonical order items == entitlement grants/updates (`reconcile_order_items_with_entitlement_grants`)
- subscription renewal events == recurring order stream (`reconcile_subscription_renewal_events_with_recurring_orders`)

Output includes `actionable_alerts` with ownership metadata (`owner_team`, `owner_contact`) and remediation hints (`recommended_action`) so API/Billing/Support owners can triage drift quickly.

### Replay/repair game-day flow

1. Run cross-system invariants in dry-run and export alert rows.
2. For billed/order drift, run order/billing correction tooling and rerun invariants.
3. For order/entitlement drift, replay entitlement grants from canonical orders.
4. For renewal/recurring drift, emit missing recurring orders or backfill missing renewal events.
5. Re-run invariants and capture before/after evidence for staging sign-off.

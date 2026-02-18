# API Usage Shadow Billing & Production Cutover Checklist (AMB-062)

## Objective
De-risk API usage billing launch by running a full shadow-billing cycle, validating variance against expected samples, and enforcing explicit go-live/rollback signoff criteria.

## Shadow cycle procedure

1. **Freeze comparison target**
   - Finalize snapshot for target period/version (`API_USAGE#SNAPSHOT#<period>#V####`).
2. **Run shadow validation**
   - Execute `POST /v1/admin/api-usage/billing/shadow-validation` with:
     - `expected_total_micros` from manual/finance baseline,
     - `sample_expected_by_route` for sampled route checks,
     - `variance_threshold_micros` agreed by finance + product,
     - `cycle_id` identifying the full cycle run.
3. **Verify threshold result**
   - `within_threshold=true` is required.
   - Review both:
     - `variance_vs_expected_micros`
     - `variance_vs_snapshot_micros`
4. **Store artifacts**
   - Persisted report row: `API_USAGE#SHADOW_BILLING#<period>#V#####<cycle_id>`.

## Cutover criteria
Cutover is allowed only when all are true:
- At least one full-cycle shadow report exists for the period.
- Shadow report `within_threshold=true`.
- Product, Finance, and Engineering approvals are all recorded.
- Rollback criteria are explicitly documented.

Record signoff via:
- `POST /v1/admin/api-usage/billing/cutover-signoff`
- Required fields include `product_approved_by`, `finance_approved_by`, `engineering_approved_by`, `cutover_criteria`, `rollback_criteria`.

Persisted signoff row:
- `API_USAGE#CUTOVER_SIGNOFF#<period>#V####`

## Rollback criteria template
Use explicit objective conditions, for example:
- Shadow or live billing variance exceeds `<threshold>` for `<duration>`.
- Snapshot finalization failure count > 0 in billing window.
- Reconciliation drift rows remain > 0 for > 1 hour after recompute.

## Signoff checklist
- [ ] Product signoff recorded.
- [ ] Finance signoff recorded.
- [ ] Engineering signoff recorded.
- [ ] Shadow report linked in signoff payload.
- [ ] Cutover criteria captured.
- [ ] Rollback criteria captured.

## Audit trail
- Shadow validation events: `api_usage_shadow_billing_validation_run`
- Cutover signoff events: `api_usage_billing_cutover_signoff_created`

See also:
- `docs/api-usage-metering-runbook.md`
- `docs/api-usage-observability-dashboards-alerts.md`

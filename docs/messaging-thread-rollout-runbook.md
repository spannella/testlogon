# Messaging Thread Promotion Rollout Runbook (THR-020)

This runbook defines staged deployment and rollout controls for threaded message promotion.

## Feature flags and tenant cohorts

Thread promotion is controlled through `MESSAGING_THREAD_PROMOTION_MODE`:

- `enabled` (default): promotion allowed for all tenants.
- `disabled`: promotion blocked globally (kill switch).
- `internal`: promotion only for `MESSAGING_THREAD_PROMOTION_INTERNAL_TENANT_IDS`.
- `selective`: promotion only for `MESSAGING_THREAD_PROMOTION_ENABLED_TENANT_IDS`.

Tenant lists are comma-delimited tenant IDs.

## Deployment order

1. **Deploy application build** containing THR-020 promotion controls.
2. Set `MESSAGING_THREAD_PROMOTION_MODE=disabled` in production initially.
3. Validate non-thread message flows remain stable.
4. Enable `internal` for internal tenants and hold for validation window.
5. Expand to `selective` tenant cohort.
6. Move to `enabled` after gates pass.

## Rollout gates and dashboard checks

Use `docs/dashboards/messaging-thread-ops-dashboard.json` and the
`docs/messaging-thread-observability.md` queries as promotion gates.

Required checks before each cohort expansion:

- `messaging_thread_promotion_events_total{stage="thread_record",outcome=~"failed_.*"}` remains below SLO threshold.
- `messaging_thread_promotion_retries_total` does not show sustained spikes.
- Thread query latency (`messaging_thread_query_latency_seconds`) remains within baseline.
- Reconciliation anomalies (`messaging_thread_reconciliation_anomalies_total`) stay at zero/expected floor.

## Rollback and recovery

If any gate fails:

1. Set `MESSAGING_THREAD_PROMOTION_MODE=disabled` immediately.
2. Pause cohort expansion.
3. Triage failures from promotion and retry counters.
4. Re-run message thread backfill/reconciliation jobs if required.
5. Resume at the previous safe cohort only after a clean hold window.

## Post-deploy validation checklist

- [ ] Kill switch (`disabled`) verified in production.
- [ ] Internal cohort run completed with clean metrics.
- [ ] Selective tenant cohort run completed with clean metrics.
- [ ] Full enablement approved by operations and on-call.

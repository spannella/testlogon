# CCE-052 Production Readiness, Rollout, and Cutover Runbook

This runbook defines staged rollout, SLOs/alerts, rollback, and go/no-go controls for commercialization entitlement enforcement.

## Feature-flag sequencing

Commercialization rollout uses **global + product-family flags**:

- `CATALOG_COMMERCIALIZATION_ENABLED`
- `CATALOG_FILE_BUNDLE_ENABLED`
- `CATALOG_API_PACKAGE_ENABLED`
- `CATALOG_INTERNAL_API_PACKAGE_ENABLED`

### Sequence

1. **Dark launch (staging)**
   - Enable global flag only for non-prod.
   - Keep all family flags disabled.
   - Verify no request-path behavior changes in staging.
2. **File bundle rollout**
   - Enable `CATALOG_FILE_BUNDLE_ENABLED` in staging, then canary prod.
   - Validate preview/download gates and user entitlement visibility.
3. **External API package rollout**
   - Enable `CATALOG_API_PACKAGE_ENABLED` in staging, then canary prod.
   - Validate middleware denies, usage burn-down, threshold alerts.
4. **Internal API package rollout**
   - Enable `CATALOG_INTERNAL_API_PACKAGE_ENABLED` in staging, then canary prod.
   - Validate messaging/file-manager enforcement and meter events.
5. **Scale-out**
   - Increase traffic gradually per family with explicit hold points.

## SLOs and alerting

## Entitlement check SLO targets

- p95 entitlement check latency: **< 100ms** per family.
- entitlement denial error-contract correctness: **99.9%** sampled responses include expected `detail.code` and reason taxonomy.
- availability of entitlement check path: **99.95%** successful check execution (allow/deny) excluding downstream hard outages.

## Metrics

- `entitlement_check_latency_seconds{product_family=...}`
- `entitlement_checks_total{product_family=...,outcome=...,reason=...}`
- existing deny metrics and service-specific usage metrics:
  - `api_usage_limit_deny_total`
  - reconciliation drift gauges/counters.

## Alert policies

- **Latency page:** p95 `entitlement_check_latency_seconds` > 0.1 for 15m.
- **Error budget alert:** unexpected check failures > 0.5% over 15m.
- **Deny anomaly:** sudden deny spikes > 3x baseline for 30m by family.
- **Reconciliation drift:** non-zero drift sustained > 1h.

## Rollback procedure

1. Disable affected family flag (or global flag if multi-family incident).
2. Confirm request paths are bypassing entitlement enforcement.
3. Keep ledger/state intact (no destructive migration required).
4. Triage root cause using audit + entitlement metrics + drift reports.
5. Re-run staging game-day scenario before re-enable.

Disabling flags bypasses enforcement and does **not** delete entitlements/usage/payment data, enabling safe rollback without data loss.

## Incident-response procedure

1. Declare incident and identify impacted family (`file_bundle`, `api_package`, `internal_api_package`).
2. Freeze rollout progression and switch affected family flag off.
3. Capture:
   - top failing routes/actions,
   - deny reason distribution,
   - entitlement check latency/error trends,
   - recent deploys/config changes.
4. If usage drift suspected, run CCE-050 reconciliation dry-run first.
5. Apply repair (replay/recompute/manual adjustment) only with support + engineering approval.
6. Post-incident: update thresholds/runbook and add regression tests.

## Staging game-day validation

Execute and record:

- [ ] Happy path for each family.
- [ ] Flag-off bypass behavior for each family.
- [ ] Intentional entitlement expiry/out-of-scope deny behavior.
- [ ] Alert trigger simulation (latency/deny spike).
- [ ] Reconciliation dry-run + repair dry-run evidence.

## Go / no-go checklist (approval gates)

- [ ] Engineering sign-off (owner + on-call): SLO dashboards/alerts healthy.
- [ ] Product sign-off: entitlement behavior and UX copy validated.
- [ ] Support sign-off: manual adjustment workflows (CCE-051) verified.
- [ ] Billing sign-off: reconciliation reports and rollback path validated.
- [ ] Runbook link distributed to incident channel + on-call handoff.

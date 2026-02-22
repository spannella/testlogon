# Project Tracking Observability Runbook (PL-012)

This runbook defines metrics, dashboards, and alert thresholds for project tracking and reconciliation.

## Metrics used

- `project_count`
- `tracked_file_count`
- `reconcile_failures_total{provider,reason}`
- `provider_latency_seconds{provider,operation}`
- `provider_failure_streak{provider}`
- `provider_failure_alerts_total{provider}`

Label assumptions (low cardinality):
- `provider`: `local|github|gitlab|unknown`
- `operation`: currently `reconcile`
- `reason`: `provider_http_error|provider_error|unknown`

---

## Dashboard panels

### 1) Project count (gauge)

```promql
project_count
```

### 2) Tracked file count (gauge)

```promql
tracked_file_count
```

### 3) Reconcile failure rate by provider

```promql
sum by (provider) (rate(reconcile_failures_total[10m]))
```

### 4) Provider p95 latency for reconciliation

```promql
histogram_quantile(
  0.95,
  sum by (le, provider) (rate(provider_latency_seconds_bucket{operation="reconcile"}[10m]))
)
```

### 5) Provider failure streak (operational panel)

```promql
provider_failure_streak
```

---

## Alert rules

### Alert: reconcile failures elevated (warning)

```promql
sum(rate(reconcile_failures_total[15m])) > 0.2
```

- For: `15m`
- Severity: `warning`

### Alert: provider repeated failures threshold exceeded (critical)

```promql
max by (provider) (provider_failure_streak) >= 5
```

- For: `5m`
- Severity: `critical`
- Runtime threshold config is controlled by env: `PROJECTS_PROVIDER_FAILURE_ALERT_THRESHOLD`.

### Alert: provider latency degradation (warning)

```promql
histogram_quantile(
  0.95,
  sum by (le, provider) (rate(provider_latency_seconds_bucket{operation="reconcile"}[10m]))
) > 1.5
```

- For: `10m`
- Severity: `warning`

---

## Notes

- Metrics are exposed through the existing telemetry endpoint `/metrics` when metrics are enabled (`APP_ENV=prod|production`).
- Reconciliation emits `provider_error` project events and increments `reconcile_failures_total` so alerts can correlate metrics with project-level activity.

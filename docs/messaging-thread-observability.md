# Messaging Thread Observability (THR-019)

This runbook defines operational telemetry for threaded messaging promotion, query health, and reconciliation anomalies.

## Metrics

### Promotion outcomes
- `messaging_thread_promotion_events_total{stage,outcome}`
  - `stage=linkage` outcomes:
    - `no_promotion`
    - `reused_parent_thread`
    - `promoted`
  - `stage=thread_record` outcomes:
    - `created`
    - `reused_existing`
    - `reused_after_retry`
    - `failed_non_retryable`
    - `failed_exhausted`

### Promotion retries
- `messaging_thread_promotion_retries_total{reason}`
  - `reason` is bounded to low-cardinality error codes (e.g. `transactioncanceledexception`).

### Thread query latency
- `messaging_thread_query_latency_seconds{endpoint,outcome}`
  - endpoint currently: `list_thread_messages`
  - outcomes: `success`, `not_found`, `forbidden`

### Reconciliation anomalies
- `messaging_thread_reconciliation_anomalies_total{reason}`
  - currently emitted reasons:
    - `missing_ancestor`
    - `missing_root_item`

---

## Dashboard panels

Dashboard JSON: `docs/dashboards/messaging-thread-ops-dashboard.json`

Minimum panels:
1. Promotion outcomes by stage/outcome (5m rate).
2. Promotion retries by reason (5m rate).
3. Thread list query p95 latency (`histogram_quantile`).
4. Thread list query error outcomes (`not_found` + `forbidden`) 5m rate.
5. Reconciliation anomalies by reason (15m rate).

---

## Alert thresholds

> Tune post-rollout; these defaults are intentionally conservative.

### A1 — Promotion failure spike (warning/critical)
- **Expr**:
  - `sum(rate(messaging_thread_promotion_events_total{stage="thread_record",outcome=~"failed_.*"}[10m]))`
- **Warning**: `> 0.2`
- **Critical**: `> 1.0`

### A2 — Promotion retry surge
- **Expr**:
  - `sum(rate(messaging_thread_promotion_retries_total[10m]))`
- **Warning**: `> 1.0`
- **Critical**: `> 5.0`

### A3 — Thread query latency regression
- **Expr**:
  - `histogram_quantile(0.95, sum by (le) (rate(messaging_thread_query_latency_seconds_bucket{endpoint="list_thread_messages",outcome="success"}[10m])))`
- **Warning**: `> 0.25`
- **Critical**: `> 0.75`

### A4 — Reconciliation anomaly detection
- **Expr**:
  - `sum(rate(messaging_thread_reconciliation_anomalies_total[15m]))`
- **Warning**: `> 0`
- **Critical**: `> 0.2`

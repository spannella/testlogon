# API Usage Metering/Billing Observability (AMB-061)

## Objective
Detect ingestion, enforcement, reconciliation, and billing pipeline failures quickly with standard dashboards, paging alerts, and on-call runbook links.

## SLOs

### Ingestion completeness SLO
- **Target**: `>= 99.99%` eligible API calls persist usage events within 5 minutes.
- **Measure**:
  - numerator: `api_usage_ingest_events_total{outcome="success"}`
  - denominator: `success + duplicate + error`
- **Burn policy**:
  - page when 1h success ratio `< 99.9%`
  - ticket when 24h success ratio `< 99.99%`

### Aggregation latency SLO
- **Target**: `99%` of event-to-aggregate lag `< 60s`; `99.9%` `< 300s`.
- **Measure**: `api_usage_ingest_lag_seconds` histogram quantiles.
- **Burn policy**:
  - page when p99 `> 300s` for 15m
  - ticket when p99 `> 60s` for 2h

## Dashboards

### 1) API usage ingest health
Panels:
- ingest outcomes by result (`success/duplicate/error`) from `api_usage_ingest_events_total`.
- ingest lag p50/p95/p99 from `api_usage_ingest_lag_seconds`.
- route/key event query volume from API usage table read/write metrics.

### 2) Enforcement/deny health
Panels:
- deny rate by scope/limit type from `api_usage_limit_deny_total`.
- request 429 ratio for metered endpoints.
- warning header occurrence rates (from access logs if available).

### 3) Billing finalization & reconciliation
Panels:
- snapshot finalize outcomes (`api_usage_snapshot_finalize_total{outcome=*}`).
- reconciliation drift rows by area (`api_usage_reconciliation_drift_rows{area=period|key|route|daily}`).
- invoice generation failures (admin endpoint 5xx/4xx and task/job errors).

## Alerts

### Pager alerts (high urgency)
1. **Ingest failures spike**
   - condition: `rate(api_usage_ingest_events_total{outcome="error"}[5m]) > 0`
   - for: 10m
2. **Ingest lag spike**
   - condition: p99 ingest lag `> 300s`
   - for: 15m
3. **Snapshot finalize failures**
   - condition: `increase(api_usage_snapshot_finalize_total{outcome="error"}[15m]) > 0`

### Ticket/non-paging alerts
1. **Reconciliation drift present**
   - condition: any `api_usage_reconciliation_drift_rows > 0` for 1h
2. **Deny rate anomaly**
   - condition: deny rate > configured threshold for 2h
3. **Billing artifact generation warnings**
   - condition: invoice/adjustment endpoint 4xx/5xx rate > baseline for 1h

## Alert simulation checklist (paging path verification)
Run in staging and verify alert route/page delivery.

1. **Simulate ingest lag**
   - temporarily pause aggregate writer or inject delayed events.
   - verify ingest lag alert fires and pages on-call.
2. **Simulate finalize failure**
   - force snapshot finalize to fail (bad table config or injected exception).
   - verify `snapshot_finalize_error` alert pages.
3. **Simulate reconciliation drift**
   - mutate one period aggregate row manually.
   - run recompute; verify drift metric/alert and ticket route.

Record for each simulation:
- trigger timestamp
- alert firing timestamp
- paging destination received
- runbook link opened and resolved

## On-call runbook links
- Storage + metering runbook: `docs/api-usage-metering-runbook.md`
- Pricing governance: `docs/api-pricing-catalog-governance.md`
- Route contract: `docs/api-route-id-contract.md`
- Plan and ticket map:
  - `docs/api-management-metering-billing-plan.md`
  - `docs/api-management-metering-billing-tickets.md`

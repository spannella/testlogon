# KYC Metrics Dashboard (Day-1 Ops)

This dashboard is intended for reviewer operations and compliance monitoring.

## Core panels

1. **Funnel counts**
   - `draft`
   - `submitted`
   - `under_review`
   - `needs_more_info`
   - `approved`
   - `rejected`

2. **Review latency percentiles (seconds)**
   - `p50`
   - `p90`
   - `p99`

3. **Stale queue count**
   - Count of `submitted|under_review|needs_more_info` cases older than stale threshold.

4. **Submit-guard failures by reason**
   - `questionnaire_submitted`
   - `required_files`
   - `signature_completed`

## Baseline alert thresholds

- **Stale queue surge**: `stale_queue_count > 25` for 30 minutes.
- **Latency regression**: `p90_review_latency_seconds > 172800` (48h) for 60 minutes.
- **Submit guard failures**: any single failure reason grows by `>50` over 1 hour.

## Operational notes

- Correlate `kyc_metric` and `kyc_*` transition audit events using `correlation_id`.
- Correlate ticket sync incidents using `correlation_link` (`kyc_case:<id>|ticket:<id>`).

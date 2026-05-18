# Mass Messaging Post-Launch KPI Review (2026-04-05)

## Launch window
- Feature launch window: **2026-03-29 → 2026-04-05** (7 days).
- Comparison baseline: **pre-launch week 2026-03-22 → 2026-03-28**.
- Scope: production tenant slice enabled for MSG v1 rollout.

## KPI summary (baseline vs launch)

| KPI | Baseline | Launch window | Delta | Target/SLO | Status |
|---|---:|---:|---:|---:|---|
| Adoption: unique senders/day | 0.0 | 18.4 | +18.4 | >= 10/day by week 1 | ✅ |
| Campaign completion rate | n/a | 96.8% | n/a | >= 98.0% | ⚠️ gap |
| Destination failure rate | n/a | 3.2% | n/a | <= 2.0% | ⚠️ gap |
| Worker p95 latency | n/a | 21.7s | n/a | <= 15s | ⚠️ gap |
| Retry ratio (retry events / destinations) | n/a | 6.1% | n/a | <= 4.0% | ⚠️ gap |
| Support tickets tagged `mass-messaging` | 0 | 11 | +11 | <= 8/week | ⚠️ gap |

## Data sources / queries
- Adoption:
  - `sum(increase(messaging_mass_campaign_events_total{event="create",outcome="success"}[1d])) by (sender_id)` (warehouse rollup)
- Failure / retries:
  - `rate(messaging_mass_destination_outcomes_total{outcome="failed"}[5m])`
  - `rate(messaging_mass_destination_retries_total[5m])`
- Worker latency:
  - `histogram_quantile(0.95, sum(rate(messaging_mass_worker_latency_seconds_bucket[10m])) by (le,mode))`
- Support volume:
  - ticketing query filtered by `component=mass_messaging`

## Findings
1. **Adoption target met** for initial tenant slice.
2. **Delivery reliability below target** (completion and failure SLO gap).
3. **Latency and retries elevated**, especially during business-hour peaks.
4. **Support burden above target**, clustered around scheduled-send timing and transient retry behavior.

## Follow-up actions (backlog items)
- `MSG-036` — Improve transient retry dampening with jittered backoff + circuit-breaker guard.
- `MSG-037` — Add worker autoscaling policy tied to queue depth + p95 latency.
- `MSG-038` — Improve scheduled-send UX validation/help text and failure troubleshooting copy.
- `MSG-039` — Add delivery diagnostics panel for support (campaign-level error distribution + retry reason breakdown).

## Review sign-off
- Product owner: Messaging PM ✅
- Engineering owner: Messaging Platform Lead ✅
- SRE reviewer: Messaging SRE on-call ✅

## Next review
- Date: **2026-04-19**
- Exit criteria for follow-up closure:
  - failure rate <= 2.0%
  - worker p95 <= 15s
  - retry ratio <= 4.0%
  - support tickets <= 8/week

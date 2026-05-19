# Messaging Lottery Observability (LOT-402)

This runbook defines counters, latency timers, and alert thresholds for DM lottery reliability.

## Metrics

All lottery metrics are labeled by:
- `environment`
- `client_version`

### Counters

- `messaging_lottery_sends_total{environment,client_version,outcome}`
  - create/send outcomes (`success`, `invalid_config`, `config_persist_error`, `message_persist_error`)
- `messaging_lottery_unlock_attempts_total{environment,client_version}`
- `messaging_lottery_unlock_results_total{environment,client_version,outcome}`
  - unlock outcomes (`success`, `idempotent`, `rate_limited`, `message_not_found`, `invalid_config`, etc.)

### Latency timers

- `messaging_lottery_unlock_latency_seconds{environment,client_version,outcome}`
  - API latency for unlock endpoint
- `messaging_lottery_reveal_latency_seconds{environment,client_version,outcome}`
  - reveal latency, using client-reported `x-lottery-reveal-latency-ms` when available, else server fallback

## Dashboard

- Import: `docs/dashboards/messaging-lottery-unlock-reliability-dashboard.json`
- Filter by `environment` and `client_version` template variables.

## Alert thresholds

Recommended Prometheus rules:

```yaml
groups:
  - name: messaging-lottery-unlock
    rules:
      - alert: MessagingLotteryUnlockErrorRateHigh
        expr: |
          (
            sum(rate(messaging_lottery_unlock_results_total{environment="staging",outcome!~"success|idempotent"}[10m]))
            /
            clamp_min(sum(rate(messaging_lottery_unlock_attempts_total{environment="staging"}[10m])), 1)
          ) > 0.15
        for: 10m
        labels:
          severity: page
        annotations:
          summary: "Lottery unlock error-rate spike (staging)"

      - alert: MessagingLotteryUnlockErrorRateWarn
        expr: |
          (
            sum(rate(messaging_lottery_unlock_results_total{environment="staging",outcome!~"success|idempotent"}[10m]))
            /
            clamp_min(sum(rate(messaging_lottery_unlock_attempts_total{environment="staging"}[10m])), 1)
          ) > 0.05
        for: 15m
        labels:
          severity: warn
        annotations:
          summary: "Lottery unlock error-rate elevated (staging)"

      - alert: MessagingLotteryUnlockLatencyP95High
        expr: |
          histogram_quantile(0.95,
            sum(rate(messaging_lottery_unlock_latency_seconds_bucket{environment="staging",outcome=~"success|idempotent"}[10m])) by (le)
          ) > 2.5
        for: 10m
        labels:
          severity: warn
        annotations:
          summary: "Lottery unlock API latency p95 high (staging)"
```

## Staging test scenario (alert trigger verification)

1. Enable lottery flags in staging.
2. Run synthetic unlock failure traffic (invalid IDs + forced rate-limit path) for 15+ minutes.
3. Confirm dashboard "Unlock Error Rate" rises above warning/critical lines.
4. Confirm alert rules fire in Alertmanager for warning and critical thresholds.
5. Stop synthetic load and verify alerts auto-resolve.


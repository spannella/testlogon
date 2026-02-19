# Once-Media Observability Runbook (MOM-041)

This runbook defines the telemetry contract and dashboard panels for once-media rollout monitoring.

## Metrics

### Send + consume counters

- `messaging_once_media_send_total{media_kind,consumption_policy,cohort}`
- `messaging_once_media_consume_total{media_kind,outcome,reason,cohort}`
- `messaging_once_media_conflicts_total{media_kind,cohort}`

### Grant counters + latency

- `messaging_once_media_grant_total{media_kind,outcome,reason,cohort}`
- `messaging_once_media_grant_latency_seconds{media_kind,outcome,cohort}`

## Label cardinality guardrails

Labels are intentionally constrained to low-cardinality values:

- `media_kind`: `image|video|audio|unknown`
- `consumption_policy`: `view_once|listen_once|unknown`
- `outcome`: `success|error`
- `reason`: stable error codes only (examples: `already_consumed`, `grant_expired`, `consume_threshold_not_met`, `none`)
- `cohort`: sanitized rollout bucket from `X-Once-Media-Cohort` header; defaults to `default`

Do **not** include message content, attachment URLs, grant tokens, file paths, encryption materials, or user identifiers in metric labels.

## Dashboard panels

### 1) Once-media sends by media kind/policy and cohort

```promql
sum by (media_kind, consumption_policy, cohort) (
  rate(messaging_once_media_send_total[15m])
)
```

### 2) Consume success rate by media kind + cohort

```promql
sum by (media_kind, cohort) (rate(messaging_once_media_consume_total{outcome="success"}[10m]))
/
clamp_min(sum by (media_kind, cohort) (rate(messaging_once_media_consume_total[10m])), 1)
```

### 3) Consume failure rate by reason

```promql
sum by (media_kind, reason, cohort) (
  rate(messaging_once_media_consume_total{outcome="error"}[10m])
)
```

### 4) Grant p95 latency by media kind + cohort

```promql
histogram_quantile(
  0.95,
  sum by (le, media_kind, cohort) (
    rate(messaging_once_media_grant_latency_seconds_bucket[10m])
  )
)
```

### 5) Grant failure rate by reason

```promql
sum by (media_kind, reason, cohort) (
  rate(messaging_once_media_grant_total{outcome="error"}[10m])
)
```

### 6) Conflict/race rate

```promql
sum by (media_kind, cohort) (
  rate(messaging_once_media_conflicts_total[10m])
)
```

## Suggested alerts

### Consume failure spike (warning)

```promql
(
  sum(rate(messaging_once_media_consume_total{outcome="error"}[10m]))
  /
  clamp_min(sum(rate(messaging_once_media_consume_total[10m])), 1)
) > 0.10
```

- For: `15m`

### Grant latency degradation (warning)

```promql
histogram_quantile(
  0.95,
  sum by (le) (rate(messaging_once_media_grant_latency_seconds_bucket[15m]))
) > 0.5
```

- For: `15m`

### Conflict/race surge (warning)

```promql
sum(rate(messaging_once_media_conflicts_total[15m])) > 0.5
```

- For: `20m`

# Messaging Message Controls Observability

This runbook defines metrics, logs, dashboard panels, and alert thresholds for message controls:

- hide / unhide
- pin / unpin
- report message
- report validation failures

## Metrics

### `messaging_message_control_actions_total{action,result}`

Incremented on message-control handler outcomes.

- `action`: `hide | unhide | pin | unpin | report`
- `result`: `success | rate_limited | unknown`

### `messaging_report_validation_errors_total{reason}`

Incremented when report payload validation fails.

- `reason`: `reason_code_required | statement_too_short | statement_too_long | unknown`

## Structured logs

Message control events emit structured logs under:

- `event`: `messaging.message_control`

With attributes:

- `actor_user_id`
- `conversation_id`
- `message_id`
- `action`
- `result`
- `detail` (optional scope/context)

This allows per-actor and per-conversation forensic trails during abuse investigations and rollback triage.

## Dashboard

Dashboard spec:

- `docs/dashboards/messaging-message-controls-dashboard.json`

Recommended panels:

1. Action throughput by action/result.
2. Report rate-limited events.
3. Report validation error rate by reason.
4. Message-control API error ratio (5xx + 429) via API usage metering.

## Alerts

### Report spike warning

```promql
sum(rate(messaging_message_control_actions_total{action="report",result="success"}[5m])) > 2
```

- For: `10m`
- Severity: `warning`

### Report spike critical

```promql
sum(rate(messaging_message_control_actions_total{action="report",result="success"}[5m])) > 5
```

- For: `10m`
- Severity: `critical`

### Report abuse/rate-limit warning

```promql
sum(rate(messaging_message_control_actions_total{action="report",result="rate_limited"}[10m])) > 0.2
```

- For: `15m`
- Severity: `warning`

### Message controls API error ratio warning

```promql
(
  sum(rate(api_usage_requests_total{endpoint=~"/messaging/conversations/.*/messages/.*/(hide|pin|report)",status_class=~"4xx|5xx",http_status!="404"}[10m]))
  /
  clamp_min(sum(rate(api_usage_requests_total{endpoint=~"/messaging/conversations/.*/messages/.*/(hide|pin|report)"}[10m])), 1)
) > 0.05
```

- For: `15m`
- Severity: `warning`

## Validation / simulation checklist

1. Trigger hide/unhide/pin/unpin/report actions in staging and verify action counters increase.
2. Submit invalid report payloads to verify validation error counter labels.
3. Generate burst reports from a test user to verify rate-limit counters and warnings.
4. Confirm structured log fields are present in log explorer.
5. Confirm dashboard thresholds transition to warning/critical when replaying synthetic load.

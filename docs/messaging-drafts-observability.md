# Messaging Drafts Observability & Analytics

## Goals

Provide operational visibility for draft CRUD reliability and client fallback behavior without collecting draft content.

## Backend metrics

The following Prometheus metrics are emitted from draft endpoints:

- `messaging_draft_operations_total{operation,source,result}`
  - operation: `list|create|get|update|delete`
  - source: `server`
  - result: `success|error`
- `messaging_draft_operation_duration_seconds{operation,source}`
  - latency histogram for draft operations (p50/p95/p99)
- `messaging_draft_fallback_total{reason}`
  - used for client-reported fallback rollups (e.g. `refresh_failed`, `create_failed`)

## Suggested dashboards

1. **Draft operation volume**
   - Panel: `sum(rate(messaging_draft_operations_total[5m])) by (operation, result)`
2. **Draft endpoint latency percentiles**
   - Panel: `histogram_quantile(0.95, sum(rate(messaging_draft_operation_duration_seconds_bucket[5m])) by (le, operation))`
3. **Fallback usage trend**
   - Panel: `sum(rate(messaging_draft_fallback_total[5m])) by (reason)`

## Suggested alerts

- **High draft error ratio** (critical)
  - Trigger when `error / (success + error) > 5%` for 15 minutes per operation.
- **Create latency regression** (warning)
  - Trigger when create p95 exceeds 1s for 10 minutes.
- **Fallback spike** (warning)
  - Trigger when `create_failed` or `refresh_failed` fallback rate exceeds rolling 7-day baseline by 2x.

## Client event schema (privacy-safe)

Client draft analytics events must conform to `docs/messaging-drafts-event-schema.json` and only include metadata fields.

**Never include:**
- draft `text`
- raw message body
- encryption password or secret material

## Event examples

```json
{
  "event": "draft_save",
  "outcome": "success",
  "source": "local",
  "conversation_id_present": true,
  "at_ms": 1712312345678
}
```

```json
{
  "event": "draft_fallback",
  "outcome": "success",
  "source": "local",
  "reason": "create_failed",
  "conversation_id_present": true,
  "at_ms": 1712312346789
}
```

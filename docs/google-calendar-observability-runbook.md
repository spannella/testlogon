# Google Calendar Observability Runbook (GCAL-021)

## Metrics dashboard (recommended panels)

### Throughput and outcomes
- `google_calendar_sync_jobs_total{flow="outbound",state="done"}`
- `google_calendar_sync_jobs_total{flow="outbound",state="retry_pending"}`
- `google_calendar_sync_jobs_total{flow="outbound",state="dead_letter"}`
- `google_calendar_sync_jobs_total{flow="inbound_incremental",state=~"created|updated|deleted|errors"}`
- `google_calendar_sync_jobs_total{flow="inbound_full",state=~"created|updated|errors"}`

### Latency
- `histogram_quantile(0.95, sum(rate(google_calendar_sync_latency_seconds_bucket[5m])) by (le,flow))`

### Backlog and reliability
- `google_calendar_outbox_backlog{status="pending"}`
- `google_calendar_outbox_backlog{status="retry_pending"}`
- `google_calendar_outbox_backlog{status="dead_letter"}`
- `google_calendar_sync_conflicts_total`
- `google_calendar_token_refresh_failures_total`

## Alert policy thresholds (staging/prod baseline)
- **Outbox backlog high**
  - trigger: `google_calendar_outbox_backlog{status="pending"} > 200 for 10m`
- **Dead-letter growth**
  - trigger: `increase(google_calendar_sync_jobs_total{flow="outbound",state="dead_letter"}[15m]) > 5`
- **Conflict spike**
  - trigger: `increase(google_calendar_sync_conflicts_total[15m]) > 20`
- **Token refresh/auth failures**
  - trigger: `increase(google_calendar_token_refresh_failures_total[10m]) > 3`
- **Latency regression**
  - trigger: `histogram_quantile(0.95, sum(rate(google_calendar_sync_latency_seconds_bucket{flow="outbound"}[10m])) by (le,flow)) > 15`

## Correlation + tracing
Structured logs emit `correlation_id` and mapping identifiers:
- enqueue: `google_calendar_outbound_job_enqueued`
- processing: `google_calendar_outbound_job_processed`
- error: `google_calendar_outbound_job_error`
- token lifecycle: `google_calendar_token_refreshed`
- API call completion: `google_calendar_api_request_completed`

Correlate a single event by searching logs on:
- `correlation_id`
- `mapping_internal_calendar_id`
- `mapping_internal_event_id`
- `dedup_key`

## Staging simulation checklist
1. Force transient provider failure (503) and verify `retry_pending` growth and later `done`.
2. Force repeated transient failures beyond retry budget and verify `dead_letter` + alert.
3. Force auth/token refresh failure (`invalid_grant`) and verify token refresh alert.
4. Trigger etag conflict and verify conflict metric/alert.

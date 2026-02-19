# API Usage Metering Storage Runbook (AMB-012)

## Purpose
Operational guidance for the `api_usage_events` storage layer: durability, indexing, TTL retention, and failure/backpressure handling.

## Table and index model
- Table name: `API_USAGE_TABLE_NAME` (default fallback: `api_usage_events` for local bootstrap)
- Primary keys:
  - `PK = USER#{user_sub}`
  - `SK = API_USAGE#EVENT#{event_id}`
- GSIs:
  - `GSI_PERIOD` (`GSI_PERIOD_PK=PERIOD#{period_id}`, `GSI_PERIOD_SK=USER#{user_sub}#TS#{timestamp}#EVT#{event_id}`)
  - `GSI_API_KEY` (`GSI_API_KEY_PK=APIKEY#{api_key_id|NONE}`, `GSI_API_KEY_SK=PERIOD#{period_id}#TS#{timestamp}#EVT#{event_id}`)
  - `GSI_ROUTE` (`GSI_ROUTE_PK=ROUTE#{route_id}`, `GSI_ROUTE_SK=PERIOD#{period_id}#TS#{timestamp}#EVT#{event_id}`)

This supports query paths by user+period, period, api key, and route.

Aggregate entities updated per event:
- `api_usage_period_totals` (account period totals)
- `api_key_usage_period_totals` (per API key per period)
- `api_route_usage_period_totals` (per route per period, includes `unit_price_micros`)
- `api_usage_daily` (daily usage series for charting)

## Retention policy
- TTL attribute: `ttl_epoch` (`DDB_TTL_ATTR` default)
- Event retention days: `API_USAGE_EVENT_RETENTION_DAYS` (default `365`)
- Local bootstrap script enables TTL on `api_usage_events` where DynamoDB API supports it.

## Durability and idempotency
- Raw events are append-only with conditional put (`attribute_not_exists`).
- Duplicate retries are deduped via deterministic `event_id`.
- Aggregate increments are guarded by `aggregates_applied` to keep replay deterministic after partial failures.

## Backpressure / failure handling

### Symptoms
- Elevated middleware metering failures.
- Increased event persistence latency.
- Missing period totals compared with raw request volume.

### Immediate actions
1. Verify table/index health (`describe-table`, GSI status ACTIVE).
2. Check write throttling/errors for `api_usage_events` and GSIs.
3. Confirm `API_USAGE_TABLE_NAME` is configured in target environment.
4. Validate TTL config is enabled for `ttl_epoch`.

### Mitigations
- If throughput pressure occurs, keep billing path stable by:
  - retaining dedupe keys and replaying failed events,
  - re-running aggregate recompute from stored raw events.
- If persistence is unavailable, record incident and enable replay once storage recovers.

### Recovery
- Run deterministic recompute job `recompute_api_usage_aggregates(...)` from raw `api_usage_event` rows.
- Replay event feed (or reprocess persisted events) with idempotent write guards enabled.
- Verify aggregate parity by sampling counts per period/user/route and daily series.

## Verification checklist
- [ ] Event rows writable and queryable by user+period.
- [ ] `GSI_PERIOD` query returns period-scoped records.
- [ ] `GSI_API_KEY` query returns key-scoped records.
- [ ] `GSI_ROUTE` query returns route-scoped records.
- [ ] TTL enabled and `ttl_epoch` populated on writes.


## Drift report
Recompute returns `drift_report` buckets for `period`, `key`, `route`, and `daily` mismatches to support repair auditing.


## Quota denial response contract
Pre-request account quota checks return deterministic `429` payloads (`code=api_limit_exceeded`) and headers:
- `x-api-limit-code`
- `x-api-limit-scope`
- `x-api-limit-type`
- `x-api-limit-reset-at` (when available)


## Observability dashboards and alerts (AMB-061)
- See `docs/api-usage-observability-dashboards-alerts.md` for SLOs, dashboard definitions, alert thresholds, simulation steps, and paging verification checklist.


## Shadow billing and cutover checklist (AMB-062)
- See `docs/api-usage-shadow-billing-cutover.md` for full-cycle shadow validation, variance thresholds, cutover criteria, rollback criteria, and go-live signoff workflow.

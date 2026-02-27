# API Package Usage Burn-down & Alerting (CCE-032)

This document defines API package usage visibility and threshold alerting.

## Usage API

- Endpoint: `GET /v1/entitlements/usage`
- Auth: UI session (`require_ui_session`)
- Optional filters:
  - `status` (for example `active`, `upcoming`, `expired`)

Response includes, per API entitlement:

- `usage_limit`, `usage_consumed`, `remaining`, `percent_used`
- `ledger_consumed` from `entitlement_usage_events`
- `ledger_matches` to verify reconciliation with entitlement counters
- `recent_usage_events` with event and idempotency context

## Thresholds

Two configurable threshold families are supported:

- `API_ENTITLEMENT_LOW_BALANCE_THRESHOLDS` (remaining ratio), default: `0.2,0.1,0.05`
- `API_ENTITLEMENT_NEAR_CAP_THRESHOLDS` (used ratio), default: `0.8,0.9,0.95`

On successful request-time consumption, threshold crossings are detected and emitted as alerts.

## Alerting Semantics

- Threshold alerts are emitted via the alert system as `security_event` with `outcome=warning`.
- Each threshold marker is emitted once per entitlement using marker idempotency on the entitlement item.
- Marker examples:
  - `low_balance:0.2`
  - `near_cap:0.9`

This guarantees one alert per entitlement/threshold crossing policy while remaining deterministic under duplicate traffic.

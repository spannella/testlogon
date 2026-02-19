# API Metering Billable-Status Policy (AMB-002)

This document defines the default status-class policy and machine-readable limit-denial contract used for API metering/quota/billing.

## Status-class policy defaults

### Billing defaults
- Billable status classes: `2xx`
- Non-billable by default: `1xx`, `3xx`, `4xx`, `5xx`

### Quota defaults
- Count toward quota: `2xx`, `4xx`, `5xx`
- Do not count by default: `1xx`, `3xx`

### Special-case overrides
- **Rate-limited calls** (typically `429`):
  - billable: `false`
  - counts toward quota: `true`
- **Auth-failed calls** (typically `401/403`):
  - billable: `false`
  - counts toward quota: `true`

These defaults are intended to prevent billing users for failed auth/throttled traffic while still protecting platform capacity against abusive traffic.

## Configuration knobs

The policy is runtime-configurable via environment variables:

- `API_USAGE_BILLABLE_STATUS_CLASSES` (default: `2xx`)
- `API_USAGE_QUOTA_STATUS_CLASSES` (default: `2xx,4xx,5xx`)
- `API_USAGE_RATE_LIMIT_BILLABLE` (default: `false`)
- `API_USAGE_RATE_LIMIT_COUNTS_TOWARD_QUOTA` (default: `true`)
- `API_USAGE_AUTH_FAILED_BILLABLE` (default: `false`)
- `API_USAGE_AUTH_FAILED_COUNTS_TOWARD_QUOTA` (default: `true`)

Allowed status-class values: `1xx`, `2xx`, `3xx`, `4xx`, `5xx`.

## Machine-readable limit denial payload contract

When quota/rate/spend limits are exceeded, API responses should return `429` with:

```json
{
  "code": "api_limit_exceeded",
  "limit_type": "monthly_calls",
  "scope": "api_key",
  "current": 1001,
  "limit": 1000,
  "reset_at": 1738368000,
  "route_id": "POST:/v1/messages/send",
  "api_key_id": "k_123"
}
```

Fields:
- `code`: stable error discriminator
- `limit_type`: e.g. `rps`, `daily_calls`, `monthly_calls`, `monthly_spend`
- `scope`: `account`, `api_key`, or `route`
- `current`: observed usage at deny time
- `limit`: configured threshold
- `reset_at`: epoch seconds when bucket/period resets
- `route_id`/`api_key_id`: optional context when applicable

## Approval workflow

This policy document is intended for signoff by:
- Product (customer impact/UX)
- Finance (billing fairness)
- Engineering (operational behavior and abuse controls)

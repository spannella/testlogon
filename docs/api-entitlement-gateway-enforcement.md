# External API Entitlement Gateway Enforcement (CCE-031)

`app/services/api_usage_entitlements.py` enforces external API entitlements at request time from the gateway middleware in `app/main.py`.

## Enforcement flow
1. Resolve `route_id`, `user_sub`, and `api_key_id` from request metadata.
2. Resolve active `api_package` entitlements for the caller.
3. Enforce route allowlist access (`access_template.route_allowlist`).
4. Enforce entitlement capacity (`usage_limit` and/or `limit_overrides.monthly_call_limit`).
5. Atomically consume one request unit using DynamoDB transaction with idempotent event write.

## Deterministic denial contract
Denials return HTTP `403` with detail:
- `code: api_entitlement_denied`
- `reason` in:
  - `no_entitlement`
  - `unauthorized_route`
  - `expired_entitlement`
  - `quota_exceeded`
- `route_id`, `entitlement_id`, `user_sub`

## Atomic/idempotent consumption
- Transaction writes a usage event (`entitlement_usage_events`) with deterministic idempotency key.
- Same transaction conditionally increments `entitlements.usage_consumed` while below limit.
- Duplicate idempotent requests return replay headers and avoid double-count increments.

## Observability headers
Successful requests include:
- `x-api-entitlement-id`
- `x-api-entitlement-route`
- `x-api-entitlement-idempotency`
- `x-api-entitlement-replayed`

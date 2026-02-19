# API Usage Event Schema (AMB-010)

This schema is emitted by request middleware for each eligible API request.

## Emitted fields
- `user_sub` (string): authenticated/derived user subject (may be empty for unauthenticated traffic)
- `api_key_id` (string): parsed API key id when request carries an API key
- `route_id` (string): canonical route id (`METHOD:/path-template`)
- `status_code` (int): HTTP response status code
- `request_id` (string): `x-request-id`/`x-correlation-id` if provided
- `period_id` (string): UTC billing period (`YYYY-MM`)
- `billable` (bool): computed from AMB-002 policy
- `request_units` (int): quota units (default `1` when quota-counting, else `0`)
- `unit_price_micros` (int): resolved route unit price at event time
- `cost_micros` (int): billable cost contribution for the event
- `pricing_catalog_version` (string): catalog version used for rating
- `timestamp` (string): ISO8601 UTC event timestamp

## Exclusion behavior
Events are not emitted for explicitly non-metered routes, including:
- `/`
- `/metrics`, `/openapi.json`, `/docs`, `/redoc`, `/static/*`
- health probes (`.../health`, `.../healthz`)

## Notes
- Middleware emits one event per eligible request after response status is known.
- Persistence sink is intentionally abstracted (`emit_api_usage_event`) for AMB-011/AMB-012.


## Idempotency semantics
- `idempotency_key` is deterministic: `request_id + route_id + request_attempt + status_code`.
- `event_id` is deterministic hash of `idempotency_key`.
- Storage write is conditional (`attribute_not_exists`) to prevent duplicate event rows.
- Aggregate mutation is guarded by `aggregates_applied`; retries only apply missing aggregate updates once.

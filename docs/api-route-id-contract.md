# API Metering Route ID Contract

This contract defines the canonical operation identifier used for API metering and billing.

## Route ID format

`route_id = {METHOD}:{PATH_TEMPLATE}`

Examples:
- `GET:/ui/api_keys`
- `POST:/v1/messages/send`
- `DELETE:/v1/fs/delete`

## Normalization rules

1. Method is uppercased (`get` -> `GET`).
2. Path uses router template path (not concrete runtime path).
3. Path always starts with `/`.
4. Repeated/trailing slashes are collapsed/trimmed (`/v1//x/` -> `/v1/x`).

## Dynamic path mapping examples

Dynamic segments use the route template exactly as registered by FastAPI:
- `GET /v1/fs/shared/{token}` -> `GET:/v1/fs/shared/{token}`
- `POST /v1/messaging/threads/{thread_id}/reply` -> `POST:/v1/messaging/threads/{thread_id}/reply`
- `GET /v1/purchase-history/{order_id}` -> `GET:/v1/purchase-history/{order_id}`

## Excluded non-billable probe/internal surfaces

The following paths are intentionally excluded from API call metering/billing:
- exact root: `/`
- metrics and docs surfaces: `/metrics`, `/openapi.json`, `/docs`, `/redoc`, `/static/*`
- health probes: any route ending in `/health` or `/healthz`

## Route catalog generation

Route catalog generation walks registered FastAPI `APIRoute`s and emits a unique row for each canonical HTTP method in:
- `GET`, `POST`, `PUT`, `PATCH`, `DELETE`

This excludes synthetic methods (`HEAD`, `OPTIONS`) from billing identifiers.

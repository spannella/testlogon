# UPS Integration

This service now includes a **minimal UPS integration** for local testing and early provider wiring.

## Implemented endpoints

### App endpoints
- `POST /api/ups/quote` — request a shipping quote.
- `POST /api/ups/label` — create a shipping label.
- `POST /api/ups/tracking/webhook` — receive tracking updates (HMAC signature optional/configurable).

### Local mock/provider endpoints
- `POST /mock/ups/oauth/token`
- `POST /mock/ups/quote`
- `POST /mock/ups/label`
- `POST /emit/ups-tracking-webhook` (helper to emit signed tracking events to the app webhook)

## Configuration

- `UPS_BASE_URL`
- `UPS_AUTH_URL`
- `UPS_CLIENT_ID`
- `UPS_CLIENT_SECRET`
- `UPS_WEBHOOK_SECRET`

For local usage, point UPS base/auth to the in-app mock endpoints (see `docs/local-dev-stack.md`).

## Notes

- The current implementation is intentionally minimal and aimed at local simulation.
- Quote/label API payloads are passed through to the configured UPS base URL.
- Tracking webhook events are stored under `UPS_TRACKING` records in the billing table for verification.

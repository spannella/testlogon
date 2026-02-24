# Unified Checkout Session API (CCE-064)

`POST /ui/checkout/session` provides one checkout entrypoint across:

- `source=cart`
- `source=direct`
- `source=subscription_action`

## Contract

Request model: `UnifiedCheckoutSessionIn`

Response model: `UnifiedCheckoutSessionOut`

Normalized response fields:

- `order_id`
- `checkout_session_id`
- `line_items`
- `source`
- `status`

## Compatibility wrappers

Specialized checkout routes remain available and act as wrappers:

- `POST /ui/checkout/session/file-bundle`

The wrapper now routes through the unified checkout service so existing clients continue to work while new clients can adopt the unified endpoint.

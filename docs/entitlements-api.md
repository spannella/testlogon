# Entitlements API (CCE-022, CCE-068)

## `GET /v1/entitlements`

Lists account entitlements with user-visible status and source attribution.

### Query params

- `product_type` (optional)
- `status` (optional; compatibility filter)
- `lifecycle_status` (optional; preferred lifecycle filter)
- `source_system` (optional; e.g. `shopping_cart`, `commercial_direct`, `subscription_cycle`)

### Response fields

Each entitlement item includes:

- core fields: `entitlement_id`, `sku`, `product_type`, `status`, `starts_at`, `ends_at`, usage counters
- scope fields for file bundles (`selection_type`, `date_start`, `date_end`, `access_mode`)
- denial explainability hint: `denial_reason_hint`
- source attribution:
  - `source_system`
  - `order_id`
  - optional `subscription_id`
  - `billing_metadata` pointers (`invoice_id`, `provider_invoice_id`, provider/payment-event pointers)

This allows Support to explain access outcomes from one entitlement response, including subscription-derived entitlements.

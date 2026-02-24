# Canonical Commercial Line-Item Schema (CCE-060)

`app/services/commercial_line_items.py` defines a canonical, versioned commercial line-item contract used to normalize billable payloads from shopping cart, direct commercialization checkout, and subscription renewals.

## Schema

- `schema_version` (string, default `v1`)
- `sku` (string, required)
- `product_type` (enum)
  - `file_bundle`
  - `api_package`
  - `internal_api_package`
- `billing_model` (enum)
  - `one_time`
  - `rental`
  - `subscription`
  - `credit_pack`
- `source_system` (enum)
  - `shopping_cart`
  - `commercial_direct`
  - `subscription_cycle`
- `quantity` (integer, >=1)
- `scope` (object)
- `pricing_ref` (object)

Validation entrypoint:

- `validate_commercial_line_item(payload)`

## Adapters

- `from_shopping_cart_item(item)`
- `from_direct_checkout_request(payload)`
- `from_subscription_plan(plan)`

All adapters output the same canonical schema and pass through the same validator.

## Contract fixtures

Canonical fixture examples are published in:

- `tests/fixtures/commercial_line_items/file_bundle_line_item.json`
- `tests/fixtures/commercial_line_items/api_package_line_item.json`
- `tests/fixtures/commercial_line_items/internal_api_package_line_item.json`
- `tests/fixtures/commercial_line_items/subscription_renewal_line_item.json`

# API Package Catalog Templates (CCE-030)

`POST /ui/catalog/api-packages` creates versioned `api_package` SKU entries backed by `catalog_product_versions`.

## Supported template fields
At least one template must be provided:

- `credit_grant`
  - `credits` (int > 0)
  - `bucket` (string)
- `limit_overrides`
  - `period` (must be `monthly`)
  - `monthly_call_limit` (int > 0, optional)
  - `monthly_spend_micros_limit` (int > 0, optional)
  - `rps_limit` (int > 0, optional)
  - `unlimited_calls` (bool, optional)
- `access_template`
  - `route_allowlist` (array, optional)
  - `feature_unlocks` (array, optional)

## Compatibility checks
- Reject when all templates are absent.
- Reject when `limit_overrides.unlimited_calls=true` and `monthly_call_limit` is also set.
- Reject when `route_allowlist` and `feature_unlocks` overlap by identifier.

## Versioning behavior
- Each version is keyed by `sku + effective_at` and written to `catalog_product_versions`.
- A latest-pointer snapshot is written to `catalog_products` for quick lookup.

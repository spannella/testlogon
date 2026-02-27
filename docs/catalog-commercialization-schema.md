# Catalog Commercialization Schema (CCE-001)

This document defines the canonical typed catalog schema for commercialization products and the validation rules enforced by `app/services/catalog_commercialization.py`.

## Environment flags
- `CATALOG_COMMERCIALIZATION_ENABLED` — when `false`, typed catalog loading is disabled and existing catalog readers continue unchanged.
- `CATALOG_PRICING_CATALOG` — JSON payload that contains `versions[]` entries.

## Canonical JSON shape

```json
{
  "versions": [
    {
      "sku": "files-daily-2026-01",
      "product_type": "file_bundle",
      "display_name": "Daily files Jan",
      "billing_model": "rental",
      "effective_at": "2026-01-01T00:00:00Z",
      "sunset_at": "2026-12-31T23:59:59Z",
      "amount": 1999,
      "currency": "USD",
      "tax_code": "digital_goods",
      "config": {
        "selection_type": "date_range",
        "date_start": "2026-01-01T00:00:00Z",
        "date_end": "2026-01-31T23:59:59Z",
        "access_mode": "rental",
        "rental_duration_hours": 72
      }
    }
  ]
}
```

## Required common fields
Each version entry requires:
- `sku`
- `product_type` (`file_bundle` | `api_package` | `internal_api_package`)
- `display_name`
- `billing_model` (`one_time` | `rental` | `subscription` | `credit_pack`)
- `effective_at` (epoch seconds or ISO8601 UTC)
- `amount` (integer, >= 0)
- `currency`

Optional common fields:
- `sunset_at`
- `tax_code`
- `config` (object, default `{}`)

## Product-specific config rules

### `file_bundle`
`config` requires:
- `selection_type` must be `date_range`
- `date_start`
- `date_end`
- `access_mode` must be `purchase` or `rental`
- `rental_duration_hours` must be > 0 when `billing_model=rental` or `access_mode=rental`

### `api_package`
`config` must include at least one of:
- `route_allowlist` (array)
- `credit_amount` (> 0)
- `monthly_call_limit` (> 0)

### `internal_api_package`
`config` requires:
- `internal_namespaces` as a non-empty array (e.g., `messaging.*`, `filemanager.*`)

## Additional examples

### External API package
```json
{
  "sku": "api-pro-credits",
  "product_type": "api_package",
  "display_name": "API Pro Credits",
  "billing_model": "credit_pack",
  "effective_at": "2026-01-01T00:00:00Z",
  "amount": 4900,
  "currency": "USD",
  "config": {
    "credit_amount": 50000,
    "route_allowlist": ["POST:/v1/messages/send"]
  }
}
```

### Internal API package
```json
{
  "sku": "internal-msg-plus",
  "product_type": "internal_api_package",
  "display_name": "Internal Messaging Plus",
  "billing_model": "subscription",
  "effective_at": "2026-01-01T00:00:00Z",
  "amount": 9900,
  "currency": "USD",
  "config": {
    "internal_namespaces": ["messaging.*", "filemanager.*"]
  }
}
```

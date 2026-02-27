# File Bundle Entitlement Enforcement (CCE-021)

File preview/download routes enforce file-bundle entitlements via `app/services/file_bundle_entitlements.py`.

## Enforced routes
- `GET /v1/fs/download`
- `GET /v1/fs/preview`
- `GET /v1/fs/shared-download`
- `GET /v1/fs/shared-preview`

## Enforcement behavior
- Requires active `file_bundle` entitlement when commercialization flag is enabled.
- Validates entitlement validity window (`starts_at` / `ends_at`).
- Validates file timestamp (`created_at` fallback `upload_at`) is within entitlement scope date window (`scope.date_start` / `scope.date_end`).

## Authorization payload
Denials return a consistent payload:
- `code = file_bundle_access_denied`
- `reason` in:
  - `no_entitlement`
  - `expired_entitlement`
  - `out_of_scope`
  - `missing_file_timestamp`
- `required_product_type = file_bundle`

# File Manager Internal Entitlement Enforcement (CCE-042)

File Manager internal APIs enforce `internal_api_package` entitlements for the `filemanager.*` namespace when commercialization is enabled.

## Covered operations

- `list_directory` on `GET /v1/fs/list`
- `upload_file` on `POST /v1/fs/upload`
- `upload_file` on `POST /v1/fs/complete-upload`
- `download_file` on `GET /v1/fs/download`
- `download_file` on `GET /v1/fs/shared-download`
- `preview_file` on `GET /v1/fs/preview`
- `preview_file` on `GET /v1/fs/shared-preview`
- `delete_file` on `DELETE /v1/fs/file`

## Enforcement and metering behavior

- Denied requests return HTTP 403 with deterministic payload:
  - `detail.code = internal_api_entitlement_denied`
  - `detail.reason` in `{no_entitlement, expired_entitlement, exhausted}`
- Allowed requests consume usage atomically and emit `entitlement_usage_events` with file-manager meters (for example `filemanager.file.download.bytes`).
- Usage events are keyed to `entitlement_id` and queryable by entitlement for reconciliation.

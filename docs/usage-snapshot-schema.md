# Billing Usage Snapshot Schema Versioning (MTR-003)

This document defines billing usage snapshot schema versions and compatibility behavior.

## Snapshot revision vs schema version

- `version`: snapshot revision for a given `(user_id, period_id)` (e.g. `V0001`, `V0002`) used when finalizing repeatedly.
- `schema_version`: payload schema version inside the snapshot item.

## Schema versions

### `schema_version = 1` (legacy)
Fields include core file-manager dimensions:
- `upload_bytes_total`
- `download_bytes_total`
- `storage_bytes_peak`
- `storage_byte_seconds`

### `schema_version = 2` (current)
Includes schema v1 fields plus:
- `message_send_count_total`
- `post_publish_count_total`
- `messaging_upload_bytes_total`
- `messaging_download_bytes_total`
- `newsfeed_upload_bytes_total`
- `newsfeed_download_bytes_total`

## Finalization behavior

- New snapshots are finalized with `schema_version = 2`.
- Snapshot builder initializes all v2 counters to `0`.
- Finalization copies known counters from period aggregates and falls back to `0` if absent.

## Compatibility behavior

- Older v1 snapshots remain readable.
- Readers must use `int(snapshot.get(field) or 0)` for new fields to avoid failures on legacy snapshots.

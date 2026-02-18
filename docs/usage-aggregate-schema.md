# Usage Aggregate Schema (MTR-002)

This document captures aggregate schema additions for unit-based billing counters.

## Updated aggregate entities

### `usage_period_totals`
Adds:
- `message_send_count_total` (number, default `0`)
- `post_publish_count_total` (number, default `0`)

### `usage_daily`
Adds:
- `message_send_count_total` (number, default `0`)
- `post_publish_count_total` (number, default `0`)

## Backward-compatibility / migration behavior

- New writes initialize these fields to `0` on create paths.
- Aggregate update expressions use `if_not_exists(field, 0)` before incrementing, so older rows that do not yet contain these fields are backfilled lazily on first write.
- Existing readers should use `int(item.get(field) or 0)` style access so missing fields on old rows do not raise errors.

## Notes

This schema update is additive and does not remove or rename existing aggregate fields.

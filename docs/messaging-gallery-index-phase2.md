# Messaging Gallery Phase 2: Materialized Index (MGL-017)

## Objective

Scale gallery reads for large conversations by moving from message-table scan/filter reads to a materialized gallery projection indexed by conversation + type + timestamp.

## Storage design

- **Table name:** `DDB_MESSAGE_GALLERY_INDEX` (env configured).
- **Primary key:**
  - `gallery_partition` (PK): `<conversation_id>#<gallery_type>`
  - `gallery_sort` (SK): `<created_at_padded>#<message_id>`
- **Projection attributes:**
  - `conversation_id`, `message_id`, `type`, `sender_id`, `created_at`
  - `url`, `thumbnail_url`, `title`, `file_name`, `content_type`, `size`
  - `deleted_for`, `revoked_at`

This preserves reverse-chronological reads by querying `gallery_partition` with `ScanIndexForward=False`.

## Event-driven index updates

`sync_gallery_index_entries(...)` performs idempotent replace-per-message semantics:

1. delete any existing row for each gallery type (`image`, `video`, `file`, `link`) for that message key.
2. insert current projected rows derived from canonical message payload.

Update triggers in messaging router:

- message create (text/image/file/video/audio/forwarded)
- message edit (text)
- delete-for-me (updates visibility metadata projection)
- revoke-for-all (removes effective visibility via projection recompute)

## Read path rollout

- New feature flag: `MESSAGING_GALLERY_INDEX_ENABLED`.
- When enabled and index table is configured, gallery endpoint reads from materialized index.
- API path and response contract remain unchanged:
  - `GET /messaging/conversations/{conversation_id}/gallery`
  - same request params and response schema.

## Backfill strategy

Backfill runs per conversation using:

- `backfill_conversation_gallery_index(...)`

Procedure:

1. Query source messages in reverse-chronological pages.
2. Reproject message payload to gallery entries using the same classification logic as live writes.
3. Upsert into index with replace semantics.
4. Emit run summary (`messages_scanned`, `entries_upserted`).

Recommended ops runbook:

- Start with inactive conversations, then top-N active conversations.
- Throttle write capacity per batch window.
- Re-run incremental backfill after deployment to close drift.

## Consistency checks

Use `check_gallery_index_consistency(...)` to compare expected projection tuples from source messages to actual index tuples.

Success criteria:

- `ok=true`
- `missing_count=0`
- `unexpected_count=0`

## Expected performance impact

Compared with phase-1 scan/filter reads, index reads should:

- reduce read amplification for large conversations,
- improve p95 latency on gallery tabs,
- lower DynamoDB read cost for deep history tabs.

Threshold verification is tracked via gallery observability dashboard (`messaging_gallery_latency_seconds`, `messaging_gallery_cursor_page_depth`).

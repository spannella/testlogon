# DLU-003 — Internal Dev Tools API Contract and Pagination

This document finalizes the read-only API contract for Dev Log UI endpoints.

## Base
- Prefix: `/internal/dev-tools`
- Verbs: **GET only**
- Cursor format: URL-safe base64 JSON payload (`{"offset": <non-negative int>}`)

## Error mapping
- `400 invalid_cursor`: cursor is not URL-safe base64 JSON or has invalid `offset` shape.
- `422 validation_error`: invalid enum values / `limit` outside `[1, 200]` / malformed query fields.

## Endpoints

### `GET /internal/dev-tools/email/messages`
Query params:
- `mailbox` (optional)
- `thread_id` (optional)
- `q` (optional search)
- `state` (optional enum: `all | unread | sent`, default `all`)
- `limit` (optional int, default `50`, min `1`, max `200`)
- `cursor` (optional base64 cursor)

Response model: `DevtoolsEmailMessagesOut`

### `GET /internal/dev-tools/sms/conversations`
Query params:
- `participant` (optional)
- `q` (optional search)
- `limit` (optional int, default `50`, min `1`, max `200`)
- `cursor` (optional base64 cursor)

Response model: `DevtoolsSmsConversationsOut`

### `GET /internal/dev-tools/billing/ledger`
Query params:
- `provider` (optional enum: `stripe | ccbill | paypal`)
- `status` (optional enum: `pending | completed | failed | refunded | canceled`)
- `from` (optional timestamp)
- `to` (optional timestamp)
- `limit` (optional int, default `50`, min `1`, max `200`)
- `cursor` (optional base64 cursor)

Response model: `DevtoolsBillingLedgerOut`

### `GET /internal/dev-tools/billing/summary`
Query params:
- `provider` (optional enum: `stripe | ccbill | paypal`)
- `status` (optional enum: `pending | completed | failed | refunded | canceled`)
- `from` (optional timestamp)
- `to` (optional timestamp)

Response model: `DevtoolsBillingLedgerSummaryOut`

## Deterministic behavior rules
- Identical query and cursor inputs return schema-equivalent output shape.
- Invalid cursor behavior is deterministic (`400` + `invalid_cursor` payload).
- Filter enums and limit bounds are validated at request boundary.

## Source of truth
- Router contract: `app/routers/internal_devtools.py`
- Output DTO models: `app/models.py`
- Contract tests: `tests/test_internal_devtools_contract.py`

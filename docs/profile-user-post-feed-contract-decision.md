# Profile User-Posts Feed Contract Decision (PUF-001)

## Ticket
- **ID:** PUF-001
- **Title:** Confirm and document reusable newsfeed contract for author-scoped queries
- **Status:** Implemented
- **Date:** 2026-03-25

## Decision Summary
We will **reuse the existing `GET /feed` contract envelope** and extend request query support for profile feed mode, rather than introducing a separate response schema.

- Reused response envelope: `{ items: Post[], next_cursor: string | null }`
- Added profile-mode request parameters (backward-compatible):
  - `author_id` (optional; when present, returns posts authored by that user)
  - `q` (optional search term)
  - `from` / `to` (optional ISO-8601 date filters)
  - `has_media` (optional boolean)
- Existing pagination remains unchanged:
  - `limit` (1..50)
  - `cursor` (opaque string)

This keeps the frontend and caching model aligned with general feed behavior while minimizing implementation divergence.

## Endpoint Audit (Current State)
Audit target: `GET /feed` in `app/routers/newsfeed.py`.

| Parameter | Supported | Notes |
|---|---|---|
| `limit` | Yes | Existing pagination size parameter (1..50). |
| `cursor` | Yes | Existing opaque cursor pagination parameter. |
| `author_id` | Yes | Profile mode scope: authored posts only. |
| `q` | Yes | Search term, applied within scoped rows. |
| `from` | Yes | ISO-8601 lower-bound filter (inclusive). |
| `to` | Yes | ISO-8601 upper-bound filter (inclusive). |
| `has_media` | Yes | Boolean media presence filter. |

## Routing Decision
- **Chosen:** Extend existing `GET /feed` request query parameters.
- **Rejected alternative:** Add a separate `/profiles/{id}/feed` endpoint or alias with a new response model.

This decision guarantees a single stable feed contract for both general feed and profile feed mode.

## Rationale
1. **Maximize reuse:** Existing feed UI and data hooks already assume the current envelope and cursor model.
2. **Backward compatibility:** Existing clients can omit new parameters and continue to behave exactly as before.
3. **Delivery speed:** Extending one endpoint avoids parallel handler and serializer maintenance.
4. **Operational simplicity:** Shared metrics and troubleshooting patterns stay consistent.

## Final Request Contract
`GET /feed`

### Query Parameters
- `limit?: number` — default `20`, min `1`, max `50`
- `cursor?: string`
- `author_id?: string`
- `q?: string`
- `from?: string` (ISO-8601 timestamp)
- `to?: string` (ISO-8601 timestamp)
- `has_media?: boolean`

### Compatibility Rules
- If `author_id` is omitted, feed behaves as existing general feed mode.
- If `author_id` is present, results are scoped to authored posts only (subject to existing access rules).
- `from` and `to` are inclusive bounds and expect ISO-8601 timestamps.
- Existing clients that only send `limit`/`cursor` remain fully compatible with no payload changes.

## Final Response Contract
```json
{
  "items": [
    {
      "post_id": "p_123",
      "author_id": "u_001",
      "body": "...",
      "created_at": "2026-03-24T00:00:00Z"
    }
  ],
  "next_cursor": "opaque_cursor_or_null"
}
```

- `items` remains the same post payload used by current feed consumers.
- `next_cursor` remains opaque and nullable.

## Contract Examples

### Example A — Existing general feed mode (unchanged)
`GET /feed?limit=20&cursor=abc`

### Example B — Profile feed mode with pagination
`GET /feed?author_id=u_001&limit=20&cursor=abc`

### Example C — Profile feed mode with search + filters
`GET /feed?author_id=u_001&q=release%20notes&from=2026-01-01T00:00:00Z&to=2026-03-24T23:59:59Z&has_media=true&limit=20`

## Canonical API Artifact Update
- OpenAPI artifact updated in `docs/swagger.json` under `GET /feed` to include:
  - query parameters: `author_id`, `q`, `from`, `to`, `has_media`
  - example payloads for both general-feed and profile-filtered modes

## Non-Goals in This Ticket
- No query/path implementation changes (handled by PUF-002+).
- No frontend wiring changes (handled by PUF-101+).
- No index/migration changes (handled by PUF-005).

## Follow-on Dependencies
- PUF-002 uses this contract for backend author-scoped query implementation.
- PUF-101/PUF-102 use this contract for profile feed API wiring and cache keys.

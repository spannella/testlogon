# Newsfeed Draft Post API Contract (NFD-002)

Status: Accepted
Last Updated: 2026-04-04
Related Tickets: `NFD-001`, `NFD-002`, `NFD-102`

## Scope

This contract defines first-class draft-post entities and payloads for server-backed drafts.

## Draft Entity

`DraftPost` fields (response shape):

- `draft_id: string`
- `author_id: string`
- `created_at: string (ISO-8601)`
- `updated_at: string (ISO-8601)`
- `body?: string`
- `body_plain?: string`
- `body_markdown?: string`
- `body_rich?: object`
- `body_format?: "plain" | "markdown" | "rich"`
- `body_version?: number`
- `image_urls?: string[]`
- `file_paths?: string[]`
- `unlock_price_cents?: number`

## Request Contracts

### CreateDraftPostRequest
Supports all composer fields needed to restore authoring state.

```json
{
  "body_plain": "Hello draft",
  "body_markdown": "# Hello draft",
  "body_format": "markdown",
  "body_version": 1,
  "image_urls": ["https://cdn.example.com/image-1.jpg"],
  "file_paths": ["/docs/contracts.pdf"],
  "unlock_price_cents": 299
}
```

### UpdateDraftPostRequest
Patch semantics; any subset of fields can be sent.

```json
{
  "body_plain": "Updated rich draft",
  "body_rich": {
    "type": "doc",
    "content": [{ "type": "paragraph", "content": [{ "type": "text", "text": "Updated rich draft" }] }]
  },
  "body_format": "rich"
}
```

## Response Contracts

### DraftPostResponse
Returns a single `DraftPost`.

### ListDraftPostsResponse
```json
{
  "items": [
    {
      "draft_id": "dft_123",
      "author_id": "user_123",
      "created_at": "2026-04-04T00:00:00Z",
      "updated_at": "2026-04-04T00:10:00Z",
      "body_plain": "Saved draft body",
      "body_format": "plain"
    }
  ],
  "next_cursor": "eyJwayI6ICJ..."
}
```

## Backward Compatibility

- Legacy publish clients that only send `body` remain valid for published post flows.
- Draft clients can send either legacy `body` or newer content fields (`body_plain`, `body_markdown`, `body_rich`, `body_format`, `body_version`).
- Draft consumers should tolerate absent optional fields and default to plain rendering when format-specific fields are missing.
- Unknown future fields in draft payloads must be ignored by tolerant readers.

## Frontend Type Mapping

Backend ↔ Frontend contracts map 1:1 via:
- `DraftPostResponse` ↔ `DraftPost`
- `CreateDraftPostRequest` ↔ `CreateDraftPostReq`
- `UpdateDraftPostRequest` ↔ `UpdateDraftPostReq`
- `ListDraftPostsResponse` ↔ `ListDraftPostsResp`


## Publish From Draft

### Endpoint

`POST /posts/drafts/{draft_id}/publish`

### Request

```json
{
  "keep_copy": false
}
```

- `keep_copy` defaults to `false`.
- When `keep_copy=false`, the draft is deleted after successful post publish.
- When `keep_copy=true`, the draft remains after successful publish.

### Response

Returns the standard `PostResponse` payload from the existing publish pipeline.


## Quota and Retention Policy

Server policy is configurable via settings:

- `newsfeed_draft_max_per_user` (default `50`)
- `newsfeed_draft_max_payload_bytes` (default `65536`)
- `newsfeed_draft_retention_days` (default `0`, disabled)
- `newsfeed_draft_quota_bypass_user_ids` (CSV allowlist for admin/ops override)

When retention is enabled, drafts are persisted with `ttl_epoch` for expiration.

### Typed Policy Errors

#### Draft quota exceeded

```json
{
  "code": "newsfeed_draft_quota_exceeded",
  "message": "newsfeed draft quota exceeded",
  "quota_type": "newsfeed_draft",
  "limit_count": 50,
  "used_count": 50,
  "remaining_count": 0
}
```

#### Draft payload too large

```json
{
  "code": "newsfeed_draft_payload_too_large",
  "message": "newsfeed draft payload exceeds max size",
  "max_payload_bytes": 65536,
  "payload_bytes": 81234
}
```

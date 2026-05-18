# Messaging Drafts — Backend API Contract (Server-Synced)

## Document metadata
- **Feature:** Messaging Drafts (server-synced roadmap)
- **Ticket:** MSGD-003
- **Contract version:** `2026-04-05`
- **API versioning mode:** Path-stable + additive schema evolution
- **Owner:** Messaging Platform

---

## 1) Scope
This contract defines server-backed draft operations scoped to a conversation and authenticated actor.

Endpoints:
- `GET /messaging/conversations/{conversation_id}/drafts`
- `POST /messaging/conversations/{conversation_id}/drafts`
- `GET /messaging/conversations/{conversation_id}/drafts/{draft_id}`
- `PATCH /messaging/conversations/{conversation_id}/drafts/{draft_id}`
- `DELETE /messaging/conversations/{conversation_id}/drafts/{draft_id}`

---

## 2) Authentication and authorization
- Auth required (same mechanism as messaging endpoints).
- Caller must be an active participant in `conversation_id`.
- Drafts are user-owned; users can access only their own draft records.

### AuthZ failure behavior
- `401 Unauthorized` when auth is missing/invalid.
- `403 Forbidden` when caller is not allowed to access conversation draft resources.

Error envelope (standard):
```json
{
  "error": {
    "code": "forbidden",
    "message": "not allowed to access drafts for this conversation"
  }
}
```

---

## 3) Data model

## 3.1 Draft object
```json
{
  "draft_id": "drf_01HZZ...",
  "conversation_id": "c_123",
  "owner_user_id": "u_456",
  "text": "draft body",
  "client_updated_at": "2026-04-05T11:00:00Z",
  "created_at": "2026-04-05T10:50:00Z",
  "updated_at": "2026-04-05T11:00:02Z",
  "version": 3
}
```

Field notes:
- `text`: UTF-8 string, max 4000 chars.
- `client_updated_at`: optional ISO8601 timestamp sent by client for reconciliation.
- `version`: monotonic integer for optimistic concurrency.

---

## 4) Endpoint contracts

## 4.1 List drafts
`GET /messaging/conversations/{conversation_id}/drafts`

### Query params
- `limit` (optional, integer, default `20`, min `1`, max `100`)
- `cursor` (optional, opaque pagination cursor)

### Response `200`
```json
{
  "items": [
    {
      "draft_id": "drf_1",
      "conversation_id": "c_1",
      "owner_user_id": "u_1",
      "text": "hello",
      "client_updated_at": "2026-04-05T11:00:00Z",
      "created_at": "2026-04-05T11:00:00Z",
      "updated_at": "2026-04-05T11:00:05Z",
      "version": 1
    }
  ],
  "next_cursor": "eyJvZmZzZXQiOjIwfQ=="
}
```

### Ordering
- Descending by `updated_at` (newest first).

---

## 4.2 Create draft
`POST /messaging/conversations/{conversation_id}/drafts`

### Headers
- `Idempotency-Key` (required): unique key per create intent, max 128 chars.

### Request body
```json
{
  "text": "draft text",
  "client_updated_at": "2026-04-05T11:00:00Z"
}
```

### Response `201`
```json
{
  "draft": {
    "draft_id": "drf_2",
    "conversation_id": "c_1",
    "owner_user_id": "u_1",
    "text": "draft text",
    "client_updated_at": "2026-04-05T11:00:00Z",
    "created_at": "2026-04-05T11:00:01Z",
    "updated_at": "2026-04-05T11:00:01Z",
    "version": 1
  }
}
```

### Idempotency behavior
- Same `Idempotency-Key` + same payload => return same created result.
- Same `Idempotency-Key` + different payload => `409 Conflict` (`idempotency_mismatch`).

---

## 4.3 Get draft by id
`GET /messaging/conversations/{conversation_id}/drafts/{draft_id}`

### Response `200`
```json
{
  "draft": {
    "draft_id": "drf_2",
    "conversation_id": "c_1",
    "owner_user_id": "u_1",
    "text": "draft text",
    "client_updated_at": "2026-04-05T11:00:00Z",
    "created_at": "2026-04-05T11:00:01Z",
    "updated_at": "2026-04-05T11:00:01Z",
    "version": 1
  }
}
```

### Not found
- `404 Not Found` when draft does not exist or is not visible to caller.

---

## 4.4 Update draft
`PATCH /messaging/conversations/{conversation_id}/drafts/{draft_id}`

### Headers
- `If-Match-Version` (optional integer): optimistic concurrency guard.

### Request body
```json
{
  "text": "updated draft text",
  "client_updated_at": "2026-04-05T11:10:00Z"
}
```

### Response `200`
```json
{
  "draft": {
    "draft_id": "drf_2",
    "conversation_id": "c_1",
    "owner_user_id": "u_1",
    "text": "updated draft text",
    "client_updated_at": "2026-04-05T11:10:00Z",
    "created_at": "2026-04-05T11:00:01Z",
    "updated_at": "2026-04-05T11:10:02Z",
    "version": 2
  }
}
```

### Concurrency conflict
- `409 Conflict` with `code=version_conflict` when `If-Match-Version` is stale.

---

## 4.5 Delete draft
`DELETE /messaging/conversations/{conversation_id}/drafts/{draft_id}`

### Response `204`
- Empty body.

### Delete semantics
- Idempotent delete: deleting an already-missing resource returns `204`.

---

## 5) Validation errors

Common validation failures return `422 Unprocessable Entity`:
- `text` missing where required.
- `text` exceeds max length.
- malformed `client_updated_at`.
- invalid `limit` / malformed `cursor`.

Example:
```json
{
  "error": {
    "code": "validation_error",
    "message": "text must be 1..4000 characters"
  },
  "field_errors": [
    {
      "field": "text",
      "reason": "length_out_of_range"
    }
  ]
}
```

---

## 6) Pagination strategy
- Cursor-based pagination using opaque token in `next_cursor`.
- Clients treat cursor as opaque; no parsing assumptions.
- Empty page response shape is stable:
```json
{
  "items": [],
  "next_cursor": null
}
```

---

## 7) Error code catalog
- `unauthorized`
- `forbidden`
- `not_found`
- `validation_error`
- `idempotency_mismatch`
- `version_conflict`
- `rate_limited`
- `server_error`

All errors must return:
```json
{
  "error": {
    "code": "string",
    "message": "human readable"
  }
}
```

---

## 8) Versioning strategy
- Contract version marker maintained in docs and changelog.
- Backward-compatible additions allowed (new optional fields).
- Breaking changes require:
  - new contract version,
  - migration plan,
  - deprecation notice in release notes.

---

## 9) OpenAPI-style schema excerpt (YAML)
```yaml
paths:
  /messaging/conversations/{conversation_id}/drafts:
    get:
      summary: List conversation drafts for the authenticated user
      parameters:
        - in: path
          name: conversation_id
          required: true
          schema: { type: string }
        - in: query
          name: limit
          schema: { type: integer, minimum: 1, maximum: 100, default: 20 }
        - in: query
          name: cursor
          schema: { type: string }
      responses:
        "200":
          description: Draft page
    post:
      summary: Create a conversation draft
      parameters:
        - in: path
          name: conversation_id
          required: true
          schema: { type: string }
        - in: header
          name: Idempotency-Key
          required: true
          schema: { type: string, maxLength: 128 }
      responses:
        "201":
          description: Draft created
  /messaging/conversations/{conversation_id}/drafts/{draft_id}:
    get:
      summary: Fetch a single draft
      responses:
        "200":
          description: Draft resource
    patch:
      summary: Update an existing draft
      parameters:
        - in: header
          name: If-Match-Version
          required: false
          schema: { type: integer, minimum: 1 }
      responses:
        "200":
          description: Draft updated
    delete:
      summary: Delete a draft
      responses:
        "204":
          description: Draft deleted
```

---

## 10) Acceptance checklist for MSGD-003
- Contract includes `GET/POST/PATCH/DELETE` draft endpoints under conversation scope.
- Schemas are defined for list/create/get/update/delete responses.
- Idempotency behavior is defined for create.
- Pagination semantics and cursor behavior are defined.
- AuthZ failures and validation errors are explicitly documented.
- Versioning strategy and change policy are documented.

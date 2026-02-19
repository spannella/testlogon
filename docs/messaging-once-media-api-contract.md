# Messaging Once-Media API Contract (MOM-002)

## Status
- **Ticket:** MOM-002
- **State:** Draft for review
- **Contract version:** `2026-02-once-media-v1`
- **Compatibility mode:** additive, backwards-compatible
- **Canonical base OpenAPI:** `docs/swagger.json`

This document defines the contract extension for one-time-consumption media while preserving compatibility with non-once clients.

---

## 1) Versioning and compatibility strategy

### 1.1 API version marker
- Add response metadata field:
  - `messaging_contract_version: "2026-02-once-media-v1"`
- Field is optional for legacy responses and present for once-media-enabled endpoints/records.

### 1.2 Backward compatibility guarantees
- Existing clients that do not support once-media continue functioning because:
  - New fields are additive and optional.
  - Existing required fields for messages remain unchanged.
  - Unknown fields can be ignored safely.
- When legacy clients render once-media records, they must show an unsupported placeholder and not crash.

### 1.3 Forward compatibility
- `consumption_policy` and `consumption_state` are enums with `unknown` fallback handling guidance on client.
- Future enum additions must not break clients that default unknown variants to non-replayable placeholders.

---

## 2) Message contract field additions

The following fields are added to messaging payloads where message media metadata is returned.

| Field | Type | Required | Allowed values | Notes |
|---|---|---|---|---|
| `consumption_policy` | string | no | `none`, `view_once`, `listen_once` | Defaults to `none` when omitted |
| `media_kind` | string | conditional | `image`, `video`, `audio` | Present when message includes media |
| `consumption_state` | string | conditional | `pending`, `consumed`, `expired`, `failed` | Per-recipient state |
| `consumed_at` | integer (unix seconds) \| null | no | epoch seconds | Null/omitted until consumed |
| `consumption_attempt_id` | string | request-only | UUID/opaque id | Idempotency key for consume attempts |

### Validation rules
- `consumption_policy=none`:
  - `consumption_state` may be omitted.
  - `consumed_at` should be omitted.
- `consumption_policy=view_once`:
  - `media_kind` must be `image` or `video`.
- `consumption_policy=listen_once`:
  - `media_kind` must be `audio`.
- `consumption_state=consumed`:
  - `consumed_at` must be present and a valid unix-seconds integer.
- `consumption_attempt_id`:
  - required on consume/grant-confirmation operations.
  - treated as idempotency key with deterministic replay response.

---

## 3) Endpoint behavior updates

## 3.1 Send message
- **Request:** may include `consumption_policy` for media messages.
- **Validation:** reject invalid policy/media combinations.
- **Response:** includes additive once-media fields when applicable.

## 3.2 List/Get message
- Include once-media fields in message objects.
- `consumption_state` is recipient-contextual.

## 3.3 Consume/grant endpoint
- **Request includes:** `message_id`, `consumption_attempt_id`, `trigger`, and optional `playback_seconds`.
- **Success:** returns short-lived media grant and updated consumption state.
- **Idempotency:** repeated `consumption_attempt_id` returns same outcome category.


### 3.4 Media-specific consume trigger semantics
- `image` once-media: `trigger=open` required.
- `video` once-media: `trigger=play` required and `playback_seconds` must meet server threshold.
- `audio` once-media: `trigger=play` required and `playback_seconds` must meet server threshold.
- Before threshold is reached, server returns retryable `consume_threshold_not_met`.

---

## 4) Error contract

Error envelope shape (existing pattern, additive codes):

```json
{
  "error": {
    "code": "already_consumed",
    "message": "Message has already been consumed.",
    "retryable": false
  }
}
```

### 4.1 New standardized error codes
| Code | HTTP status | Retryable | Meaning |
|---|---|---|---|
| `already_consumed` | 409 | false | Recipient has already consumed this once-media message |
| `grant_expired` | 410 | true | Access grant expired before use; client may request new grant if state is still pending |
| `retryable_network` | 503 | true | Temporary upstream/network issue; safe to retry with same attempt id |

### 4.2 Deterministic validation errors
| Code | HTTP status | Retryable | Meaning |
|---|---|---|---|
| `invalid_consumption_policy` | 422 | false | Unsupported or invalid `consumption_policy` value |
| `invalid_media_kind_for_policy` | 422 | false | Policy does not match media type |
| `missing_consumption_attempt_id` | 422 | false | Required idempotency key omitted on consume request |
| `invalid_consumption_state_transition` | 409 | false | Illegal state transition request |

---

## 5) Legacy client behavior contract

- Legacy clients that do not send any once-media fields continue to create normal media messages (`consumption_policy=none`).
- Legacy clients receiving once-media messages:
  - Must not attempt replay after server indicates consumed/expired.
  - Should render generic unsupported/consumed placeholder.
- Server must not require once-media fields on non-once message requests.

---

## 6) Review checklist (MOM-002 acceptance)

- [ ] API contract docs updated (`docs/messaging-once-media-api-contract.md`).
- [ ] Schema artifact updated (`docs/messaging-once-media-schema-v1.json`).
- [ ] Deterministic validation behavior documented.
- [ ] Error contract includes `already_consumed`, `grant_expired`, `retryable_network`.
- [ ] Backward compatibility behavior documented and approved.


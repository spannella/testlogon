# DM Lottery Messages API Contract (LOT-001)

## Status
- **Ticket:** LOT-001
- **State:** Approved
- **Contract version:** `2026-03-dm-lottery-v1`
- **Compatibility mode:** additive, backwards-compatible
- **Feature flag:** `messaging.dm_lottery`
- **Canonical base OpenAPI:** `docs/swagger.json`
- **Backend approval:** Messaging Platform (approved on 2026-03-25)
- **Frontend approval:** Messaging Web (approved on 2026-03-25)

This document finalizes the product/API contract for DM-only lottery messages where senders configure weighted outcomes and recipients unlock one server-authoritative result.

---

## 1) Scope and compatibility

### 1.1 Scope
- Applies to **direct messages only** (1:1 conversations).
- Supports outcome payload types:
  - `text`
  - `image`
  - `video`
- Unlock is one-time and idempotent per `(message_id, recipient_id)`.

### 1.2 Compatibility strategy
- All lottery fields are additive and optional for non-lottery messages.
- Existing message send/list/get APIs remain compatible for clients that ignore unknown fields.
- If feature flag is off, lottery create/unlock endpoints must return deterministic feature-disabled errors.

### 1.3 Contract version marker
- Add optional response metadata when lottery content is present:
  - `messaging_contract_version: "2026-03-dm-lottery-v1"`

---

## 2) Message and outcome model

### 2.1 New message type
- `message_type = "lottery_dm"`

### 2.2 Lottery configuration shape (immutable after send)

```json
{
  "lottery_config": {
    "version": "v1",
    "outcomes": [
      {
        "outcome_id": "o_01J...",
        "display_label": "Common",
        "weight_bps": 7000,
        "payload_type": "text",
        "text_content": "You got 50 points!"
      },
      {
        "outcome_id": "o_01K...",
        "display_label": "Rare",
        "weight_bps": 3000,
        "payload_type": "image",
        "media_asset_id": "asset_abc123"
      }
    ]
  }
}
```

### 2.3 Weight precision and validation rules
- `weight_bps` is an integer basis-point value per outcome.
- Sum of all outcomes must equal `10_000`.
- Outcome count range for v1: `2..10`.
- `payload_type=text` requires `text_content` and forbids `media_asset_id`.
- `payload_type=image|video` requires `media_asset_id` and forbids `text_content`.

### 2.4 Recipient state projection
- Timeline/list/get responses include:
  - `lock_state`: `"locked" | "unlocked"`
- When `lock_state="unlocked"`, include `selected_outcome` payload for current recipient.
- When `lock_state="locked"`, `selected_outcome` must be omitted.

---

## 3) Endpoint contracts

## 3.1 Create lottery message
`POST /messages/lottery`

### Request

```json
{
  "conversation_id": "conv_123",
  "message_type": "lottery_dm",
  "lottery_config": {
    "version": "v1",
    "outcomes": [
      {
        "display_label": "Common",
        "weight_bps": 7000,
        "payload_type": "text",
        "text_content": "You got 50 points!"
      },
      {
        "display_label": "Rare",
        "weight_bps": 3000,
        "payload_type": "video",
        "media_asset_id": "asset_vid_42"
      }
    ]
  }
}
```

Optional header:

- `Idempotency-Key: <token>` (max 128 chars, allowed chars: `A-Z a-z 0-9 . _ : -`)
  - Replaying the same key with the same payload returns the original logical result.
  - Replaying the same key with a different payload returns `409` (`idempotency-conflict`).

### Behavior
- Requires authenticated sender access to the DM conversation.
- Rejects non-DM conversations.
- Persists message and config atomically.
- Server generates stable `outcome_id` values if omitted by client.
- When `Idempotency-Key` is provided, server enforces dedupe semantics and may return an idempotent replay response.

### Success response (200)
- Returns created message envelope with:
  - `message_type="lottery_dm"`
  - immutable `lottery_config`
  - recipient-contextual `lock_state` for caller
  - `idempotent` flag (`true` when response is from idempotent replay, else `false`)

## 3.2 Unlock lottery message
`POST /messages/{message_id}/lottery/unlock`

### Request
- Empty body (`{}`) in v1.

### Behavior
- Requires authenticated recipient access.
- Transactional semantics:
  1. If unlock row exists, return existing `selected_outcome` (idempotent).
  2. Else compute weighted selection using secure server RNG and persist unlock row.
- Selection is authoritative on server and never client-derived.

### Success response (200)

```json
{
  "message_id": "msg_123",
  "lock_state": "unlocked",
  "selected_outcome": {
    "outcome_id": "o_01J...",
    "payload_type": "text",
    "text_content": "You got 50 points!"
  },
  "unlocked_at": 1774310400
}
```

## 3.3 Timeline/list/get message projection
- Lottery message objects return:
  - `message_type`
  - `lottery_config` (policy-controlled fields)
  - `lock_state`
  - `selected_outcome` only when unlocked for current viewer
- Optional dedicated fetch endpoint:
  - `GET /messages/{message_id}/lottery`
  - Returns the same `LotteryMessageOut` projection shape as timeline records.

---

## 4) Data leakage and policy contract

### 4.1 Before unlock (locked)
- Client may receive:
  - message is lottery type
  - display shell metadata needed for locked card
- Client must **not** receive:
  - recipient-specific selected outcome

### 4.2 Optional visibility policy
- v1 default: full weighted internals (`weight_bps`, complete outcomes list) may be visible to sender and recipient clients.
- If product policy changes, add redacted projection mode in v2 without breaking v1 clients.

---

## 5) Error contract

Error envelope follows existing API pattern:

```json
{
  "detail": {
    "code": "invalid-config",
    "message": "Outcome weights must sum to 10,000 basis points."
  }
}
```

### 5.1 Standardized lottery error codes
| Code | HTTP status | Retryable | Meaning |
|---|---|---|---|
| `invalid-config` | 422 | false | Outcome count/weights/payload fields invalid |
| `unauthorized` | 403 | false | Caller lacks access to this message/conversation |
| `not-dm` | 422 | false | Lottery create attempted outside DM context |
| `already-unlocked` | 200 | false | Alias state: unlock idempotently returns prior outcome |
| `idempotency-conflict` | 409 | false | Same `Idempotency-Key` replayed with different payload/context |
| `invalid-idempotency-key` | 422 | false | `Idempotency-Key` exceeds limits or contains disallowed characters |
| `feature-disabled` | 403 | false | `messaging.dm_lottery` is disabled |
| `rate_limited` | 429 | true | Unlock/create limit exceeded |
| `message-not-found` | 404 | false | Unknown message id or not visible to caller |
| `unlock-persist-error` | 500 | true | Unlock row could not be persisted; client may retry safely |

### 5.2 Deterministic validation examples
- Weights total not equal to 10,000 bps -> `invalid-config`.
- `payload_type=text` with `media_asset_id` present -> `invalid-config`.
- One outcome only -> `invalid-config`.
- Unlock by non-recipient/non-member -> `unauthorized`.

---

## 6) Review and acceptance checklist (LOT-001)

- [x] Contract document created: `docs/dm-lottery-messages-api-contract.md`.
- [x] Create endpoint contract defined (`POST /messages/lottery`).
- [x] Unlock endpoint contract defined (`POST /messages/{message_id}/lottery/unlock`).
- [x] Error model includes `invalid-config`, `already-unlocked`, `unauthorized`, `not-dm`.
- [x] Client-visible states include `message_type=lottery_dm` and `lock_state`.
- [x] Data leakage policy (locked vs unlocked) documented.
- [x] Backend owner approval recorded.
- [x] Frontend owner approval recorded.

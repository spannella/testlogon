# Newsfeed Unlock-Limit API Contract

This document defines the API contract and error model for capped unlocks on locked posts.

## Scope
- Endpoints:
  - `POST /posts` (create post)
  - `PATCH /posts/{post_id}` (edit post)
  - `GET /posts/{post_id}` and feed/list surfaces returning serialized posts
  - `POST /posts/unlock` (unlock flow)
- Feature: optional `unlock_limit` cap for locked posts.

## Field contract

### Request fields

#### `CreatePostRequest`
| Field | Type | Nullable | Required | Behavior |
|---|---|---:|---:|---|
| `unlock_price_cents` | `int` | yes | no | If `> 0`, post is considered locked. |
| `unlock_limit` | `int` | yes | no | Optional cap; must be `>= 1`; only valid when post is locked. |

#### `EditPostRequest`
| Field | Type | Nullable | Required | Behavior |
|---|---|---:|---:|---|
| `unlock_limit` | `int` | yes | no | Optional cap update; nullable to clear cap; only valid on locked posts. |

### Response fields (`PostResponse` and serialized post payloads)
| Field | Type | Nullable | Meaning |
|---|---|---:|---|
| `unlock_limit` | `int` | yes | Max number of distinct users that may unlock the post. `null` means uncapped. |
| `unlock_count` | `int` | no | Number of successful unlock reservations/records associated with the post. |
| `unlock_limit_reached` | `bool` | no | Derived state; `true` when `unlock_limit != null` and `unlock_count >= unlock_limit`. |

## Locked vs unlocked behavior
- Unlocked posts (`unlock_price_cents` absent/`<=0`):
  - `unlock_limit` must not be supplied on create/edit.
- Locked posts (`unlock_price_cents > 0`):
  - `unlock_limit` is optional.
  - If set, unlock attempts are capped at `unlock_limit`.

## Error payload schema
All unlock-limit validation/enforcement errors use this schema:

```json
{
  "code": "string",
  "message": "string"
}
```

## Standardized error codes

### `unlock_limit_requires_locked_post` (HTTP 400)
Returned when `unlock_limit` is supplied on a post that is not locked.

Used by:
- `POST /posts`
- `PATCH /posts/{post_id}`

### `unlock_limit_below_unlock_count` (HTTP 400)
Returned when an edit attempts to set `unlock_limit` below current `unlock_count`.

Used by:
- `PATCH /posts/{post_id}`

### `unlock_limit_reached` (HTTP 409)
Returned when an unlock attempt is rejected because cap is exhausted.

Used by:
- `POST /posts/unlock`

### `post_lock_expired` (HTTP 409)
Returned when a locked post has an expired lock window.

Used by:
- `POST /posts/unlock`

### `unlock_attempt_throttled` (HTTP 429)
Returned when repeated rapid unlock requests for the same `(user_id, post_id)` exceed throttle limits.

Used by:
- `POST /posts/unlock`

## Precedence rules (NUL-010)
- Unlock endpoint precedence:
  1. If lock is expired, return `post_lock_expired`.
  2. Otherwise, enforce cap and return `unlock_limit_reached` when exhausted.
- Read-surface precedence:
  - `lock_expired=true` takes precedence over sold-out signaling; `unlock_limit_reached` is reported as `false` for expired locks.

## Compatibility notes
- Existing clients that ignore unknown response fields remain compatible.
- `unlock_limit` is optional and defaults to uncapped behavior.

## Reservation + payment consistency strategy (NUL-008)
- Ordering strategy: **reserve slot first, then charge payment**.
- Compensation rule:
  - if payment method validation fails, payment intent creation fails, or payment confirmation fails, backend performs best-effort compensation by decrementing `unlock_count` and clearing the in-progress unlock attempt record.
- Transaction fallback rule:
  - backend prefers a DynamoDB transactional write path to reserve capacity and create the in-progress unlock record atomically.
  - if transaction API is unavailable, backend falls back to the guarded two-step path (`begin unlock attempt` + conditional reservation) and retains compensation + reconciliation safeguards.
- Success rule:
  - unlock is finalized only after payment confirmation succeeds.

### Expected invariants
- Failed payments do not permanently consume unlock capacity.
- Successful unlocks correspond to confirmed payment intents.
- Any rare drift is handled by reconciliation/ops tooling documented in the implementation tickets.

## Unlock telemetry events (NUL-011)
Backend emits structured lifecycle logs with dimensions `user_id`, `post_id`, `reason_code`, `payment_status`, `unlock_limit`, and `unlock_count` where available.

- `unlock_attempt`
- `unlock_success`
- `unlock_limit_reached`
- `unlock_payment_failed`

## Cap-reached author notification (NUL-012)
- When cap exhaustion is detected, backend attempts a one-time author notification (`post_unlock_limit_reached`).
- Deduplication is enforced by a post-scoped marker item (`UNLOCK_LIMIT_REACHED_NOTIF`) written with a conditional expression.
- Repeated blocked unlock attempts do not create duplicate author notifications.

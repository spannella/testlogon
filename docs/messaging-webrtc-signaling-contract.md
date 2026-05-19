# Messaging WebRTC Direct Chat — Signaling Contract (v1)

## Document control
- **Status:** Approved-for-implementation draft
- **Version:** v1.1
- **Last updated:** 2026-04-04
- **Owners:** Messaging Backend, Frontend Platform
- **Related:**
  - `docs/messaging-webrtc-direct-chat-spec.md`
  - `docs/messaging-webrtc-signaling-schema-v1.json`
  - `docs/messaging-webrtc-direct-chat-implementation-plan.md`

---

## 1) Purpose
Define the canonical signaling protocol for 1:1 WebRTC direct calls.
This document is normative for envelope structure, event payloads, validation/rejection behavior, and compatibility/versioning.

---

## 2) Transport and trust model
- Events are exchanged over authenticated messaging realtime transport.
- Server is authoritative for authorization, timestamp validity, and call lifecycle state.
- Clients MUST treat server-accepted event stream as source of truth.

---

## 3) Envelope (required)
All events MUST include this envelope:

| Field | Type | Required | Validation |
|---|---|---|---|
| `type` | string | yes | One of enumerated event types |
| `version` | integer | yes | MUST be `1` for this contract |
| `event_id` | string | yes | UUID |
| `conversation_id` | string | yes | Non-empty ID; must map to DM conversation |
| `call_id` | string | yes | UUID, stable for call lifetime |
| `sender_user_id` | string | yes | Must match authenticated principal |
| `recipient_user_id` | string | yes | Must be other DM participant |
| `created_at` | string | yes | RFC3339 UTC timestamp |
| `payload` | object | yes | Event-specific payload |
| `idempotency_key` | string | conditional | Required for state-changing client commands |

### Envelope invariants
1. Unknown required field omission -> reject with `validation_error`.
2. `version != 1` -> reject with `unsupported_version`.
3. Auth mismatch (`sender_user_id` != session principal) -> reject with `unauthorized`.
4. Non-participant sender/recipient for conversation -> reject with `forbidden`.
5. `call_id` collision across different active conversations -> reject with `validation_error`.

---

## 4) Event catalog (v1)

### 4.1 `call.invite`
Initiates a call attempt.

**Payload**
- `mode`: `audio` | `video`
- `ring_timeout_sec` (optional): integer, `5..120`, default `30`
- `client_capabilities` (optional object)

---

### 4.2 `call.ring`
Server indicates recipient alerting has started.

**Payload**
- `expires_at`: RFC3339 UTC timestamp

---

### 4.3 `call.accept`
Recipient accepts invite.

**Payload**
- `accepted_mode`: `audio` | `video`

---

### 4.4 `call.decline`
Recipient declines invite.

**Payload**
- `reason` (optional): `declined` | `busy` | `blocked` (default `declined`)

---

### 4.5 `webrtc.offer`
Offer SDP transfer.

**Payload**
- `sdp`: string, max 65535
- `sdp_type`: literal `offer`

---

### 4.6 `webrtc.answer`
Answer SDP transfer.

**Payload**
- `sdp`: string, max 65535
- `sdp_type`: literal `answer`

---

### 4.7 `webrtc.ice_candidate`
ICE candidate exchange.

**Payload**
- `candidate`: string, max 8192
- `sdp_mid` (optional): string or `null`
- `sdp_mline_index` (optional): integer >= 0 or `null`
- `username_fragment` (optional): string

---

### 4.8 `call.end`
Terminates active/connecting session.

**Payload**
- `reason`: `ended` | `canceled` | `failed` | `timeout`
- `duration_sec` (optional): integer >= 0

---

## 5) Deterministic validation and rejection matrix

| Validation step | Condition | Result |
|---|---|---|
| Envelope shape | Missing required envelope fields | `validation_error` |
| Version gate | `version` unknown | `unsupported_version` |
| Authentication | Sender mismatch with auth principal | `unauthorized` |
| Authorization | Sender/recipient not eligible conversation participants | `forbidden` |
| Payload schema | Payload fails type/range/enum checks | `validation_error` |
| State transition | Event invalid for current call state | `invalid_state_transition` |
| Replay control | Duplicate `event_id` in replay window | `stale_event` |
| Rate limiting | Invite threshold exceeded | `rate_limited` |
| Busy detection | Recipient in active/connecting call | `busy` |

Validation order MUST be deterministic and applied in table order.

---

## 6) State transition constraints

| Current state | Allowed event types |
|---|---|
| `invited` | `call.ring`, `call.accept`, `call.decline`, `call.end` |
| `ringing` | `call.accept`, `call.decline`, `call.end` |
| `connecting` | `webrtc.offer`, `webrtc.answer`, `webrtc.ice_candidate`, `call.end` |
| `connected` | `webrtc.ice_candidate`, `call.end` |
| terminal (`declined`, `busy`, `timed_out`, `failed`, `ended`, `canceled`) | none |

---

## 7) Error contract

| Code | Meaning | Retry guidance |
|---|---|---|
| `validation_error` | Required/typed payload rule failed | fix payload |
| `unsupported_version` | Event `version` unknown | upgrade client or fallback |
| `unauthorized` | Sender identity invalid | no retry |
| `forbidden` | Sender/recipient not allowed in conversation | no retry |
| `call_not_found` | Unknown `call_id` | refresh session |
| `invalid_state_transition` | Not valid in current call state | sync state |
| `stale_event` | Replayed/expired event | regenerate event |
| `rate_limited` | Invite throttling triggered | retry with backoff |
| `busy` | Recipient unavailable | retry later |
| `payload_too_large` | SDP/candidate exceeds limits | shrink payload |

---

## 8) Versioning and compatibility

### Backward compatibility (v1 consumers)
- MUST ignore unknown optional fields.
- MUST reject unknown enum values in known fields with `validation_error`.

### Forward compatibility rules
- New optional fields MAY be added in v1 without version bump.
- New required fields or incompatible type/semantic changes REQUIRE `version = 2`.
- Unknown versions MUST be rejected deterministically with `unsupported_version`.

### Ambiguity guard
- Event parsing MUST use discriminator `type` + `version`.
- If payload shape could match multiple event schemas, server MUST reject with `validation_error`.

---

## 9) Observability requirements
Emit structured logs/metrics per event handling attempt:
- `event_type`
- `version`
- `event_id`
- `call_id`
- `conversation_id`
- `result` (`accepted` | `rejected` | `errored`)
- `error_code` (if any)
- `latency_ms`

Raw SDP or ICE candidate strings MUST NOT be logged.

---

## 10) Normative schema
Machine-readable normative schema:
- `docs/messaging-webrtc-signaling-schema-v1.json`

---

## 11) WRTC-002 acceptance traceability
- ✅ Contract published at `docs/messaging-webrtc-signaling-contract.md`.
- ✅ Versioned JSON schema published at `docs/messaging-webrtc-signaling-schema-v1.json`.
- ✅ Deterministic validation/rejection behavior documented (Section 5).
- ✅ Compatibility behavior for unknown versions documented (Section 8).
- ✅ Event set (`call.invite`, `call.ring`, `call.accept`, `call.decline`, `webrtc.offer`, `webrtc.answer`, `webrtc.ice_candidate`, `call.end`) defined (Section 4).

# Messaging Local Encryption Plan (Password-Protected Messages)

## Goal
Add a message-level encryption workflow for direct and group chats where:

1. Sender encrypts message content locally before send.
2. Backend stores and relays only ciphertext + non-secret encryption metadata.
3. Recipients decrypt message content locally by entering a shared password.
4. Password is never transmitted to backend services.

This mirrors the client-side file encryption model and preserves backend zero-knowledge for protected message bodies.

## Scope

### In scope (phase 1)
- Opt-in encrypted text messages for DM and group conversations.
- Local browser encrypt/decrypt using WebCrypto.
- Ciphertext+metadata transport through existing messaging APIs.
- Decrypt prompt UX for recipients.
- Backward-compatible rendering with existing plaintext messages.

### Out of scope (phase 1)
- Password recovery.
- Automatic key exchange/escrow.
- Full end-to-end identity-key protocol (e.g., Signal-style ratcheting).
- Encrypted server-side search/indexing over protected message bodies.

---

## Product/UX Plan

## Sender flow
1. User composes a message.
2. User toggles **Encrypt message** in composer.
3. UI prompts for password (and optional confirm on first use in thread/session).
4. Client encrypts message payload locally.
5. Sender transmits ciphertext envelope as the message body payload.
6. Message bubble shows lock badge + "Encrypted" status.

## Recipient flow
1. Recipient sees encrypted message placeholder in thread.
2. On click/tap, UI prompts for password.
3. Client decrypts locally and renders plaintext in-memory.
4. On failure, show safe error copy (wrong password or corrupted payload).

## Group messaging behavior
- Same ciphertext blob is delivered to all participants.
- Password must be shared out-of-band by sender/group admin.
- Optional remember-on-device remains off by default and is scoped per conversation.

## UX copy requirements
- Explicit warning: "If password is lost, message cannot be recovered."
- Guidance: "Share password through a separate channel."

---

## Data and API Contract Changes

## Message schema additions
Canonical contract (finalized):
- `is_encrypted: true|false`
- `encryption` object (required when `is_encrypted=true`) with:
  - `version` (`1`)
  - `alg` (`AES-256-GCM`)
  - `kdf` (`PBKDF2-SHA256`)
  - `iterations` (bounded integer)
  - `salt_b64` (must decode to 16 bytes)
  - `iv_b64` (must decode to 12 bytes)
  - `ciphertext_b64` (base64 ciphertext+tag transport field)

Representation decision:
- Use `ciphertext_b64` as canonical wire/storage representation in phase 1.
- Do not introduce a binary transport field until we have a concrete payload-size need.

Validation rules:
- Accept **either** plaintext `text` **or** `encryption`; reject requests that include both.
- Reject encrypted payloads that include link previews.
- Return deterministic validation error codes for malformed envelopes (for example: `enc_salt_invalid`, `enc_iv_length`, `message_text_encryption_conflict`).

For encrypted messages:
- `text` is omitted/null and must not contain plaintext.
- Existing clients without encryption support should show "Unsupported encrypted message" fallback.

## Endpoint expectations
- `send message` accepts encrypted payload and metadata.
- `list/get messages` returns encryption metadata unchanged.
- `edit message` for encrypted messages should either:
  - be disabled in phase 1, or
  - require re-encrypt with fresh IV.
- `search messages` excludes encrypted content from plaintext indexing/matching.

## Eventing/SSE behavior
- Realtime message events carry encrypted envelope exactly as stored.
- No server-side decrypt attempt in stream handlers.

---

## Cryptography Design

## Recommended primitives
- Symmetric cipher: AES-256-GCM
- KDF: PBKDF2-HMAC-SHA256
- Salt: 16 bytes random
- IV/nonce: 12 bytes random per message
- KDF iterations: align with file encryption baseline (e.g., 600k) and tune for chat latency

## Envelope example
```json
{
  "version": 1,
  "alg": "AES-256-GCM",
  "kdf": "PBKDF2-SHA256",
  "iterations": 600000,
  "salt_b64": "...",
  "iv_b64": "...",
  "ciphertext_b64": "..."
}
```

## Key handling rules
- Never send password to backend.
- Keep password/derived key in memory only.
- Zeroize transient buffers where possible.
- Avoid localStorage/sessionStorage by default.

---

## Security Model

## Threat assumptions
- Backend/database compromise should not reveal plaintext encrypted messages.
- Conversation membership controls ciphertext access, not password possession.

## Controls
- Local-only encrypt/decrypt.
- No plaintext message logging for encrypted messages.
- Telemetry contains category-only errors (`wrong_password`, `tampered_payload`, `crypto_error`).

## Residual risks
- Weak/reused passwords.
- Out-of-band password channel compromise.
- Message forward/screenshot risk after local decrypt.

## Mitigations
- Password strength guidance and warnings.
- Optional password rotation guidance for long-running groups.
- Security education copy in composer + decrypt prompt.

---

## Implementation Plan

## Phase A — Contract and storage readiness
1. Extend messaging message model with encryption fields.
2. Update send/list/event serialization paths for encrypted envelopes.
3. Add compatibility fallback for legacy clients.
4. Ensure message search/indexing skips encrypted content.

## Phase B — Frontend encryption UX
1. Add composer toggle + password prompt UX.
2. Implement `encryptMessage` utility (WebCrypto).
3. Render encrypted message placeholder + lock badge.
4. Implement recipient decrypt prompt + in-memory plaintext rendering.

## Phase C — Hardening and controls
1. Add per-conversation remember-password opt-in (default off).
2. Define edit/delete behavior for encrypted messages.
3. Add telemetry and dashboards for encrypted message adoption/failures.
4. Security review + abuse/support playbook updates.

## Phase D — Optional enhancements (future)
- Password hints encrypted client-side.
- Per-recipient wrapped keys (hybrid model) to avoid shared password reuse.
- Identity-key based E2EE migration path.

---

## Testing Plan

## Unit tests
- Message encrypt/decrypt roundtrip.
- Wrong password failure classification.
- Envelope schema validation and missing-field handling.

## API/integration tests
- Send encrypted DM message -> recipient decrypt success.
- Send encrypted group message -> multiple recipients decrypt success.
- Wrong password -> decrypt fails without plaintext leak.
- Plaintext messaging unaffected.

## Contract tests
- Verify encrypted payload fields are present in list and realtime event responses.
- Verify legacy-client fallback rendering behavior.

## Security tests
- Ensure encrypted messages are excluded from message search indexes.
- Ensure server logs/metrics do not contain decrypted content.
- Tampered metadata/ciphertext yields safe failure.

---

## Rollout Strategy
1. Feature flag: `messaging_encrypted_messages` (off by default).
2. Internal dogfood on DM conversations.
3. Expand to selected groups.
4. Gradual general availability with monitoring gates.

## Success metrics
- % of messages sent with encryption enabled.
- Decrypt success rate.
- Wrong-password retry rate.
- Median encrypt/decrypt latency in supported browsers.

## Definition of Done
- Users can send encrypted messages in DM and groups.
- Recipients can decrypt locally with password.
- Backend never receives plaintext password or decrypted content.
- Search/indexing and logs avoid encrypted plaintext exposure.
- Feature is documented, tested, and release-gated.

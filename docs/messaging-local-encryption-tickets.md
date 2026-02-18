# Messaging Local Encryption — Ticket Breakdown

This ticket set maps directly to `docs/messaging-local-encryption-plan.md` and is sequenced to reduce risk, preserve backward compatibility, and allow progressive rollout under a feature flag.

---

## Milestone 0 — Architecture, contract, and guardrails

### MLE-001: Finalize encrypted message envelope contract
**Scope**
- Define canonical encrypted message shape for API and storage.
- Decide representation (`ciphertext_b64` vs binary transport field).
- Document required vs optional fields and validation rules.

**Acceptance criteria**
- Contract is documented in API source/spec and shared with frontend.
- Validation rejects malformed envelopes with deterministic error codes.
- Legacy clients can still parse non-encrypted messages unchanged.

**Dependencies**
- None.

---

### MLE-002: Add encrypted message fields to backend models and serializers
**Scope**
- Extend messaging DTOs/models with encryption metadata fields.
- Ensure send/list/detail/event payload serializers include new fields.
- Preserve existing plaintext response fields for unencrypted messages.

**Acceptance criteria**
- Encrypted fields are round-trippable in API responses.
- Plaintext messages are unaffected and require no client migration.

**Dependencies**
- MLE-001.

---

### MLE-003: Add feature flag and rollout switches
**Scope**
- Add `messaging_encrypted_messages` feature flag.
- Add per-environment defaults and kill switch behavior.
- Add backend and frontend checks to gate encrypted send/decrypt UI.

**Acceptance criteria**
- When flag is off, encrypted composer/decrypt UI is hidden/disabled.
- Existing messaging flows function identically with flag off.

**Dependencies**
- MLE-001.

---

### MLE-004: Encrypted message search/indexing exclusions
**Scope**
- Ensure encrypted message payloads are excluded from text indexing.
- Ensure fallback search paths do not attempt plaintext matching on encrypted payloads.

**Acceptance criteria**
- Encrypted message text is never indexed/searched as plaintext.
- Search for unencrypted messages remains unchanged.

**Dependencies**
- MLE-002.

---

## Milestone 1 — Crypto utilities and frontend foundations

### MLE-010: Implement frontend crypto utilities for messages
**Scope**
- Build `encryptMessage` and `decryptMessage` utilities using WebCrypto.
- Implement PBKDF2 key derivation and AES-GCM encryption/decryption helpers.
- Add envelope encode/decode helpers.

**Acceptance criteria**
- Roundtrip encryption/decryption works for representative message sizes.
- Wrong-password and tamper failures are distinguishable and safe.

**Dependencies**
- MLE-001.

---

### MLE-011: Composer encrypted-send UX
**Scope**
- Add “Encrypt message” toggle to message composer.
- Add password entry/confirm flow and warning copy.
- Wire send path to encrypt locally before API call.

**Acceptance criteria**
- Encrypted messages are sent as ciphertext envelopes only.
- Password is not included in request payloads/network logs.
- Sender gets clear encrypted-message visual badge/state.

**Dependencies**
- MLE-003, MLE-010.

---

### MLE-012: Encrypted message rendering and decrypt prompt
**Scope**
- Render encrypted placeholder card for encrypted messages.
- Add decrypt prompt modal and local decrypt execution.
- Render decrypted plaintext in memory with retry/cancel behavior.

**Acceptance criteria**
- Recipients can decrypt with correct password.
- Wrong password shows user-friendly error and allows retry.
- No decrypted text is persisted locally by default.

**Dependencies**
- MLE-003, MLE-010, MLE-002.

---

### MLE-013: Legacy-client compatibility fallback
**Scope**
- Define and implement fallback rendering for clients without encryption support.
- Ensure unsupported clients show non-breaking “Encrypted message unsupported” state.

**Acceptance criteria**
- Legacy clients do not crash on encrypted message payloads.
- Unsupported state includes clear user action guidance.

**Dependencies**
- MLE-002.

---

## Milestone 2 — Messaging backend behavior and realtime

### MLE-020: Backend send-message support for encrypted payloads
**Scope**
- Extend send-message handler to accept encrypted envelope fields.
- Enforce input validation and content-size constraints.
- Prevent plaintext + encrypted payload dual submission unless explicitly supported.

**Acceptance criteria**
- Encrypted messages persist and return expected metadata.
- Invalid envelope submissions are rejected with stable error responses.

**Dependencies**
- MLE-001, MLE-002.

---

### MLE-021: Realtime/SSE parity for encrypted messages
**Scope**
- Ensure SSE/realtime event stream emits encrypted fields consistently.
- Verify no server-side decrypt/transformation occurs in event fanout.

**Acceptance criteria**
- Encrypted messages received via stream match list/get schema.
- Event delivery for plaintext messages remains unchanged.

**Dependencies**
- MLE-020.

---

### MLE-022: Edit/delete semantics for encrypted messages
**Scope**
- Decide phase-1 behavior: disable edit for encrypted messages or require re-encrypt.
- Ensure delete/redaction behavior remains supported and predictable.
- Update API validation and frontend affordances accordingly.

**Acceptance criteria**
- Behavior is consistent across API and UI.
- Tests cover selected policy path.

**Dependencies**
- MLE-020.

---

## Milestone 3 — Security, telemetry, and compliance controls

### MLE-030: Add telemetry for encrypted message usage and failures
**Scope**
- Add low-cardinality metrics for encrypted send/decrypt attempts.
- Add categorized decrypt failure reasons (wrong password, tampered payload, crypto error).
- Add feature-flag segment labels for rollout monitoring.

**Acceptance criteria**
- Metrics dashboard can report adoption and failure rates.
- No plaintext/password material appears in metric labels or logs.

**Dependencies**
- MLE-011, MLE-012, MLE-020.

---

### MLE-031: Audit and logging hardening
**Scope**
- Audit messaging logs and remove potential plaintext leakage paths.
- Add explicit checks/redaction for encrypted message events.

**Acceptance criteria**
- Logging pipeline contains no decrypted message content from encrypted flows.
- Security review sign-off on log redaction points.

**Dependencies**
- MLE-020.

---

### MLE-032: Threat model and abuse/support playbook
**Scope**
- Produce focused threat model update for password-protected chat messages.
- Document support guidance for wrong-password, lost-password, and tamper scenarios.

**Acceptance criteria**
- Threat model approved by security stakeholders.
- Support runbook published and linked from internal docs.

**Dependencies**
- MLE-011, MLE-012.

---

## Milestone 4 — Test coverage and release readiness

### MLE-040: Unit test coverage for crypto and schema handling
**Scope**
- Add frontend unit tests for message encryption/decryption helpers.
- Add backend unit tests for encrypted schema validation and serialization.

**Acceptance criteria**
- Roundtrip, wrong-password, and tampered-envelope tests pass.
- Serializer tests cover encrypted and unencrypted payload variants.

**Dependencies**
- MLE-010, MLE-002.

---

### MLE-041: Integration/E2E tests for DM and group scenarios
**Scope**
- Add integration tests for encrypted DM send/decrypt.
- Add integration tests for encrypted group send/decrypt by multiple recipients.
- Add regression tests for plaintext messaging behavior.

**Acceptance criteria**
- End-to-end encrypted send/decrypt succeeds in both DM and group flows.
- Wrong-password path fails safely without data leakage.

**Dependencies**
- MLE-011, MLE-012, MLE-020, MLE-021.

---

### MLE-042: Contract tests for API and stream payload parity
**Scope**
- Validate encryption fields on list/get/send responses.
- Validate parity between REST payloads and realtime stream payloads.

**Acceptance criteria**
- Contract test suite prevents drift across frontend/backend models.
- CI fails on missing/envelope field mismatch.

**Dependencies**
- MLE-002, MLE-021.

---

### MLE-043: Rollout gates and launch checklist
**Scope**
- Define staged rollout (internal, limited beta, GA).
- Set SLO thresholds for decrypt success/error rates.
- Add rollback and kill-switch procedures.

**Acceptance criteria**
- Launch checklist completed and approved by eng/security/product.
- Rollout can be halted safely via feature flag.

**Dependencies**
- MLE-030, MLE-041, MLE-042.

---

## Suggested execution order (epic sequence)
1. **Foundation:** MLE-001 → MLE-004
2. **Frontend core:** MLE-010 → MLE-013
3. **Backend parity:** MLE-020 → MLE-022
4. **Security/observability:** MLE-030 → MLE-032
5. **Validation/release:** MLE-040 → MLE-043

This ordering allows early contract lock-in, incremental frontend/backend implementation under flag, and a controlled rollout with measurable safety gates.

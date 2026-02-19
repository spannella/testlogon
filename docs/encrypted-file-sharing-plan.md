# Encrypted File Sharing Plan (Password-Protected, Shareable Files)

## Goal
Allow users to share client-side encrypted files with other users **without exposing plaintext to the backend**, while requiring recipients to enter a password in the UI to decrypt locally.

## Product Requirements
- Encrypted files remain shareable through existing sharing primitives.
- Recipient can access/download encrypted bytes if authorized by share ACL.
- Recipient must provide correct password before local decrypt/open.
- Password is never sent to backend APIs.
- Password is communicated out-of-band (chat/email/in-person/password manager link) unless sender opts into a secure in-product helper flow (future phase).

## Non-Goals (initial rollout)
- Server-side password recovery.
- Backend-side decryption or content indexing of encrypted files.
- Automatic key escrow.

---

## UX Design

## Sender flow
1. User uploads encrypted file (existing flow).
2. User clicks **Share** and selects recipients.
3. Share dialog shows encrypted-file notice:
   - "This file is encrypted. Recipients need the password to open it."
4. Optional helper text includes safe password-sharing guidance:
   - "Share password through a different channel."
5. Share completes as usual (ACL + permissions).

## Recipient flow
1. Recipient sees shared encrypted file with lock badge.
2. Recipient clicks Preview/Download/Open.
3. UI enforces password prompt:
   - Enter password
   - Optional remember-on-device (opt-in, existing mechanism)
4. If password is correct: local decrypt + open/save with original name/type.
5. If wrong: friendly failure + retry.

## Edge UX
- If share exists but encryption metadata is missing/corrupt, show explicit unsupported/error state.
- Keep preview/search disabled for encrypted files (including shared views).
- Audit-visible event: encrypted shared access attempt.

---

## Technical Approach

## 1) Sharing semantics
Reuse existing file-sharing ACL model unchanged for authorization. Add encrypted-awareness to shared-file UI/actions:
- `is_encrypted` flag and encryption metadata must be included in shared-file info payloads.
- Shared download path should return ciphertext bytes exactly as stored.

## 2) Metadata contract for shared recipients
Ensure recipient-facing metadata includes stable fields required for client decrypt:
- `is_encrypted`
- `enc_version`
- `enc_alg`
- `enc_kdf`
- `enc_kdf_iterations`
- `enc_salt_b64`
- `enc_iv_b64`
- `enc_orig_name`
- `enc_orig_size`
- `enc_orig_content_type`

Continue serving `enc_metadata` for backward compatibility, but recipient flows should rely on explicit flattened fields first.

## 3) Decrypt-on-shared-download flow
For shared encrypted files:
- Fetch metadata (`shared info` or file info endpoint).
- Fetch blob bytes (ciphertext).
- Prompt for password.
- Run local decrypt with metadata envelope.
- Emit non-sensitive telemetry on failure categories.

## 4) Password handoff model
Initial model (required):
- Out-of-band password transfer by sender.

Optional future model (phase 2+):
- In-product encrypted note/hint channel with strict warnings and expiry.
- One-time password reveal token (never stores password plaintext server-side; stores sender-encrypted payload only).

---

## Security Model

## Threat assumptions
- Backend/storage compromise should not reveal plaintext content without password.
- Shared recipients may be trusted for file access but not necessarily for password secrecy.

## Controls
- No password transmitted to backend.
- Decrypt only in browser memory.
- Continue encrypted-file preview/search blocking server-side.
- Keep remember-password opt-in default OFF.
- Maintain telemetry categories only (`wrong_password`, `corrupted_metadata`, `crypto_error`) without secrets.

## Residual risks
- Sender may choose weak/reused passwords.
- Out-of-band channel compromise may expose password.

## Mitigations
- Strong password policy UX + entropy guidance.
- Sender education copy in share dialog.
- Optional per-file password rotation workflow (future).

---

## API/Backend Changes

## Required
1. Ensure shared file listing/detail endpoints include encryption fields for recipients.
2. Ensure shared preview endpoint returns encrypted-file unsupported behavior.
3. Ensure shared search/content indexing excludes encrypted files as already done for owned files.
4. Add audit dimensions:
   - `encrypted_shared_access_attempt=true|false`
   - `share_scope=direct|link` (if link shares exist)

## Optional enhancement
- Add `shared_encrypted_download` metric counter for adoption/SLO tracking.

---

## Frontend Changes

1. **Share dialog updates**
   - Add encrypted-file warning block and out-of-band password guidance.
2. **Shared file table/list**
   - Lock badge and "Encrypted" label for shared items.
3. **Shared file actions**
   - Route open/download through existing decrypt prompt flow.
4. **Remembered-password integration**
   - Use file-specific remembered key for shared paths as well.
5. **Error copy**
   - Distinguish wrong password vs metadata/corruption issues with safe messaging.

---

## Rollout Plan

## Phase A — Contract + Backend parity
- Validate shared endpoints return encryption metadata fields.
- Add/verify encrypted shared preview/search blocking behavior.
- Add observability dimensions for encrypted shared access.

## Phase B — Frontend shared UX
- Share dialog warning copy.
- Shared list badges and decrypt-required behavior.
- Retry/cancel/mismatch handling in shared-context prompt.

## Phase C — Hardening + analytics
- Dashboard for encrypted shared access and decrypt failure rate.
- Security copy review and support playbook.

---

## Testing Plan

## Unit tests
- Shared endpoint serialization includes encryption fields.
- Shared preview rejects encrypted files.
- Decrypt prompt appears for shared encrypted download path.

## Integration tests
- Sender uploads encrypted file and shares with recipient.
- Recipient can download ciphertext and decrypt with correct password.
- Recipient fails decrypt with wrong password.
- Unencrypted shared files remain unaffected.

## Failure tests
- Missing encryption metadata on shared file -> explicit failure state.
- Corrupted ciphertext -> decrypt failure telemetry path.

---

## Definition of Done
- Encrypted files can be shared with current ACL model.
- Recipients must provide password to open/decrypt locally.
- No password is sent to backend.
- Shared encrypted behavior is observable and tested.
- Existing unencrypted sharing continues to work unchanged.

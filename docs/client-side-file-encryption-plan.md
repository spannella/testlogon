# Client-Side File Encryption Plan (Password-Protected Upload/Download)

## Objective
Add a user-facing workflow where:

1. User sets a password in the UI for a file upload.
2. File is encrypted **locally in the browser** before upload.
3. Server stores only encrypted bytes + encryption metadata (never plaintext password).
4. On download, UI prompts for password and decrypts **locally**.

This enables end-to-end style confidentiality for file content against backend plaintext exposure.

## Scope

### In scope
- Browser-side encryption/decryption pipeline
- Password UX for upload and download
- File metadata to indicate encrypted objects
- Backward-compatible support for unencrypted existing files

### Out of scope (phase 1)
- Password recovery (cannot recover client-only secrets)
- Server-side content indexing/preview for encrypted files
- Multi-recipient key sharing model

## Cryptography Design

## Algorithm choices
- Symmetric encryption: **AES-256-GCM**
- KDF: **PBKDF2-HMAC-SHA256** (WebCrypto compatible)
- Random values per file:
  - 16-byte salt
  - 12-byte IV/nonce

## File format (envelope)
Store ciphertext plus a small header blob:

```json
{
  "version": 1,
  "alg": "AES-256-GCM",
  "kdf": "PBKDF2-SHA256",
  "iterations": 600000,
  "salt_b64": "...",
  "iv_b64": "...",
  "orig_name": "report.pdf",
  "orig_size": 123456,
  "mime": "application/pdf"
}
```

- Header can be stored either:
  - in file-manager metadata record (preferred), and/or
  - prepended to object payload as a compact envelope.

## Key handling rules
- Password is never sent to API.
- Derived key and plaintext file bytes are held in-memory only.
- Do not persist password in localStorage/sessionStorage.
- Zeroize temporary buffers where practical after use.

## UI/UX Plan

## Upload flow
1. User selects file.
2. Optional toggle: **"Encrypt with password"**.
3. If enabled:
   - require password + confirm password
   - show strength guidance + warning: "If you forget this password, file cannot be recovered."
4. Browser encrypts file stream/chunks.
5. Upload encrypted blob via existing upload endpoint.
6. Mark file as encrypted in list/details UI (lock icon + metadata).

## Download flow
1. User downloads encrypted file.
2. Prompt for password.
3. Download encrypted bytes.
4. Browser attempts decrypt:
   - on success: trigger save/open with original filename/mime
   - on failure: user-friendly error (wrong password or corrupted data)

## UX edge cases
- Cancel encryption/decryption gracefully.
- Large file progress bar for crypto + upload/download separately.
- Explicit warning that preview/search are unavailable for encrypted files.

## Backend/API Plan

## Metadata additions (file node)
Add fields for encrypted uploads:

- `is_encrypted: true|false`
- `enc_version`
- `enc_alg`
- `enc_kdf`
- `enc_kdf_iterations`
- `enc_salt_b64`
- `enc_iv_b64`
- `enc_orig_name`
- `enc_orig_size`
- `enc_orig_content_type`

## Endpoint behavior changes
- Existing upload endpoints remain, but accept encrypted payloads as normal bytes.
- Server should not attempt media probing/thumbnails for encrypted files.
- Preview endpoint should return explicit unsupported for encrypted files.
- Search/content indexing should skip encrypted files.

## Security & Compliance Notes
- Treat encrypted metadata carefully; avoid storing sensitive user hints.
- Validate encryption metadata schema server-side.
- Add audit events:
  - encrypted upload
  - encrypted download attempt
  - decrypt failure signal (client telemetry optional)

## Implementation Phases

## Phase 1 — Core encrypted upload/download
- Frontend WebCrypto utilities:
  - `deriveKey(password, salt, iterations)`
  - `encryptFile(file, password)`
  - `decryptFile(blob, password, metadata)`
- Upload UI toggle + password dialog
- Download password prompt + local decrypt
- Backend metadata persistence and encrypted-file flags

## Phase 2 — Performance and large files
- Chunked encryption/decryption to reduce peak memory
- Streaming progress instrumentation
- Optional Web Worker offload for crypto operations

## Phase 3 — Product hardening
- Better password policy UX
- Optional device keychain-assisted remembering (opt-in, encrypted)
- Security review and threat modeling pass

## Testing Plan

## Unit tests
- Crypto utility correctness (encrypt/decrypt roundtrip)
- Wrong password failure behavior
- Metadata schema validation

## Integration tests
- Encrypted upload -> download -> successful decrypt
- Encrypted upload -> wrong password -> expected failure
- Unencrypted file behavior unchanged

## Failure tests
- Corrupt metadata / tampered ciphertext
- Missing required encryption metadata
- Very large file timeout/memory-pressure scenarios

## Frontend test cases
- Password confirmation mismatch
- User cancels password prompt
- Retry after wrong password

## Risks and Mitigations
- **User forgets password**: irreversible by design; strong warnings and confirmations.
- **Performance for large files**: chunking + workers.
- **Browser compatibility**: rely on standard WebCrypto APIs and graceful fallback messaging.
- **Feature confusion**: clear "encrypted" badges and documentation in UI.

## Definition of Done
- Users can upload encrypted files with password and decrypt locally on download.
- Backend stores only ciphertext and non-secret encryption metadata.
- Existing unencrypted workflow remains fully functional.
- Tests cover success/failure paths for encrypted and unencrypted files.
- Documentation includes user guidance and operational constraints.

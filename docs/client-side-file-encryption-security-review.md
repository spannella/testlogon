# Client-Side File Encryption: Security Review & Threat Model (Phase 3)

## Scope
This review covers the Phase 1-3 client-side encryption flow in the TypeScript UI:
- Password-derived key encryption before upload.
- Local decryption after download.
- Optional encrypted password remembering on device (opt-in).

## Assets
- User file plaintext.
- User encryption password.
- Encryption metadata (`salt`, `iv`, `iterations`, original name/size).
- Stored remembered password ciphertext.

## Trust Boundaries
- **Browser UI runtime:** trusted execution environment for cryptographic operations.
- **Backend/storage:** untrusted for plaintext confidentiality; trusted for availability and metadata integrity controls.
- **Local device storage:** semi-trusted; protected at-rest via encrypted blob, but still vulnerable to full browser compromise.

## Threats and Mitigations

### 1) Weak user-chosen passwords
**Threat:** low-entropy passwords enable offline brute-force.

**Mitigations implemented:**
- Password policy UX requires stronger passphrases (length, upper/lower/number/symbol, common-pattern rejection).
- PBKDF2 iterations remain high and encoded in metadata.

**Residual risk:** motivated attackers can still brute-force weak-but-policy-compliant passwords.

### 2) Metadata tampering or wrong password injection
**Threat:** decryption failures or confusion via modified metadata.

**Mitigations implemented:**
- AES-GCM authentication failures fail closed during decryption.
- File-specific remembered-password lookup key incorporates path and metadata-derived fields.

**Residual risk:** metadata remains client-visible and not signed end-to-end.

### 3) Device storage disclosure
**Threat:** stored remembered passwords leaked from local storage.

**Mitigations implemented:**
- Remembering passwords is explicit opt-in.
- Remembered value is encrypted with a non-extractable WebCrypto AES key persisted in IndexedDB.
- Clear-on-failure behavior removes stale/invalid remembered credentials.

**Residual risk:** if browser context is fully compromised (XSS/session hijack), attacker may request decrypt operations in-process.

### 4) XSS and malicious script execution
**Threat:** script injection can exfiltrate plaintext/passwords at runtime.

**Mitigations recommended:**
- Strict CSP (no unsafe-inline/eval), dependency hygiene, output encoding, and React escaping discipline.
- Security headers + periodic frontend dependency review.
- Keep crypto in worker path for reduced UI-thread exposure (already supported).

### 5) DoS / oversized file processing
**Threat:** memory/CPU exhaustion during crypto operations.

**Mitigations implemented:**
- Chunked encryption/decryption path.
- Progress instrumentation and worker offload.

## Operational Security Checklist
- [x] Document password reset/lost-password expectations (server cannot recover client-only encrypted payload). *(SEC-201 closeout package)*
- [x] Review CSP and script loading policy before production rollout. *(SEC-201)*
- [x] Add telemetry for decrypt failure reasons (without sensitive content). *(SEC-202)*
- [x] Add user-facing control to clear all remembered passwords from this device. *(SEC-203)*
- [x] Include this flow in regular threat-model review cadence. *(SEC-204)*

## Recurring Threat-Model Cadence
- Cadence: **quarterly** (or sooner when crypto/storage architecture changes).
- Owner: **security-review-board** with file-manager engineering participation.
- Release gate: `python scripts/check_security_release_gate.py` validates checklist closure before release promotion.

## Go/No-Go Recommendation
Proceed with release only when `docs/security-release-gate.json` remains green and recent per gate policy.

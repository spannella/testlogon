# GAP-0025: Webhook `secret` is stored in plaintext in DynamoDB

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: KYC-021 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/KYC-021.md`); see also `docs/tickets/writeups/KYC-021.md`

## Location
`secret`

## Problem / Impact
Webhook `secret` is stored in plaintext in DynamoDB

## Fix
encrypt the secret with KMS (reuse `app/core/crypto.py`'s `kms_encrypt` / `kms_decrypt`) before storing and decrypt on read in `_emit_callback`; alternatively store a PBKDF2-derived verification hash and require partners to rotate

## Notes
This gap was identified by the second-pass as-built review of KYC-021. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

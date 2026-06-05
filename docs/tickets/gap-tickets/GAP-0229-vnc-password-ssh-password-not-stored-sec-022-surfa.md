# GAP-0229: VNC password / SSH password not stored (SEC-022 surface)

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-006 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/INFRA-006.md`); see also `docs/tickets/writeups/INFRA-006.md`

## Location
`app/services/connection_profiles.py:50,171-252`

## Problem / Impact
VNC password / SSH password not stored (SEC-022 surface)

## Fix
add optional `vnc_password` / `ssh_password` fields with KMS-encrypt on write (using `app/core/crypto.kms_encrypt`) and `has_password: bool` on read; never return plaintext (aligns with SEC-022 pattern)

## Notes
This gap was identified by the second-pass as-built review of INFRA-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

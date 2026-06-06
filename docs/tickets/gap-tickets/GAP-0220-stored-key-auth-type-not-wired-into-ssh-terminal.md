# GAP-0220: `stored_key` auth type NOT wired into SSH terminal

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-002 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/INFRA-002.md`); see also `docs/tickets/writeups/INFRA-002.md`

## Location
`stored_key`

## Problem / Impact
the entire "private key never reaches the browser" security guarantee is therefore not delivered

## Fix
add `"stored_key"` to the `authType` allowlist; in the connect handler, if `authType == "stored_key"` fetch `keyId` from payload, call `get_decrypted_private_key(user_sub, key_id)`, pass result as `private_key` to `ParamikoSshBridge`, and call `record_connection()` on the associated host

## Notes
This gap was identified by the second-pass as-built review of INFRA-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.

# GAP-0031: No `POST /{packet_id}/signers` API endpoint

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: CRIT (Critical) · **Source ticket**: SIGN-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/SIGN-001.md`); see also `docs/tickets/writeups/SIGN-001.md`

## Location
`POST /{packet_id}/signers`

## Problem / Impact
No `POST /{packet_id}/signers` API endpoint

## Fix
add `POST /{packet_id}/signers` and `DELETE /{packet_id}/signers/{signer_id}` per ticket §2.1

## Notes
This gap was identified by the second-pass as-built review of SIGN-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

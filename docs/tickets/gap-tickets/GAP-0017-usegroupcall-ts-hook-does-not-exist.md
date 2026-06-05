# GAP-0017: `useGroupCall.ts` hook does not exist

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: CRIT (Critical) · **Source ticket**: CALL-012 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/CALL-012.md`); see also `docs/tickets/writeups/CALL-012.md`

## Location
`useGroupCall.ts`

## Problem / Impact
`useGroupCall.ts` hook does not exist

## Fix
implement hook with mesh/SFU mode selection driven by join response per §4.1

## Notes
This gap was identified by the second-pass as-built review of CALL-012. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

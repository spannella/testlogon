# GAP-0144: No automatic `call.end` signal sent to remote peer on `failure` phase

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: CALL-008 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/CALL-008.md`); see also `docs/tickets/writeups/CALL-008.md`

## Location
`call.end`

## Problem / Impact
remote peer overlay stays visible and DDB session remains non-terminal until stale-session scan

## Fix
add `useEffect` on `phase === "failure"` to call `callActionMutation.mutate({action:"end", callId, reason:"reconnect_failed"})` per §4.1

## Notes
This gap was identified by the second-pass as-built review of CALL-008. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.

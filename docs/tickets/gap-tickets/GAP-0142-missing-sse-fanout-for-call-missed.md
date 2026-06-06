# GAP-0142: Missing SSE fanout for `call.missed`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: CALL-007 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/CALL-007.md`); see also `docs/tickets/writeups/CALL-007.md`

## Location
`call.missed`

## Problem / Impact
callee learns of timeout only via slow SSE poll (up to 1-3s delay); callee ringing UI rings past intended timeout

## Fix
add `fanout_event_to_conversation(...)` call after `timeout_call()` in both the endpoint and the backstop per §4.1

## Notes
This gap was identified by the second-pass as-built review of CALL-007. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.

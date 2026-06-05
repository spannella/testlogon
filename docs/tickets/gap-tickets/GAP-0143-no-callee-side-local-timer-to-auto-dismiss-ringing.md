# GAP-0143: No callee-side local timer to auto-dismiss ringing overlay

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: CALL-007 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/CALL-007.md`); see also `docs/tickets/writeups/CALL-007.md`

## Location
`frontend/src/pages/messages/ConversationView.tsx`

## Problem / Impact
if `call.missed` SSE event is lost or delayed, callee sees ringing UI indefinitely

## Fix
add `useEffect` firing `REMOTE_DECLINE` at `ringing_timeout + 2000ms` on `incoming_ringing` phase per §4.2

## Notes
This gap was identified by the second-pass as-built review of CALL-007. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

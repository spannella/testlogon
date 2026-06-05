# GAP-0124: `behavior="end"` not fully wired in accept handler

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: BCAST-011 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BCAST-011.md`); see also `docs/tickets/writeups/BCAST-011.md`

## Location
`behavior="end"`

## Problem / Impact
when `behavior="end"`, the accept route transitions session to `"private"` status but never calls `stop_session_with_provider()`; MediaLive channel continues running

## Fix
call `stop_session_with_provider(session_id, actor, reason="go_private_end")` when `body.behavior == "end"`

## Notes
This gap was identified by the second-pass as-built review of BCAST-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

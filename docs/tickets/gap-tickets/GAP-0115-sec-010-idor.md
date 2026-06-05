# GAP-0115: SEC-010 IDOR

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: BCAST-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BCAST-004.md`); see also `docs/tickets/writeups/BCAST-004.md`

## Location
`broadcast.py:717`

## Problem / Impact
SSE event stream lacks viewer access check

## Fix
call `check_viewer_access(session_id, ctx["user_sub"], ...)` before queue subscription

## Notes
This gap was identified by the second-pass as-built review of BCAST-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

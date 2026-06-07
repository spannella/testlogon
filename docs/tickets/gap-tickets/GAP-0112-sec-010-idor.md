# GAP-0112: SEC-010 IDOR

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: BCAST-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BCAST-002.md`); see also `docs/tickets/writeups/BCAST-002.md`

## Location
`broadcast.py:717`

## Problem / Impact
SSE event stream lacks viewer access check

## Fix
call `check_viewer_access(session_id, ctx["user_sub"], ...)` before subscribing

## Notes
This gap was identified by the second-pass as-built review of BCAST-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

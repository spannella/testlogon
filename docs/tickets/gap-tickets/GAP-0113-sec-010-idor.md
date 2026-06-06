# GAP-0113: SEC-010 IDOR

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: BCAST-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BCAST-002.md`); see also `docs/tickets/writeups/BCAST-002.md`

## Location
`broadcast.py:1763`

## Problem / Impact
chat stream lacks viewer access check

## Fix
call `check_viewer_access` and pass `viewer_user_id=ctx["user_sub"]` to `_chat_msg_out`

## Notes
This gap was identified by the second-pass as-built review of BCAST-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

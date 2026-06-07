# GAP-0116: SEC-010 IDOR

**Status**: No change needed (covered by GAP-0113/0114, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: BCAST-005 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BCAST-005.md`); see also `docs/tickets/writeups/BCAST-005.md`

## Location
`check_viewer_access`

## Problem / Impact
chat SSE stream no `check_viewer_access`

## Fix
call `check_viewer_access` + pass `viewer_user_id=ctx["user_sub"]` to `_chat_msg_out`

## Notes
This gap was identified by the second-pass as-built review of BCAST-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

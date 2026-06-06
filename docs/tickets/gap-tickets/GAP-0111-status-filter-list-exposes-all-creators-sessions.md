# GAP-0111: Status-filter list exposes all creators' sessions

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: BCAST-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BCAST-001.md`); see also `docs/tickets/writeups/BCAST-001.md`

## Location
`broadcast.py:316`

## Problem / Impact
non-admin broadcaster can enumerate all sessions platform-wide via `?status=live`

## Fix
scope `list_sessions_by_status` to `creator_id=ctx["user_sub"]` for non-admin callers

## Notes
This gap was identified by the second-pass as-built review of BCAST-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

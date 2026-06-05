# GAP-0152: dashboard_sse_publish has no call sites

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: CREATOR-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/CREATOR-003.md`); see also `docs/tickets/writeups/CREATOR-003.md`

## Location
`app/services/dashboard_sse.py:39`

## Problem / Impact
SSE publish infrastructure exists but real-time earnings/milestone events are never pushed

## Fix
call dashboard_sse_publish from write_tip_ledger (earnings:update) and check_milestone (milestone:reached)

## Notes
This gap was identified by the second-pass as-built review of CREATOR-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

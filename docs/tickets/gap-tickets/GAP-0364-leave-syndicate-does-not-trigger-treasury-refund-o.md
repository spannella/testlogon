# GAP-0364: leave_syndicate does NOT trigger treasury refund-on-leave

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SYND-004 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/SYND-004.md`); see also `docs/tickets/writeups/SYND-004.md`

## Location
`app/services/syndicates.py:393-426`

## Problem / Impact
the spec (SYND-004 §3.3) requires `refund_on_member_leave` to be called before removing the member; the current implementation removes the member and dissolves the syndicate without calculating or issuing any proportional refund; members lose contributed funds on departure

## Fix
import `syndicate_treasury.refund_on_member_leave` (and `refund_on_dissolution`) and call them inside `leave_syndicate` before `_remove_member`, mirroring the design in SYND-004 §3.3

## Notes
This gap was identified by the second-pass as-built review of SYND-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.

# GAP-0021: `dissolve_group()` never calls `dissolve_treasury()`

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: GROUP-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/GROUP-004.md`); see also `docs/tickets/writeups/GROUP-004.md`

## Location
`dissolve_group()`

## Problem / Impact
result: when a group is dissolved all contributed and donated funds are permanently orphaned in the `billing` table under `GROUP#{group_id}` with no wallet to debit them from (group is dissolved but treasury balance remains positive); contributors get no refund and donations never reach escrow

## Fix
add `from app.services import group_treasury as treasury_svc` to `user_groups.py` and call `treasury_svc.dissolve_treasury(group_id)` before member cleanup in `dissolve_group()`

## Notes
This gap was identified by the second-pass as-built review of GROUP-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0153: check_milestone has no call sites

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: CREATOR-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/CREATOR-003.md`); see also `docs/tickets/writeups/CREATOR-003.md`

## Location
`app/services/milestones.py:49`

## Problem / Impact
milestones can only be created by manually seeding DynamoDB; no automatic detection

## Fix
call check_milestone from tip_ledger write, subscription signup, and analytics rollup completion

## Notes
This gap was identified by the second-pass as-built review of CREATOR-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

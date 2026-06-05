# GAP-0305: frontend entirely absent

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MOD-003 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/MOD-003.md`); see also `docs/tickets/writeups/MOD-003.md`

## Location
`frontend/src/`

## Problem / Impact
frontend entirely absent

## Fix
create the four files listed in section 4.6-4.7 and add routes per section 4.8

## Notes
This gap was identified by the second-pass as-built review of MOD-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

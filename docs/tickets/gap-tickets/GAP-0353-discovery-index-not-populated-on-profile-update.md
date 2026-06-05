# GAP-0353: Discovery index not populated on profile update

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SOC-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/SOC-003.md`); see also `docs/tickets/writeups/SOC-003.md`

## Location
`app/services/profile.py:apply_profile_update()`

## Problem / Impact
Discovery index not populated on profile update

## Fix
add `index_user_for_discovery(user_sub)` (non-fatal try/except) at end of `apply_profile_update()` per ticket §4.6

## Notes
This gap was identified by the second-pass as-built review of SOC-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

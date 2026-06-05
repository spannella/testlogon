# GAP-0047: BROADCAST_PREROLL_ENABLED and BROADCAST_MIDROLL_ENABLED flags absent

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-006 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-006.md`); see also `docs/tickets/writeups/ADS-006.md`

## Location
`app/core/settings.py`

## Problem / Impact
broadcast ad features cannot be independently gated for rollout

## Fix
add both flags to settings.py and gate in build_pre_roll and trigger_ad_break_route

## Notes
This gap was identified by the second-pass as-built review of ADS-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

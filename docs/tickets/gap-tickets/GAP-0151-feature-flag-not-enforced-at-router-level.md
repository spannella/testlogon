# GAP-0151: feature flag not enforced at router level

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: CREATOR-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/CREATOR-002.md`); see also `docs/tickets/writeups/CREATOR-002.md`

## Location
`app/routers/fan_club.py`

## Problem / Impact
FAN_CLUBS_ENABLED=0 has no effect; all endpoints remain live

## Fix
add _check_enabled() call in each handler matching collaborations.py:89 pattern

## Notes
This gap was identified by the second-pass as-built review of CREATOR-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

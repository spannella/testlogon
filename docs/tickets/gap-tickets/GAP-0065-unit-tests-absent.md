# GAP-0065: unit tests absent

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADS-016 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-016.md`); see also `docs/tickets/writeups/ADS-016.md`

## Location
`tests/`

## Problem / Impact
no test_ad_scheduling.py; all dayparting logic untested offline

## Fix
create test_ad_scheduling.py with 9 tests covering validation, eligibility, flight resolution, and pacing

## Notes
This gap was identified by the second-pass as-built review of ADS-016. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

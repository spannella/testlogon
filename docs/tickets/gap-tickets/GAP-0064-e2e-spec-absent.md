# GAP-0064: E2E spec absent

**Status**: No change needed (verified artifacts already exist, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADS-016 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ADS-016.md`); see also `docs/tickets/writeups/ADS-016.md`

## Location
`frontend/e2e/`

## Problem / Impact
no ad-scheduling.spec.ts; 12 tests in sections 408-410 are entirely unwritten

## Fix
create spec covering dayparting CRUD, flight scheduling, eligibility and pacing endpoints

## Notes
This gap was identified by the second-pass as-built review of ADS-016. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0063: E2E spec absent

**Status**: No change needed (verified artifacts already exist, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADS-015 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ADS-015.md`); see also `docs/tickets/writeups/ADS-015.md`

## Location
`frontend/e2e/`

## Problem / Impact
no ad-affiliate-promo.spec.ts; redirect URL, cookie setting, and attribution recording are untested

## Fix
create spec with 18 tests covering sections 405-408

## Notes
This gap was identified by the second-pass as-built review of ADS-015. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

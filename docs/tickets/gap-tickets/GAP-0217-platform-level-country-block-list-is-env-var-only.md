# GAP-0217: Platform-level country block list is env-var only

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: GEO-001 · **Effort**: ?
**From**: gap audit (`docs/tickets/gaps/GEO-001.md`); see also `docs/tickets/writeups/GEO-001.md`

## Location
`app/services/geo_check.py:53`

## Problem / Impact
Platform-level country block list is env-var only

## Fix
See source write-up.

## Notes
This gap was identified by the second-pass as-built review of GEO-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0057: ads:* scopes not surfaced in frontend API key creation UI

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-011 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-011.md`); see also `docs/tickets/writeups/ADS-011.md`

## Location
`frontend/src/pages/security/`

## Problem / Impact
advertisers cannot select ads:manage/read/serve scopes via the UI; must use direct API call

## Fix
add ads:manage, ads:read, ads:serve to the capability selector component

## Notes
This gap was identified by the second-pass as-built review of ADS-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

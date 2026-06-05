# GAP-0069: account suspension does not cascade to pause active campaigns

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-018 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-018.md`); see also `docs/tickets/writeups/ADS-018.md`

## Location
`app/services/admin_ad_platform.py:moderate_account`

## Problem / Impact
suspended advertiser's active campaigns continue serving ads

## Fix
in moderate_account for action=suspend, update all active campaigns for the account to status=paused

## Notes
This gap was identified by the second-pass as-built review of ADS-018. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

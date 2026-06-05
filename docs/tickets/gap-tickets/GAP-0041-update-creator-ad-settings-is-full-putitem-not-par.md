# GAP-0041: update_creator_ad_settings is full PutItem, not partial update

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-003.md`); see also `docs/tickets/writeups/ADS-003.md`

## Location
`app/services/creator_ad_prefs.py:update_creator_ad_settings`

## Problem / Impact
PATCH with only allow_ads=false silently clears all other stored preferences

## Fix
replace PutItem with UpdateExpression SET using only non-None fields

## Notes
This gap was identified by the second-pass as-built review of ADS-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

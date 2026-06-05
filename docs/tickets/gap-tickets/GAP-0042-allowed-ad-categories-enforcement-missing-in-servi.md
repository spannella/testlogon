# GAP-0042: allowed_ad_categories enforcement missing in serving engine

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-003.md`); see also `docs/tickets/writeups/ADS-003.md`

## Location
`app/services/ad_serving.py`

## Problem / Impact
creators setting allowed_ad_categories still receive ads from non-matching categories

## Fix
read allowed_ad_categories from creator_settings in serve_ad campaign loop and skip non-matching campaigns

## Notes
This gap was identified by the second-pass as-built review of ADS-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

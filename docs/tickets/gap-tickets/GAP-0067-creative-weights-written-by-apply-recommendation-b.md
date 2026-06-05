# GAP-0067: creative_weights written by apply_recommendation but not consumed by serving engine

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-017 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-017.md`); see also `docs/tickets/writeups/ADS-017.md`

## Location
`app/services/ad_serving.py:serve_ad`

## Problem / Impact
applying reallocate_budget recommendation has no observable effect on ad delivery

## Fix
read campaign.get("creative_weights") in serve_ad and pass to random.choices as weights

## Notes
This gap was identified by the second-pass as-built review of ADS-017. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

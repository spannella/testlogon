# GAP-0062: ROAS calculation service not implemented

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-015 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ADS-015.md`); see also `docs/tickets/writeups/ADS-015.md`

## Location
`app/services/`

## Problem / Impact
no ad_roas.py, no GET /ui/ads/campaigns/{id}/roas endpoint; advertisers cannot measure campaign effectiveness via conversion attribution

## Fix
create app/services/ad_roas.py with calculate_campaign_roas and wire GET endpoint in ad_creative_affiliate.py router

## Notes
This gap was identified by the second-pass as-built review of ADS-015. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

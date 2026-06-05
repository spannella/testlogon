# GAP-0044: bid_cpm_cents not a campaign field

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-004.md`); see also `docs/tickets/writeups/ADS-004.md`

## Location
`app/models.py:CampaignCreateIn`

## Problem / Impact
all campaigns default to 500 CPM; auction cannot rank by advertiser bid

## Fix
add bid_cpm_cents to CampaignCreateIn/CampaignOut (coordinate with ADS-001 model)

## Notes
This gap was identified by the second-pass as-built review of ADS-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0072: BROADCAST_ADS_BILLING_ENABLED feature flag missing

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-020 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-020.md`); see also `docs/tickets/writeups/ADS-020.md`

## Location
`app/core/settings.py`

## Problem / Impact
billing integration cannot be deployed and rolled back independently

## Fix
add broadcast_ads_billing_enabled bool to settings.py; add to .env.local.example

## Notes
This gap was identified by the second-pass as-built review of ADS-020. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0071: record_ad_event does not write to ad_billing, ad_fraud_prevention, or ad_analytics

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADS-020 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ADS-020.md`); see also `docs/tickets/writeups/ADS-020.md`

## Location
`app/services/broadcast_ads.py:record_ad_event:185–216`

## Problem / Impact
broadcast impressions generate zero revenue, zero fraud signals, zero analytics

## Fix
wire charge_ad_event, check_impression_fraud, and record_impression_event into record_ad_event gated by BROADCAST_ADS_BILLING_ENABLED flag

## Notes
This gap was identified by the second-pass as-built review of ADS-020. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

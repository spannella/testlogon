# GAP-0053: record_transparency() never called from billing pipeline

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADS-010 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-010.md`); see also `docs/tickets/writeups/ADS-010.md`

## Location
`app/services/content_ad_controls.py:243`

## Problem / Impact
get_advertiser_transparency always returns empty array; transparency feature is non-functional

## Fix
call record_transparency from ad_billing._split_revenue after writing creator credit

## Notes
This gap was identified by the second-pass as-built review of ADS-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

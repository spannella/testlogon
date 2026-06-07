# GAP-0050: compute_hourly_rollup never called by anything

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADS-008 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ADS-008.md`); see also `docs/tickets/writeups/ADS-008.md`

## Location
`app/services/ad_analytics.py:compute_hourly_rollup`

## Problem / Impact
AdAnalyticsRollups table always empty; all dashboard endpoints return zeros

## Fix
register hourly background task in app/main.py startup that calls compute_hourly_rollup for all active campaigns

## Notes
This gap was identified by the second-pass as-built review of ADS-008. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

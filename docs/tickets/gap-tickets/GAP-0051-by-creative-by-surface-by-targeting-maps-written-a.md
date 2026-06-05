# GAP-0051: by_creative, by_surface, by_targeting maps written as empty dicts

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADS-008 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ADS-008.md`); see also `docs/tickets/writeups/ADS-008.md`

## Location
`app/services/ad_analytics.py:compute_hourly_rollup:201–203`

## Problem / Impact
get_breakdown always returns empty arrays for all dimension breakdowns

## Fix
compute breakdown maps from billing ledger entries grouped by creative_id and surface

## Notes
This gap was identified by the second-pass as-built review of ADS-008. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

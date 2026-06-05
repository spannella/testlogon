# GAP-0054: dynamic per-creator revenue share not connected to billing engine

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-010 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ADS-010.md`); see also `docs/tickets/writeups/ADS-010.md`

## Location
`app/services/ad_billing.py:_split_revenue`

## Problem / Impact
hard-coded PLATFORM_REVENUE_SHARE_PCT=30 used for all creators; per-creator bps overrides ignored

## Fix
call get_creator_revenue_share_bps(creator_id) and convert bps to pct in _split_revenue

## Notes
This gap was identified by the second-pass as-built review of ADS-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

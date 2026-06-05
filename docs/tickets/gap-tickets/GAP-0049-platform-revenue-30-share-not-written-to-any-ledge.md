# GAP-0049: platform revenue (30% share) not written to any ledger

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADS-007 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-007.md`); see also `docs/tickets/writeups/ADS-007.md`

## Location
`app/services/ad_billing.py:_split_revenue`

## Problem / Impact
no audit trail for platform-side revenue; reconciliation is impossible

## Fix
write platform_revenue entry to ad_billing table with PK=PLATFORM#revenue after each split

## Notes
This gap was identified by the second-pass as-built review of ADS-007. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

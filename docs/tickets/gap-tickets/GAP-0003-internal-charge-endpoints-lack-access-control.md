# GAP-0003: internal charge endpoints lack access control

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: ADS-007 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-007.md`); see also `docs/tickets/writeups/ADS-007.md`

## Location
`app/routers/ads.py:447,460,473`

## Problem / Impact
any authenticated user can post arbitrary charges against any advertiser account, draining balances to zero

## Fix
add account ownership verification before each charge handler, or move to require_admin_or_root

## Notes
This gap was identified by the second-pass as-built review of ADS-007. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

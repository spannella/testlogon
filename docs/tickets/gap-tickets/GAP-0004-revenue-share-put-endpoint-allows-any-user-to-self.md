# GAP-0004: revenue-share PUT endpoint allows any user to self-set share to 100%

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: ADS-010 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-010.md`); see also `docs/tickets/writeups/ADS-010.md`

## Location
`app/routers/content_ad_controls.py:116`

## Problem / Impact
creator can set revenue_share_bps=10000 (100%), giving 0% to platform; severe revenue leakage

## Fix
gate PUT /revenue-share on require_admin_or_root; add creator_sub to request body

## Notes
This gap was identified by the second-pass as-built review of ADS-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

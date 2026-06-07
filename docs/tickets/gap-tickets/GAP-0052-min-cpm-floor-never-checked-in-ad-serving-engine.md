# GAP-0052: min-CPM floor never checked in ad serving engine

**Status**: No change needed (covered by GAP-0042, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADS-010 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-010.md`); see also `docs/tickets/writeups/ADS-010.md`

## Location
`app/services/ad_serving.py:serve_ad`

## Problem / Impact
ads with bid below creator's minimum CPM still serve; creator's min_cpm_cents setting has no effect

## Fix
read get_full_ad_settings(creator_id) in campaign loop and skip campaigns with bid_cpm < min_cpm

## Notes
This gap was identified by the second-pass as-built review of ADS-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

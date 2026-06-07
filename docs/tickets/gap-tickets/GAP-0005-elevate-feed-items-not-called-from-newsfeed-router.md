# GAP-0005: elevate_feed_items() not called from newsfeed router

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: CRIT (Critical) · **Source ticket**: ADS-012 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-012.md`); see also `docs/tickets/writeups/ADS-012.md`

## Location
`app/routers/newsfeed.py`

## Problem / Impact
creators are charged for boosts that have no effect on reach; every boost is a misleading charge

## Fix
call elevate_feed_items(posts, viewer_id) in GET /feed handler after organic post fetch

## Notes
This gap was identified by the second-pass as-built review of ADS-012. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0002: serve_broadcast_ad stub not wired to ADS-004 engine

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: CRIT (Critical) · **Source ticket**: ADS-006 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-006.md`); see also `docs/tickets/writeups/ADS-006.md`

## Location
`app/services/broadcast_ads.py:55–83`

## Problem / Impact
all broadcast viewers see same hardcoded house creative; no targeting, frequency caps, or budget enforcement

## Fix
replace stub body with delegation to app.services.ad_serving.serve_ad with graceful degradation

## Notes
This gap was identified by the second-pass as-built review of ADS-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0007: serve_broadcast_ad not wired to real ad serving engine

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: ADS-020 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-020.md`); see also `docs/tickets/writeups/ADS-020.md`

## Location
`app/services/broadcast_ads.py:55–83`

## Problem / Impact
all broadcast ads serve hardcoded house stub; no advertiser spend, no targeting, no frequency caps

## Fix
replace stub with serve_ad() delegation; fall back to house creative on engine error

## Notes
This gap was identified by the second-pass as-built review of ADS-020. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0070: frontend AdminAdDashboard absent

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADS-018 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/ADS-018.md`); see also `docs/tickets/writeups/ADS-018.md`

## Location
`frontend/src/pages/admin/ads/`

## Problem / Impact
no AdminAdDashboard.tsx or adminAds.ts API endpoints; admins have no UI access to the ad management backend

## Fix
create AdminAdDashboard.tsx and frontend/src/api/endpoints/adminAds.ts

## Notes
This gap was identified by the second-pass as-built review of ADS-018. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

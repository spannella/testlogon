# GAP-0066: frontend components entirely absent

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-017 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ADS-017.md`); see also `docs/tickets/writeups/ADS-017.md`

## Location
`frontend/src/pages/ads/`

## Problem / Impact
no OptimizationPanel.tsx, RecommendationCards.tsx, ABTestResults.tsx, or adOptimization.ts API wrappers; advertisers cannot access optimization through the UI

## Fix
create all four files per ticket spec sections 3.8-3.9

## Notes
This gap was identified by the second-pass as-built review of ADS-017. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

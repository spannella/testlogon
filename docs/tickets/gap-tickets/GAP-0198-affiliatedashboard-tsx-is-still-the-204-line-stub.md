# GAP-0198: AffiliateDashboard.tsx is still the 204-line stub

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-010 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/FIN-010.md`); see also `docs/tickets/writeups/FIN-010.md`

## Location
`frontend/src/pages/affiliates/AffiliateDashboard.tsx`

## Problem / Impact
All analytics tabs (Analytics, Earnings, Top Products), summary cards, and chart components specified in the ticket are absent; the frontend API wrappers for the new endpoints do not exist in `affiliates.ts`

## Fix
rewrite dashboard with tabs, add `getAffiliateSummary`/`getAffiliateEarnings`/`getLinkClickTimeSeries`/`getTopProducts` wrappers, add TypeScript types

## Notes
This gap was identified by the second-pass as-built review of FIN-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

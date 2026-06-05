# GAP-0256: Admin reviewer queue page missing

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-005 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/KYC-005.md`); see also `docs/tickets/writeups/KYC-005.md`

## Location
`frontend/src/pages/kyc/KycProofOfFundsReviewQueue.tsx`

## Problem / Impact
reviewers cannot list, view, or adjudicate submissions via the UI; route not registered in App.tsx

## Fix
create page with status filter, DataTable, and adjudicate dialog; add `admin/kyc/proof-of-funds` route

## Notes
This gap was identified by the second-pass as-built review of KYC-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

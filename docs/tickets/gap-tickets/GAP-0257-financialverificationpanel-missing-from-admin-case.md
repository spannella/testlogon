# GAP-0257: FinancialVerificationPanel missing from admin case detail

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-005 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-005.md`); see also `docs/tickets/writeups/KYC-005.md`

## Location
`frontend/src/pages/admin/KycCaseDetailPage.tsx`

## Problem / Impact
reviewer cannot see score, declared amount, risk contribution, or adjudicate from the case view

## Fix
add "Financial Verification" tab fetching `GET /ui/kyc/proof-of-funds/admin/submissions?user_sub=`

## Notes
This gap was identified by the second-pass as-built review of KYC-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.

# GAP-0254: ResidencyVerificationTab missing from admin case detail

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-004 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/KYC-004.md`); see also `docs/tickets/writeups/KYC-004.md`

## Location
`frontend/src/pages/admin/KycCaseDetailPage.tsx`

## Problem / Impact
reviewer cannot see address comparison or match status per document in the case view

## Fix
add "Residency" tab with two-column address comparison and per-field match badges

## Notes
This gap was identified by the second-pass as-built review of KYC-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

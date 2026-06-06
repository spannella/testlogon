# GAP-0250: VerificationCallPanel missing from admin case detail

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-003 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/KYC-003.md`); see also `docs/tickets/writeups/KYC-003.md`

## Location
`frontend/src/pages/admin/KycCaseDetailPage.tsx`

## Problem / Impact
reviewers cannot see call status, outcome, or recording reference from the case view

## Fix
add collapsible `VerificationCallPanel` section with schedule/conduct/result states and a "Schedule Call" dialog

## Notes
This gap was identified by the second-pass as-built review of KYC-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.

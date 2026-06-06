# GAP-0288: `KycPiiSection` component is never used in any page

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-023 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-023.md`); see also `docs/tickets/writeups/KYC-023.md`

## Location
`KycPiiSection`

## Problem / Impact
the component composes `PiiFieldDisplay` + `PiiAuditLog` for the admin case detail view as specified in the ticket (§3.12), but `frontend/src/pages/admin/KycCaseDetailPage.tsx` (685 lines) imports neither `KycPiiSection` nor `PiiFieldDisplay`; admins cannot view masked PII or click "Reveal" despite the backend endpoints being fully implemented

## Fix
import `KycPiiSection` into `KycCaseDetailPage.tsx` and render it in the case detail body with `caseId`, `isAssigned`, and `isRoot` props

## Notes
This gap was identified by the second-pass as-built review of KYC-023. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.

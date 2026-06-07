# GAP-0244: KycCaseDetailPage missing

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/KYC-001.md`); see also `docs/tickets/writeups/KYC-001.md`

## Location
`frontend/src/pages/admin/KycCaseDetailPage.tsx`

## Problem / Impact
no document viewer, no approve/reject/request-info dialogs, no timeline; App.tsx lazy-import fails at runtime

## Fix
create two-column page with CaseInfoPanel, CaseActionPanel (all three dialogs), CaseTimeline

## Notes
This gap was identified by the second-pass as-built review of KYC-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Resolved — already implemented (verified 2026-06-06)

SKIP/already-built: KycCaseDetailPage.tsx (685 lines) already has DocumentViewer, CaseTimeline, Approve/Reject/Request-Info dialogs with reason codes + optimistic-conflict handling, lazy import + route. E2E section 155 covers it. No code change needed.

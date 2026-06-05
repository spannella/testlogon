# GAP-0247: ExtractionResultsPanel not integrated into admin case detail

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-002.md`); see also `docs/tickets/writeups/KYC-002.md`

## Location
`frontend/src/pages/admin/KycCaseDetailPage.tsx`

## Problem / Impact
reviewer cannot see extracted OCR fields, match status, or overall confidence without switching to a separate queue page

## Fix
add "Document Extraction" tab with per-document ExtractionResultsPanel calling `GET /ui/kyc/documents/admin/by-status?case_id=`

## Notes
This gap was identified by the second-pass as-built review of KYC-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

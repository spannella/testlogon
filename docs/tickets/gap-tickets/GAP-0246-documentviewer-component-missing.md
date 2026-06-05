# GAP-0246: DocumentViewer component missing

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-001.md`); see also `docs/tickets/writeups/KYC-001.md`

## Location
`frontend/src/components/shared/DocumentViewer.tsx`

## Problem / Impact
no zoom/rotate/fullscreen for identity document review

## Fix
create component with tab bar, zoom/rotation controls, VerificationStateBadge overlay, presigned-URL caching

## Notes
This gap was identified by the second-pass as-built review of KYC-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

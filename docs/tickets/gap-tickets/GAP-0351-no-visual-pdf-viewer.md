# GAP-0351: No visual PDF viewer

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SIGN-001 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/SIGN-001.md`); see also `docs/tickets/writeups/SIGN-001.md`

## Location
`frontend/src/pages/files/SignaturePacketComposer.tsx:609-629`

## Problem / Impact
No visual PDF viewer

## Fix
install react-pdf, render source PDF pages, overlay field boxes per ticket §1b

## Notes
This gap was identified by the second-pass as-built review of SIGN-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

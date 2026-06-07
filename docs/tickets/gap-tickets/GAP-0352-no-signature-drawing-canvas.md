# GAP-0352: No signature drawing canvas

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SIGN-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/SIGN-001.md`); see also `docs/tickets/writeups/SIGN-001.md`

## Location
`SignaturePacketComposer.tsx:565`

## Problem / Impact
No signature drawing canvas

## Fix
add an HTML5 canvas component for freehand drawing per ticket §1c

## Notes
This gap was identified by the second-pass as-built review of SIGN-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.

# GAP-0365: Ctrl+Enter send not wired in ComposeBar

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: UX-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/UX-002.md`); see also `docs/tickets/writeups/UX-002.md`

## Location
`frontend/src/pages/messages/ComposeBar.tsx:690-694`

## Problem / Impact
Ctrl+Enter send not wired in ComposeBar

## Fix
add `if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); void handleSubmit(); }` to `handleKeyDown` in `ComposeBar.tsx:694`

## Notes
This gap was identified by the second-pass as-built review of UX-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.

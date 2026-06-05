# GAP-0156: /delegates route missing from App.tsx

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: DELEGATE-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/DELEGATE-001.md`); see also `docs/tickets/writeups/DELEGATE-001.md`

## Location
`frontend/src/App.tsx:~346`

## Problem / Impact
DelegatesPage exists and is functional but cannot be navigated to; all E2E tests that navigate to the page will fail

## Fix
add <Route path="delegates" element={<DelegatesPage />} /> alongside delegation-api route

## Notes
This gap was identified by the second-pass as-built review of DELEGATE-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

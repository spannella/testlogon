# GAP-0109: frontend shows hard dead-end with no recovery UI

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AUTH-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AUTH-001.md`); see also `docs/tickets/writeups/AUTH-001.md`

## Location
`frontend/src/pages/Register.tsx:616`

## Problem / Impact
emailStatus==="unavailable" renders only "An account with this email already exists" with no resend button or recovery link; next button is disabled; user cannot proceed

## Fix
split into unavailable_verified (keep error) and unavailable_unverified (show resend + start-over options); wire to POST /register/resend

## Notes
This gap was identified by the second-pass as-built review of AUTH-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

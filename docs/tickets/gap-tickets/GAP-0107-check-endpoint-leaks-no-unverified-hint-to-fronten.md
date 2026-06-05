# GAP-0107: /check endpoint leaks no unverified hint to frontend

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: AUTH-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AUTH-001.md`); see also `docs/tickets/writeups/AUTH-001.md`

## Location
`app/routers/register.py:153`

## Problem / Impact
register_check returns only {"available": bool}; no distinction between pending_verification and active accounts; frontend cannot show recovery UI for abandoned registrations

## Fix
implement check_email_status returning {"available": bool, "unverified": bool}; update RegisterEmailCheckResp model and /check response

## Notes
This gap was identified by the second-pass as-built review of AUTH-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

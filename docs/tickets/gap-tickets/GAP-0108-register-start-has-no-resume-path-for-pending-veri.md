# GAP-0108: /register/start has no resume path for pending_verification accounts

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: AUTH-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AUTH-001.md`); see also `docs/tickets/writeups/AUTH-001.md`

## Location
`app/routers/register.py:114`

## Problem / Impact
re-submitting start for an existing pending_verification email silently returns generic response but issues no new challenge (dev path); user cannot re-trigger verification without direct resend call

## Fix
add resume branch before create_user_record that detects pending_verification and re-issues challenge; gate on REGISTRATION_ALLOW_RESUME_UNVERIFIED setting

## Notes
This gap was identified by the second-pass as-built review of AUTH-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

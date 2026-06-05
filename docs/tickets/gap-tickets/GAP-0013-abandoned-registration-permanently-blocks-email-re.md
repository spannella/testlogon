# GAP-0013: abandoned registration permanently blocks email re-use

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: AUTH-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AUTH-001.md`); see also `docs/tickets/writeups/AUTH-001.md`

## Location
`app/services/registration.py:79`

## Problem / Impact
T.users PutItem and account_state record written at register/start with no TTL; challenge expires but user record persists; is_email_available() returns false; user on different device/browser sees "already exists" dead-end with no recovery path

## Fix
set DDB TTL (registration_expires_at) on T.users and T.account_state items when verification_required=True; add REGISTRATION_PENDING_TTL_DAYS setting

## Notes
This gap was identified by the second-pass as-built review of AUTH-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

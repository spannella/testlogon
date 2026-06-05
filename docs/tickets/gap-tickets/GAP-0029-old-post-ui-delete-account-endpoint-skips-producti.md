# GAP-0029: Old `POST /ui/delete-account` endpoint skips production password verification

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: PLATFORM-018 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/PLATFORM-018.md`); see also `docs/tickets/writeups/PLATFORM-018.md`

## Location
`POST /ui/delete-account`

## Problem / Impact
cross-ref: SEC-018 session revocation

## Fix
remove or redirect the old endpoint, or add `verify_user_password` call matching `account_deletion.py:67`

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-018. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

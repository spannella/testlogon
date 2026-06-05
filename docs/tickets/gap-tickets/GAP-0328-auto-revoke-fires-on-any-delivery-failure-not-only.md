# GAP-0328: Auto-revoke fires on any delivery failure, not only definitive 410/404

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-010 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/PLATFORM-010.md`); see also `docs/tickets/writeups/PLATFORM-010.md`

## Location
`app/services/push.py:300-310`

## Problem / Impact
Auto-revoke fires on any delivery failure, not only definitive 410/404

## Fix
have `web_push_send()` return a 3-value enum or raise a distinct `StaleSubscriptionError` on 410/404 so the caller can distinguish permanent from transient failures; only revoke on permanent

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

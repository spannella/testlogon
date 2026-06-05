# GAP-0330: Auto-revoke fires on ALL web_push_send failures, not only 410 Gone

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-016 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/PLATFORM-016.md`); see also `docs/tickets/writeups/PLATFORM-016.md`

## Location
`app/services/push.py:300-312`

## Problem / Impact
legitimate devices are silently deleted on transient errors

## Fix
have `web_push_send` return a typed result distinguishing `(True, None)` / `(False, "410")` / `(False, "other")`; only revoke on `"410"`

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-016. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

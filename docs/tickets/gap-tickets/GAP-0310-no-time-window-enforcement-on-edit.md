# GAP-0310: no time-window enforcement on edit

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MSG-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/MSG-001.md`); see also `docs/tickets/writeups/MSG-001.md`

## Location
`app/routers/messaging.py:11003`

## Problem / Impact
no time-window enforcement on edit

## Fix
add `if now_ts() - int(msg.get("created_at",0)) > S.message_edit_window_seconds: raise HTTPException(400, ...)` and add `message_edit_window_seconds: int` to `app/core/settings.py`

## Notes
This gap was identified by the second-pass as-built review of MSG-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

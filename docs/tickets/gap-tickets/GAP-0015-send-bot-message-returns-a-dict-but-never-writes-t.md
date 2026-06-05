# GAP-0015: `send_bot_message()` returns a dict but never writes to DynamoDB

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: BOT-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/BOT-001.md`); see also `docs/tickets/writeups/BOT-001.md`

## Location
`send_bot_message()`

## Problem / Impact
the function increments `message_count` and returns a dict but makes no DDB write and does not call into the messaging pipeline; callers relying on it to produce a visible message will get nothing

## Fix
implement `create_internal_bot_message()` helper in `messaging.py` and call it from `send_bot_message()`

## Notes
This gap was identified by the second-pass as-built review of BOT-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0137: `start_bot_scheduler_task` may raise RuntimeError at startup

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: BOT-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BOT-002.md`); see also `docs/tickets/writeups/BOT-002.md`

## Location
`start_bot_scheduler_task`

## Problem / Impact
`start_bot_scheduler_task` may raise RuntimeError at startup

## Fix
convert to `async def` and register with `@app.on_event("startup")`

## Notes
This gap was identified by the second-pass as-built review of BOT-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

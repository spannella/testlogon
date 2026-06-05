# GAP-0133: No post-send trigger hook in `send_text_message()`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: BOT-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/BOT-001.md`); see also `docs/tickets/writeups/BOT-001.md`

## Location
`send_text_message()`

## Problem / Impact
bot auto-reply evaluation is never invoked after a message is persisted; bots are effectively inert for all conversation traffic

## Fix
spawn `asyncio.create_task(_run_bot_trigger_evaluation(...))` after the message write at line ~8053

## Notes
This gap was identified by the second-pass as-built review of BOT-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

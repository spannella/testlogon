# GAP-0138: Orphaned auto-reply rules on bot deletion

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: BOT-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BOT-003.md`); see also `docs/tickets/writeups/BOT-003.md`

## Location
`app/services/chat_bot.py:167`

## Problem / Impact
Orphaned auto-reply rules on bot deletion

## Fix
extend cascade to query and delete `SK begins_with RULE#` items in `T.chat_bots`

## Notes
This gap was identified by the second-pass as-built review of BOT-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

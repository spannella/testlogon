# GAP-0014: `_message_out_from_item` never populates bot fields

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: BOT-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BOT-001.md`); see also `docs/tickets/writeups/BOT-001.md`

## Location
`_message_out_from_item`

## Problem / Impact
`_message_out_from_item` never populates bot fields

## Fix
add `sender_type=merged_item.get("sender_type")`, `bot_id=...`, `bot_name=...`, `bot_avatar_url=...`, `quick_replies=...` to the `return MessageOut(...)` call

## Notes
This gap was identified by the second-pass as-built review of BOT-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

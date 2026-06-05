# GAP-0130: `_find_sort_key()` is O(n) scan for reactions/unlocks

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: BCAST-015 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BCAST-015.md`); see also `docs/tickets/writeups/BCAST-015.md`

## Location
`_find_sort_key()`

## Problem / Impact
forward query scanning up to all messages in session to find one item by `message_id`; unacceptable latency at >5k messages

## Fix
add `MessageIdIndex` GSI to `BroadcastChatMessages` (pk=`message_id`) or accept `sort_key` from caller

## Notes
This gap was identified by the second-pass as-built review of BCAST-015. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0134: Wildcard scope assignments never resolved in `get_bots_for_conversation()`

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: BOT-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/BOT-001.md`); see also `docs/tickets/writeups/BOT-001.md`

## Location
`get_bots_for_conversation()`

## Problem / Impact
only direct `CONV#{conversation_id}` GSI assignments are queried; `SCOPE#ALL_DMS`, `SCOPE#ALL_GROUPS` records have no `GSI1PK` and are never found

## Fix
add a secondary lookup for wildcard-scoped bot assignments per creator

## Notes
This gap was identified by the second-pass as-built review of BOT-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

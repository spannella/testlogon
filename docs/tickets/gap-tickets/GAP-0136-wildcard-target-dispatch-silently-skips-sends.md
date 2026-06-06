# GAP-0136: Wildcard target dispatch silently skips sends

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: BOT-002 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/BOT-002.md`); see also `docs/tickets/writeups/BOT-002.md`

## Location
`app/services/bot_scheduler.py:276`

## Problem / Impact
Wildcard target dispatch silently skips sends

## Fix
implement `_resolve_target_conversations()` to fan out wildcard targets (cap at 500)

## Notes
This gap was identified by the second-pass as-built review of BOT-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

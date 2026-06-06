# GAP-0125: Private chat messages exposed in public chat history

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: BCAST-012 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BCAST-012.md`); see also `docs/tickets/writeups/BCAST-012.md`

## Location
`broadcast_chat_store.py:296`

## Problem / Impact
Private chat messages exposed in public chat history

## Fix
add `FilterExpression=Attr("kind").ne("private_chat")` to `get_chat_history()` by default

## Notes
This gap was identified by the second-pass as-built review of BCAST-012. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

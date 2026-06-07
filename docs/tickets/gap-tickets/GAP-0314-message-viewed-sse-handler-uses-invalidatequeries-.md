# GAP-0314: `message:viewed` SSE handler uses `invalidateQueries` (triggers a full refetch) instead of `setQueriesData` for the messages cache

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MSG-005 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/MSG-005.md`); see also `docs/tickets/writeups/MSG-005.md`

## Location
`message:viewed`

## Problem / Impact
every time any participant views any message the entire message list is re-fetched from the server, causing significant unnecessary traffic and a perceptible flicker in the UI; the ticket design explicitly called for synchronous `setQueriesData` cache mutation

## Fix
replace `queryClient.invalidateQueries({ queryKey: ["messages", conversationId] })` with `queryClient.setQueriesData(...)` that surgically increments `read_by_count` / `read_by_user_ids` on the matching message item

## Notes
This gap was identified by the second-pass as-built review of MSG-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.

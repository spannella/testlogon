# GAP-0163: Poll vote does not publish SSE events

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENGAGE-002 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ENGAGE-002.md`); see also `docs/tickets/writeups/ENGAGE-002.md`

## Location
`app/routers/newsfeed.py:6659`

## Problem / Impact
the endpoint casts the vote and returns updated counts but never calls `sse_hub.publish()`; the real-time "live vote count" feature described in the ticket is completely absent

## Fix
after cast_vote, build a `poll:vote` payload and call `asyncio.get_event_loop().create_task(sse_hub.publish(post_owner_id, payload))` (or publish to all subscribers of the post's feed); alternatively push via the author's SSE stream and fan-out via existing notify path

## Notes
This gap was identified by the second-pass as-built review of ENGAGE-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.

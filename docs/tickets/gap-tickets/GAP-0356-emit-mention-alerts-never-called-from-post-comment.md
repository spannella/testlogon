# GAP-0356: `emit_mention_alerts()` never called from post/comment creation

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SOC-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/SOC-004.md`); see also `docs/tickets/writeups/SOC-004.md`

## Location
`emit_mention_alerts()`

## Problem / Impact
mention parsing (`extract_mentions`, `emit_mention_alerts`) exists in `social_alerts.py:667-701` but is never invoked from any post or comment handler; @mentions never generate notifications

## Fix
call `emit_mention_alerts(text=body, author_user_id=user_id, ...)` at end of create_post and create_comment handlers

## Notes
This gap was identified by the second-pass as-built review of SOC-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.

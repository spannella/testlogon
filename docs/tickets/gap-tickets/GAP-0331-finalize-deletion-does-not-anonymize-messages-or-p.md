# GAP-0331: `finalize_deletion` does not anonymize messages or posts

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-018 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/PLATFORM-018.md`); see also `docs/tickets/writeups/PLATFORM-018.md`

## Location
`finalize_deletion`

## Problem / Impact
deleted-user messages remain visible with real sender identity

## Fix
add `_anonymize_messages(user_sub)` and `_anonymize_posts(user_sub)` steps in `finalize_deletion` that overwrite `sender_display_name`/`text` and `author_id`/`content` fields with "Deleted User" / "[This message was deleted]"

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-018. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.

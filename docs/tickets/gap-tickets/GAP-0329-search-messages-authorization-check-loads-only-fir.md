# GAP-0329: `_search_messages` authorization check loads only first 500 conversations

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-011 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/PLATFORM-011.md`); see also `docs/tickets/writeups/PLATFORM-011.md`

## Location
`_search_messages`

## Problem / Impact
`_search_messages` authorization check loads only first 500 conversations

## Fix
paginate `list_user_conversations` until exhausted (or use a participant-indexed GSI query) to build the complete `allowed_conv_ids` set before filtering

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

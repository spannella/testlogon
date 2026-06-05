# GAP-0380: Comments are stored in the VideoViews table using a `VCOMMENT#` prefix instead of the newsfeed `app_single_table`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-017 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/VOD-017.md`); see also `docs/tickets/writeups/VOD-017.md`

## Location
`VCOMMENT#`

## Problem / Impact
the ticket design (Section 3.5) requires either a shadow post record in `app_single_table` or separate video comment endpoints; using the VideoViews table means comment data is co-mingled with view records and TTL-expired (VideoViews items use 90-day TTL) losing comments after 90 days

## Fix
store comments in a dedicated table or in `app_single_table` with the `POST#{video_id}` shadow-record pattern described in the ticket

## Notes
This gap was identified by the second-pass as-built review of VOD-017. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

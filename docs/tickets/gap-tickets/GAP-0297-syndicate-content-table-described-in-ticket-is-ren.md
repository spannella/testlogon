# GAP-0297: `syndicate_content` table described in ticket is renamed `syndicate_open_licensing` in implementation, with only GSI1 (not the ticket-specified single GSI)

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: LICENSE-005 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/LICENSE-005.md`); see also `docs/tickets/writeups/LICENSE-005.md`

## Location
`syndicate_content`

## Problem / Impact
The ticket specifies a `syndicate_content` table with `CREATOR_SYND#{user_id}/CONTENT#{content_id}` pattern and GSI1; the implementation uses `syndicate_open_licensing` with a compatible but differently named table, and stores config (`CONFIG` SK) in the same table rather than in the syndicates META record as specified; no `CREATOR_SYND#` index pattern exists in the implementation

## Fix
naming divergence is acceptable if consistent; verify the `CREATOR_SYND#` pattern used by `list_syndicate_content` with `creator_id` filter is implemented

## Notes
This gap was identified by the second-pass as-built review of LICENSE-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

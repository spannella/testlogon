# GAP-0298: `GET /ui/licenses/compliance/content/{content_id}` blocks admin access

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: LICENSE-006 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/LICENSE-006.md`); see also `docs/tickets/writeups/LICENSE-006.md`

## Location
`GET /ui/licenses/compliance/content/{content_id}`

## Problem / Impact
The compliance detail endpoint enforces `creator_id == session["user_sub"]` with a 403 for any other user; admins cannot view compliance status for arbitrary content without a separate admin endpoint; the ticket specifies "Content owner or admin"

## Fix
add a role check

## Notes
This gap was identified by the second-pass as-built review of LICENSE-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

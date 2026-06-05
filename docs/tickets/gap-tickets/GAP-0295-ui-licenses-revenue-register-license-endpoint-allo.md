# GAP-0295: `/ui/licenses/revenue/register-license` endpoint allows spoofing `licensor_id`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: LICENSE-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/LICENSE-003.md`); see also `docs/tickets/writeups/LICENSE-003.md`

## Location
`/ui/licenses/revenue/register-license`

## Problem / Impact
The body-supplied `licensor_id` field overrides the authenticated user's sub; any authenticated user can register an arbitrary license mapping claiming any licensor, enabling fraudulent revenue credits

## Fix
remove `licensor_id` from the request body; always use `ctx["user_sub"]` as the licensor, or restrict this endpoint to admin/internal use only

## Notes
This gap was identified by the second-pass as-built review of LICENSE-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

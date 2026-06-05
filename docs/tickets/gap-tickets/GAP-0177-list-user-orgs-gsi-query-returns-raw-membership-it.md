# GAP-0177: `list_user_orgs` GSI query returns raw membership items, not org metadata

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENTERPRISE-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ENTERPRISE-003.md`); see also `docs/tickets/writeups/ENTERPRISE-003.md`

## Location
`list_user_orgs`

## Problem / Impact
The `user-orgs-index` GSI is queried but only membership items (with `sk=MEMBER#{user_sub}`) project to that index, not the org `#META` items. The result is a list of membership records without org name/status, and the follow-up `get_org()` per-membership call is an N+1 pattern.

## Fix
Project `org_id`, `org_role` and `status` from the GSI; do a `batch_get_item` for the `#META` records.

## Notes
This gap was identified by the second-pass as-built review of ENTERPRISE-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

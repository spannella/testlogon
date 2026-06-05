# GAP-0169: `delete_clip` does not check admin/moderator role

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENGAGE-005 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ENGAGE-005.md`); see also `docs/tickets/writeups/ENGAGE-005.md`

## Location
`delete_clip`

## Problem / Impact
authorization only checks `actor == creator_user_id or actor == broadcaster_user_id`; admin users (role >= ADMIN) cannot moderate or remove clips from any broadcast even if the feature is described as "admin can also delete" in the docstring

## Fix
pass `role` into `delete_clip` and add `or role in (Role.ADMIN, Role.ROOT)` to the authorization check

## Notes
This gap was identified by the second-pass as-built review of ENGAGE-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0360: Block/Unblock UI is absent from `PublicUserProfilePage`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SOCIAL-004 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/SOCIAL-004.md`); see also `docs/tickets/writeups/SOCIAL-004.md`

## Location
`PublicUserProfilePage`

## Problem / Impact
users have no surface to initiate a block from a profile; the only blocking surface is `BlockedUsersPage` (unblock only); acceptance criteria 10 fails

## Fix
create `BlockButton.tsx` shared component; import `getBlockStatus`/`blockUser`/`unblockUser` in `PublicUserProfilePage`; add a "Block" option in a `DropdownMenu` alongside the Follow button

## Notes
This gap was identified by the second-pass as-built review of SOCIAL-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0131: Expired invite not checked in `accept_guest_invite()`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: BCAST-016 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BCAST-016.md`); see also `docs/tickets/writeups/BCAST-016.md`

## Location
`accept_guest_invite()`

## Problem / Impact
only `status == "pending"` checked; expired invites in pending state can still be accepted if cleanup sweep hasn't run

## Fix
add `if now_ts() > int(invite.expires_at): raise HTTPException(410, "Invite has expired")`

## Notes
This gap was identified by the second-pass as-built review of BCAST-016. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

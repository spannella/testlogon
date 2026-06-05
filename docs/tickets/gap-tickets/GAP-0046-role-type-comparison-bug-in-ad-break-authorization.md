# GAP-0046: role-type comparison bug in ad-break authorization

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADS-006 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-006.md`); see also `docs/tickets/writeups/ADS-006.md`

## Location
`app/routers/broadcast_ads.py:127`

## Problem / Impact
ctx["role"] is a Role enum but compared against {"admin","root"} strings; admins incorrectly fail the check

## Fix
change comparison to {Role.ADMIN, Role.ROOT} using imported Role enum

## Notes
This gap was identified by the second-pass as-built review of ADS-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

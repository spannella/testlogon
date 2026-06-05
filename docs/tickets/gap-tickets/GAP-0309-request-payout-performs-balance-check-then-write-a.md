# GAP-0309: `request_payout` performs balance check then write as two separate non-atomic operations without any conditional write

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MON-004 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/MON-004.md`); see also `docs/tickets/writeups/MON-004.md`

## Location
`request_payout`

## Problem / Impact
a creator submitting two concurrent requests can both pass the `_has_active_payout` and `amount > available` checks before either `put_item` lands, creating duplicate payout requests that together exceed the available balance

## Fix
use a DDB conditional write with `ConditionExpression="attribute_not_exists(payout_id)"` on the payout record and a version counter on the user's payout state row

## Notes
This gap was identified by the second-pass as-built review of MON-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

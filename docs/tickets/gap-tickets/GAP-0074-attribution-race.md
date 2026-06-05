# GAP-0074: Attribution race

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: AFFILIATE-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AFFILIATE-001.md`); see also `docs/tickets/writeups/AFFILIATE-001.md`

## Location
`put_item`

## Problem / Impact
concurrent signups with same `referred_user_id` both pass the `existing` get-check and both write attributions, creating duplicate referrer credits

## Fix
add `ConditionExpression="attribute_not_exists(pk)"` and catch `ConditionalCheckFailedException` (cross-ref SEC-013)

## Notes
This gap was identified by the second-pass as-built review of AFFILIATE-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

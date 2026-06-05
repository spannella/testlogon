# GAP-0008: Commission replay

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: AFFILIATE-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AFFILIATE-001.md`); see also `docs/tickets/writeups/AFFILIATE-001.md`

## Location
`put_item`

## Problem / Impact
no idempotency guard on `put_item`

## Fix
write dedup sentinel `COMMISSION_DEDUP#{transaction_id}` with `attribute_not_exists(pk)` before commission put, or drop `ts` from SK and add `ConditionExpression="attribute_not_exists(pk)"` (cross-ref SEC-013, SEC-004)

## Notes
This gap was identified by the second-pass as-built review of AFFILIATE-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

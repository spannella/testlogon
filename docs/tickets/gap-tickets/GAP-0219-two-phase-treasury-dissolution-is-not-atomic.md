# GAP-0219: Two-phase treasury dissolution is not atomic

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: GROUP-004 · **Effort**: L ��� (Cross-ref: **SEC-004**)
**From**: gap audit (`docs/tickets/gaps/GROUP-004.md`); see also `docs/tickets/writeups/GROUP-004.md`

## Location
`app/services/group_treasury.py:487-635`

## Problem / Impact
balance is zeroed last (`line:616`) so a failure leaves the treasury in a partially-distributed state with a non-zero balance

## Fix
use DDB `TransactWriteItems` for batches of up to 25; for larger contributor counts use a saga pattern with a `dissolution_state` marker to enable idempotent retry

## Notes
This gap was identified by the second-pass as-built review of GROUP-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

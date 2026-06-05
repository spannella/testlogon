# GAP-0167: `participant_count` can go negative and has no floor

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENGAGE-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ENGAGE-004.md`); see also `docs/tickets/writeups/ENGAGE-004.md`

## Location
`participant_count`

## Problem / Impact
`participant_count` can go negative and has no floor

## Fix
use `ConditionExpression="participant_count > :zero"` with `:zero=0` on decrement calls, or use `SET participant_count = :max(participant_count + :d, :zero)` via a conditional

## Notes
This gap was identified by the second-pass as-built review of ENGAGE-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

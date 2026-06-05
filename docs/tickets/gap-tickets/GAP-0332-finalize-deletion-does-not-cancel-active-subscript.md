# GAP-0332: `finalize_deletion` does not cancel active subscriptions before deletion

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-018 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/PLATFORM-018.md`); see also `docs/tickets/writeups/PLATFORM-018.md`

## Location
`finalize_deletion`

## Problem / Impact
`finalize_deletion` does not cancel active subscriptions before deletion

## Fix
add a `_cancel_active_subscriptions(user_sub)` step in `finalize_deletion` before DDB delete that calls the subscription cancellation service

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-018. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

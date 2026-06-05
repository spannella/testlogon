# GAP-0016: `useCallBillingHeartbeat.ts` hook does not exist

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: CRIT (Critical) · **Source ticket**: CALL-011 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/CALL-011.md`); see also `docs/tickets/writeups/CALL-011.md`

## Location
`useCallBillingHeartbeat.ts`

## Problem / Impact
no periodic `PATCH /messaging/messages/calls/{call_id}/heartbeat` is sent during connected paid calls; billing cycles never fire mid-call; `finalize_call_billing` at end attempts to charge entire duration in one shot which may exceed wallet balance

## Fix
implement hook with `setInterval` at `heartbeat_interval_seconds`, dispatch `end_call` action on `action==="end_call"` response per §4.1

## Notes
This gap was identified by the second-pass as-built review of CALL-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

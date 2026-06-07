# GAP-0249: `expire_stale_calls` not wired as background task

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-003.md`); see also `docs/tickets/writeups/KYC-003.md`

## Location
`expire_stale_calls`

## Problem / Impact
missed calls remain `scheduled` indefinitely; conflict check blocks re-scheduling; `ByStatus` GSI `scheduled` partition grows without bound

## Fix
wire `expire_stale_calls` as a periodic asyncio task at startup, matching `start_kyc_sla_checker_task` pattern at `app/main.py:528`

## Notes
This gap was identified by the second-pass as-built review of KYC-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.

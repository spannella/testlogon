# GAP-0230: Auto-restart policy not implemented

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-008 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/INFRA-008.md`); see also `docs/tickets/writeups/INFRA-008.md`

## Location
`_check_restart_policy`

## Problem / Impact
ticket design: `_check_restart_policy` + `record_timeline_event` + `PATCH /restart-policy`

## Fix
add `auto_restart_enabled` + `max_restarts` + `restart_count` fields to EC2/K8s instance items; implement `_check_restart_policy()`; add `PATCH /ui/compute/monitoring/instances/{id}/restart-policy` endpoint

## Notes
This gap was identified by the second-pass as-built review of INFRA-008. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.

# GAP-0231: Event timeline not implemented

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-008 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/INFRA-008.md`); see also `docs/tickets/writeups/INFRA-008.md`

## Location
`TIMELINE#{instance_id}#{ts}#{event_id}`

## Problem / Impact
ticket design: `TIMELINE#{instance_id}#{ts}#{event_id}` SK pattern in ec2_instances/k8s_pods tables

## Fix
implement `record_timeline_event()` service function; wire it into ec2/k8s launch, stop, terminate paths; add `GET /ui/compute/monitoring/instances/{id}/timeline` endpoint

## Notes
This gap was identified by the second-pass as-built review of INFRA-008. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.

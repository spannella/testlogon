# GAP-0234: no per-host `record_sessions` flag (INFRA-001 dependency)

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-010 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/INFRA-010.md`); see also `docs/tickets/writeups/INFRA-010.md`

## Location
`record_sessions`

## Problem / Impact
ticket requires a `record_sessions: bool` field on each host record to control auto-recording; `remote_hosts` service exists but has no such field; the `_should_record()` gate from the ticket design is entirely absent; recording is only started if the caller explicitly POSTs `/ui/compute/ssh-recordings`

## Fix
add `record_sessions: bool` to the host schema and call `start_recording()` automatically in the WebSocket `connect` handler when the flag is set

## Notes
This gap was identified by the second-pass as-built review of INFRA-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

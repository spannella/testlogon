# GAP-0233: SSH terminal does not hook into session recorder

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-010 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/INFRA-010.md`); see also `docs/tickets/writeups/INFRA-010.md`

## Location
`app/routers/browser_ssh_terminal.py:452-488`

## Problem / Impact
the `ParamikoSshBridge` output loop never calls `append_events()`; recordings can only be populated via explicit API calls (`POST /ui/compute/ssh-recordings/{id}/events`), so live terminal sessions produce zero-event recordings unless the browser client explicitly streams chunks

## Fix
in the WebSocket output handler call `append_events(user_sub, recording_id, [[elapsed, "o", data]])` for each received SSH output chunk; requires wiring `SessionRecorder`/recording-id into the `connect` message handler

## Notes
This gap was identified by the second-pass as-built review of INFRA-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.

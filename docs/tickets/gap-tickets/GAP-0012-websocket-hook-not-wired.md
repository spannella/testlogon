# GAP-0012: WebSocket hook not wired

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: CRIT (Critical) · **Source ticket**: AGENT-006 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/AGENT-006.md`); see also `docs/tickets/writeups/AGENT-006.md`

## Location
`app/routers/browser_ssh_terminal.py`

## Problem / Impact
SSH WebSocket data bypasses process_terminal_output; entire detection pipeline (buffer → pattern match → feedback request) never fires automatically

## Fix
tap terminal data in WebSocket forwarding loop, call process_terminal_output and dispatch on returned signal

## Notes
This gap was identified by the second-pass as-built review of AGENT-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0086: create_feedback_request does not pause agent

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-006 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-006.md`); see also `docs/tickets/writeups/AGENT-006.md`

## Location
`app/services/terminal_monitor.py:191`

## Problem / Impact
after feedback pattern detected, agent continues running and generates duplicate feedback records; awaiting_feedback state transition is missing

## Fix
add transition_agent_state(user_id, worker_id, "awaiting_feedback") inside create_feedback_request

## Notes
This gap was identified by the second-pass as-built review of AGENT-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

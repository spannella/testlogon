# GAP-0011: respond_to_feedback does not inject response or resume agent

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: AGENT-006 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/AGENT-006.md`); see also `docs/tickets/writeups/AGENT-006.md`

## Location
`app/services/terminal_monitor.py:233`

## Problem / Impact
respond_to_feedback updates DDB record only; _inject_into_terminal and transition_agent_state("working") are absent; agent remains in awaiting_feedback indefinitely

## Fix
call _inject_into_terminal(sanitized_response) and transition_agent_state(user_id, worker_id, "working") inside respond_to_feedback

## Notes
This gap was identified by the second-pass as-built review of AGENT-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

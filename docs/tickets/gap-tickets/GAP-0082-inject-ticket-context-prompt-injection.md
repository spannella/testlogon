# GAP-0082: inject_ticket_context prompt injection

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: AGENT-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-003.md`); see also `docs/tickets/writeups/AGENT-003.md`

## Location
`app/services/agent_orchestrator.py:598`

## Problem / Impact
ticket title/description interpolated directly into context string; adversarial [AGENT_COMPLETE] in ticket content triggers false completion signal

## Fix
apply _sanitize_ticket_field to escape signal tokens before interpolation

## Notes
This gap was identified by the second-pass as-built review of AGENT-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

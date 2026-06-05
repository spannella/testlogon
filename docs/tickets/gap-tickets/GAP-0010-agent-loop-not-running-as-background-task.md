# GAP-0010: agent loop not running as background task

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: AGENT-003 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/AGENT-003.md`); see also `docs/tickets/writeups/AGENT-003.md`

## Location
`app/services/agent_orchestrator.py:705`

## Problem / Impact
start_agent_loop sets DDB state but spawns no asyncio coroutine; agent never autonomously picks up tickets

## Fix
add _running_loops registry, create asyncio.create_task(run_agent_loop(...)) in start_agent_loop

## Notes
This gap was identified by the second-pass as-built review of AGENT-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

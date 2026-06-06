# GAP-0105: no automatic cost collection schedule

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-018 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-018.md`); see also `docs/tickets/writeups/AGENT-018.md`

## Location
`app/main.py`

## Problem / Impact
POST /collect triggers one manual collection but no asyncio background task is registered in app/main.py even when accountant_agent_execute_commands=True

## Fix
add hourly asyncio background task calling run_cost_collection_if_enabled gated by S.accountant_agent_execute_commands

## Notes
This gap was identified by the second-pass as-built review of AGENT-018. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

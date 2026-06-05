# GAP-0098: trigger_review in-memory lock not distributed

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: AGENT-013 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-013.md`); see also `docs/tickets/writeups/AGENT-013.md`

## Location
`app/services/agent_pm.py:714`

## Problem / Impact
_RUNNING_REVIEWS is a module-level set; with multiple uvicorn workers two concurrent requests both pass and double-execute

## Fix
replace with DDB conditional put_item on LOCK# item with TTL

## Notes
This gap was identified by the second-pass as-built review of AGENT-013. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

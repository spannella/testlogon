# GAP-0097: backlog scan misses sparse tickets

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-012 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-012.md`); see also `docs/tickets/writeups/AGENT-012.md`

## Location
`app/services/agent_project.py:685`

## Problem / Impact
_scan_backlog_tickets uses FilterExpression with Limit=500 without LastEvaluatedKey loop; sparse status values silently miss items beyond first page

## Fix
add pagination loop collecting up to limit matching results

## Notes
This gap was identified by the second-pass as-built review of AGENT-012. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

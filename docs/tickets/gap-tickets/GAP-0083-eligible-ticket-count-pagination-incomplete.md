# GAP-0083: eligible ticket count pagination incomplete

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-004.md`); see also `docs/tickets/writeups/AGENT-004.md`

## Location
`app/services/agent_fleet.py:288`

## Problem / Impact
_count_eligible_tickets uses FilterExpression without LastEvaluatedKey loop; sparse tickets table silently returns incorrect (low) count

## Fix
add pagination loop over LastEvaluatedKey collecting COUNT

## Notes
This gap was identified by the second-pass as-built review of AGENT-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0081: double-write claim race

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-003 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/AGENT-003.md`); see also `docs/tickets/writeups/AGENT-003.md`

## Location
`app/services/agent_orchestrator.py:255`

## Problem / Impact
claim_ticket writes AGENT_CLAIM# then TICKET#META in sequence; second write failure leaves orphaned claim record that permanently blocks the ticket

## Fix
wrap both writes in TransactWriteItems

## Notes
This gap was identified by the second-pass as-built review of AGENT-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

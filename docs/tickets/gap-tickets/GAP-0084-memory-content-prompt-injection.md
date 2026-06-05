# GAP-0084: memory content prompt injection

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-005 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-005.md`); see also `docs/tickets/writeups/AGENT-005.md`

## Location
`app/services/agent_memory.py:400`

## Problem / Impact
assemble_full_context concatenates memory entry content directly; [AGENT_COMPLETE] written into memory re-triggers false completion on future tickets

## Fix
apply _sanitize_ticket_field signal-token escaping to all memory content and title fields before assembly

## Notes
This gap was identified by the second-pass as-built review of AGENT-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

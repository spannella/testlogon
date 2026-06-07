# GAP-0093: auto_deploy_on_qa_approved trigger not wired

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-010 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/AGENT-010.md`); see also `docs/tickets/writeups/AGENT-010.md`

## Location
`app/services/agent_devops.py`

## Problem / Impact
config field auto_deploy_on_qa_approved is stored but AGENT-003 polling loop never acts on qa_approved status

## Fix
add qa_approved filter in AGENT-003 worker loop when this flag is set

## Notes
This gap was identified by the second-pass as-built review of AGENT-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

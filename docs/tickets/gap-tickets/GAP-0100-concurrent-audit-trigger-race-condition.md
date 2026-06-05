# GAP-0100: concurrent audit trigger race condition

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: AGENT-015 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-015.md`); see also `docs/tickets/writeups/AGENT-015.md`

## Location
`app/services/agent_compliance.py:788`

## Problem / Impact
trigger_audit reads get_running_audit then start_audit in sequence; two concurrent requests both pass the read and create duplicate running audits

## Fix
add conditional put_item on RUNNING_LOCK item in start_audit with attribute_not_exists ConditionExpression

## Notes
This gap was identified by the second-pass as-built review of AGENT-015. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

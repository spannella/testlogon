# GAP-0080: idle-worker auto-shutdown stub not implemented

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: AGENT-002 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/AGENT-002.md`); see also `docs/tickets/writeups/AGENT-002.md`

## Location
`app/services/agent_worker_provisioner.py:462`

## Problem / Impact
check_idle_workers returns 0; workers never stopped automatically, accumulating compute cost in prod

## Fix
query ByStatus GSI for ready workers, filter by last_activity_at < now-idle_timeout, call stop_worker

## Notes
This gap was identified by the second-pass as-built review of AGENT-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

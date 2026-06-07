# GAP-0096: absolute path not rejected in scan_paths

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-011 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-011.md`); see also `docs/tickets/writeups/AGENT-011.md`

## Location
`app/services/agent_architect.py:204`

## Problem / Impact
validate_architect_config rejects ".." but not absolute paths like /etc/passwd; scan_paths=["/etc/passwd"] passes validation

## Fix
add str(path).startswith("/") check to reject absolute paths

## Notes
This gap was identified by the second-pass as-built review of AGENT-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

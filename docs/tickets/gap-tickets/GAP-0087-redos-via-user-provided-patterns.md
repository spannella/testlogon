# GAP-0087: ReDoS via user-provided patterns

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-006 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-006.md`); see also `docs/tickets/writeups/AGENT-006.md`

## Location
`app/services/terminal_monitor.py:410`

## Problem / Impact
update_pattern_config validates regex syntax but not catastrophic backtracking; pattern (a+)+$ compiles but times out exponentially

## Fix
probe compiled pattern on 1000-char string with signal.setitimer timeout; reject on timeout

## Notes
This gap was identified by the second-pass as-built review of AGENT-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

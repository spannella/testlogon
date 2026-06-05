# GAP-0090: build_pr_command double-quote injection

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-008 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-008.md`); see also `docs/tickets/writeups/AGENT-008.md`

## Location
`app/services/agent_coder.py:482`

## Problem / Impact
title/body_escaped use replace('"',"'") which is not shell-safe; title with ' breaks escaping

## Fix
apply single-quote escaping _sq(v) = "'" + v.replace("'","'\\''"+"'") + "'"

## Notes
This gap was identified by the second-pass as-built review of AGENT-008. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

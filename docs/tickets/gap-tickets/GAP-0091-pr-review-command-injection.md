# GAP-0091: PR review command injection

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: AGENT-009 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-009.md`); see also `docs/tickets/writeups/AGENT-009.md`

## Location
`app/services/agent_qa.py:890`

## Problem / Impact
build_pr_review_command interpolates report Markdown into double-quoted shell argument; report containing " or $() executes when QA_AGENT_EXECUTE_COMMANDS=1

## Fix
apply single-quote escaping _sq(v) to report body

## Notes
This gap was identified by the second-pass as-built review of AGENT-009. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

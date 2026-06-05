# GAP-0089: command injection in build_coder_workflow coding_cmd

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: AGENT-008 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/AGENT-008.md`); see also `docs/tickets/writeups/AGENT-008.md`

## Location
`app/services/agent_coder.py:559`

## Problem / Impact
prompt[:200] f-stringed inside double-quoted shell argument to claude/codex; ticket subject with " or $(...) breaks or executes when AGENT_CODER_EXECUTE_COMMANDS=1

## Fix
store as structured argv field; exec via subprocess(argv, shell=False)

## Notes
This gap was identified by the second-pass as-built review of AGENT-008. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

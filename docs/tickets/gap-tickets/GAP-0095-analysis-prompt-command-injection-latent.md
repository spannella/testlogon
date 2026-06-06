# GAP-0095: analysis prompt command injection latent

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-011 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/AGENT-011.md`); see also `docs/tickets/writeups/AGENT-011.md`

## Location
`app/services/agent_architect.py:1144`

## Problem / Impact
analysis_prompt[:160] f-stringed into double-quoted claude invocation; user-controlled ticket subject with " or $() executes when ARCHITECT_EXECUTE_COMMANDS=1

## Fix
store as argv field, exec via subprocess(argv, shell=False)

## Notes
This gap was identified by the second-pass as-built review of AGENT-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

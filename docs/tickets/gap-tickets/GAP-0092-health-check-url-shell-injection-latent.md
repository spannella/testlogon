# GAP-0092: health check URL shell injection latent

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-010 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-010.md`); see also `docs/tickets/writeups/AGENT-010.md`

## Location
`app/services/agent_devops.py:1217`

## Problem / Impact
run_health_checks builds "curl -sf {h['url']}" f-string; URL with shell metacharacters (;, &&) executes when DEVOPS_AGENT_EXECUTE_COMMANDS=1

## Fix
use subprocess.run(["curl","--silent","--fail",url], shell=False)

## Notes
This gap was identified by the second-pass as-built review of AGENT-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

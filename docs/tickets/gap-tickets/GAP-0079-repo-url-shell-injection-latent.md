# GAP-0079: repo_url shell injection latent

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-002.md`); see also `docs/tickets/writeups/AGENT-002.md`

## Location
`app/services/agent_worker_provisioner.py`

## Problem / Impact
startup script f-strings repo_url into "git clone {repo_url}" shell string; semicolon or ext:: transport enables arbitrary code execution

## Fix
subprocess(["git","clone","--",repo_url,...], shell=False) after validating https:// or git@ only, no shell metacharacters

## Notes
This gap was identified by the second-pass as-built review of AGENT-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0094: repo_branch shell injection latent

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-011 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-011.md`); see also `docs/tickets/writeups/AGENT-011.md`

## Location
`app/services/agent_architect.py:1153`

## Problem / Impact
git clone command f-strings branch from config; validate_architect_config does not validate repo_branch at all

## Fix
add _sanitize_branch() in _normalize_config and validate repo_branch in validate_architect_config

## Notes
This gap was identified by the second-pass as-built review of AGENT-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

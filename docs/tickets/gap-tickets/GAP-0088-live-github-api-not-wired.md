# GAP-0088: live GitHub API not wired

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: AGENT-007 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-007.md`); see also `docs/tickets/writeups/AGENT-007.md`

## Location
`app/services/agent_pr_integration.py:380`

## Problem / Impact
_create_pr_via_api raises NotImplementedError when method="api" and a real token is configured; production PR creation via API is blocked

## Fix
implement httpx POST to GitHub REST API /repos/{owner}/{repo}/pulls with parsed owner/repo from repo_url

## Notes
This gap was identified by the second-pass as-built review of AGENT-007. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0101: SEC-021 latent: no repo_url validation before real execution

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-015 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-015.md`); see also `docs/tickets/writeups/AGENT-015.md`

## Location
`app/services/agent_compliance.py:1041`

## Problem / Impact
review_pr_mock has no repo_url allowlist; when compliance_agent_execute_commands=True PR source URLs go to Worker Agent Framework unvalidated

## Fix
validate repo_url against allowed_repo_hosts allowlist before dispatching

## Notes
This gap was identified by the second-pass as-built review of AGENT-015. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0102: SEC-022: GitHub token must not be stored in DDB config

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: AGENT-015 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/AGENT-015.md`); see also `docs/tickets/writeups/AGENT-015.md`

## Location
`app/services/agent_compliance.py`

## Problem / Impact
ticket spec §7 requires GitHub review service account token in secrets manager; if future config extension adds plaintext github_token it must be stripped from GET responses

## Fix
add github_token_secret_name (reference only) to config; resolve via KMS at execution time, expose only has_github_token: bool

## Notes
This gap was identified by the second-pass as-built review of AGENT-015. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

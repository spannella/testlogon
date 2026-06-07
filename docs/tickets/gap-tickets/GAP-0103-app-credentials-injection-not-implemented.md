# GAP-0103: app credentials injection not implemented

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-016 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/AGENT-016.md`); see also `docs/tickets/writeups/AGENT-016.md`

## Location
`app/services/agent_stylist.py:721`

## Problem / Impact
update_stylist_config has no app_auth_credentials_secret field; no mechanism to inject live-app auth for real Playwright browsing

## Fix
add app_auth_credentials_secret_name to config; resolve via KMS at trigger time, expose only has_app_credentials: bool

## Notes
This gap was identified by the second-pass as-built review of AGENT-016. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

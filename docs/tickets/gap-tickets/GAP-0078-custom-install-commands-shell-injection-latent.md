# GAP-0078: custom_install_commands shell injection latent

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: AGENT-002 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/AGENT-002.md`); see also `docs/tickets/writeups/AGENT-002.md`

## Location
`app/models.py:5276`

## Problem / Impact
custom_install_commands and custom_verify_command stored and will execute with shell=True if prod provisioner naively runs them

## Fix
either remove the fields or validate against an allowlist of named steps; exec via argv with shell=False only

## Notes
This gap was identified by the second-pass as-built review of AGENT-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

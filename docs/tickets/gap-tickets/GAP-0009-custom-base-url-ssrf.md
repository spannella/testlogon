# GAP-0009: custom base_url SSRF

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: AGENT-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-001.md`); see also `docs/tickets/writeups/AGENT-001.md`

## Location
`app/services/llm_provider_keys.py:173`

## Problem / Impact
provider="custom" allows user-supplied base_url; test_key issues GET to that URL with no SSRF guard

## Fix
validate https:// scheme only, reject RFC-1918/link-local/loopback ranges in field_validator

## Notes
This gap was identified by the second-pass as-built review of AGENT-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

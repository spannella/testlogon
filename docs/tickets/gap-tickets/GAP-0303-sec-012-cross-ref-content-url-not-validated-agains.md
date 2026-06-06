# GAP-0303: SEC-012 cross-ref: content_url not validated against SSRF or internal network targets

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MOD-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/MOD-002.md`); see also `docs/tickets/writeups/MOD-002.md`

## Location
`app/services/dmca_content_operations.py:35-62`

## Problem / Impact
SEC-012 cross-ref: content_url not validated against SSRF or internal network targets

## Fix
reject non-relative URLs or validate against platform hostname allowlist in `DmcaClaimIn._validate_content_url`; the existing `javascript:`/`data:` check in the ticket design is absent from the implementation

## Notes
This gap was identified by the second-pass as-built review of MOD-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.

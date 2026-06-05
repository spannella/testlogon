# GAP-0318: IP spoofing via untrusted X-Forwarded-For header

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/PLATFORM-001.md`); see also `docs/tickets/writeups/PLATFORM-001.md`

## Location
`app/core/normalize.py:9`

## Problem / Impact
IP spoofing via untrusted X-Forwarded-For header

## Fix
only honour XFF when `request.client.host` falls within configured `TRUSTED_PROXY_CIDRS`; default to empty (direct IP only) in dev

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

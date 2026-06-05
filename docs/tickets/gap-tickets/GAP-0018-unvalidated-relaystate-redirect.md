# GAP-0018: Unvalidated `RelayState` redirect

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: ENTERPRISE-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ENTERPRISE-002.md`); see also `docs/tickets/writeups/ENTERPRISE-002.md`

## Location
`RelayState`

## Problem / Impact
The ACS endpoint redirects to `str(relay_state or "/")` without validating that the URL is local/same-origin, creating a classic open-redirect (CWE-601) that an attacker can exploit by crafting a malicious IdP response with `RelayState=https://evil.com/steal`. SEC-011 requires RelayState validation.

## Fix
Parse the RelayState URL; reject any value whose host differs from the platform's own origin; default to `/` on rejection.

## Notes
This gap was identified by the second-pass as-built review of ENTERPRISE-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

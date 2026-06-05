# GAP-0174: `MockSamlAuth` used in production path

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENTERPRISE-002 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ENTERPRISE-002.md`); see also `docs/tickets/writeups/ENTERPRISE-002.md`

## Location
`MockSamlAuth`

## Problem / Impact
The router imports and uses `MockSamlAuth` (not `OneLogin_Saml2_Auth`) for both the login redirect and ACS response processing; SAML assertions are never cryptographically verified. Any POST to `/saml/acs` can be accepted with forged attributes.

## Fix
Conditionally use the real `OneLogin_Saml2_Auth` when `not S.dev_mode`; restrict `MockSamlAuth` to `S.dev_mode` only.

## Notes
This gap was identified by the second-pass as-built review of ENTERPRISE-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

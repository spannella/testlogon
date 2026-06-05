# GAP-0175: `relay_state` carries attacker-controlled form field not sanitised

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENTERPRISE-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ENTERPRISE-002.md`); see also `docs/tickets/writeups/ENTERPRISE-002.md`

## Location
`relay_state`

## Problem / Impact
`relay_state` carries attacker-controlled form field not sanitised

## Fix
Limit RelayState to ≤2 KB, restrict to printable ASCII, and validate the URL before use.

## Notes
This gap was identified by the second-pass as-built review of ENTERPRISE-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

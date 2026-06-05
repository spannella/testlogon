# GAP-0206: `toggle_provider` does not enforce payment initiation gate

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-014 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/FIN-014.md`); see also `docs/tickets/writeups/FIN-014.md`

## Location
`toggle_provider`

## Problem / Impact
`toggle_provider` does not enforce payment initiation gate

## Fix
add `is_provider_enabled(provider)` guard at the start of each billing router's charge path (cross-ref SEC-004)

## Notes
This gap was identified by the second-pass as-built review of FIN-014. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

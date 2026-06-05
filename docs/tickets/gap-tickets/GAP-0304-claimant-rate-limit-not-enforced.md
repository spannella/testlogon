# GAP-0304: claimant rate-limit not enforced

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MOD-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/MOD-002.md`); see also `docs/tickets/writeups/MOD-002.md`

## Location
`app/services/dmca_claims.py:443`

## Problem / Impact
claimant rate-limit not enforced

## Fix
query `ByClaimantCreatedAt` before inserting; reject with 429 if claimant has N claims in the last 24h (configurable)

## Notes
This gap was identified by the second-pass as-built review of MOD-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

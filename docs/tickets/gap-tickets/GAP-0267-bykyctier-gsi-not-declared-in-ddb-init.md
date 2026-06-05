# GAP-0267: `ByKycTier` GSI not declared in DDB init

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-009 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-009.md`); see also `docs/tickets/writeups/KYC-009.md`

## Location
`ByKycTier`

## Problem / Impact
`ByKycTier` GSI not declared in DDB init

## Fix
add the GSI and `attr_types` to the users `TableDef`

## Notes
This gap was identified by the second-pass as-built review of KYC-009. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

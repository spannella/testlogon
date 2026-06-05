# GAP-0024: `ByCase` GSI fallback performs full table scan

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: KYC-010 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-010.md`); see also `docs/tickets/writeups/KYC-010.md`

## Location
`ByCase`

## Problem / Impact
on GSI query failure the `except` block falls through to scanning the entire `kyc_id_scans` table, returning all users' scans to any caller

## Fix
replace fallback with `logger.exception(...); return []` to return an empty list safely

## Notes
This gap was identified by the second-pass as-built review of KYC-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0260: `attr_types={"created_at":"N"}` must be verified on `kyc_screening_results` table

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-006 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-006.md`); see also `docs/tickets/writeups/KYC-006.md`

## Location
`attr_types={"created_at":"N"}`

## Problem / Impact
omitting `attr_types` causes DynamoDB to store `created_at` as String, breaking `ScanIndexForward` queries with numeric predicates on both `ByUserSub` and `ByStatus` GSIs

## Fix
confirm `attr_types={"created_at": "N"}` is present in the `TableDef`; add if missing

## Notes
This gap was identified by the second-pass as-built review of KYC-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Resolved — already correct (verified 2026-06-06)

SKIP/already-correct: scripts/local-ddb-init.py kyc_screening_results TableDef already has attr_types={"created_at":"N"} (line ~229) for its ByUserSub/ByStatus numeric GSI sort key, with only the key attr listed. Regression guard added (tests/test_local_ddb_init_kyc_screening.py). No code change needed.

# GAP-0023: Users table key schema mismatch

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: CRIT (Critical) · **Source ticket**: KYC-009 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-009.md`); see also `docs/tickets/writeups/KYC-009.md`

## Location
`app/services/kyc_tiers.py`

## Problem / Impact
service accesses `T.users` with `Key={"user_sub": user_sub}` while `kyc_risk_scoring._compute_country_risk()` uses `Key={"pk": f"USER#{user_sub}", "sk": "PROFILE"}`; if the table uses composite PK+SK, tier service reads silently return empty items and every user defaults to Tier 0

## Fix
audit `scripts/local-ddb-init.py` for the users table key schema; correct all `GetItem`/`UpdateItem` calls in `kyc_tiers.py` to use the canonical key format

## Notes
This gap was identified by the second-pass as-built review of KYC-009. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

# GAP-0270: Profile field name misalignment causes zero match score

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-010 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-010.md`); see also `docs/tickets/writeups/KYC-010.md`

## Location
`app/services/kyc_id_scanner.py`

## Problem / Impact
reads `profile.get("first_name")` / `profile.get("last_name")`; if the profile stores only `display_name`, both fields are empty, name comparison scores 0, scan is flagged for all users

## Fix
add fallback to split `display_name` when `first_name`/`last_name` are absent

## Notes
This gap was identified by the second-pass as-built review of KYC-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

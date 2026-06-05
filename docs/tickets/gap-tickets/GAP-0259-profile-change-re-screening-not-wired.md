# GAP-0259: Profile-change re-screening not wired

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-006 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-006.md`); see also `docs/tickets/writeups/KYC-006.md`

## Location
`app/routers/settings.py`

## Problem / Impact
changing `display_name`, `date_of_birth`, or `nationality` after case approval does not trigger re-screening; AML continuous monitoring requirement violated

## Fix
add hook in profile update endpoint to call `SCREENING_STORE.rescreen_user()` when sensitive fields change

## Notes
This gap was identified by the second-pass as-built review of KYC-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

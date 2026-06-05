# GAP-0269: Auto-upgrade triggers not wired

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-009 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-009.md`); see also `docs/tickets/writeups/KYC-009.md`

## Location
`app/routers/register.py`

## Problem / Impact
Auto-upgrade triggers not wired

## Fix
add `auto_evaluate_tier(user_sub)` in try/except at each of the three trigger points

## Notes
This gap was identified by the second-pass as-built review of KYC-009. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

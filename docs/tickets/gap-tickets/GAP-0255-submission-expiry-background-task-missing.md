# GAP-0255: Submission expiry background task missing

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-005 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-005.md`); see also `docs/tickets/writeups/KYC-005.md`

## Location
`app/main.py`

## Problem / Impact
verified submissions from over a year ago remain in `verified` status indefinitely; a stale submission continues to satisfy any readiness gate check

## Fix
add `expire_stale_submissions()` to the service and wire as a periodic asyncio task in `app/main.py` every 6 hours

## Notes
This gap was identified by the second-pass as-built review of KYC-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

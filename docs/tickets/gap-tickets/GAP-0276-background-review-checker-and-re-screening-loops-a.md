# GAP-0276: Background review-checker and re-screening loops are never started

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-016 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/KYC-016.md`); see also `docs/tickets/writeups/KYC-016.md`

## Location
`app/main.py`

## Problem / Impact
The ticket spec requires `kyc_monitoring_scheduler.py` background loops registered via `app.add_event_handler("startup", ...)`. Neither `kyc_monitoring_scheduler.py` nor any equivalent startup hook exists; overdue reviews are never auto-detected and tier downgrades never fire without manual admin API calls

## Fix
create `app/services/kyc_monitoring_scheduler.py` with `_kyc_review_checker_loop` / `_kyc_rescreening_loop` asyncio tasks and register via `app.add_event_handler("startup", kyc_monitoring_startup)` in `app/main.py`

## Notes
This gap was identified by the second-pass as-built review of KYC-016. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

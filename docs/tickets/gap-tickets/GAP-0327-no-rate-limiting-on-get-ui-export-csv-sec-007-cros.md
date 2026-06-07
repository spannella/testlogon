# GAP-0327: No rate limiting on `GET /ui/export/csv` (SEC-007 cross-ref)

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-009 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/PLATFORM-009.md`); see also `docs/tickets/writeups/PLATFORM-009.md`

## Location
`GET /ui/export/csv`

## Problem / Impact
Any authenticated user can hammer the endpoint to bulk-exfiltrate contacts and billing data; each call triggers full DDB pagination (up to 50,000 rows × multiple tables). Ticket section 9.5 specifies 5 exports/minute/user via the existing rate-limit middleware, but no `can_send_alert_channel` or token-bucket call was wired in

## Fix
add a call to `_check_rate_limit(user_sub, "csv_export", max_n=5, window=60)` (or reuse the existing `rate_limit.py` bucket pattern) at the top of `export_csv()` and raise HTTP 429 when exceeded

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-009. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.

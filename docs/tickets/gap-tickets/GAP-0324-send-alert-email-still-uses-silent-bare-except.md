# GAP-0324: send_alert_email() still uses silent bare except

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-006 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/PLATFORM-006.md`); see also `docs/tickets/writeups/PLATFORM-006.md`

## Location
`app/services/alerts.py:458`

## Problem / Impact
the old `except Exception: pass` implementation remains; SES rejections, quota exhaustion, and domain verification errors are silently swallowed with no log, no metric, and no retry notification; callers always receive None and cannot distinguish success from failure

## Fix
replace with logged version that calls `logger.exception()`, increments `EMAIL_FAILED`, calls `record_email_failure()`, and returns None explicitly

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.

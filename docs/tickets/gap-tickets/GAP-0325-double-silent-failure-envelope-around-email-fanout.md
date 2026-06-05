# GAP-0325: Double silent-failure envelope around email fanout

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-006 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/PLATFORM-006.md`); see also `docs/tickets/writeups/PLATFORM-006.md`

## Location
`app/services/alerts.py:670`

## Problem / Impact
the email section of the alert fanout is wrapped in its own `except Exception: pass` in addition to the one inside `send_alert_email()`; security alert emails (login from new device, MFA changes) may vanish with no trace

## Fix
remove the outer `except Exception: pass` from the email fanout section; let exceptions surface to the caller

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

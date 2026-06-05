# GAP-0319: SNS notification endpoint unauthenticated and reachable without network restriction

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-002 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/PLATFORM-002.md`); see also `docs/tickets/writeups/PLATFORM-002.md`

## Location
`app/routers/ses_notifications.py`

## Problem / Impact
SNS notification endpoint unauthenticated and reachable without network restriction

## Fix
restrict endpoint to VPC-only traffic via security group; document required network controls in ops runbook

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

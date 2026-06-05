# GAP-0181: Per-delivery stats (`webhook_stats`) not recorded

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENTERPRISE-005 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ENTERPRISE-005.md`); see also `docs/tickets/writeups/ENTERPRISE-005.md`

## Location
`webhook_stats`

## Problem / Impact
Per-delivery stats (`webhook_stats`) not recorded

## Fix
Call `record_delivery_stat(endpoint_id, result)` after `mark_delivery_success` and `handle_delivery_failure` in the dispatcher loop.

## Notes
This gap was identified by the second-pass as-built review of ENTERPRISE-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

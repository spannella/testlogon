# GAP-0180: Circuit breaker not integrated into dispatcher loop

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENTERPRISE-005 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ENTERPRISE-005.md`); see also `docs/tickets/writeups/ENTERPRISE-005.md`

## Location
`app/services/webhook_dispatcher.py:44-71`

## Problem / Impact
The `webhook_circuit_breaker.py` module (`should_attempt_delivery`, `record_delivery_result`) is fully implemented but the dispatcher loop in `webhook_dispatcher.py` never imports or calls it. Every delivery is attempted regardless of circuit state; the circuit breaker has no effect in production.

## Fix
Import `should_attempt_delivery` and `record_delivery_result` in `webhook_dispatcher.py` and call them around each delivery attempt (mirroring the dispatcher snippet in the ticket's section 3.4).

## Notes
This gap was identified by the second-pass as-built review of ENTERPRISE-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.

# GAP-0228: Background billing timer not wired

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-005 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/INFRA-005.md`); see also `docs/tickets/writeups/INFRA-005.md`

## Location
`app/main.py:740-741`

## Problem / Impact
auto-deduction never runs; resources accrue charges only via manual POST `/ui/remote/billing/tick`; zero-balance auto-terminate never fires

## Fix
register `asyncio.create_task(run_compute_billing_timer())` in the `startup` lifespan event and add `run_compute_billing_timer` to `app/services/compute_billing.py`

## Notes
This gap was identified by the second-pass as-built review of INFRA-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

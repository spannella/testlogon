# GAP-0347: Low-stock alert has no throttle/dedup

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SHOP-001 · **Effort**: S; cross-ref SEC-024
**From**: gap audit (`docs/tickets/gaps/SHOP-001.md`); see also `docs/tickets/writeups/SHOP-001.md`

## Location
`app/routers/catalog.py:611-634`

## Problem / Impact
every stock adjustment that crosses the threshold fires `write_alert` unconditionally; on high-velocity items (e.g., 1000 purchases/hour) this generates 1000 alerts; ticket specified a 1-hour TTL sentinel to prevent duplicates but it was not implemented

## Fix
add a sentinel check (DDB `put_item` with `ConditionExpression=attribute_not_exists` + TTL) before calling `write_alert`

## Notes
This gap was identified by the second-pass as-built review of SHOP-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.

# GAP-0348: `adjust_stock` uses a full-table scan to find item by `item_id`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SHOP-001 · **Effort**: S; cross-ref SEC-024
**From**: gap audit (`docs/tickets/gaps/SHOP-001.md`); see also `docs/tickets/writeups/SHOP-001.md`

## Location
`adjust_stock`

## Problem / Impact
`adjust_stock` uses a full-table scan to find item by `item_id`

## Fix
change route to `PATCH /ui/catalog/categories/{category_id}/items/{item_id}/stock` to accept the PK directly, or add a `ByItemId` GSI on the catalog table

## Notes
This gap was identified by the second-pass as-built review of SHOP-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

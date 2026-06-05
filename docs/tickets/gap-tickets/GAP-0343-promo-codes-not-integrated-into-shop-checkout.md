# GAP-0343: Promo codes not integrated into shop checkout

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PROMO-001 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/PROMO-001.md`); see also `docs/tickets/writeups/PROMO-001.md`

## Location
`app/routers/catalog.py`

## Problem / Impact
Customers cannot apply promo codes to shop purchases; `shop` `applies_to` type is orphaned

## Fix
either build a catalog checkout endpoint (larger effort) or gate `applies_to: ["shop"]` behind a future-ticket flag

## Notes
This gap was identified by the second-pass as-built review of PROMO-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

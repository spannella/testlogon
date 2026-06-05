# GAP-0216: Catalog item detail (`GET /ui/catalog/categories/{cat_id}/items` and item search) does not enforce `geo_mode`/`geo_countries`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: GEO-001 · **Effort**: ?
**From**: gap audit (`docs/tickets/gaps/GEO-001.md`); see also `docs/tickets/writeups/GEO-001.md`

## Location
`GET /ui/catalog/categories/{cat_id}/items`

## Problem / Impact
Catalog item detail (`GET /ui/catalog/categories/{cat_id}/items` and item search) does not enforce `geo_mode`/`geo_countries`

## Fix
See source write-up.

## Notes
This gap was identified by the second-pass as-built review of GEO-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

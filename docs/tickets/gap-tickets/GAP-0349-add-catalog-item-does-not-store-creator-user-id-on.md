# GAP-0349: `add_catalog_item` does not store `creator_user_id` on the cart item record

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SHOP-002 · **Effort**: S; cross-ref SEC-024
**From**: gap audit (`docs/tickets/gaps/SHOP-002.md`); see also `docs/tickets/writeups/SHOP-002.md`

## Location
`add_catalog_item`

## Problem / Impact
the `add_catalog_item` helper fetches the catalog item but only copies `sku`, `name`, `quantity`, `unit_price_cents` into the cart item; `creator_id` from the catalog item is not included; consequently `_resolve_cart_creator` (`shoppingcart.py:457-465`) always returns `None` at purchase time, causing the code to fall back to `user_sub` (the buyer) as `creator_user_id` for promo validation, meaning creator-scoped promo codes will always fail with "not valid for this creator" for all catalog-backed cart items

## Fix
add `"creator_user_id": item.get("creator_id")` to the payload dict in `add_catalog_item`

## Notes
This gap was identified by the second-pass as-built review of SHOP-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

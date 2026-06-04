# SEC-024: E-commerce Price/Quantity Tampering + Entitlement-After-Refund

**Ticket**: SEC-024 · **Status**: Open · **Priority**: Critical · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 4)

## Problem
- **Client-controlled price**: `POST /ui/shoppingcart/carts/{id}/items` →
  `app/services/shoppingcart.py:346` stores `unit_price_cents` straight from the request
  body (only bounded `0..1e8`, never validated against the server catalog). A user sets
  price to 0/1 and checks out → **buys for free/arbitrary price**.
- **Entitlement not revoked on refund/cancel**: `purchase_history.py:501-535`
  (`mark_reverted`/cancel) flips status to CANCELLED/REVERTED but **never revokes the
  granted entitlement** (digital goods, file bundles, API access) → buy → receive item
  → refund → keep access.
- (Confirmed safe: cart/transaction/invoice reads are user-PK-scoped — no IDOR; promo
  discount capped at item price; stock decrement atomic via ConditionExpression.)

## Fix
- For catalogue items, derive `unit_price_cents` **server-side** from the catalog SKU;
  reject/ignore a client-supplied price (or only allow it for explicitly free-form
  items with seller authorization). Enforce `quantity >= 1` on add.
- On status transition to CANCELLED/REVERTED/refunded, call
  `revoke_entitlements_for_transaction(txn_id)` (and reverse any granted access/credits).

## Testing
pytest: adding a catalog item ignores a client price and uses the catalog price;
checkout total matches server pricing; refunding a digital-good order revokes the
entitlement (subsequent access → 403).

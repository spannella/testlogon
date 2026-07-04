# ECOM Bug #2 — shop order stuck at `pending_payment` after a completed cart purchase (2026-07-04)

## Symptom
`POST /ui/shoppingcart/carts/{id}/purchase` completes the purchase (buyer
purchase-history txn `COMPLETED`, stock decremented, seller credited), but the
associated `/ui/orders/{order_id}` lifecycle header stays at
`status="pending_payment"` (`lifecycle_status="created"`) forever. The order-detail
screen shows a paid order as still awaiting payment.

## Root cause
`commerce_order_service.create_order` seeds the header at `lifecycle_status="created"`
(legacy mirror `status="pending_payment"`) when `ORDER_LIFECYCLE_ENABLED=1` (it is, on
prod). `shoppingcart.purchase_cart` captures payment synchronously but never advances
that header — nothing calls the `app.services.order_lifecycle` state machine after a
successful one-shot purchase, so the order is orphaned in the initial state.

## Fix
After a fully successful `purchase_cart` (right after `_ecm_commit`, before the return),
advance the order via the EXISTING state machine `order_lifecycle.transition_order(order_id,
"approved", actor=buyer, reason="Cart purchase paid", idempotency_key=canonical_idempotency_key)`.

- Transition chosen: `created -> approved` — the ONLY forward/positive edge out of `created`
  in the 11-state graph (`created -> {approved, held, cancelled}`). `approved` legacy-mirrors
  to `"approved"` = payment approved / paid. No new states invented.
- `completed` is deliberately NOT targeted: it is a post-shipment terminal state
  (`shipped -> completed`); reaching it would require falsely asserting allocate/pick/pack/ship
  events for (possibly physical) cart goods that never happened. `approved` is the correct
  "paid, awaiting fulfillment" state; the buyer txn/stock/earnings were already correct.
- Safe + idempotent: guarded on `lifecycle_status == "created"` (so an already-advanced or
  admin-moved order is never re-transitioned), the transition itself is version-gated (CAS on
  current status) with an idempotency-key fast-path, and the whole block is best-effort
  (try/except + log) so a lifecycle hiccup never blocks or reverses the purchase.
- Only fires on the FIRST successful purchase: replays (cart already `PURCHASED`, or the
  CAS-conflict replay branch) return earlier and never reach this block. The checkout-session /
  redirect path (which legitimately stays pending until a webhook) is untouched — this only
  runs inside the synchronous `purchase_cart` money-capture path.

## Files
- `app/services/shoppingcart.py` — `purchase_cart` (prod serving path
  `/home/ubuntu/testlogon`). Prod-only: the `order_lifecycle` router/service and this diverged
  `purchase_cart` do not exist in the android-impl dev clone, so this is a prod-apply record
  (`bug2_order_lifecycle_advance.patch`), not a runnable branch fold.

## Verified (prod, real sessions, https://tl-api.bitbazaar.cc)
Buyer `ecbuyer1783123620@testlogon.example`, physical widget @2500c, category `22d0a057…`.
- BEFORE (8 orders created pre-fix): all `status=pending_payment / lifecycle_status=created`.
- AFTER (new purchase, order `c9d4e9d32a2808741d1db9030c3352bf`):
  `status=approved / lifecycle_status=approved`.
  `GET /ui/orders/{id}/history` = `None->created (order_created)` then
  `created->approved (actor=buyer, reason "Cart purchase paid")`.
  `GET /ui/orders` list shows the new order `approved` while older ones stay `pending_payment`.
- Buyer `GET /ui/purchase-history/transactions/{txn}` = `status=COMPLETED`,
  `external_ref = c9d4e9d32a2808741d1db9030c3352bf` (order/txn linkage intact).
- Idempotent replay: re-`POST …/purchase` on the same cart returns the same `order_id`,
  order stays `approved`, history still exactly 2 rows (no double transition, no error).

## Ops
- Backup: `app/services/shoppingcart.py.bak_ecom2_1783144144` (on prod `/home/ubuntu/testlogon`).
- Restart: `su - ubuntu -c "bash /home/ubuntu/restart_backend.sh"`; `/openapi.json` polled 200.
- Fold record: `ops/prod-hotfixes/ecom/bug2_order_lifecycle_advance.patch` + this README.

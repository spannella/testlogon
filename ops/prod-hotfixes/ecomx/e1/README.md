# ECOMX EPIC E1 — MONEY-CORRECTNESS (real charge / paid-gating / reversible refund / full clawback / one commission / rail hardening)

Live prod hotfix folded here. All 5 files are **byte-identical dev==prod==repo** (md5-verified).
Verified 29/29 on BOTH the live dev-clone uvicorn and the live PROD uvicorn over real HTTP
(+ live DDB-Local + live stripe-mock) — NOT an in-process TestClient.

## Files (md5)
- `shoppingcart.py`        `921498e42ca3376970e831dd634e8fc8`
- `purchase_history.py`    `ef694c42d76ca874473cfa5b2f75a8f5`
- `refund_requests.py`     `05081a50a75d2ad13da5cc10743f5a8f`
- `live_commerce_split.py` `dc1491ea414175968187b214e50a7d5f`
- `order_lifecycle.py`     `4f5118193a844d49b025f551768e5d0e`

## Ticket-by-ticket
- **A1 REAL CHECKOUT CHARGE** (`shoppingcart.purchase_cart` + new `_charge_cart_payment_intent`
  / `_resolve_cart_payment_method`): the buyer PM is charged on the honest stripe-mock rail
  (off_session+confirm+idempotency_key, accept-under-mock, real CardError→402) BEFORE the cart
  CAS / order-paid mark / seller credit. No charge → no completed order. The canonical per-cart
  idempotency key is the Stripe idempotency_key so a double-submit charges once at the processor;
  a decline/no-valid-PM raises 402 and restores the decremented stock.
- **A2 PAID-GATING** (`shoppingcart` + `commerce_entitlement_orchestrator`): the order header is
  marked `payment_status="paid"` only after a successful charge, and `process_order_entitlements`
  runs only then; a deferral is now logged loudly instead of `except: pass`.
- **A3 REVERSIBLE REFUND** (`order_lifecycle._maybe_refund`): owner/admin cancel-refund on a cart
  order now drives the real refund (create+approve refund_request off the stamped
  `buyer_debit_txn_id`) — no more silent no-op; a missing ref is a LOGGED error.
- **A4 REFUND WINDOW / POST-SHIP** (existing owner-cancel gate at {created,approved} + A9 below):
  owner cancel is blocked once the order advances past approved (allocated/picking/packed/shipped).
- **A5 REFUND ATTRIBUTION** (`purchase_history.record_cart_purchase` + `shoppingcart`): the buyer-debit
  ledger meta carries `recipient_user_id` / `refund_seller_ids` / `refund_host_id`.
- **A13 FULL CLAWBACK** (`refund_requests.approve_request`): reverses the buyer + EVERY seller of a
  multi-seller cart AND the livecom host — clawing each party's ACTUAL net credited for the order
  (never the gross buyer amount, so it cannot over- or under-claw). Net order ledger → ~0.
- **A6 ONE COMMISSION MODEL** (`shoppingcart` shop credit): a regular shop sale now nets the seller
  the SAME platform fee (`LIVECOM_PLATFORM_FEE_BPS`, 1500 bps) as an in-stream sale and records the
  fee in the same `PLATFORM#revenue` ledger. Previously shop paid GROSS (seller earned 15% more
  off-stream; the fee was phantom).
- **A7 LIVECOM SETTLE MARKER AFTER CREDITS** (`live_commerce_split.settle_stream_order` + `_credit`
  + `_platform_fee_record`): each credit / platform-fee row is now written with a DETERMINISTIC sk
  under `attribute_not_exists`, and the replay short-circuit gates on `status=="settled"` (the
  TERMINAL marker), not mere marker existence. A crash between the `settling` claim and the terminal
  marker re-drives (idempotently) the credits so the seller/host are never stranded un-paid.
- **A8 DDB-TRANSACT** (`refund_requests.approve_request`): the clawback transact is built from
  `ddb_transact_client()` with NATIVE AttributeValue items (the tips-fixed seam — the resource
  client's document transform 500s on DDB-Local), with a compensating-delete guard on the sequential
  fallback so a partial write can't leave the ledger half-reversed.
- **A9 CLOSE REFUND WINDOW AFTER SHIPPED** (`refund_requests.create_refund_request`): a self-service
  refund on an order whose lifecycle is packed/shipped/completed → 400 (use the return flow).
- **A10 STOCK vs CAS** (`shoppingcart`): the decremented-stock list is restored on a charge failure,
  and a concurrent double-tap yields exactly one order (cart CAS + Stripe idempotency) with no oversell.

## LIVE-server verify matrix (29/29 on dev AND prod, real HTTP)
See `verify_ecomx1.py`. Covers: charge→paid+debit+seller-net+platform-fee+stock; decline (no-valid-PM)
→402/OPEN-cart/stock-restored/no-debit; idempotent re-submit → one order/one debit; refund → buyer
credit + BOTH sellers clawed + host clawed + net~0; A8 transact atomic (approve 200, no 500 fallback);
owner cancel-refund reverses charge + claws seller; A7 crashed-marker replay pays + second settle
idempotent no-op; A9 shipped→400; A10 concurrent double-tap → one order, no oversell. 0 residue.

## Deploy (prod)
`.bak_ecomx1_20260716_144505` on prod for all 5 files. Restarted via
`pkill -f 'uvicorn app.main'` (SSM-root) + `sudo -u ubuntu bash /home/ubuntu/restart_backend.sh`;
single healthy worker on :8000, local + public openapi 200.

## Notes / residuals (non-blocking)
- `ORDER_LIFECYCLE_ENABLED=1` on prod (owner-cancel + ship-group tail); added to the dev-clone
  `.env.local` (gitignored) to mirror prod for verify. The flag was already live on prod.
- Pre-existing (NOT introduced here): tipx `A4 collab split atomic` is 1 known failure in
  `verify_tipx_a` inside `tips.maybe_collaboration_split` (unrelated to any E1 file); the tipx A2
  single-recipient clawback still PASSES against the rewritten `approve_request`.

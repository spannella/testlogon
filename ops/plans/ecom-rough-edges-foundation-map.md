# E-COMMERCE ROUGH-EDGES AUDIT — FOUNDATION MAP (shared)

Author: audit subagent. Branch android-impl @ ad7cea3f (dev host .249). Prod EC2
i-08f937fc705ebea75 (tl-api.bitbazaar.cc), read-only via /tmp/ssm_send.py.
This doc is the shared foundation for the per-dimension auditors. It maps what was
BUILT, marks DEV vs PROD-ONLY per area, traces the two flows + the state machine,
and lists the sharpest open questions. NO e-commerce behavior changed.

## 0. DEV vs PROD divergence (correcting the memory)
The memory said "the whole order-lifecycle subsystem exists only on PROD." That is
NOW ONLY PARTLY TRUE. md5 comparison dev vs prod:
- IDENTICAL on both: app/services/order_lifecycle.py, app/routers/order_lifecycle.py,
  app/routers/shipping.py, app/services/live_commerce_split.py, app/services/order_ship_groups.py,
  commerce_order_service.py, order_store.py, orders.py router, shipment_tracking.py router.
  So the ORDER STATE MACHINE + read/history/cancel + ORD-008/009 adjustments/ship-groups
  ARE readable/runnable on the dev clone.
- DIVERGENT (prod newer): app/services/shoppingcart.py (prod 1105 / dev 1063). The prod
  tail of purchase_cart (created->approved lifecycle advance + seller_ship_groups
  populate_on_approval) is PROD-ONLY (dev clone omits it — dev purchase_cart returns right
  after _ecm_commit, leaving the order header orphaned at created/pending_payment).
- PROD-ONLY FILES (absent from dev): app/services/seller_ship_groups.py + app/routers/
  seller_ship_groups.py (ECOM-SELLER), app/services/shipment_tracking.py (ECOM D4 — dev has
  the ROUTER shipment_tracking.py but NOT the service). Folded snapshots live under
  ops/prod-hotfixes/ecom-ship/seller_ship_groups.py (md5-identical to live prod service).

## 1. What was BUILT (by program) + anchors + DEV/PROD
- #105 full verify / #106 money+state (ops/prod-hotfixes/ecom/README.md): shoppingcart
  purchase_cart seller credit (BUG A/D), stock decrement (BUG B), refundability (BUG C),
  refund entry_id (BUG E), digital-goods credit type=credit (BUG F), created->approved
  advance (BUG G, PROD-ONLY). Anchors: app/services/shoppingcart.py::purchase_cart;
  app/services/purchase_history.py::record_cart_purchase L244-311; refund_requests.py.
- ECOM-SELLER G1-G4 (ops/prod-hotfixes/ecom-seller): per-seller ship groups + you-sold-it
  push + buyer address + scoped queue + real line names. Files seller_ship_groups.py
  (svc+router). PROD-ONLY. **See CRITICAL FINDING #1 — the router is NOT mounted on the live
  prod server.**
- ECOM-SHIP D1-D4 (ops/prod-hotfixes/ecom-ship): D1 store-mgmt owner-scope (no backend
  change), D3 buyer order_shipped push, D4 shipment_tracking subsystem (carrier detect +
  out-for-delivery/delivered pushes + webhook/poll seams + simulate). PROD service
  shipment_tracking.py; router IS live (/ui/orders/tracking/{sg}, /ui/shipping/tracking/*,
  /ui/admin/shipment-tracking/{sg}/simulate).
- ECOM-EASYPOST (ops/prod-hotfixes/ecom-ship/easypost): EasyPost seam in shipment_tracking
  create_on_ship/poll_tracking/ingest_webhook (config-gated on EASYPOST_API_KEY; no-op if absent).
- AD-ECOM (ops/prod-hotfixes/ad-ecom/shop_ads.py): sponsored products serve
  (/ui/ads/shop/serve, live on prod) + boost_listing; charge reuses /ui/ads/track
  (funds-guarded, idempotent, per its own header). shop_ads.py exists DEV+PROD (md5 identical).
- LIVE-COMMERCE (ops/prod-hotfixes/live-commerce + live_commerce_split.py): in-stream buy
  (purchase_cart broadcast_session_id/host_id) + settle_stream_order commission split
  (platform fee -> seller_pool -> host affiliate commission / seller_net). DEV+PROD identical.

## 2. ORDER LIFECYCLE state machine (order_lifecycle.py, DEV==PROD)
11-state graph L37-55: created->{approved,held,cancelled}; approved->{allocated,held,
backorder,cancelled}; allocated->picking; picking->packed; packed->shipped;
shipped->{completed,returned}; completed->returned; held->{...}; backorder->{allocated,
cancelled}; cancelled/returned terminal. Legacy `status` mirror L58-70. transition_order
L209-321 = CAS on lifecycle_status + HIST# audit + audit_event; idempotent replay on
same-state+key. Router order_lifecycle.py: /transition is ADMIN-ONLY (require_admin_or_root_csrf);
/cancel is owner-or-admin, owner-cancellable only at {created,approved} with refund=body.refund.
- Header seeded `created`/pending_payment by commerce_order_service.create_order.
- created->approved: PROD-ONLY tail of purchase_cart.
- **NO trigger advances the CONSUMER order header past `approved`.** Only shoppingcart
  (created->approved) and shipping_fulfillment.py (wired ONLY to facilities.py B2B shipments,
  NOT the consumer cart) call transition_order. A real buyer's /ui/orders/{id}/lifecycle
  header DEAD-ENDS at `approved`; never shipped/completed/delivered.
- The seller ship-group table and shipment_tracking table are SEPARATE state machines that
  NEVER write back to the T.orders header. Seller "mark shipped" advances the ship-group only.
- THREE parallel fragmented ship/fulfil models, none synced: (a) T.orders ORD-009 ship-groups
  (/ui/orders/{id}/ship-groups, order_ship_groups.py); (b) seller_ship_groups table
  (/ui/seller/sales — DEAD, #1); (c) shipping_fulfillment shipments
  (/ui/shop/shipping/shipments/{id}/advance).

## 3. BUYER PURCHASE path
browse catalog (/ui/catalog/*) -> add to cart (shoppingcart.add_item L339, enriches
creator_user_id from catalog L395-402; add_catalog_item L411) -> purchase
(POST /ui/shoppingcart/carts/{id}/purchase -> purchase_cart L519):
1. stock validate + atomic decrement (CAS stock_count>=qty, rollback on fail) L545-585
2. promo validation/discount L592-625
3. create_order_from_line_items (header seeded `created`) L628-645
4. record_cart_purchase L718 -> **writes purchase_transactions status=COMPLETED + T.billing
   DEBIT ledger, but NO real payment-method charge / Stripe PaymentIntent / balance
   decrement** (purchase_history.py L244-311). Bookkeeping-only "charge".
5. seller credit ledger (type=credit, "Shop sale", pro-rated to final_total) L736-773;
   skipped for stream-attributed sales.
6. livecom split settle_stream_order L778-787 (when broadcast_session_id).
7. invoice best-effort L799-821; _ecm_commit reservations L826.
8. PROD-ONLY tail: created->approved + seller_ship_groups.populate_on_approval.

## 4. SELLER FULFILLMENT path (ECOM-SELLER, PROD)
populate_on_approval (seller_ship_groups.py L121) splits paid cart into per-seller groups
(idempotent sha1(order#seller)), backfills real line names onto T.order_items (G4),
resolves buyer ship_to (G2), writes group row status=`approved`, notify_seller (G1 alert
shop_item_sold + FCM push, deep-link /seller/orders?sale={sg}).
Seller queue = /ui/seller/sales (list/get/transition), require_ui_session non-admin,
scoped to own groups. transition() L346 advances approved->allocated->picking->packed->
shipped via order_lifecycle.TRANSITIONS; on `shipped` fires _notify_buyer_shipped (D3) +
shipment_tracking.create_on_ship (D4). **BUT /ui/seller/sales is NOT mounted on live prod
(#1) — groups ARE created + sellers ARE pushed, but they have NO live endpoint to see or
fulfil them. The app's feature/sellerstore SellerSalesViewModel calls a dead route.**

## 5. Routers / app screens / carrier seam
ROUTERS (dev unless noted): catalog.py (1540; reviews L873-985, no wishlist here),
shoppingcart.py (401), order_lifecycle.py (207), orders.py (209 ORD-008/009 adj+ship-grp),
shipping.py (321), shipment_tracking.py (121), refund_requests.py (163), live_commerce.py
(83); PROD-ONLY: seller_ship_groups.py router (150, DEAD-not-mounted). Returns subsystem
live on prod: /ui/returns[/admin/...]. Wishlist: ops/prod-hotfixes/wishlist/wishlist.py —
NOT in dev main, NOT in prod openapi (confirm whether mounted at all).
APP SCREENS (android/feature): catalog/ProductDetail, cart/Cart, checkout/CheckoutSession +
checkout/address/AddressShipping, purchases/OrderDetail, ordertracking/OrderTracking,
tracking/Tracking, sellerstore/{SellerStore,SellerSales,SellerOrders,ListingEditor},
wishlist/Wishlist, broadcast_shelf/ProductsShelf, broadcasthost GoalsProducts.
CARRIER/EASYPOST seam (shipment_tracking.py): detect_carrier L51 (USPS/UPS/FedEx/DHL by #
format), create_on_ship L178 (EasyPost tracker if key), advance L308 (buyer pushes,
_claim_notify string-set once-only L249), ingest_webhook L376, poll_tracking L440,
simulate_step L344.

## 6. DDB-Local / transact failure-class scan (tipping lesson)
- refund_requests.approve_request L295: `T.billing.meta.client.transact_write_items` with
  `_serialize_item(...)` PRE-SERIALIZED AV maps = the exact tipping DDB-Local 500 class.
  MITIGATED by try/except(ClientError,TypeError)->sequential ddb_put fallback, BUT the
  fallback is NON-ATOMIC (buyer refund_credit + seller refund_debit can half-land) — verify
  on the running server whether the transact path 500s and the split is ever left partial.
- shipment_tracking._claim_notify L249: `ADD notified_statuses :s` (string set) update_item
  on the resource table — lower risk than transact, but is the once-only delivery-push guard;
  verify string-set ADD works on the target DDB.
- live_commerce_split settle: SETTLEMENT marker conditional-put FIRST, per-seller _credit
  AFTER + best-effort -> a mid-loop crash leaves partial credits with the idempotency marker
  set (replay = no-op) => some sellers never credited. assert L189 in prod path.

## 7. Sharpest open questions per dimension
MONEY-CORRECTNESS: (a) Is ANY real payment-method charge ever made, or is every shop/livecom/
digital purchase a ledger-only "COMPLETED" with no card capture? (record_cart_purchase). (b)
Refund of a never-captured charge (owner /cancel?refund=true, refund_requests approve) — does
billing.refund_payment issue real money-out with no capture? (c) livecom refund: clawback only
recovers ONE seller_user_id from meta — host affiliate commission is NEVER clawed back. (d)
partial-credit windows (livecom settle, refund transact fallback). (e) order header amount_cents
vs cart total vs ORD-008 adjustments never reconciled into the "charge".
BUYER FLOW/UX: order header dead-ends at `approved` while /ui/orders/tracking/{sg} (live) moves
to delivered — buyer OrderDetail/OrderTracking may contradict. Reviews have NO verified-purchase
gate + caller-supplied `reviewer` name (spoofable, not tied to user_sub) + no rating bounds
(catalog.py add_review L907).
SELLER FULFILLMENT: /ui/seller/sales DEAD on live prod (P0) — seller gets the sold-push but
cannot list/fulfil; app SellerSalesViewModel hits a dead route. Which of the 3 parallel ship
models (if any) does the app actually drive to mark-shipped?
ORDER-LIFECYCLE+SHIPPING (prod): nothing bridges ship-group/tracking status back to the order
header; delivered never -> completed; no auto out-for-delivery/delivered without admin simulate
or an EasyPost webhook (is EASYPOST_API_KEY set on prod?).
COVERAGE/MEASUREMENT/NOTIFICATIONS: the ecom-seller 32/32 + ecom-ship 52/52 verifies ran via
in-process TestClient that MOUNTS the router itself — masking that the live server never mounts
/ui/seller/sales (recurring "verify shim masks running-server failure" lesson). Re-verify every
ecom claim against the LIVE openapi, not the harness.

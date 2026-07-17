# E-Commerce Subsystem — Rough-Edges Audit & Smoothing Plan (ECOMX-*)

Audit target: `android-impl` @ HEAD `e5418353`. Read-only audit of the shipped e-commerce program
(#105 full-verify, #106 money/state, #107 app surfaces, ECOM-SELLER, ECOM-SHIP, ECOM-EASYPOST,
AD-ECOM, LIVE-COMMERCE) spanning catalog/cart/checkout/orders/fulfilment/shipping/reviews/wishlist
/digital-goods/live-commerce, over the shared `T.billing` ledger. This document is the ONLY write
from the audit; it changes no e-commerce behavior.

Ground-truth notes: file:line anchors are on the DEV clone unless marked PROD. The order-lifecycle /
seller-fulfilment / shipping subsystem was believed prod-only; md5 comparison during this audit
proved **most of it is byte-identical dev==prod** (`order_lifecycle.py`, `shipment_tracking.py`,
`carrier_tracking*.py`, `orders.py`, `order_ship_groups.py`, `shoppingcart` core). **Genuinely
prod-only / divergent:** the `seller_ship_groups.py` service+router, the `shoppingcart` created→
approved + ship-group-populate tail, and the `shipment_tracking` service (dev has only its router).
Folds live under `ops/prod-hotfixes/**`.

---

## 1. HEADLINE VERDICT

**E-commerce is a well-built, well-scaffolded SHELL wrapped around (a) a purchase that never charges
real money and (b) a fulfilment/tracking backend the buyer app is wired to the wrong key of — so the
entire post-purchase experience silently dead-ends or self-contradicts.** The catalog, cart (atomic
qty/stock CAS + optimistic rollback), review-compose, wishlist-heart, per-screen Loading/Empty/Error
scaffolds, the 11-state order graph's CAS+audit engine, ship-group idempotency, the EasyPost webhook
parser, and the live-commerce split arithmetic are all genuinely real and correct. The roughness is
not missing spinners — it is **missing and mis-wired STEPS**.

Completeness estimate: buyer browse→cart ~85% (solid); buyer checkout→charge ~35% (no address, no
tax/shipping, no real charge, dual dead-end CTAs); buyer post-purchase (track→receive→review→refund)
~25% (tracking reads the wrong key, no receive step, no digital-goods access, refund pushes
suppressed); seller fulfilment ~15% on the LIVE server (the non-admin queue router is not mounted;
the app's alternate path hits an admin-only transition against a buyer-scoped list); order-lifecycle
progression ~20% (header dead-ends at `approved`; delivered never → completed; returns dead);
carrier tracking ~10% in prod (EasyPost unconfigured, poller off — advances only via an admin
"simulate" button); measurement/notifications ~30% (shop earnings collapse into "other", no seller
analytics, refund/review pushes suppressed or absent).

### The 5 load-bearing rough edges (fix these and e-commerce goes from "rough" to "trustworthy")

1. **Checkout never charges real money; the "charge" is a ledger memo, and every downstream payout /
   refund pays out cash that was never collected (P0, MONEY).** `shoppingcart.purchase_cart` +
   `purchase_history.record_cart_purchase:244` write a `purchase_transactions` row `status=COMPLETED`
   and a `T.billing` DEBIT with **no PaymentIntent, no card capture, no balance decrement, no
   insufficient-funds guard**. Digital-goods entitlement is then gated on `payment_status ∈
   {paid,captured}` which the cart never sets → buyer "pays," gets **no download/access** (deferred
   forever, silently). Every order is effectively free; every seller credit and refund is an
   over-payment against money never taken.

2. **The seller cannot fulfil a sale on the LIVE server — both app paths dead-end (P0, SELLER).** The
   non-admin `/ui/seller/sales` router (`seller_ship_groups.py`) exists but is **not mounted in prod
   `app/main.py`** (verified: no `/ui/seller/sales*` in live openapi), while `populate_on_approval`
   still fires the "you sold it" push deep-linking there. The app's alternate `SellerOrders` path
   calls the **admin-only** `POST /ui/orders/{id}/transition` (403 for a real seller) against a
   **buyer-scoped** `GET /ui/orders` list (shows the seller's own purchases, not their sales). A real
   creator who makes a sale today gets the push and then hits a wall — no view, no address, no
   mark-shipped. Root cause: the "verify shim mounts the router in-process" trap masked a dead live
   route (recurring lesson).

3. **The buyer's order state is fragmented across THREE unsynced models that never reconcile (P0/P1,
   LIFECYCLE).** (a) order header `lifecycle_status` dead-ends at `approved` — nothing advances a
   consumer order past it; (b) `seller_ship_groups.status` advances to `shipped` but **never writes
   back to the header**; (c) `shipment_tracking.status` can reach `delivered` but touches neither.
   So `/ui/orders/{id}/lifecycle` shows `approved` while `/ui/orders/tracking/{sg}` shows delivered —
   the two contradict, `completed`/`returned` are unreachable, and buyer in-app tracking is
   **permanently empty** because the app reads tracking by **txn-id** while the seller writes it by
   **ship-group-id** (no bridge). Buyer buys → seller ships with a real number → Track screen shows
   nothing forever.

4. **Owner cancel-with-refund silently no-ops AND post-ship refunds leak money (P0/P1, MONEY).**
   `order_lifecycle._maybe_refund:445` refunds only if the order carries a `payment_intent_id`/
   `ledger_sk` — cart orders carry none → `POST /cancel?refund=true` returns 200 "cancelled" with **no
   money moved and no error**. Because the header never leaves `approved`, the owner-cancel window
   stays open **even after the goods ship / are out for delivery** → seller loses product AND money.
   Separately, the admin refund path's **seller/host clawback never fires** (no `recipient_user_id`
   in the buyer-debit meta) → every approved shop refund credits the buyer while the seller keeps
   100% (double-enrichment), and the livecom host commission is never clawed back.

5. **Checkout is missing the address / tax / shipping step; measurement and refund/review
   notifications are largely dark (P1/P2, BUYER-FLOW + COVERAGE).** The buyer app has **no reachable
   shipping-address step** (the AddressShipping screen is a fully-built ORPHAN nothing navigates to),
   **no tax, no shipping cost** — the cart total is item-subtotal only, and the shipping-rate engine
   is orphaned. Shop + live-commerce earnings **collapse into the "other" bucket** (unattributable to
   the seller), there is **no seller sales/GMV analytics surface** at all, refund `refund_approved`/
   `refund_denied` alerts are **unregistered → push permanently suppressed + dead-linked**, and
   there is **no review-received notification** and **no verified-purchase gate** on reviews
   (spoofable author, unbounded rating, unauthenticated delete).

### Cross-cutting DEV/PROD divergence liability (call-out for the coming main-merge)
The seller-fulfilment layer (`seller_ship_groups.py` svc+router, the `shoppingcart` approve+populate
tail, the `shipment_tracking` service) exists **only on the running prod EC2, folded under
`ops/prod-hotfixes/`, and is NOT in the dev clone / repo**. This means: (a) any dev-side build or the
main-merge will **silently regress the seller sale→fulfil→ship→track flow** because the code that
implements it is not in the branch; (b) the "verify shim" that mounts routers in-process will keep
reporting these features GREEN while the live server 404s/403s them; (c) the one live seller push
deep-links to a route that only exists in the fold. **This is the single biggest structural risk and
must be reconciled into the repo BEFORE any further e-commerce work — hence a FOUNDATION epic (E0)
below.**

---

## 2. PRIORITIZED PUNCH-LIST (deduped across all five dimensions)

Severity P0 (money leak / dead flow / lost order) → P3 (polish). Effort S/M/L. Location DEV/PROD.
Overlapping findings from multiple dimension audits are merged; the originating IDs are noted.

### A. MONEY-CORRECTNESS
| # | Sev | Finding (merged) | Buyer/Seller impact | Fix-shape | Eff | Loc |
|---|-----|------------------|---------------------|-----------|-----|-----|
| A1 | P0 | Checkout never charges a PM; ledger-memo only; no funds guard (money#1, B2) | Every order effectively free; all payouts/refunds are over-payments | Insert real charge (default PM / funded-balance decrement under accept-under-mock seam) between cart CAS and `record_cart_purchase`; roll back stock+cart on failure; only then mark paid | M | DEV==PROD `shoppingcart.purchase_cart` L519+, `purchase_history.record_cart_purchase:244` |
| A2 | P0 | Digital-goods entitlement deferred forever — paid, no access (money#2, B5) | Buyer pays, receives no download/access, no error | After successful charge set order `payment_status="paid"` before `process_order_entitlements`; surface the deferral instead of `try/except: pass` | S | DEV==PROD `commerce_entitlement_orchestrator:167`, `shoppingcart:695` |
| A3 | P0 | Owner cancel-refund silently no-ops (no intent/ledger ref on cart orders) (money#5, lifecycle P1-1) | Buyer told "cancelled", no refund issued, no error | Persist buyer-debit ledger sk/entry_id on order metadata at purchase; make missing ref a logged error not a silent skip | S | DEV==PROD `order_lifecycle._maybe_refund:445`, `shoppingcart:628` |
| A4 | P0 | Post-ship cancel window stays open → refund after goods shipped (lifecycle P0-3) | Seller ships, buyer cancels-refund mid-transit, out product AND money | Gate owner-cancel on aggregate ship-group state (block once any group ≥ packed/shipped); route post-ship to RETURN flow | M | DEV==PROD `order_lifecycle` cancel router |
| A5 | P1 | Refund seller/host clawback never fires → double-enrichment on every shop/livecom refund (money#3) | Buyer credited + seller keeps 100% + livecom host commission never reversed | Stamp `recipient_user_id`/`seller_id`/`host_id` into buyer-debit meta at purchase; make `approve_request` reverse ALL seller/host credits (multi-seller aware) | M | DEV==PROD `refund_requests.approve_request:275` |
| A6 | P1 | Regular shop sale pays seller GROSS (no `platform_fee_bps`); livecom takes 15% — inconsistent + fee never collected (money#4) | Same product earns seller 15% more off-stream; platform revenue is phantom | Apply one commission model (net-of-`platform_fee_bps`) on regular shop credit; record platform fee consistently | M | DEV==PROD `shoppingcart:736`, `live_commerce_split:169` |
| A7 | P2 | Cart total has no tax + no shipping; rate engine orphaned (money#8, B3) | Physical orders collect no shipping/tax; seller eats cost; total ≠ any quoted total | Compute shipping (`shipping_rates`) + tax into `final_total` before charge; thread components into order lines | M | DEV==PROD `shoppingcart:546` |
| A8 | P2 | livecom idempotency marker claimed BEFORE per-seller credits → crash strands payout permanently (money#6) | Seller/host never paid after mid-settle crash; summary reports zeros | Write credits first (each idempotent), terminal marker last; gate replay on `settled` not mere existence | S | DEV==PROD `live_commerce_split.settle_stream_order:110` |
| A9 | P2 | Refund clawback transact uses resource-client + pre-serialized AV maps (DDB-Local 500 class); fallback is non-atomic (money#7) | On running server atomic path may always throw → non-atomic double-write can leave ledger unbalanced | Build transact from the table's own client with native items (tips-fixed helper); guard sequential fallback with compensating write | S | DEV==PROD `refund_requests:295` |
| A10 | P2 | Stock decremented BEFORE cart-status CAS; losing double-tap oversells/leaks stock (money related-bug, seller#7-adjacent) | Concurrent double-tap decrements stock twice; CAS-fail path 409s without restoring | Move stock decrement after (or into) the cart-CAS transaction; restore stock on cart-CAS failure | S | DEV==PROD `shoppingcart:565` vs `:648` |

### B. BUYER-FLOW / UX
| # | Sev | Finding | Impact | Fix-shape | Eff | Loc |
|---|-----|---------|--------|-----------|-----|-----|
| B1 | P1 | Buyer in-app tracking permanently EMPTY — app reads by txn-id, seller writes by ship-group-id, no bridge (B1) | Buyer sees "Not shipped" forever; push deep-link shows nothing | On ship-group `shipped`, also `update_shipping(buyer_sub, txn_id, …)` (map order_id→txn_id) OR repoint app tracking GET at `/ui/orders/tracking/{sg}` | M | app `TrackingApi.kt:28`; PROD `shipment_tracking:178`, `seller_ship_groups:373` |
| B2 | P1 | Order reads "Completed" at t=0 (txn status), contradicting "Not shipped" (B2) | No processing/pending state; false "where's my stuff" + premature refunds | Seed txn PENDING; drive header off lifecycle status; flip Completed only on delivery | M | DEV==PROD `purchase_history:244`; app `PurchasesDomain.kt:28` |
| B3 | P1 | No reachable shipping-address step; AddressShipping screen is an orphan; no shipping/tax line (B3, money#8) | Buyer can't enter/confirm delivery address; seller may ship to stale address | Insert `AddressShippingDest` into OrderReview→place-order; require address before enabling Place order; surface shipping+tax | M | app `CartNavigation.kt:92`, `OrderReviewScreen.kt`, `CheckoutDomain.kt:116` |
| B4 | P2 | Two disjoint checkout CTAs — "Choose payment method" redirect flow never creates the order (B4) | Confusing dual CTA; redirect path no-ops or (if enabled) double-charges | Collapse to one CTA; make redirect-success feed a PM/intent into `purchase_cart` completing the SAME order; hide while payments stubbed | M | app `OrderReviewScreen.kt`, `CartNavigation.kt:66`, `RedirectCheckoutViewModel.kt` |
| B5 | P2 | No digital-goods access/download surface in the app (B5, money#2) | Buyer pays for digital content, no way to get it | Add product-type to catalog model + a "Library/Access" surface / Download on OrderDetail hitting the entitlement endpoint | M | app `CatalogDomain.kt:22`; DEV==PROD `shoppingcart:695` |
| B6 | P2 | No "mark received / confirm delivery" affordance; order never reaches buyer-visible terminal (B6, lifecycle P1-3) | Buyer can't confirm receipt (gates return window / payout release); state frozen | Add "Confirm delivery" on OrderDetail when tracking=delivered (or auto on delivered push) → completed | S | app OrderDetail; DEV==PROD `shipment_tracking.advance:308` |
| B7 | P3 | No qty picker / no variant selection on PDP; add-to-cart hardwired qty=1 (B7) | Clunky multi-qty; variant goods unshoppable from detail | Add qty stepper to PDP add bar; add variant model+selector if variants are real, else document single-SKU only | S | app `ProductDetailViewModel.kt:150`, `CatalogDomain.kt:34` |
| B8 | P3 | Nullable `purchase_txn_id` dumps buyer to raw history instead of confirmation; txn write can be silently swallowed (B8) | No per-order confirmation in degraded case; potential lost order handle | Make txn-write failure fatal/surfaced; route confirmation off `orderId` (always present) not nullable txn id | S | app `CartNavigation.kt:74`, `CartDomain.kt:104`; DEV==PROD `purchase_history:283` |

### C. SELLER-FULFILMENT
| # | Sev | Finding | Impact | Fix-shape | Eff | Loc |
|---|-----|---------|--------|-----------|-----|-----|
| C1 | P0 | `/ui/seller/sales` router NOT mounted on live prod (seller#1, coverage C8) | Seller gets "sold" push to a dead route; can't view/address/ship the sale | `include_router(seller_ship_groups.router)` in prod `main.py`; re-verify against LIVE openapi not harness | S | PROD `main.py` (missing), `seller_ship_groups.py` router |
| C2 | P0 | App's `SellerOrders` path hits admin-only `POST /ui/orders/{id}/transition` (403 for real seller) (seller#2) | No working mark-shipped for a non-admin seller today | Point app fulfilment at `/ui/seller/sales/{sg}/transition` (once C1 mounted); retire `/ui/orders/transition` for sellers OR add owner-scoped transition | S | PROD `order_lifecycle.py:114`; app `SellerOrdersApi.kt:33` |
| C3 | P1 | `GET /ui/orders` returns the seller's own PURCHASES, not their SALES (seller#3) | "Seller Orders" screen shows wrong dataset | Source sales from `seller_ship_groups.list_for_seller` (i.e. C1's route), not `/ui/orders` | S | PROD `order_lifecycle.py:47` |
| C4 | P2 | Sold-notification degrades to empty `ship_to`; populate is fire-and-forget (partial multi-seller populate leaves later sellers un-notified) (seller#6) | "You sold it" with blank address; a later seller silently never notified | Mark group `ship_to_missing` + alert to supply address; make populate resumable (already idempotent per-seller) not swallowed | S | PROD `seller_ship_groups._resolve_ship_to`, `shoppingcart:866` |
| C5 | P2 | oversell guard bypassed for lines missing `category_id`/`item_id` or null `stock_count` (seller#7) | Stream/livecom/ad-sourced lines sold with zero inventory enforcement | Require catalog keys on any stock-tracked line; fail closed (409) rather than skip | S | PROD/DEV `shoppingcart:547` |
| C6 | P3 | Multi-seller split silently drops self-purchase / sellerless lines from ship-groups after stock already decremented (seller#8) | Buyer pays for an item that lands in no queue → never ships, no dead-letter | Route sellerless/self lines to a fallback/admin bucket (or digital auto-deliver) instead of dropping | S | PROD `seller_ship_groups.populate_on_approval` |

### D. ORDER-LIFECYCLE + SHIPPING (state machine + carrier tracking + delivery)
| # | Sev | Finding | Impact | Fix-shape | Eff | Loc |
|---|-----|---------|--------|-----------|-----|-----|
| D1 | P0 | Consumer order header permanently stuck at `approved` — nothing advances it; shipped/completed/returned unreachable (lifecycle P0-1) | Buyer "My Orders" never progresses; seller work invisible to header; analytics report all paid orders as approved | In `seller_ship_groups.transition` bridge to `transition_order` on group edges (after multi-seller aggregation, D3); add delivered→completed bridge (D4) | M | DEV==PROD `order_lifecycle`, `seller_ship_groups.transition:346` |
| D2 | P0 | NO automatic carrier sync in prod — status moves only via admin "simulate" or manual webhook POST; EasyPost unconfigured, poller off (lifecycle P0-2, seller#5) | After ship, tracking sits at `label_created` forever; carrier tracking is a demo harness | Provision `EASYPOST_API_KEY` + register `tracker.updated` webhook to `/ui/shipping/tracking/webhook` (parser ready) OR run real poll loop; ship dark until wired | M | DEV==PROD `carrier_tracking_poller:200`, `shipment_tracking:213`, `easypost_client:89` |
| D3 | P1 | Multi-seller order: no aggregation; partial ship has no header representation (lifecycle P1-2) | First seller to ship would flip whole header to shipped; no "partially shipped" | Aggregate group statuses in `list_by_order`; derive header (min across groups); add `partially_shipped` or hold at packed until all ship | M | DEV==PROD `seller_ship_groups.populate_on_approval:121`, `list_by_order:325` |
| D4 | P1 | Nothing bridges delivered→completed; `COMPLETED` unreachable (lifecycle P1-3, B6) | Orders never complete; completion-gated payout/review/reorder never fire | On `advance(...delivered...)` call `transition_order(order_id,"completed")` once all groups delivered (idempotent) | S | DEV==PROD `shipment_tracking.advance:308` |
| D5 | P1 | `RETURNED` state + whole return flow dead; refunds never mark order returned or restock (lifecycle P1-4) | Can't distinguish clean sale from return; no restock on return | `refund_requests.approve_request` (post-ship) → `transition_order(...,"returned")` + restock; define who triggers SHIPPED→RETURNED | M | DEV==PROD `order_lifecycle:43`, `refund_requests` |
| D6 | P1 | Two divergent `detect_carrier` impls disagree → order tracked under wrong carrier / dead tracking URL (lifecycle P1-5) | Buyer clicks a tracking link that 404s at the carrier | Collapse to one `detect_carrier` (the `shipment_tracking` one); `carrier_tracking` imports it | S | DEV==PROD `carrier_tracking:56`, `shipment_tracking:56` |
| D7 | P2 | `_claim_notify` once-only push guard drops delivery push on ANY non-conditional error (no retry) (lifecycle P2-1) | Buyer silently misses out-for-delivery/delivered push on transient DDB error | Distinguish conditional-fail (dedupe) from other errors (retry/still push); push after successful claim commit | S | DEV==PROD `shipment_tracking._claim_notify:238` |
| D8 | P2 | `advance()` writes status with no CAS → out-of-order carrier events regress delivered→in_transit (lifecycle P2-2) | Confusing tracking UI; delivered flips backward with no correcting push | Guard with status-rank (advance only forward in PROGRESSION, allow exception) or CAS on updated_at | S | DEV==PROD `shipment_tracking.advance:296` |
| D9 | P2 | Two delivery notification rails: `shipment_tracking` pushes; `carrier_tracking` in-app-only + mis-typed (`delivery_confirmed` to seller) (lifecycle P2-3, coverage) | Inconsistent buyer experience; latent double/mismatched notifications | Delete/redirect `carrier_tracking` notify path to canonical `shipment_tracking._notify_buyer`; one rail | S | DEV==PROD `carrier_tracking:200` |
| D10 | P3 | `approved→shipped` is an illegal edge → wired B2B `transition_order("shipped")` silently fails (swallowed) (lifecycle P3-1) | B2B/facilities shipments also never advance the header; dead code that looks live | Walk intermediate states or add documented fast-forward edge; don't swallow the exception | S | DEV==PROD `shipping_fulfillment:204`, `order_lifecycle` TRANSITIONS |
| D11 | P3 | Orphan-order window: header seeded `created` pre-approve; crash leaves permanent pending_payment ghost with committed side effects (lifecycle P3-2) | Buyer paid but order shows pending; needs manual admin transition | Reconciliation job promoting `created` headers with a COMPLETED purchase_transactions row to `approved` | S | DEV==PROD `shoppingcart:833` |

### E. COVERAGE / MEASUREMENT / NOTIFICATIONS
| # | Sev | Finding | Impact | Fix-shape | Eff | Loc |
|---|-----|---------|--------|-----------|-----|-----|
| E1 | P1 | Shop + live-commerce earnings all collapse into "other" — unattributable (coverage C1) | Seller can't see product-sales revenue or livecom commission as a line; no reconciliation | Add `classify_entry` branches (reason startswith "Shop sale"/"Live-stream" or `meta.category`); add `shop_sales`+`live_commerce` fields to `EarningsBreakdown` | S | DEV==PROD `creator_earnings.classify_entry:36`, `models.EarningsBreakdown:2635` |
| E2 | P1 | No seller sales/GMV/units/AOV/fulfilment-funnel analytics surface exists (coverage C2) | Seller flies blind; store-mgmt has CRUD but no measurement | Add `/ui/seller/analytics` aggregating `seller_ship_groups` + "Shop sale" ledger; (first mount C1) | M | PROD (new) |
| E3 | P1 | Refund `refund_approved`/`refund_denied` unregistered → push permanently suppressed + in-app dead-linked (coverage C5) | Refund lands silently; no push, no tappable "view refund" | Register events in `ALERT_EVENT_TYPES` + `DEFAULT_PUSH_EVENT_TYPES`; add `url_map` entries; pass `action_url` | S | DEV==PROD `refund_requests:337`, `alerts.py:163`, `push.py:335` |
| E4 | P1 | Reviews: no verified-purchase gate, spoofable `reviewer`, no rating bounds, unauthenticated delete (coverage C9, map#4) | Astroturfed reviews; out-of-range stars; anyone can wipe any review | Require matching purchase for (user_sub,item_id); clamp rating 1..5; force reviewer from user_sub; scope delete to author-or-admin | M | DEV==PROD `catalog.add_review:907`, `delete_review:953` |
| E5 | P1 | Wishlist router NOT mounted (app screen 404s); no restock/price-drop notify (coverage C11) | Wishlist may be entirely dead; core "notify when back in stock" absent | Mount `wishlist` router; add stock/price watcher diffing saved snapshot → `wishlist_restock`/`wishlist_price_drop` alerts | M | `ops/prod-hotfixes/wishlist/wishlist.py`, `main.py` |
| E6 | P2 | Sponsored-product/boost spend has NO conversion attribution (no ROAS) (coverage C3) | Boost looks like pure cost; ROAS/CPA unmeasurable | Thread `ad_click_id` from sponsored card into cart→purchase; write conversion on `record_cart_purchase`; surface in seller ad analytics | M | DEV==PROD `shop_ads.py`, `shoppingcart`/`purchase_history` |
| E7 | P2 | No per-stream live-commerce sales/commission analytics (coverage C4) | Broadcaster can't tell what a shopping stream earned | `/ui/live-commerce/sessions/{id}/summary` reading settle lines (already store `host_commission_cents`/`seller_net_cents`) | S | DEV==PROD `live_commerce.py`, `live_commerce_split` |
| E8 | P2 | No review-received notification; buyer self-cancel-refund fires no notification (coverage C6, C7) | Reviews accumulate silently; buyer cancels-refund with zero confirmation | `write_alert("review_received")` on `add_review`; emit `order_refunded` from cancel-refund branch; register+default-on | S | DEV==PROD `catalog.add_review:907`, `order_lifecycle` cancel |
| E9 | P2 | Buyer order/tracking split across FOUR+ unsynced surfaces; shipping push deep-links onto the dead-ending header (coverage C12) | History/tracking screens disagree; "tap to track" shows contradictory/stale state | Pick ONE canonical buyer order read joining header+ship-group tracking; point all deep-links at it; deprecate redundant surfaces | M | DEV==PROD `purchase_history`, `order_lifecycle`, `order_ship_groups`, `shipment_tracking` |
| E10 | P3 | No seller response to reviews; no review edit (coverage C10) | Seller can't address a bad review publicly | Add `POST /items/{id}/reviews/{rid}/response` (owner-scoped) + `seller_response` field | S | DEV==PROD `catalog` review model |

### F. DEV/PROD DIVERGENCE (structural — its own bucket)
| # | Sev | Finding | Impact | Fix-shape | Eff | Loc |
|---|-----|---------|--------|-----------|-----|-----|
| F1 | P0 | Seller-fulfilment layer (`seller_ship_groups` svc+router, `shoppingcart` approve+populate tail, `shipment_tracking` service) lives ONLY on prod, folded under `ops/prod-hotfixes/`, NOT in the repo | Main-merge / dev build silently regresses seller sale→fulfil→ship→track; verify shims report GREEN while live 404s | Reconcile the prod-only files into the dev clone/repo (diff fold vs live, land in `app/`), add a live-openapi assertion to CI | M | `ops/prod-hotfixes/ecom-*/**` vs `app/` |

---

## 3. TICKETED PLAN (ECOMX-*)

Dependency-ordered epics. **Money-correctness and the FOUNDATION reconciliation come first** — do not
build fulfilment/lifecycle features on top of a prod-only layer that isn't in the repo, and do not
pay/refund against a charge that never happened.

### EPIC E0 — FOUNDATION: reconcile the prod-only e-commerce layer into the repo (do FIRST)
Rationale: everything downstream (D*, C*) touches files that today exist only on the running prod
box. Merge them into the branch before editing them, so the main-merge cannot regress the flow.

- **ECOMX-01** — Land `seller_ship_groups.py` (svc+router), the `shoppingcart` created→approved +
  ship-group-populate tail, and the `shipment_tracking` *service* into `app/` on `android-impl`.
  *AC:* dev clone byte-diff vs the folds is empty; app builds; `git grep seller_ship_groups app/main.py`
  matches. (F1)
- **ECOMX-02** — Mount the seller + wishlist routers in `app/main.py`; add a CI assertion that the
  LIVE `/openapi.json` contains `/ui/seller/sales*` and `/ui/wishlist*`. *AC:* both paths present in a
  fresh boot's openapi; the assertion fails if a router is dropped. (C1, E5, F1)
- **ECOMX-03** — Repoint the app's seller fulfilment at `/ui/seller/sales*` and retire the
  `/ui/orders/transition` seller path (or add an owner-scoped transition). *AC:* a non-admin seller can
  list sales and mark-shipped end-to-end against the live server (not the harness). (C2, C3)

### EPIC E1 — MONEY-CORRECTNESS: real charge, correct payout, correct refund
- **ECOMX-10** — Real charge step in `purchase_cart`: charge default PM / decrement funded balance
  under the accept-under-mock seam; 402 before any ledger write; roll back stock+cart on failure; set
  order `payment_status="paid"` on success. *AC:* $0-balance buyer is declined (no ledger debit, no
  order); a successful charge writes debit + marks order paid; decline restores stock and cart status.
  (A1, A2 dependency)
- **ECOMX-11** — Grant digital entitlements after paid: call `process_order_entitlements` only after
  `payment_status="paid"`, and surface (not swallow) deferrals. *AC:* buying a digital good yields an
  entitlement + an app-visible access affordance; a deferral raises/logs visibly. (A2, B5)
- **ECOMX-12** — Reversible refund metadata + real refund on cancel: persist buyer-debit ledger
  sk/entry_id + `recipient_user_id`/`seller_id`/`host_id` on the order at purchase; make
  `_maybe_refund` reverse it and log-loudly on a missing ref. *AC:* `POST /cancel?refund=true` moves
  money for a cart order or returns an explicit error; no silent 200. (A3, A5 dependency)
- **ECOMX-13** — Full seller/host clawback on approved refund (multi-seller + livecom host aware);
  reverse ALL seller/host credits for the order. *AC:* after refund the order's net ledger is zero
  across buyer+seller(s)+host; livecom host commission is clawed back. (A5)
- **ECOMX-14** — One commission model: apply net-of-`platform_fee_bps` on regular shop credit; record
  the platform fee consistently for shop + livecom. *AC:* identical product earns the seller the same
  net on- and off-stream; a platform-fee ledger entry exists for both. (A6)
- **ECOMX-15** — Cart tax + shipping into `final_total` via `shipping_rates`; thread components into
  order/invoice lines. *AC:* a physical order's charged total = subtotal + shipping + tax; components
  visible on the order. (A7, B3 dependency)
- **ECOMX-16** — Harden the money rails: livecom write-credits-before-marker; refund transact via the
  table's own client with native items + compensating-write guard on fallback; move stock decrement
  into/after the cart-CAS with restore on CAS-fail. *AC:* mid-settle crash replay still pays; refund
  transact succeeds on the running DDB-Local server; concurrent double-tap yields one purchase with no
  stock leak. (A8, A9, A10)

### EPIC E2 — ORDER-LIFECYCLE: one reconciled state model
- **ECOMX-20** — Bridge ship-group edges to the order header with multi-seller aggregation: derive
  header state from min across groups; add `partially_shipped`; header→`shipped` only when all groups
  ship. *AC:* header advances past approved; a partial ship shows partial, not fully-shipped. (D1, D3)
- **ECOMX-21** — delivered→completed bridge (all groups delivered, idempotent) + buyer "Confirm
  delivery" affordance. *AC:* a delivered order reaches `completed`; completion-gated logic fires once.
  (D4, B6)
- **ECOMX-22** — Return flow: `SHIPPED/COMPLETED→RETURNED` on approved refund + restock; define the
  RMA trigger. *AC:* a post-delivery refund marks the order `returned` and restocks inventory. (D5)
- **ECOMX-23** — Reconcile the four buyer order/tracking surfaces into one canonical read; point all
  deep-links at it; fix the txn-vs-ship-group tracking key so buyer tracking populates. *AC:* the push
  deep-link and OrderDetail show the same live state; buyer tracking shows the seller's real number.
  (B1, B2, E9, D1)
- **ECOMX-24** — Orphan-order reconciliation job (promote `created` headers with a COMPLETED
  purchase_transactions row to approved). *AC:* a crash mid-purchase self-heals within one sweep. (D11)

### EPIC E3 — CARRIER TRACKING: real advancement, one detector
- **ECOMX-30** — Wire real carrier sync: provision `EASYPOST_API_KEY` + register the
  `tracker.updated` webhook to `/ui/shipping/tracking/webhook` (or enable the poll loop). *AC:* a real
  tracking number advances label_created→…→delivered without an admin clicking simulate. (D2)
- **ECOMX-31** — Collapse to one `detect_carrier` (the `shipment_tracking` impl); `carrier_tracking`
  imports it; single delivery-notification rail. *AC:* one number resolves to one carrier + one valid
  tracking URL; one delivery push. (D6, D9)
- **ECOMX-32** — Harden tracking writes: monotonic status guard (CAS/rank) on `advance`; distinguish
  dedupe-vs-error in `_claim_notify` (retry on transient). *AC:* an out-of-order event can't regress
  delivered; a transient DDB error doesn't drop the delivery push. (D7, D8)

### EPIC E4 — BUYER-FLOW / UX
- **ECOMX-40** — Address step: insert `AddressShippingDest` into OrderReview→place-order; require +
  pass address_id into purchase; surface shipping+tax lines. *AC:* a physical-good buyer must pick an
  address before Place order; the seller's `ship_to` is that address. (B3)
- **ECOMX-41** — One checkout CTA: collapse Place-order + Choose-payment; redirect-success feeds a
  PM/intent into the SAME `purchase_cart`; hide redirect while payments stubbed. *AC:* one path; no
  double-charge; no dead-end. (B4)
- **ECOMX-42** — Order-status realism: seed txn PENDING; drive OrderDetail header off lifecycle;
  Completed only on delivery; route confirmation off `orderId` not nullable txn-id; make txn-write
  failure fatal. *AC:* a fresh order reads processing/approved, not Completed; the confirmation always
  identifies THIS order. (B2, B8)
- **ECOMX-43** — Digital-goods library/access surface + catalog product-type. *AC:* a purchased
  digital good is downloadable/openable in-app. (B5)
- **ECOMX-44** — PDP qty stepper + variant selector (or documented single-SKU). *AC:* buy N from the
  PDP; variant goods selectable (or explicitly unsupported). (B7)

### EPIC E5 — COVERAGE / MEASUREMENT / NOTIFICATIONS
- **ECOMX-50** — Earnings attribution: classify shop + livecom credits into `shop_sales` +
  `live_commerce` breakdown fields. *AC:* the earnings summary shows shop and live-commerce as
  distinct non-zero lines; "other" no longer absorbs them. (E1)
- **ECOMX-51** — Seller sales analytics `/ui/seller/analytics` (GMV, units, AOV, pending-fulfilment).
  *AC:* a seller sees month-to-date shop revenue + top item + open-fulfilment count. (E2)
- **ECOMX-52** — Notification completeness: register + default-on + url_map + action_url for
  `refund_approved`/`refund_denied`/`order_refunded`/`review_received`; emit from cancel-refund and
  add_review. *AC:* refund, self-cancel-refund, and new-review each produce a tappable push. (E3, E8)
- **ECOMX-53** — Review integrity: verified-purchase gate, rating clamp 1..5, reviewer forced from
  user_sub, delete scoped to author-or-admin; add seller response + author edit. *AC:* only purchasers
  review; ratings bounded; a stranger can't delete a review; a seller can respond. (E4, E10)
- **ECOMX-54** — Wishlist restock/price-drop watcher (on stock/price change diff vs saved snapshot →
  alert). *AC:* a back-in-stock / price-drop on a wishlisted item pushes the buyer. (E5)
- **ECOMX-55** — Conversion attribution: thread `ad_click_id` sponsored-card→cart→purchase; write a
  conversion event; per-stream livecom summary. *AC:* a boosted-listing sale is attributable (ROAS
  computable); a shopping stream shows its GMV + host commission. (E6, E7)

### Recommended build sequence
1. **E0 (FOUNDATION)** — reconcile the prod-only layer + mount the missing routers + fix the app's
   dead seller paths. Nothing else is safe or verifiable on the live server until this lands.
2. **E1 (MONEY-CORRECTNESS)** — real charge → paid gating → reversible refund + full clawback → one
   commission model → tax/shipping → rail hardening. Stop paying/refunding against a phantom charge
   before building anything on top.
3. **E2 (ORDER-LIFECYCLE)** — collapse the three state models into one reconciled header (needs E0's
   seller layer + E1's paid/refund metadata).
4. **E3 (CARRIER TRACKING)** — make status advance for real (needs E2's bridged states to be
   meaningful).
5. **E4 (BUYER-FLOW/UX)** — address step, one CTA, realistic status, digital access, PDP polish
   (needs E1 charge + E2 states to reflect truth).
6. **E5 (COVERAGE)** — attribution, seller analytics, notifications, review integrity, wishlist,
   conversion (measurement + comms layered on a now-correct flow).

Verify EACH ticket against the **live running server + live `/openapi.json`**, never an in-process
TestClient — the recurring "verify shim masks the running server" trap is the direct root cause of
the two P0 seller findings and must not re-mask these fixes.

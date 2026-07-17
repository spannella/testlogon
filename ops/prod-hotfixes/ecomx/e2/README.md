# ECOMX EPIC E2 — ORDER-LIFECYCLE UNIFICATION (one reconciled state model)

Collapses the THREE unsynced order-state models into ONE reconciled source of truth. Before E2 an
order had three parallel state machines that never wrote back to each other:

  (1) the `T.orders` lifecycle **HEADER** (`order_lifecycle.transition_order`) — DEAD-ENDED at
      `approved` for every cart purchase (nothing advanced it);
  (2) the per-seller **`seller_ship_groups`** rows (`approved`→…→`shipped`);
  (3) the **`shipment_tracking`** record (`label_created`→…→`delivered`).

So `/ui/orders/{id}/lifecycle` (header) and `/ui/orders/tracking/{sg}` (tracking) openly
contradicted each other, a delivered order never reached `completed`, a multi-seller order could
read "shipped" while a second seller had shipped nothing, and the buyer's txn-tracking read was
permanently empty (it read the txn `shipping` key which the ship-group path never populated).

E2 makes the header a **DERIVED AGGREGATE** of its ship groups + their tracking records. New module
`app/services/order_fulfillment_bridge.py` is the single write-back point; the seller ship-group
transition and the tracking `advance` both call `reconcile_order(order_id)`.

Live prod hotfix folded here. All files are **byte-identical dev==prod==repo** (md5-verified).
Verified **33/33** against the live PROD uvicorn over real HTTP (+ live DDB-Local) — NOT an
in-process TestClient. E1 money-path re-verified **29/29** (no regression). 0 residue.

## Files (md5)
- `order_fulfillment_bridge.py` (NEW) `e352965084c176524a2a166f162b7fd9`
- `seller_ship_groups.py`             `e18f7ef6663ab105db62d0c562cec95f`
- `shipment_tracking.py`              `bdefd6bbe3179e6822398ca0ec2ab914`
- `refund_requests.py`                `7e3836ff002e0345308c498363db1400`
- `order_lifecycle.py` (router)       `6dea4bdb797aaf377b236f88bc5663f5`
- `purchase_history.py` (router)      `d2a87b938af6963eb2c71a43dff475a5`

## Ticket-by-ticket
- **ECOMX-20 (D1/D3) — bridge ship-group edges to the header + multi-seller aggregation.**
  `seller_ship_groups.transition` now calls `bridge.reconcile_order` after EVERY edge. The bridge
  computes the header lifecycle target = the MIN progress stage across all of the order's ship
  groups (capped at `packed` until every group ships), and walks the header forward through the
  canonical `order_lifecycle.transition_order` (version-gated CAS + HIST# audit) one legal step at a
  time. Header → `shipped` ONLY when EVERY group has shipped. A finer-grained derived
  `fulfillment_status` (`unfulfilled`/`processing`/`partially_shipped`/`shipped`/`out_for_delivery`/
  `delivered`/`returned`) is stamped on the header for the buyer surfaces — so a partial ship reads
  `partially_shipped`, not fully-shipped.
- **ECOMX-21 (D4/B6) — delivered→completed + buyer "Confirm delivery".** `shipment_tracking.advance`
  calls `bridge.reconcile_order` on the `out_for_delivery`/`delivered` edges; once EVERY group's
  tracking is delivered the header advances `shipped`→`completed` (idempotent). New
  `POST /ui/orders/{id}/confirm-delivery` (owner-or-admin) forces every group's tracking to delivered
  then reconciles — the buyer affordance when the carrier feed lags.
- **ECOMX-22 (D5) — return flow.** `refund_requests.approve_request` now calls `bridge.mark_returned`
  at its tail: a refund approved on a SHIPPED/COMPLETED order transitions the header
  `shipped`|`completed`→`returned` and RESTOCKS the returned inventory (sourced from the buyer-debit
  txn's stored cart items → catalog `{PK:CAT#cat, SK:ITEM#item}` `stock_count += qty`). No-op on a
  pre-ship order (that path stays a cancel, per E1 A9). Idempotent via the header CAS.
- **ECOMX-23 (B1/B2/E9/D1) — reconcile the buyer read surfaces + fix the txn↔ship-group key.**
  New canonical `GET /ui/orders/{id}/tracking` aggregates ALL of the order's ship-group
  `shipment_tracking` records (with real carrier + tracking URL). The buyer txn-tracking read
  `GET /ui/purchase-history/transactions/{txn}/tracking` — permanently empty pre-E2 because it read
  the never-written txn `shipping` key — now falls back to the order's ship-group tracking (resolved
  off the txn `external_ref`/`metadata.order_id`). Header, ship groups and tracking can no longer
  contradict.
- **ECOMX-24 (D11) — orphan / stuck-order self-heal sweep.** New
  `POST /ui/orders/admin/reconcile-stuck` (admin). Paginates T.orders (Scan filter applies AFTER
  the page read, so a single Limit-capped scan misses deep orphans — fixed to loop LastEvaluatedKey)
  and promotes any `created` header that already carries a COMPLETED buyer-debit txn (payment
  captured, crash before the approve tail) to `approved` + re-populates its ship groups. Fail-closed:
  only promotes when the txn is confirmed COMPLETED.

## Design notes
- The header lifecycle stays the strict linear enum (created→approved→allocated→picking→packed→
  shipped→completed, +held/backorder/cancelled/returned); `partially_shipped`/`out_for_delivery`/
  `delivered` are represented as the DERIVED `fulfillment_status` on the header (not new enum
  members) so the CAS state machine + GSI_STATUS consumers stay intact. The header advances through
  the REAL machine (no illegal jump possible — `transition_order` enforces the graph).
- Every bridge write is best-effort + idempotent and NEVER raises into the caller — a bridge failure
  can't block a seller shipping or a buyer's tracking read (the ship-group / tracking write already
  committed before the reconcile runs).
- Dual `detect_carrier` (carrier_tracking.py lowercase vs shipment_tracking.py uppercase) is
  DEFERRED to E3 (ECOMX-31 owns the full collapse); the two serve different rails (the poller
  subsystem vs the ship-group rail) and E2's read-surface unification (`order_tracking`) already
  removes the buyer-visible contradiction. The dual NOTIFY rails are already single-per-event
  (ship-group fires `order_shipped`; tracking fires `order_out_for_delivery`/`order_delivered`) — no
  duplicate push.

## LIVE-server verify matrix (33/33 on PROD, real HTTP — see `verify_ecomx2.py`)
Synthetic buyer + 2 sellers + admin, real catalog/carts/orders, auto-cleaned (0 residue):
- **S1** single-seller full progression: header `approved` after purchase (past `created`); header
  MIRRORS the seller group approved→allocated→picking→packed; header==`shipped` when the single
  group ships; order-tracking + txn-tracking BOTH populate with the real UPS number+URL; webhook
  `out_for_delivery`→fulfillment=out_for_delivery (lifecycle still shipped); webhook `delivered`→
  header `completed`; header(completed)==tracking(delivered) no contradiction; idempotent re-ship
  replay 200 no-op.
- **S2** MULTI-SELLER: two ship groups; ONE shipped → fulfillment=`partially_shipped`, lifecycle NOT
  shipped; BOTH shipped → header `shipped`; order-tracking aggregates 2 shipments; ONE delivered →
  NOT completed; BOTH delivered → `completed`.
- **S3** buyer confirm-delivery → header `completed`; second call idempotent (still completed).
- **S4** RETURN: refund requested while approved, order shipped, admin approves → header `returned`
  + inventory restocked by the returned qty (3).
- **S5** illegal group transition approved→shipped → 409; header unchanged (no orphan/stuck).
- **S6** ORPHAN: header forced back to `created` (txn COMPLETED, ship groups deleted) → sweep
  promotes to `approved` + re-populates the ship group.
- **REG** admin `/ui/orders/{id}/transition` still works (held). E1 money-path 29/29 (no regression).

## Routes added to the live openapi
- `GET  /ui/orders/{order_id}/tracking`          (canonical buyer order-tracking, owner-or-admin)
- `POST /ui/orders/{order_id}/confirm-delivery`  (buyer confirm delivery, owner-or-admin)
- `POST /ui/orders/admin/reconcile-stuck`        (orphan self-heal sweep, admin)

## Deploy (prod)
`.bak_ecomx_e2_20260716_185947` on prod for the 5 pre-existing files (bridge is NEW; a
`.bak_ecomx_e2_pre_sweepfix` snapshot exists from the sweep-pagination fix). Restarted via
`pkill -f 'uvicorn app.main'` (SSM-root) + `sudo -u ubuntu bash /home/ubuntu/restart_backend.sh`;
single healthy worker on :8000, local openapi 200; all 3 new routes present in the live openapi.

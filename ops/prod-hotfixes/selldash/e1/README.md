# selldash / E1 — Buyer-visible ship-group tracking (inline discovery join)

ECOMX follow-on. Closes the deep-pass finding: seller ship groups are
SELLER-partitioned (table `seller_ship_groups`, PK=seller_id / GSI_ORDER by
order_id). Before E1 the buyer order LIST + DETAIL surfaced no carrier /
tracking# / status because the buyer never held a `ship_group_id` and the
buyer-side order/ship-group list endpoints returned `[]`. The seller-entered
carrier/number/status could only be reached via the two dedicated `/tracking`
endpoints IF the caller already had the id.

E1 joins the seller ship-group tracking **INLINE** onto the buyer order (list +
detail + the ECM-007 fulfilment view) via `order_fulfillment_bridge`, WITHOUT
the buyer needing the `ship_group_id`, strictly scoped to the buyer's OWN order.

## Files (full source; copy over the prod tree)

| file (here)                 | prod path                                  |
|-----------------------------|--------------------------------------------|
| models.py                   | app/models.py                              |
| order_lifecycle.py          | app/services/order_lifecycle.py            |
| order_fulfillment_bridge.py | app/services/order_fulfillment_bridge.py   |
| order_lifecycle_router.py   | app/routers/order_lifecycle.py             |
| store_integration.py        | app/services/store_integration.py          |

## What changed

1. `order_fulfillment_bridge.order_shipments_inline(order_id, buyer_sub)` — NEW
   compact join. Delegates to the existing `order_tracking()` (one join, one
   scope check) and flattens each shipment to
   `{ship_group_id, carrier, tracking_number, tracking_url, status, last_event,
   updated_at}` + the order `fulfillment_status`. Never raises.
2. `models.OrderShipmentOut` — NEW inline shipment model. Added
   `fulfillment_status` + `shipments` to `OrderLifecycleOut` and
   `OrderListItem` (with `model_rebuild()` for the forward refs).
3. `order_lifecycle.get_order_lifecycle(..., buyer_sub=None)` — populates
   `out.shipments` + `out.fulfillment_status` from the bridge; `buyer_sub`
   scopes to the buyer's own ship groups (admin/root pass None).
4. `routers/order_lifecycle.py`:
   - `GET /ui/orders` (list) — enriches each row with inline shipments
     (scoped to the caller, bounded to a page, skips pre-ship headers).
   - `GET /ui/orders/{id}/lifecycle` + `/confirm-delivery` — pass `buyer_sub`.
5. `store_integration.get_order_fulfillment_status` (ECM-007
   `GET /ui/shoppingcart/orders/{id}`) — now populates off the REAL seller
   ship groups via the bridge (`_bridge_fulfillment_status`, composite-key
   ownership read) whenever order-lifecycle is on; the legacy SHP shipments
   table it used was never written by the seller-ship flow.

Scope-safe: a buyer only ever sees their own order's ship groups. Multi-seller
orders aggregate all groups. Read-consistent with the bridge `fulfillment_status`.

## Apply (prod, via SSM)

Probe prod first (money code is divergent). Then for each file:
`cp <prod file> <prod file>.bak_selldash_<ts>`, copy the file here over it,
`chown ubuntu:ubuntu`, `python -m py_compile`, restart backend
(`pkill -f "uvicorn app.main"` as root FIRST, then `sudo -u ubuntu bash
restart_backend.sh`), confirm `openapi.json` 200.

## Verify (LIVE HTTP — never TestClient)

`python verify_selldash_e1.py` seeds a 2-seller order, ships one group with a
carrier+tracking#, and asserts the buyer LIST + DETAIL + ECM-007 + canonical
`/tracking` all surface the same carrier/number/status, a 2nd buyer sees none
(scope), multi-seller aggregates, and delivered→completed reconciles.

e2e: `frontend/e2e/seller-buyer-tracking.spec.ts` (in ci-gate-green.txt).

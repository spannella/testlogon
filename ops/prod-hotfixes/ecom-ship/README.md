# ECOM ship-tracking hotfix — D1 (ungate store mgmt) + D3 (buyer shipped push)

LIVE PROD HOTFIX applied 2026-07-10 via SSM to EC2 `i-08f937fc705ebea75`.
`.bak_ecomd3_1783694191` on both prod files. Restart `restart_backend.sh`, openapi 200.
Prod in-process verify (verify_ecom_d1d3.py): **17/17 ALL_PASS**.

## D1 — ungate seller store management (owner-scoped, non-admin)
NO BACKEND CHANGE NEEDED. `app/routers/catalog.py` is ALREADY owner-scoped for a
NON-admin caller: every create/edit/delete endpoint uses `require_ui_session`
(not require_admin) + `_require_category_owner`/`_require_item_owner`, which 403
when `creator_id != ctx["user_sub"]`. `create_category` stamps `creator_id =
caller`; `create_item` inherits the category's `creator_id`. `list_categories`/
`list_items` gate reads via `can_access_creator`. Verified: a non-admin user
creates a category + item (owner=caller) + edits it; a DIFFERENT user gets 403 on
edit/add; each user manages only their OWN store. The remaining D1 work is the
APP `operatorOnly` gate on the store-management surfaces (separate app slice).

## D3 — buyer "Your order has shipped" push (default-ON transactional)
Two prod files patched (anchored, idempotent, py_compile-checked):

1. `app/services/alerts.py`
   - `order_shipped` registered in `ALERT_EVENT_TYPES` (so set_alert_prefs keeps it;
     mirrors the ff4c4dfd shop_item_sold learning).
   - `order_shipped` added to `DEFAULT_PUSH_EVENT_TYPES` (default-ON, opt-OUT via
     `push_opt_out_event_types`).
   - `order_shipped` added to the `commerce` alert category.

2. `app/services/seller_ship_groups.py`
   - NEW `_notify_buyer_shipped(row)`: write_alert(buyer_id, event="order_shipped",
     title "Your order has shipped", details carry carrier + tracking_number +
     order_id + summary, action_url `/orders?order={order_id}&ship_group={sg}`) +
     send_push_for_alert(buyer, "order_shipped", ...) with the same deep-link.
   - `transition(...)`: on the update into `status == "shipped"` (which captures
     tracking_number/carrier), call `_notify_buyer_shipped(updated)`.
   - IDEMPOTENT by construction: `shipped` is terminal in the state machine, so a
     repeat `shipped -> shipped` raises IllegalShipGroupTransition (409) before the
     notify — exactly one buyer push per ship-group.

## Files here
- `apply_ecom_d3.py` — anchored idempotent patcher for the two PROD service files
  (run `ROOT=/tmp/probe python apply_ecom_d3.py` to dry-run on a copy first; .bak +
  restore-on-py_compile-fail built in).
- `alerts_order_shipped_devclone.py` — the alerts.py order_shipped registration as
  applied to the DEV CLONE in-tree `app/services/alerts.py` (anchors differ slightly
  from prod: dev uses `"shop_item_sold",\n]`).
- `seller_ship_groups.py` — canonical snapshot of the PATCHED prod service file
  (the live service file is PROD-ONLY; this fold is its only git record).
- `verify_ecom_d1d3.py` — in-process prod-DDB verify (17 assertions).

## Prod ops
- Backups: `alerts.py.bak_ecomd3_1783694191`, `seller_ship_groups.py.bak_ecomd3_1783694191`.
- Buyer deep-link `/orders?order=...&ship_group=...` is forward-compatible with the
  D4 buyer tracking view (app slice) — carries the order + ship-group so tracking
  can be resolved.

## D4 — shipment-tracking subsystem (LIVE PROD HOTFIX 2026-07-10)
`.bak_ecomd4_1783695396` on 5 prod files. New table `shipment_tracking`
(PK ship_group_id, GSI GSI_TRACKING on tracking_number_norm) created on prod.
Restart openapi 200; 4 new routes live. Prod in-process verify
(verify_ecom_d4.py): **52/52 ALL_PASS**.

### New service `app/services/shipment_tracking.py`
- `detect_carrier(#)` -> USPS | UPS | FedEx | DHL | unknown by number format
  (UPS 1Z+16; USPS 20-22 digits beginning 9 / 2-alpha+9-digit+US; FedEx 12/15/20
  digits; DHL 10/11 digits) + `CARRIER_TRACKING_URLS` public tracking-page
  templates + `tracking_url(carrier,#)`.
- Tracking record keyed to the ship-group: carrier + tracking_number + status in
  {label_created,in_transit,out_for_delivery,delivered,exception} + `events`
  history (ts/status/location?/description?/source). `create_on_ship(sg_row)`
  mints it on SHIP (status=label_created, carrier detected from #, idempotent).
- `advance(...)` appends an event + fires the buyer delivery pushes IDEMPOTENTLY
  (atomic `_claim_notify` string-set claim -> each status pushes at most once).
- INGESTION SEAMS: `ingest_webhook(payload)` (maps EasyPost/Shippo/AfterShip/
  carrier status vocab -> internal status -> advance) + `poll_tracking(#)` stub
  (query-by-tracking# drop-in). SIMULATE driver `simulate_step`/`simulate_to_delivered`
  advances label_created->in_transit->out_for_delivery->delivered for demos.
- Delivery pushes: out_for_delivery -> buyer `order_out_for_delivery` Your order

## D4 — shipment-tracking subsystem (LIVE PROD HOTFIX 2026-07-10)
`.bak_ecomd4_1783695396` on 5 prod files. New table `shipment_tracking`
(PK ship_group_id, GSI GSI_TRACKING on tracking_number_norm) created on prod.
Restart openapi 200; 4 new routes live. Prod in-process verify
(verify_ecom_d4.py): **52/52 ALL_PASS**.

### New service `app/services/shipment_tracking.py`
- `detect_carrier(#)` -> USPS | UPS | FedEx | DHL | unknown by number format
  (UPS 1Z+16; USPS 20-22 digits beginning 9 / 2-alpha+9-digit+US; FedEx 12/15/20
  digits; DHL 10/11 digits) + `CARRIER_TRACKING_URLS` public tracking-page
  templates + `tracking_url(carrier,#)`.
- Tracking record keyed to the ship-group: carrier + tracking_number + status in
  {label_created,in_transit,out_for_delivery,delivered,exception} + `events`
  history (ts/status/location?/description?/source). `create_on_ship(sg_row)`
  mints it on SHIP (status=label_created, carrier detected from #, idempotent).
- `advance(...)` appends an event + fires the buyer delivery pushes IDEMPOTENTLY
  (atomic `_claim_notify` string-set claim -> each status pushes at most once).
- INGESTION SEAMS: `ingest_webhook(payload)` (maps EasyPost/Shippo/AfterShip/
  carrier status vocab -> internal status -> advance) + `poll_tracking(#)` stub
  (query-by-tracking# drop-in). SIMULATE driver `simulate_step` / `simulate_to_delivered`
  advances label_created->in_transit->out_for_delivery->delivered for demos.
- Delivery pushes: out_for_delivery -> buyer `order_out_for_delivery` "Your order
  is out for delivery"; delivered -> `order_delivered` "Your order was delivered";
  both default-ON transactional, deep-link `/orders?order=..&ship_group=..&track=1`.

### Router `app/routers/shipment_tracking.py`
- GET  /ui/orders/tracking/{ship_group_id}          buyer tracking view (buyer-scoped, 404 else)
- GET  /ui/shipping/tracking/{tracking_number}/poll poller stub (buyer/admin)
- POST /ui/shipping/tracking/webhook                ingestion seam (optional X-Webhook-Secret)
- POST /ui/admin/shipment-tracking/{sg}/simulate    demo driver (admin/root; ?to= optional)

### alerts.py
`order_out_for_delivery` + `order_delivered` registered in ALERT_EVENT_TYPES +
DEFAULT_PUSH_EVENT_TYPES (default-ON, opt-out via push_opt_out_event_types) +
the `commerce` category.

### seller_ship_groups.py (PROD-ONLY)
`transition(...)`: on the shipped edge, after `_notify_buyer_shipped`, best-effort
`shipment_tracking.create_on_ship(updated)`.

### Files
- `apply_ecom_d4.py` — anchored idempotent patcher (writes the 2 new files from
  base64 + patches alerts/settings/tables/main/seller_ship_groups; ROOT/TS/APPLY_TABLE
  env; .bak + restore-on-compile-fail; ensure_table on APPLY_TABLE=1). Probed on a
  /tmp/probe copy of the real prod files first (all anchors matched).
- `verify_ecom_d4.py` — in-process prod-DDB verify (52 assertions: carrier matrix,
  create-on-ship, simulate progression + idempotent pushes, webhook ingestion,
  poller, registration/default-ON, buyer tracking view).

## D2 (per-event PUSH-pref toggle) - backend, LIVE PROD HOTFIX

App slice needs a per-event PUSH toggle over the opt-in/opt-out alert-prefs model. The existing
`POST /ui/alerts/push_prefs` only set `push_event_types` (opt-IN) and there was no GET, so the
app could neither read the default-ON transactional set nor opt OUT of a default-ON event.

Applied via SSM (EC2 i-08f937fc705ebea75), backups `*.bak_ecomd2_1783696499`:
- `app/models.py`: `AlertPushPrefsReq` -> both `push_event_types` and `push_opt_out_event_types`
  Optional (None preserves the current list).
- `app/routers/alerts.py`: import `DEFAULT_PUSH_EVENT_TYPES`; NEW `GET /ui/alerts/push_prefs`
  returning `{push_event_types, push_opt_out_event_types, default_push_event_types}`; extended
  `POST /ui/alerts/push_prefs` to pass BOTH lists to `set_alert_prefs`.

restart_backend.sh -> openapi 200; both GET+POST /ui/alerts/push_prefs present. In-process verify
(`verify_ecom_d2.py`): default (no prefs) empty (opt-out model -> default-ON events push); opt-out
`order_shipped` persists; opt-out filters non-default events; explicit opt-in of a non-default event
persists. Patcher: `apply_ecom_d2.py` (anchored, idempotent, .bak). Dev clone patched in-tree.

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

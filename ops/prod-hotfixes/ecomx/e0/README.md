# ECOMX E0 — FOUNDATION: reconcile the prod-only e-commerce layer + mount the dead routers

Tickets: ECOMX-01, ECOMX-02, ECOMX-03 (plan `ops/plans/ecommerce-rough-edges-plan.md`).
Branch `android-impl`. Prod EC2 `i-08f937fc705ebea75` (tl-api.bitbazaar.cc), dev clone `~/dev/testlogon`.

## What was broken
- `seller_ship_groups` (service + router) + the `shoppingcart` created→approved + ship-group
  populate tail lived ONLY on prod (folded under `ops/prod-hotfixes/ecom-*/`), NOT in the repo →
  a main-merge / dev boot silently regressed seller sale→fulfil→ship→track (F1).
- `/ui/seller/sales*` router was NOT `include_router`'d in prod `main.py` → absent from the live
  openapi → seller got the "you sold it" push to a DEAD route; app `SellerSalesViewModel` hit a
  404; the app fallback (admin-only `/ui/orders/transition`) 403'd for a real seller (C1/C2/C3).
- `wishlist` router likewise unmounted (E5 precursor); it declares the api-key policy dep so
  mounting it un-registered would add to `uncovered_policy_routes` (#118 parity guard).

## What E0 did (make-it-exist-and-reachable; NO money/lifecycle logic changed)
1. RECONCILE (dev==prod==repo, byte-identical, md5-verified vs live prod):
   - `app/services/seller_ship_groups.py`  (md5 1e7d3ab1a59a807f4c853c51586f1898)
   - `app/routers/seller_ship_groups.py`   (md5 11207280d8f7fac23f3e5765b3253aeb)
   - `app/routers/wishlist.py`             (md5 a79f91255322d35ef28133e484cd6f22)
   - `app/services/shoppingcart.py`        (md5 595dac9c7501ffa96798d9c11afd547f) — prod tail
     (created→approved lifecycle advance + `seller_ship_groups.populate_on_approval`) folded in.
   - `app/services/shipment_tracking.py`   (md5 11f62bfd55dca25ec2ee81b46bd9fd11) — dev already
     had the service byte-identical to prod (map was stale); left as-is, verified equal.
2. MOUNT on BOTH dev-clone `main.py` AND prod (live hotfix):
   `include_router(seller_ship_groups_router)` + `include_router(wishlist_router)` (see
   `mount_routers.py`, anchored on the existing `shipment_tracking_router` import/mount lines).
3. #118 PARITY: registered the 3 wishlist policy-guarded routes in
   `app/services/api_key_route_scope_registry.py` (product "shopping", scopes
   `shopping:catalog:read` GET / `shopping:cart:write` POST+DELETE — both are valid catalog
   scopes) so mounting wishlist does NOT add to `uncovered_policy_routes` (see `reg_wishlist.py`).
4. APP: no source change needed — the app was already built for these routes. The seller sold-
   queue is `SellerSalesApi` → `/ui/seller/sales*`; the admin `/ui/orders` entry (`seller_orders`)
   is already `operatorOnly`-gated so a non-admin seller only sees `My sales`; the sold-push
   deep-link `/seller/orders?sale={sg}` already routes to `SellerSalesDest` (sales screen).

## Files in this fold
- `seller_ship_groups_service.py` / `seller_ship_groups_router.py` / `wishlist_router.py` —
  the reconciled prod-only files (== app/ == live prod).
- `mount_routers.py`  — idempotent anchored insert of the two `include_router` calls + imports.
- `reg_wishlist.py`   — idempotent anchored insert of the 3 wishlist registry rows.
- `e2e_seller_sales.py` — LIVE-HTTP verifier (synthetic seller+ship-group → real HTTP
  /ui/seller/sales list/detail/transition + cross-seller 404 scoping; auto-clean). Run on prod:
  `set -a; . .env.local; set +a; .venv/bin/python3 e2e_seller_sales.py`.

## Apply on prod
Backups `*.bak_ecomx_<ts>` beside each edited file; chown ubuntu:ubuntu; restart via
`sudo -u ubuntu bash /home/ubuntu/restart_backend.sh` (NOTE: SSM runs as root — the old
root-owned uvicorn must be `pkill`'d before restart or two workers race the port); openapi 200.

## LIVE verify (real HTTP, running uvicorn — NOT in-process)
- Live prod openapi (public ingress tl-api.bitbazaar.cc): `/ui/seller/sales`,
  `/ui/seller/sales/{ship_group_id}`, `/ui/seller/sales/{ship_group_id}/transition`,
  `/ui/wishlist`, `/ui/wishlist/{category_id}/{item_id}` PRESENT (2976→2981 paths). Were ABSENT.
- Unauth probes → 401 (live+gated) not 404 (dead).
- `e2e_seller_sales.py`: 9/9 PASS incl. seller lists their real sold group, detail carries buyer
  ship_to + real line name, non-admin seller transition approved→allocated, foreign seller 404.
- On-device (A15): sold-push deep-link opened "My sales" → seeded sale row + detail (ship_to)
  rendered off the now-live routes.

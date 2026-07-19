# ECOMX selldash-E2 — web seller dashboard + buyer tracking render

Follow-on to selldash-E1 (buyer-visible tracking join, backend). **E2 is
frontend-only** — no backend hotfix, so there are no server files to mirror to
prod here (unlike E1's `../e1/`). This README is the running-log entry.

## What E2 shipped (web SPA, tsc-0)

1. **Seller dashboard** — new SPA routes `/seller/sales` (list) and
   `/seller/sales/:shipGroupId` (detail) + a "Seller Dashboard" nav entry in the
   Commerce group. Lists the seller's OWN sold ship groups from
   `GET /ui/seller/sales` (buyer, real line-item names, fulfilment state,
   tracking), analytics cards (GMV / units·orders / AOV / to-fulfil) from
   `GET /ui/seller/analytics`, a detail view with a fulfilment progress bar +
   ship-to + items, and a **MARK-SHIPPED** dialog that POSTs
   `/ui/seller/sales/{sg}/transition {target_status:"shipped", carrier,
   tracking_number}`. Loading / empty / error(503 feature-off) states.

2. **Buyer tracking render** — the buyer order-detail page (`/orders/:orderId`)
   now renders the E1 inline shipment(s): carrier, tracking number (as a link to
   the carrier URL when present), status badge, a coarse milestone timeline
   (Label created → In transit → Out for delivery → Delivered), and the last
   event. Shared render in `components/shared/ShipmentTracking.tsx`. The block is
   gated on real shipment data so pre-ship orders show nothing.

## Files (all under frontend/)

- `src/api/endpoints/sellerSales.ts` — seller sales/analytics wrappers + helpers.
- `src/api/endpoints/orderLifecycle.ts` — +`OrderShipment` type; +`shipments` /
  `fulfillment_status` on `OrderLifecycle` and `OrderListItem` (mirror E1 models).
- `src/components/shared/ShipmentTracking.tsx` — buyer tracking render.
- `src/pages/seller/SellerSalesPage.tsx` — dashboard list + analytics.
- `src/pages/seller/SellerSaleDetailPage.tsx` — sale detail + mark-shipped.
- `src/pages/seller/__tests__/sellerSales.test.tsx` — vitest (7).
- `src/pages/orders/OrderDetailPage.tsx` — render the tracking card.
- `src/App.tsx` — routes; `src/components/layout/Sidebar.tsx` + `i18n/en.json` — nav.
- `e2e/seller-sales-dashboard.spec.ts` — e2e (6); added to `e2e/ci-gate-green.txt`.

## Verify (real HTTP + real SPA + on-phone)

- tsc-0, `npm run build` green, vitest 7/7.
- e2e `seller-sales-dashboard` 6/6 (seed via real HTTP → seller dashboard UI →
  mark-ship from web → buyer sees tracking → 2nd-buyer scope 404). Regression:
  `seller-buyer-tracking` (E1) 9/9 + `order-lifecycle` 11/11 green.
- On-phone A15 (SM-A156U) Chrome via CDP against the served SPA: seller
  dashboard (GMV/units/AOV/to-fulfil), mark-shipped dialog (ups +
  1Z999AA1…), buyer tracking card (UPS / tracking# / Label Created / timeline).

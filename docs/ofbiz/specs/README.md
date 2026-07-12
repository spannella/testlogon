# OFBiz Full Buildout — Per-Ticket Design Specs

Generated 2026-06-10 via a 206-ticket multi-agent workflow: each ticket got a ~5-page grounded design spec (Stage 1) followed by a verification + citation pass against the live codebase (Stage 2, appended as a `## 12. Verification Log`).

**Aggregate:** 206 specs, ~1.04M words (~5,000 words/spec); verification caught **867 corrections** and flagged **451 unconfirmed assumptions** (build-time risks). Two specs (PRD-010, FAC-006) returned `verified:false` — extra scrutiny warranted at build.

Constraints baked into every spec: additive + default-OFF flag-gated; GL derives from the existing single-entry ledger (never forks billing); refunds reuse `refund_payment`; deterministic-id idempotency; single-table DDB with `attr_types` for numeric GSI sort keys; hermetic offline tests (frozen `T`/`S` via `object.__setattr__`).

| # | Module | Tickets | Source ticket file |
|---|--------|--------:|--------------------|
| 1 | Party / CRM | 15 | `PARTY_CRM_TICKETS.md` |
| 2 | Catalog depth | 16 | `CATALOG_DEPTH_TICKETS.md` |
| 3 | Order lifecycle | 15 | `ORDER_LIFECYCLE_TICKETS.md` |
| 4 | Facility / fulfillment | 15 | `FACILITY_FULFILLMENT_TICKETS.md` |
| 5 | Purchasing / SCM | 17 | `PURCHASING_SCM_TICKETS.md` |
| 6 | Shipping / logistics | 19 | `SHIPPING_LOGISTICS_TICKETS.md` |
| 7 | Marketing / campaigns | 14 | `MARKETING_CAMPAIGNS_TICKETS.md` |
| 8 | eCommerce integration | 15 | `ECOMMERCE_INTEGRATION_TICKETS.md` |
| 9 | Manufacturing / MRP | 14 | `MANUFACTURING_MRP_TICKETS.md` |
| 10 | Point of Sale | 14 | `POS_TICKETS.md` |
| 11 | Human Resources | 13 | `HR_TICKETS.md` |
| 12 | Fixed Assets | 17 | `FIXED_ASSETS_TICKETS.md` |
| 13 | OFBiz commerce core (inventory/returns/accounting/pricing) | 22 | `OFBIZ_COMMERCE_TICKETS.md` |

---


## Party / CRM (PTY)

| Ticket | Title | Corr. | Unconf. |
|--------|-------|------:|--------:|
| [PTY-001](PTY-001.md) | Party/CRM feature flag & settings keys | ? | ? |
| [PTY-002](PTY-002.md) | Party single-table DynamoDB definition + handle | ? | ? |
| [PTY-003](PTY-003.md) | Party / role / relationship / contact-mech Pydantic models | ? | ? |
| [PTY-004](PTY-004.md) | Party CRUD service (PERSON / PARTY_GROUP) | ? | ? |
| [PTY-005](PTY-005.md) | Party role assignment service | ? | ? |
| [PTY-006](PTY-006.md) | Party relationship service | ? | ? |
| [PTY-007](PTY-007.md) | Unified contact-mechanism service (email / phone / postal) | ? | ? |
| [PTY-008](PTY-008.md) | B2B organization account service | ? | ? |
| [PTY-009](PTY-009.md) | Additive contacts→party migration (back-compatible) | ? | ? |
| [PTY-010](PTY-010.md) | Link PERSON parties to users/profiles/addresses | ? | ? |
| [PTY-011](PTY-011.md) | Party/CRM router (parties, roles, relationships, mechs) | ? | ? |
| [PTY-012](PTY-012.md) | B2B org-account router + migration admin endpoints | ? | ? |
| [PTY-013](PTY-013.md) | Frontend types + endpoint wrappers | ? | ? |
| [PTY-014](PTY-014.md) | Party/CRM page, route & nav entry | ? | ? |
| [PTY-015](PTY-015.md) | Party/CRM hermetic pytest + E2E suite | ? | ? |

## Catalog depth (PRD)

| Ticket | Title | Corr. | Unconf. |
|--------|-------|------:|--------:|
| [PRD-001](PRD-001.md) | Product-depth scoping spike & single-table key design | ? | ? |
| [PRD-002](PRD-002.md) | Product-depth tables, settings & feature flag | ? | ? |
| [PRD-003](PRD-003.md) | Product-depth Pydantic models | ? | ? |
| [PRD-004](PRD-004.md) | Category-tree service (parent/child rollup) | ? | ? |
| [PRD-005](PRD-005.md) | Category-tree router endpoints | ? | ? |
| [PRD-006](PRD-006.md) | Product feature & feature-category model | ? | ? |
| [PRD-007](PRD-007.md) | Virtual↔variant product service | ? | ? |
| [PRD-008](PRD-008.md) | Variant & feature router endpoints | ? | ? |
| [PRD-009](PRD-009.md) | Bundle/kit composition service | ? | ? |
| [PRD-010](PRD-010.md) | Product associations service | ? | ? |
| [PRD-011](PRD-011.md) | Bundle & association router endpoints | ? | ? |
| [PRD-012](PRD-012.md) | Product-level price components | ? | ? |
| [PRD-013](PRD-013.md) | Price-component router endpoints | ? | ? |
| [PRD-014](PRD-014.md) | Frontend types & endpoint wrappers | ? | ? |
| [PRD-015](PRD-015.md) | Catalog-depth admin UI (variants, features, bundles, tree) | ? | ? |
| [PRD-016](PRD-016.md) | Hermetic offline pytest + E2E tests | ? | ? |

## Order lifecycle (ORD)

| Ticket | Title | Corr. | Unconf. |
|--------|-------|------:|--------:|
| [ORD-001](ORD-001.md) | Order-lifecycle scoping & state-machine design | ? | ? |
| [ORD-002](ORD-002.md) | Feature flag & settings | ? | ? |
| [ORD-003](ORD-003.md) | DDB single-table items, GSIs, and table handles | ? | ? |
| [ORD-004](ORD-004.md) | Pydantic models for lifecycle, history, ship groups, adjustments | ? | ? |
| [ORD-005](ORD-005.md) | Order state-machine service | ? | ? |
| [ORD-006](ORD-006.md) | Order status-history (append-only audit trail) | ? | ? |
| [ORD-007](ORD-007.md) | Lifecycle integration at order creation (flag-gated) | ? | ? |
| [ORD-008](ORD-008.md) | Order adjustments (discount/surcharge/tax/shipping lines) | ? | ? |
| [ORD-009](ORD-009.md) | Ship groups | ? | ? |
| [ORD-010](ORD-010.md) | Cancel & return transitions (refund via existing billing) | ? | ? |
| [ORD-011](ORD-011.md) | Order-lifecycle router (transitions, history, adjustments, ship groups) | ? | ? |
| [ORD-012](ORD-012.md) | Status & ship-date list/query endpoints | ? | ? |
| [ORD-013](ORD-013.md) | Frontend types & endpoint wrappers | ? | ? |
| [ORD-014](ORD-014.md) | Order-lifecycle admin page, customer view, route & nav | ? | ? |
| [ORD-015](ORD-015.md) | Hermetic backend + E2E tests | ? | ? |

## Facility / fulfillment (FAC)

| Ticket | Title | Corr. | Unconf. |
|--------|-------|------:|--------:|
| [FAC-001](FAC-001.md) | Facility/fulfillment scoping spike & data-model delta | ? | ? |
| [FAC-002](FAC-002.md) | Facility tables, settings & feature flag | ? | ? |
| [FAC-003](FAC-003.md) | Facility/fulfillment Pydantic models | ? | ? |
| [FAC-004](FAC-004.md) | Facility & location service (CRUD + location dimension) | ? | ? |
| [FAC-005](FAC-005.md) | Facility router (registered in main.py) | ? | ? |
| [FAC-006](FAC-006.md) | Stock transfers between locations | ? | ? |
| [FAC-007](FAC-007.md) | Receiving (inbound goods → on-hand) | ? | ? |
| [FAC-008](FAC-008.md) | Picklist generation & pick confirmation | ? | ? |
| [FAC-009](FAC-009.md) | Pack into packages | ? | ? |
| [FAC-010](FAC-010.md) | Ship shipment (carrier, tracking, order linkage) | ? | ? |
| [FAC-011](FAC-011.md) | Fulfillment router (registered in main.py) | ? | ? |
| [FAC-012](FAC-012.md) | Frontend types & endpoint wrappers | ? | ? |
| [FAC-013](FAC-013.md) | Warehouse / fulfillment admin page + route + nav | ? | ? |
| [FAC-014](FAC-014.md) | Lot / serial tracking (optional) | ? | ? |
| [FAC-015](FAC-015.md) | Hermetic pytest + E2E test suite | ? | ? |

## Purchasing / SCM (PUR)

| Ticket | Title | Corr. | Unconf. |
|--------|-------|------:|--------:|
| [PUR-001](PUR-001.md) | Purchasing/SCM data-model & sequencing spike | ? | ? |
| [PUR-002](PUR-002.md) | Purchasing/SCM scaffolding (tables, settings, flag, handles) | ? | ? |
| [PUR-003](PUR-003.md) | Supplier (vendor party) model & CRUD service | ? | ? |
| [PUR-004](PUR-004.md) | Supplier-product pricing (supplier↔SKU price / lead-time / MOQ) | ? | ? |
| [PUR-005](PUR-005.md) | Supplier & supplier-product models + router | ? | ? |
| [PUR-006](PUR-006.md) | Purchase-order entity & creation | ? | ? |
| [PUR-007](PUR-007.md) | PO approval lifecycle state machine | ? | ? |
| [PUR-008](PUR-008.md) | Receiving against PO → inventory increment | ? | ? |
| [PUR-009](PUR-009.md) | PO → AP payable / supplier payment via existing ledger | ? | ? |
| [PUR-010](PUR-010.md) | Purchase-order models + router endpoints | ? | ? |
| [PUR-011](PUR-011.md) | Reorder-driven PO suggestions from low-stock signals | ? | ? |
| [PUR-012](PUR-012.md) | Reorder-suggestion endpoints + optional background scan | ? | ? |
| [PUR-013](PUR-013.md) | Frontend types + endpoint wrappers | ? | ? |
| [PUR-014](PUR-014.md) | Suppliers admin page | ? | ? |
| [PUR-015](PUR-015.md) | Purchase-orders admin page (create / approve / receive) | ? | ? |
| [PUR-016](PUR-016.md) | Route + navigation entries | ? | ? |
| [PUR-017](PUR-017.md) | Purchasing/SCM hermetic offline + E2E tests | ? | ? |

## Shipping / logistics (SHP)

| Ticket | Title | Corr. | Unconf. |
|--------|-------|------:|--------:|
| [SHP-001](SHP-001.md) | Shipping module scoping & data-model delta | ? | ? |
| [SHP-002](SHP-002.md) | Shipping tables, settings & feature flags scaffolding | ? | ? |
| [SHP-003](SHP-003.md) | Shipping Pydantic models | ? | ? |
| [SHP-004](SHP-004.md) | Carrier & ship-method service | ? | ? |
| [SHP-005](SHP-005.md) | Carrier/ship-method admin router | ? | ? |
| [SHP-006](SHP-006.md) | Shipping-rate estimation engine | ? | ? |
| [SHP-007](SHP-007.md) | Rate-estimation router + cart/checkout estimate endpoint | ? | ? |
| [SHP-008](SHP-008.md) | Shipment & ship-group service | ? | ? |
| [SHP-009](SHP-009.md) | Package contents & packing | ? | ? |
| [SHP-010](SHP-010.md) | Shipment lifecycle state machine | ? | ? |
| [SHP-011](SHP-011.md) | Shipments + ship-groups router | ? | ? |
| [SHP-012](SHP-012.md) | Tracking-number/status on shipments (reuse carrier_tracking) | ? | ? |
| [SHP-013](SHP-013.md) | Carrier-tracking poller integration for shipments | ? | ? |
| [SHP-014](SHP-014.md) | Link shipments to order fulfillment + purchase-history tracking | ? | ? |
| [SHP-015](SHP-015.md) | Refund of paid shipping via existing billing | ? | ? |
| [SHP-016](SHP-016.md) | Shipping TypeScript types & API endpoints | ? | ? |
| [SHP-017](SHP-017.md) | Shipping admin UI (carriers, rates, shipments) | ? | ? |
| [SHP-018](SHP-018.md) | Buyer shipping/tracking UI integration | ? | ? |
| [SHP-019](SHP-019.md) | Shipping/logistics tests (hermetic pytest + e2e) | ? | ? |

## Marketing / campaigns (MKT)

| Ticket | Title | Corr. | Unconf. |
|--------|-------|------:|--------:|
| [MKT-001](MKT-001.md) | Marketing module scoping spike & data-model delta | ? | ? |
| [MKT-002](MKT-002.md) | Marketing settings, feature flag & table handles | ? | ? |
| [MKT-003](MKT-003.md) | Marketing Pydantic models | ? | ? |
| [MKT-004](MKT-004.md) | Marketing campaign service (CRUD + deterministic ids) | ? | ? |
| [MKT-005](MKT-005.md) | Campaign ↔ ads / promo linkage & spend rollup | ? | ? |
| [MKT-006](MKT-006.md) | Campaign lifecycle state machine | ? | ? |
| [MKT-007](MKT-007.md) | Contact lists (static membership) | ? | ? |
| [MKT-008](MKT-008.md) | Party segments (rule-based dynamic membership) | ? | ? |
| [MKT-009](MKT-009.md) | Segment/list-targeted campaign send via existing channels | ? | ? |
| [MKT-010](MKT-010.md) | Tracking codes (visit + order + redemption attribution) | ? | ? |
| [MKT-011](MKT-011.md) | Marketing campaign router (registered in main.py) | ? | ? |
| [MKT-012](MKT-012.md) | Frontend types & endpoint wrappers | ? | ? |
| [MKT-013](MKT-013.md) | Marketing campaigns page, route & nav | ? | ? |
| [MKT-014](MKT-014.md) | Marketing module tests (hermetic pytest + E2E) | ? | ? |

## eCommerce integration (ECM)

| Ticket | Title | Corr. | Unconf. |
|--------|-------|------:|--------:|
| [ECM-001](ECM-001.md) | Store-integration scoping spike & integration-surface map | ? | ? |
| [ECM-002](ECM-002.md) | Feature flag, settings & graceful-degrade helper | ? | ? |
| [ECM-003](ECM-003.md) | Storefront integration Pydantic models | ? | ? |
| [ECM-004](ECM-004.md) | Variant-aware catalog read service | ? | ? |
| [ECM-005](ECM-005.md) | Live availability projection from inventory/reservations | ? | ? |
| [ECM-006](ECM-006.md) | Catalog router — surface variants & availability (flag-gated) | ? | ? |
| [ECM-007](ECM-007.md) | Storefront variant picker & live-availability UI | ? | ? |
| [ECM-008](ECM-008.md) | Reserve stock on add-to-cart / checkout-begin | ? | ? |
| [ECM-009](ECM-009.md) | Apply pricing rules at cart total & checkout | ? | ? |
| [ECM-010](ECM-010.md) | Convert reservations → committed inventory on purchase | ? | ? |
| [ECM-011](ECM-011.md) | Cart UI — reservation & pricing-breakdown surfacing | ? | ? |
| [ECM-012](ECM-012.md) | Order fulfillment-status read service | ? | ? |
| [ECM-013](ECM-013.md) | Frontend types & endpoint wrappers | ? | ? |
| [ECM-014](ECM-014.md) | Order fulfillment endpoint + order detail/tracking page | ? | ? |
| [ECM-015](ECM-015.md) | Hermetic offline pytest + storefront E2E suite | ? | ? |

## Manufacturing / MRP (MFG)

| Ticket | Title | Corr. | Unconf. |
|--------|-------|------:|--------:|
| [MFG-001](MFG-001.md) | Manufacturing/MRP scoping spike & inventory-integration delta | ? | ? |
| [MFG-002](MFG-002.md) | Manufacturing tables, settings & feature flag | ? | ? |
| [MFG-003](MFG-003.md) | Pydantic models for BOM, routing, work orders & MRP | ? | ? |
| [MFG-004](MFG-004.md) | BOM service (CRUD + explosion) | ? | ? |
| [MFG-005](MFG-005.md) | Work-center / routing service | ? | ? |
| [MFG-006](MFG-006.md) | BOM & routing admin UI | ? | ? |
| [MFG-007](MFG-007.md) | Work-order lifecycle service (issue → produce) | ? | ? |
| [MFG-008](MFG-008.md) | Optional costed-production GL hook | ? | ? |
| [MFG-009](MFG-009.md) | Work-order admin UI (production queue) | ? | ? |
| [MFG-010](MFG-010.md) | Lite MRP engine (requirements explosion → suggestions) | ? | ? |
| [MFG-011](MFG-011.md) | Manufacturing router (BOM / routing / work orders / MRP) | ? | ? |
| [MFG-012](MFG-012.md) | MRP suggestions admin UI | ? | ? |
| [MFG-013](MFG-013.md) | Finished-goods ↔ catalog stock integration | ? | ? |
| [MFG-014](MFG-014.md) | Manufacturing/MRP tests (hermetic pytest + e2e) | ? | ? |

## Point of Sale (POS)

| Ticket | Title | Corr. | Unconf. |
|--------|-------|------:|--------:|
| [POS-001](POS-001.md) | POS channel mapping spike & reuse contract | ? | ? |
| [POS-002](POS-002.md) | POS data model (models.py) | ? | ? |
| [POS-003](POS-003.md) | POS DynamoDB tables, settings & feature flag | ? | ? |
| [POS-004](POS-004.md) | Register & session service — open/close with cash float | ? | ? |
| [POS-005](POS-005.md) | POS cart binding — scan/add line items reusing shoppingcart | ? | ? |
| [POS-006](POS-006.md) | Cash tender, change calc & cash ledger entry | ? | ? |
| [POS-007](POS-007.md) | Card / wallet tender via existing billing | ? | ? |
| [POS-008](POS-008.md) | Void & in-person refund reusing refund_payment | ? | ? |
| [POS-009](POS-009.md) | Receipt generation reusing the receipts pipeline | ? | ? |
| [POS-010](POS-010.md) | X/Z session reports (till summary) | ? | ? |
| [POS-011](POS-011.md) | POS router (registered in app/main.py) | ? | ? |
| [POS-012](POS-012.md) | Frontend types & endpoint wrappers | ? | ? |
| [POS-013](POS-013.md) | Register terminal page + route + nav | ? | ? |
| [POS-014](POS-014.md) | POS hermetic pytest + E2E suite | ? | ? |

## Human Resources (HRM)

| Ticket | Title | Corr. | Unconf. |
|--------|-------|------:|--------:|
| [HRM-001](HRM-001.md) | HR feature flag & settings keys | ? | ? |
| [HRM-002](HRM-002.md) | HR single-table DynamoDB definition + handle | ? | ? |
| [HRM-003](HRM-003.md) | HR Pydantic models (employee / position / employment / payroll) | ? | ? |
| [HRM-004](HRM-004.md) | Employee party records (PERSON + EMPLOYEE role + EMPLOYMENT rel) | ? | ? |
| [HRM-005](HRM-005.md) | Position / job-title service | ? | ? |
| [HRM-006](HRM-006.md) | Employment-period service (hire / terminate / list) | ? | ? |
| [HRM-007](HRM-007.md) | Payroll run service (draft / compute / approve) | ? | ? |
| [HRM-008](HRM-008.md) | Payroll disbursement reuses the single billing/ledger path (no fork) | ? | ? |
| [HRM-009](HRM-009.md) | HR + payroll router (registered in app/main.py) | ? | ? |
| [HRM-010](HRM-010.md) | Payroll-expense GL journal hook (derives from the ledger) | ? | ? |
| [HRM-011](HRM-011.md) | Frontend types + endpoint wrappers | ? | ? |
| [HRM-012](HRM-012.md) | HR admin page, route & nav entry | ? | ? |
| [HRM-013](HRM-013.md) | HR hermetic pytest + E2E suite | ? | ? |

## Fixed Assets (FXA)

| Ticket | Title | Corr. | Unconf. |
|--------|-------|------:|--------:|
| [FXA-001](FXA-001.md) | Fixed-assets scoping spike & GL-touchpoint delta | ? | ? |
| [FXA-002](FXA-002.md) | Settings, feature flags & table handles | ? | ? |
| [FXA-003](FXA-003.md) | DynamoDB tables (assets, depreciation schedule, work orders) | ? | ? |
| [FXA-004](FXA-004.md) | Pydantic models for assets, schedules & work orders | ? | ? |
| [FXA-005](FXA-005.md) | Fixed-asset register service (CRUD) | ? | ? |
| [FXA-006](FXA-006.md) | Straight-line depreciation schedule generation | ? | ? |
| [FXA-007](FXA-007.md) | Asset register router | ? | ? |
| [FXA-008](FXA-008.md) | Depreciation GL accounts seed | ? | ? |
| [FXA-009](FXA-009.md) | Depreciation journal posting (non-cash, balanced, idempotent) | ? | ? |
| [FXA-010](FXA-010.md) | Depreciation poster background loop | ? | ? |
| [FXA-011](FXA-011.md) | Asset disposal with proceeds via existing refund path | ? | ? |
| [FXA-012](FXA-012.md) | Maintenance work-order service & lifecycle | ? | ? |
| [FXA-013](FXA-013.md) | Maintenance work-order router | ? | ? |
| [FXA-014](FXA-014.md) | Frontend types & endpoint wrappers | ? | ? |
| [FXA-015](FXA-015.md) | Fixed-assets admin page (register + depreciation + work orders) | ? | ? |
| [FXA-016](FXA-016.md) | Route + navigation (flag-gated) | ? | ? |
| [FXA-017](FXA-017.md) | Hermetic offline unit + E2E tests | ? | ? |

## OFBiz commerce core (inventory/returns/accounting/pricing) (OFB)

| Ticket | Title | Corr. | Unconf. |
|--------|-------|------:|--------:|
| [OFB-001](OFB-001.md) | OFBiz module mapping spike & data-model delta | ? | ? |
| [OFB-002](OFB-002.md) | Shared commerce/ERP scaffolding (tables, settings, flags) | ? | ? |
| [OFB-003](OFB-003.md) | Inventory item & stock-level model | ? | ? |
| [OFB-004](OFB-004.md) | Soft reservations on add-to-cart / checkout | ? | ? |
| [OFB-005](OFB-005.md) | Low-stock & reorder-point alerts | ? | ? |
| [OFB-006](OFB-006.md) | Inventory admin UI | ? | ? |
| [OFB-007](OFB-007.md) | Inventory & reservations E2E tests | ? | ? |
| [OFB-008](OFB-008.md) | Return/RMA entity & request flow | ? | ? |
| [OFB-009](OFB-009.md) | RMA approve/reject + receive → restock | ? | ? |
| [OFB-010](OFB-010.md) | RMA refund via existing billing | ? | ? |
| [OFB-011](OFB-011.md) | Returns/RMA admin + customer UI | ? | ? |
| [OFB-012](OFB-012.md) | Returns/RMA E2E tests | ? | ? |
| [OFB-013](OFB-013.md) | Chart of accounts & GL account model | ? | ? |
| [OFB-014](OFB-014.md) | Double-entry journal entries derived from the ledger | ? | ? |
| [OFB-015](OFB-015.md) | AR / AP subledgers | ? | ? |
| [OFB-016](OFB-016.md) | Financial statements (trial balance, P&L, balance sheet) | ? | ? |
| [OFB-017](OFB-017.md) | Accounting admin UI | ? | ? |
| [OFB-018](OFB-018.md) | Accounting/GL tests | ? | ? |
| [OFB-019](OFB-019.md) | Pricing/promotions rules engine | ? | ? |
| [OFB-020](OFB-020.md) | Apply pricing rules at cart total & checkout | ? | ? |
| [OFB-021](OFB-021.md) | Pricing/promotions admin UI | ? | ? |
| [OFB-022](OFB-022.md) | Pricing/promotions tests | ? | ? |

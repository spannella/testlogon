# OFBiz Full Commerce/ERP Buildout — Plan

**Status:** Planning (2026-06-09). Supersedes the *cherry-pick* recommendation in
`docs/adr/ADR-001-ofbiz-commerce-erp.md` — the user wants **full OFBiz
functionality**, not a cherry-picked subset. ADR-001's current-state mapping and
its GL/AR/AP + pricing-engine designs remain valid building blocks; this plan
widens the target to the full OFBiz application set and sequences it.

This is a **multi-month** initiative. It layers on the existing testlogon commerce
stack (shop catalog, cart, orders, billing ledger, invoices, subscriptions,
payouts, payment providers) — it does not replace it. Everything is additive +
flag-gated + SECOPS-007 dev/prod parity, same as every other workstream.

---

## 1. Already built (foundation, this session)

| Capability | Where | State |
|---|---|---|
| Inventory items + stock levels | `app/services/inventory.py`, `T.inventory` | ✅ Phase-1 (on-hand) |
| Soft reservations (cart/checkout) | `app/services/inventory.py`, `T.reservations` | ✅ Phase-1 |
| Inventory admin UI | `frontend/src/pages/.../inventory` | ✅ |
| Returns / RMA (request→approve→refund→restock) | `app/services/...returns`, reuses `refund_payment` | ✅ OFB-008/009/010 |

So **Facility/Inventory** and **Returns** are partially done; the plan extends them
to full and adds the missing OFBiz applications.

---

## 2. OFBiz application map → testlogon (gap analysis)

OFBiz ships ~14 applications. Mapping each to testlogon's domain (a creator-economy
SaaS) and current state:

| # | OFBiz application | OFBiz scope | testlogon today | Target | Default scope |
|---|---|---|---|---|---|
| A | **Party Manager** | Parties, roles, relationships, contact mechs, B2B accounts | `contacts`, users/profiles, addresses | Party+role model, org/B2B accounts, unified contact mechs | **IN** |
| B | **Catalog / Product** | Products, variants, categories, features, configurable/kit/bundle, product assoc, virtual/variant | Scalar catalog item + `stock_count` | Variants, category trees, features/options, bundles/kits | **IN** |
| C | **Order Manager** | Sales orders, **order lifecycle state machine**, adjustments, purchase orders, returns | `orders` stuck at `pending_payment`, no fulfillment SM | Full sales-order lifecycle (approved→picking→shipped→completed / held / cancelled / returned), order adjustments | **IN** |
| D | **Facility / Inventory** | Warehouses, locations, inventory items, **reservations**, transfers, receiving, **pick/pack/ship** | ✅ items+reservations (Phase-1) | Facilities/locations, transfers, receiving-against-PO, pick/pack/ship | **IN (extend)** |
| E | **Accounting** | **Chart of accounts, double-entry GL, journals, AR/AP**, invoices, payments, **financial statements**, billing accounts, tax authorities, fixed assets | Single-entry ledger + invoices + tax + payouts + providers + QB/Xero CSV export | Double-entry GL/AR/AP + trial balance/P&L/balance sheet, reconciling to the existing ledger+invoices | **IN** (fixed assets OUT) |
| F | **Pricing / Promotions** | Price rules (tiered/qty/party/date), promo rules, price lists | Flat promo codes (%, fixed, free-trial) | Rules engine (tiered/bulk/conditional/scoped) at cart+checkout | **IN** |
| G | **SCM / Purchasing** | Suppliers, purchase orders, requirements/MRP-lite, receiving | None | Supplier/vendor model + purchase orders + receiving → inventory | **IN** |
| H | **Shipping / Logistics** | Carriers, ship rates, shipments, tracking, ship groups | Partial: order tracking endpoint exists | Carrier/rate model, shipments, tracking, ship groups | **IN (lighter)** |
| I | **Marketing** | Campaigns, contact lists, segments, tracking codes | Ads platform + marketing agents + promo + cart reminders | Campaign/segment model tying into ads + promos | **PARTIAL / optional** |
| J | **eCommerce store** | Storefront, browse, cart, checkout, promo application | ✅ shop + cart + checkout exist | Wire new catalog depth/pricing/inventory into the existing store | **IN (integration)** |
| K | **Manufacturing / MRP** | BOM, routing, work orders, production runs, MRP | None | — | **OUT (recommend)** — confirm |
| L | **POS** | In-person point of sale | None | — | **OUT (recommend)** — confirm |
| M | **Human Resources** | Employees, positions, payroll | None | — | **OUT (recommend)** |
| N | **Asset Maintenance / FixedAsset** | Fixed assets, depreciation, maintenance | None | — | **OUT (recommend)** |

**Recommended "full commerce/ERP" scope for a creator platform = A–J** (the
commerce + accounting + supply/fulfillment + CRM core). **K–N are classic OFBiz
modules that don't fit a creator-economy SaaS** — I recommend OUT, but since you
said "full," I'll confirm before excluding (esp. Manufacturing & POS).

---

## 3. Phased roadmap (A–J)

Sequenced by dependency (each phase = a workstream → its own ticket file → a build
workflow). Foundations from this session feed Phases 2–3.

- **Phase 0 — Shared ERP scaffolding** (OFB-002 done-ish): finalize the shared
  party/org keys, money/quantity value types, the ERP feature-flag group, and the
  single-table conventions all modules reuse. Reconcile to existing
  `orders`/`billing`/`invoices`/`inventory` tables.
- **Phase 1 — Party / CRM (A)**: party + role model, org/B2B accounts, unified
  contact mechanisms, party relationships; migrate `contacts` onto it additively.
- **Phase 2 — Catalog depth (B)**: product variants, category trees, features/
  options, bundles/kits, virtual↔variant; back-compat with the existing scalar
  catalog item.
- **Phase 3 — Inventory/Facility full (D, extends foundation)**: facilities +
  locations, stock transfers, receiving, **pick/pack/ship**, lot/serial (optional).
- **Phase 4 — Order lifecycle (C)**: the sales-order **state machine**
  (approved→allocated→picking→packed→shipped→completed, + held/backorder/cancelled/
  returned), order adjustments, ship groups; drive fulfillment off Phase 3.
- **Phase 5 — Purchasing / SCM (G)**: suppliers, **purchase orders**, receiving
  against PO → inventory; reorder-driven (uses OFB-005 low-stock signals).
- **Phase 6 — Pricing / Promotions engine (F)**: tiered/bulk/conditional/scoped
  rules at cart total + checkout (OFB-019/020/021).
- **Phase 7 — Accounting depth (E)**: chart of accounts, **double-entry GL +
  journals derived from the existing single-entry ledger**, **AR/AP** subledgers
  reconciling to `invoices`, **financial statements** (trial balance, P&L, balance
  sheet); preserve the QB/Xero CSV export (OFB-013..018).
- **Phase 8 — Shipping/Logistics (H)** + **eCommerce store integration (J)**:
  carriers/rates/shipments/tracking; wire all the new depth into the existing shop
  storefront + checkout so the customer experience reflects variants, inventory,
  pricing rules, and fulfillment.
- **(Optional) Phase 9 — Marketing (I)**: campaign/segment model tying ads +
  promos + cart reminders together.

Each phase ships behind its own default-off flag and is independently testable.

---

## 4. Cross-cutting design constraints (non-negotiable)

- **DynamoDB single-table modeling** of relational ERP entities: PK/SK + GSIs;
  numeric GSI sort keys declared with `attr_types` in `local-ddb-init.py`.
- **The GL must DERIVE from the existing ledger** (`billing_shared.new_ledger_entry`)
  — not replace it. Double-entry journals are generated from ledger events; AR
  reconciles to `invoices.py`; the existing QB/Xero `audit_export_accounting` export
  must keep working. (Per ADR-001.)
- **One refund mechanism**: any money-out (RMA, order cancel) reuses
  `refund_payment` / `settle_or_reverse_ledger`. Never fork billing.
- **Idempotency**: reuse the deterministic-id pattern (`order_id = sha256(correlation_id)`)
  for new write paths.
- **Additive + flag-gated + dev/prod parity** (SECOPS-007); existing
  shop/cart/orders/billing byte-for-byte unchanged with flags off.
- **Hermetic offline tests** per module (moto-bound frozen `T`, no real AWS).

---

## 5. Effort & delivery model

Rough order-of-magnitude (A–J, excluding K–N): **~9 phases × ~12–22 tickets each ≈
130–180 tickets, multi-month.** Delivery uses the **proven workflow cadence**:
1. Generate a detailed `<MODULE>_TICKETS.md` per phase (a ticket-authoring workflow,
   like the original 17-file run), grounded in the cited current-state code.
2. Build each phase as a **sequential commit-on-green workflow** (foundations →
   FE → tests), exactly like the runs that produced the 7 foundations + their FE.
3. Verify + reconcile + push per phase; PR to `main` at sensible milestones.

The existing `OFBIZ_COMMERCE_TICKETS.md` (22 tickets) already covers Inventory (built),
Returns (built), **Accounting/GL (Phase 7)**, and **Pricing (Phase 6)** — those
become the seed for those phases; Phases 1, 2, 4, 5, 8 (Party, Catalog, Orders,
Purchasing, Shipping) are net-new ticket files to author.

---

## 6. Immediate next step

Confirm the module scope (A–J in; K–N out, or include some), then run the
**ticket-authoring workflow** to expand the in-scope phases into detailed
`<MODULE>_TICKETS.md` files — after which each phase builds via the standard
sequential build workflow.

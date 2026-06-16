# OFBiz-Inspired Commerce/ERP — Implementation Tickets

This backlog cherry-picks the highest-value Apache OFBiz commerce/ERP domains — inventory & reservations, returns/RMA, double-entry accounting (GL/AR/AP), and an advanced pricing/promotions rules engine — and layers them onto the platform's existing catalog, cart, orders, billing-ledger, and promo-code subsystems rather than adopting OFBiz wholesale. It opens with a scoping spike that maps OFBiz modules to the current data model and locks the cherry-picked set; subsequent milestones are buildable, dependency-ordered, and reuse the existing ledger/billing/refund machinery wherever possible.

## Milestone 1 — Scoping

### OFB-001: OFBiz module mapping spike & data-model delta
**Type:** Spike  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Map OFBiz commerce/ERP domains (order mgmt, inventory/warehouse, AR/AP/GL, MRP, pricing/promotions, returns) against the current model: orders (`app/services/commerce_order_service.py:39` `create_order`, statuses only `pending_payment`; tables `orders`/`order_items` in `scripts/local-ddb-init.py:288`), catalog with primitive per-item stock (`app/routers/catalog.py:94` `_compute_stock_status`, `stock_count`/`low_stock_threshold` in `app/models.py:546`), cart purchase with naive stock decrement (`app/services/shoppingcart.py:474` `purchase_cart`, conditional decrement at `:517`), single-entry ledger (`app/services/billing_shared.py:224` `new_ledger_entry`, balance deltas at `:83`), invoices (`app/services/invoices.py:272`), refunds (`app/routers/billing.py:1286` `refund_payment` + `settle_or_reverse_ledger`), promo codes (`app/services/promo_codes.py`, `VALID_DISCOUNT_TYPES` at `:26` = percentage/fixed_amount/free_trial only), and the existing accounting CSV mapper (`app/services/audit_export_accounting.py`).
- Document gaps: no warehouse/location model, no soft reservations (only decrement-at-purchase), no returns/RMA entity, no double-entry GL / chart of accounts / journal entries / AR / AP / trial balance / financial statements, no rules-based pricing (tiered/bulk/conditional).
- Decide the cherry-picked set (explicitly defer OFBiz MRP, manufacturing, shipment routing, multi-warehouse transfer orders) and define the new DynamoDB tables + GSIs, settings keys, and feature flags. Note the `GSI_LEDGER_DATE` index and `ledger_date` denorm (CLAUDE.md / `app/services/platform_financial_dashboard.py`) as the GL derivation source.

**Acceptance Criteria**
- A written design doc (`docs/ofbiz-commerce-plan.md`) enumerates every OFBiz domain considered, in/out decision, and rationale.
- Data-model delta lists each new table with PK/SK/GSIs (with `attr_types` noted for numeric keys), new `app/models.py` Pydantic shapes, and new `app/core/settings.py` keys + feature flags.
- Cross-module dependency graph and milestone sequencing are recorded; every downstream OFB ticket references a section of the doc.
- Reviewer (eng + finance stakeholder) signs off that the GL design correctly derives debits/credits from existing ledger entry types.

**Dependencies**
- None.

---

### OFB-002: Shared commerce/ERP scaffolding (tables, settings, flags)
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Land the table definitions agreed in OFB-001 into `scripts/local-ddb-init.py` (inventory, reservations, returns/RMA, GL accounts, journal entries — exact set per spike), each behind the standard `_resolve_table_name(S.<name>, "<default>")` pattern, with numeric GSI sort keys declared via `attr_types` (per the CLAUDE.md gotcha).
- Add settings keys + feature flags to `app/core/settings.py` (e.g. `INVENTORY_RESERVATIONS_ENABLED`, `RETURNS_RMA_ENABLED`, `GL_DOUBLE_ENTRY_ENABLED`, `PRICING_RULES_ENABLED`), all defaulting off so nothing activates until its milestone ships.
- Wire table handles in `app/core/tables.py` (`T.inventory`, `T.reservations`, `T.returns`, `T.gl_accounts`, `T.gl_journal`, etc.).

**Acceptance Criteria**
- `just restart` recreates all new tables locally with no `ValidationException`.
- New flags read through the `S` singleton and default to disabled.
- A smoke pytest imports `app.core.tables.T` and asserts each new handle resolves.

**Dependencies**
- OFB-001.

---

## Milestone 2 — Inventory / Stock Management & Reservations

### OFB-003: Inventory item & stock-level model
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Introduce a first-class inventory record (SKU → on-hand qty, reserved qty, available = on-hand − reserved, reorder point) in `app/services/inventory.py`, superseding the ad-hoc `stock_count` scalar on catalog items (`app/routers/catalog.py:94`, `app/models.py:546`). Keep catalog `stock_count` as a denormalized read-through mirror so the existing storefront UI keeps working.
- Support an optional `location_id` dimension (single default "warehouse" location now; multi-location deferred per OFB-001) so the schema is forward-compatible.
- Provide `get_inventory(sku)`, `set_on_hand(sku, qty, reason)`, and `adjust(sku, delta, reason)` with audit events via `app/services/alerts.audit_event` (mirroring `commerce_order_service` at `:106`).

**Acceptance Criteria**
- Creating/updating a catalog item with `stock_count` provisions/updates the matching inventory record; available reflects on-hand minus reservations.
- Manual adjustments are atomic (conditional update) and write an audit event with before/after quantities.
- pytest covers on-hand set, positive/negative adjust, and available computation.

**Dependencies**
- OFB-002.

---

### OFB-004: Soft reservations on add-to-cart / checkout
**Type:** Feature  
**Priority:** P0  
**Estimate:** 5 days

**Description**
- Replace the purchase-time decrement (`app/services/shoppingcart.py:517` conditional `stock_count >= :qty` with manual rollback at `:524`) with a reservation lifecycle: reserve available stock at checkout-begin, convert reservation → on-hand decrement on successful purchase, release on cart abandonment/expiry/failure.
- Add a TTL-based reservation expiry (reuse the cart-abandonment loop pattern at `app/services/shoppingcart.py:323` / `start_cart_abandonment_task`) so stranded reservations free up automatically.
- Make `purchase_cart` reservation-aware while preserving its idempotency key handling (`:597` `cart_purchase:` trigger) and order creation via `commerce_order_service.create_order_from_line_items` (`:581`).

**Acceptance Criteria**
- Reserving reduces `available` without changing `on_hand`; committing reduces `on_hand` and clears the reservation; releasing restores `available`.
- Concurrent checkouts of the last unit: exactly one reservation succeeds; the loser gets the existing 409 "out of stock" path.
- Expired reservations are released by the background loop and the unit becomes available again.
- pytest covers reserve→commit, reserve→release, reserve→expire, and the oversell race (single-writer guarantee).

**Dependencies**
- OFB-003.

---

### OFB-005: Low-stock & reorder-point alerts
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Emit a low-stock alert when `available` crosses `low_stock_threshold`/reorder point after any reservation/commit/adjust, reusing the existing alert plumbing (`app/services/alerts`) and the catalog low-stock sentinel/TTL machinery noted at `scripts/local-ddb-init.py:2563` (SHOP-001 / GAP-0347).
- De-duplicate alerts so a SKU hovering at threshold doesn't spam (one alert per crossing, reset when it recovers above threshold).

**Acceptance Criteria**
- Crossing the threshold downward emits exactly one alert; staying below emits no further alerts until it recovers and crosses again.
- Threshold defaults to `S.catalog_default_low_stock_threshold` (`app/core/settings.py:829`) and is per-SKU overridable.
- pytest covers crossing, de-dup, and recovery-then-recross.

**Dependencies**
- OFB-003.

---

### OFB-006: Inventory admin UI
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add an inventory management page under `frontend/src/pages/shop/admin/` (alongside `AdminCatalog.tsx`/`ItemEditor.tsx`) showing per-SKU on-hand / reserved / available / reorder point with inline adjust + a low-stock filter.
- Add TS types + endpoint wrappers (`frontend/src/api/types.ts`, `frontend/src/api/endpoints/`) and a route in `frontend/src/App.tsx`, gated on the inventory flag.

**Acceptance Criteria**
- Admin can view stock levels, perform an adjustment, and see the recalculated available without reload.
- Low-stock items are visually flagged and filterable.
- Page is admin/root-gated (`require_admin_session` on the backend endpoints).

**Dependencies**
- OFB-003, OFB-004.

---

### OFB-007: Inventory & reservations E2E tests
**Type:** Chore  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add `frontend/e2e/inventory.spec.ts` covering reservation-on-checkout, oversell prevention, low-stock alert surfacing, and the admin inventory page, following the seeded-session + CSRF patterns in CLAUDE.md / MEMORY.md.

**Acceptance Criteria**
- E2E suite covers happy-path reserve→purchase, oversell 409, and admin adjustment.
- Tests pass under the standard 1-worker Playwright config.

**Dependencies**
- OFB-004, OFB-006.

---

## Milestone 3 — Returns / RMA

### OFB-008: Return/RMA entity & request flow
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Create `app/services/returns_rma.py` + `app/routers/returns_rma.py` with a return entity (`return_id`, `order_id`, line items + qty, reason, status: `requested`→`approved`/`rejected`→`received`→`refunded`/`closed`) keyed off existing orders (`orders`/`order_items`, `commerce_order_service.py`).
- Customer endpoint to request a return against a purchased order line; validate the line belongs to the requester and the requested qty ≤ purchased qty.
- Register the router in `app/main.py` (per the CLAUDE.md router convention) under `require_ui_session`.

**Acceptance Criteria**
- A user can open a return for their own order; foreign orders → 403/404.
- Over-quantity or duplicate-open-return requests are rejected.
- Return status transitions are validated (illegal transitions → 409) and audited.

**Dependencies**
- OFB-002.

---

### OFB-009: RMA approve/reject + receive → restock
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Admin endpoints (`require_admin_session`) to approve/reject a return and to mark it received; on `received`, restock the returned qty via `inventory.adjust(sku, +qty, reason="rma_restock")` (OFB-003).
- Guard restock behind the inventory flag so RMA still functions (minus restock) if inventory is disabled.

**Acceptance Criteria**
- Approve/reject moves the return to the correct state and notifies the requester (existing alert plumbing).
- Marking received with inventory enabled increments on-hand exactly once (idempotent on replay).
- pytest covers approve→receive→restock, reject, and replay idempotency.

**Dependencies**
- OFB-008, OFB-003.

---

### OFB-010: RMA refund via existing billing
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- On a fully-received/approved return, issue the refund through the existing path — `refund_payment` / `settle_or_reverse_ledger` (`app/routers/billing.py:1286`, `:1324`) and `new_ledger_entry` with `reason="refund"` (`:1312`) — rather than minting a parallel refund mechanism, so provider attribution (`extra={"provider": ...}`, FIN-013) and the platform financial dashboard stay correct.
- Mark the originating invoice `refunded` where applicable (`app/services/invoices.py:156`), and record the refund linkage on the return record.

**Acceptance Criteria**
- A completed return produces exactly one refund ledger entry (reversed/refund state) tied to the original payment and provider.
- Partial-quantity returns refund the prorated amount; the math is unit-tested.
- Double-refund of the same return is prevented (idempotent).

**Dependencies**
- OFB-008, OFB-009.

---

### OFB-011: Returns/RMA admin + customer UI
**Type:** Feature  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- Customer "My Returns" view (request + status) and admin RMA queue (approve/reject/receive/refund) under `frontend/src/pages/shop/` and `frontend/src/pages/shop/admin/`, with TS types, endpoint wrappers, and `App.tsx` routes.

**Acceptance Criteria**
- Customer can file and track a return; admin can action the full lifecycle from the queue.
- Refund action calls the OFB-010 endpoint and reflects the new status.
- UI is flag-gated and role-gated.

**Dependencies**
- OFB-008, OFB-009, OFB-010.

---

### OFB-012: Returns/RMA E2E tests
**Type:** Chore  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add `frontend/e2e/returns-rma.spec.ts` covering request→approve→receive→refund (full lifecycle), reject, restock verification, and refund-idempotency, using seeded sessions + admin identity (`e2e_admin_session_setup.py`).

**Acceptance Criteria**
- Full lifecycle and reject paths covered; restock and refund-once assertions included.
- Suite passes under the standard Playwright config.

**Dependencies**
- OFB-011, OFB-010.

---

## Milestone 4 — Accounting Depth (Double-Entry GL / AR / AP)

### OFB-013: Chart of accounts & GL account model
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Create `app/services/gl_accounts.py` with a seedable chart of accounts (asset/liability/equity/revenue/expense classes, normal-balance side per account) and CRUD for ROOT.
- Seed default accounts matching existing money flows (Cash/Bank, Accounts Receivable, Accounts Payable, Sales Revenue, Refunds/Returns contra-revenue, Sales Tax Payable, Processor Fees) so the OFB-014 derivation can map ledger entry types onto accounts.

**Acceptance Criteria**
- Default chart seeds idempotently; each account carries class + normal balance side.
- ROOT can add/disable accounts; disabling an account with posted entries is blocked.
- pytest covers seed idempotency and account validation.

**Dependencies**
- OFB-002.

---

### OFB-014: Double-entry journal entries derived from the ledger
**Type:** Feature  
**Priority:** P0  
**Estimate:** 6 days

**Description**
- Build `app/services/gl_posting.py` that turns each existing single-entry billing ledger row (`app/services/billing_shared.py:224` `new_ledger_entry`; types/states like `settled`/`pending`/`reversed`, provider attribution, `ledger_date` denorm) into a balanced double-entry journal entry (sum of debits == sum of credits), mapping entry `type`/`reason`/`provider` to the OFB-013 accounts (e.g. a settled charge → Dr Cash / Cr Sales Revenue (+ Cr Sales Tax Payable); a `refund`/`reversed` → Dr Refunds contra / Cr Cash).
- Drive posting from the `GSI_LEDGER_DATE` day buckets (CLAUDE.md FIN-013 / `app/services/platform_financial_dashboard.py`) via a background poster (gated by `GL_DOUBLE_ENTRY_ENABLED`), idempotent per source `entry_id` (one journal entry per ledger row, replay-safe).

**Acceptance Criteria**
- Every posted journal entry balances (Σdebits = Σcredits); an unbalanced mapping fails loudly and is not persisted.
- Each source ledger `entry_id` posts at most one journal entry across re-runs (idempotent compare-and-set).
- Tax, processor fee, and refund splits land on the correct accounts; covered by pytest with representative ledger rows.
- A backfill command can post historical ledger rows for a date range without duplication.

**Dependencies**
- OFB-013.

---

### OFB-015: AR / AP subledgers
**Type:** Feature  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- Derive Accounts Receivable from the existing owed/payment balance fields (`BAL_FIELDS` + `compute_due` in `app/services/billing_shared.py:15`, `:158`) and outstanding invoices (`app/services/invoices.py`), and Accounts Payable from payouts/creator-owed flows, exposing per-party open-item aging (current / 30 / 60 / 90+).
- Ensure AR/AP totals reconcile to the corresponding GL control accounts from OFB-014.

**Acceptance Criteria**
- AR aging buckets a known set of unpaid invoices correctly; AP mirrors for payables.
- AR/AP control-account balances tie out to the GL within zero variance in a reconciliation test.
- pytest covers aging boundaries and the GL tie-out.

**Dependencies**
- OFB-014.

---

### OFB-016: Financial statements (trial balance, P&L, balance sheet)
**Type:** Feature  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- Build statement generators over the GL: trial balance (debits == credits across all accounts), income statement (revenue − expense for a period), and balance sheet (assets == liabilities + equity as-of a date), reusing the day-bucketed posting from OFB-014.
- Reconcile statement revenue against the existing platform financial dashboard GMV/net-revenue figures (`app/services/platform_financial_dashboard.py`) and flag variance.

**Acceptance Criteria**
- Trial balance always balances for any posted period; an out-of-balance result is surfaced as an error, not silently rendered.
- Balance-sheet equation holds as-of any date in test fixtures.
- Income-statement revenue reconciles to the dashboard within an explicit tolerance.

**Dependencies**
- OFB-014, OFB-015.

---

### OFB-017: Accounting admin UI
**Type:** Feature  
**Priority:** P2  
**Estimate:** 4 days

**Description**
- ROOT-only accounting section under `frontend/src/pages/admin/` (or a new `pages/accounting/`): chart of accounts, journal entry browser (with drill-through to source ledger row), AR/AP aging, and the three statements, plus export reusing the accounting CSV mapper (`app/services/audit_export_accounting.py`, QuickBooks/Xero columns).

**Acceptance Criteria**
- ROOT can view the chart, journals, aging, and statements; non-ROOT is denied.
- Journal rows drill through to their source billing ledger entry.
- Export produces QuickBooks/Xero-format CSV via the existing mapper.

**Dependencies**
- OFB-013, OFB-014, OFB-015, OFB-016.

---

### OFB-018: Accounting/GL tests
**Type:** Chore  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add pytest suites for GL posting balance/idempotency, AR/AP aging + tie-out, and statement correctness (`tests/test_ofb_gl_*.py`), plus an E2E smoke (`frontend/e2e/accounting.spec.ts`) for the ROOT statements page.

**Acceptance Criteria**
- Unit suites cover balanced-entry invariants, idempotent re-posting, aging, and statement equations.
- E2E smoke renders the trial balance and confirms it balances.

**Dependencies**
- OFB-016, OFB-017.

---

## Milestone 5 — Advanced Pricing / Promotions

### OFB-019: Pricing/promotions rules engine
**Type:** Feature  
**Priority:** P0  
**Estimate:** 6 days

**Description**
- Add `app/services/pricing_rules.py` — a rule engine supporting tiered (qty breakpoints), bulk (per-unit discount above qty N), and conditional (cart-total threshold, category/SKU scope, customer subscription tier) rules — extending the existing flat promo model (`app/services/promo_codes.py`, `VALID_DISCOUNT_TYPES` at `:26` = percentage/fixed_amount/free_trial; discount calc at `_calculate_discount` `:376`).
- Define rule precedence/stacking (best-deal-wins vs stackable) and integrate with `validate_promo_code` (`:239`) so an applied code can carry a rule reference; keep existing flat codes working unchanged.

**Acceptance Criteria**
- Tiered/bulk/conditional rules each compute the correct discount on representative carts; existing percentage/fixed/free_trial codes are unaffected.
- Stacking/precedence resolves deterministically and is unit-tested (incl. best-deal-wins).
- Rules respect scope (category/SKU/subscription tier) and threshold conditions.

**Dependencies**
- OFB-002.

---

### OFB-020: Apply pricing rules at cart total & checkout
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Hook the engine into cart totaling and purchase (`app/services/shoppingcart.py:474` `purchase_cart`, total endpoint at `app/routers/shoppingcart.py:169`) so the discounted total is authoritative at checkout and the applied rule(s) are persisted on the order line items (`commerce_order_service.create_order` line rows at `:88`).
- Ensure redemption accounting (`promo_codes.redeem_promo_code` `:398` atomic-increment + per-user caps) still runs for code-bound rules.

**Acceptance Criteria**
- Cart total and final purchase amount reflect applied rules consistently (no client/server drift).
- Applied rule references and discount amounts are stored on the order for auditing.
- Per-user/global redemption limits are enforced for code-bound rules.

**Dependencies**
- OFB-019.

---

### OFB-021: Pricing/promotions admin UI
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Admin rule builder (tier breakpoints, bulk thresholds, conditions, scope, stacking) under `frontend/src/pages/shop/admin/`, alongside the existing promo-code management, with TS types + endpoint wrappers + `App.tsx` route, flag-gated.

**Acceptance Criteria**
- Admin can create each rule type with a live preview of the resulting discount on a sample cart.
- Created rules are role-gated and immediately applicable at checkout.

**Dependencies**
- OFB-019, OFB-020.

---

### OFB-022: Pricing/promotions tests
**Type:** Chore  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- pytest for tiered/bulk/conditional math + stacking precedence + redemption caps (`tests/test_ofb_pricing_rules.py`), and `frontend/e2e/pricing-rules.spec.ts` covering a tiered rule applied through the cart to checkout.

**Acceptance Criteria**
- Unit suite covers each rule type, stacking, and cap enforcement.
- E2E confirms a tiered discount flows from cart total into the final purchase amount.

**Dependencies**
- OFB-020, OFB-021.

---

# ADR-001: OFBiz-Inspired Commerce/ERP — Cherry-Pick vs. Adopt Wholesale

## Status

**Proposed** (2026-06-09)

This ADR is the architectural decision backing the scoping spike **OFB-001** in
`OFBIZ_COMMERCE_TICKETS.md`. It supersedes the free-form design-doc deliverable
(`docs/ofbiz-commerce-plan.md`) called for in that ticket's acceptance criteria —
the in/out decisions, data-model deltas, phasing, and effort live here. Once
accepted, it unblocks OFB-002 (scaffolding) and everything downstream.

---

## Context — what exists today

testlogon already has a working, single-table-per-domain commerce stack. The OFBiz
work layers onto it; it does **not** replace it. The concrete touch points:

- **Orders.** `CommerceOrderService.create_order` (`app/services/commerce_order_service.py:39`)
  writes an `orders` row + N `order_items` rows. The order `status` is hard-coded
  to `"pending_payment"` (`:75`) and there is **no fulfillment / shipped / returned
  state machine**. `order_id` is a deterministic SHA-256 of the `correlation_id`
  (`:67`), which gives free idempotency on re-submit. Tables: `orders`
  (PK `order_id`, GSIs `GSI_USER`/`GSI_STATUS`) and `order_items` (PK `order_id`,
  SK `item_id`) — `scripts/local-ddb-init.py:288` / `:295`.
- **Catalog stock.** Stock is a single scalar `stock_count` on the catalog item,
  with a derived label from `_compute_stock_status` (`app/routers/catalog.py:94`):
  `unlimited` (None), `out_of_stock` (≤0), `low_stock` (≤ `low_stock_threshold`),
  else `in_stock`. There is **no warehouse/location, no reserved quantity, no
  reorder point as a first-class field** — `low_stock_threshold` defaults to
  `S.catalog_default_low_stock_threshold` (`app/core/settings.py:833`, default 5).
- **Cart purchase.** `purchase_cart` (`app/services/shoppingcart.py:474`) does a
  **decrement-at-purchase**: for each line it conditionally updates
  `stock_count = stock_count - :qty` with `ConditionExpression "stock_count >= :qty"`
  (`:515`–`:519`), accumulating `decremented_stock` and **manually rolling back**
  prior decrements on a `ConditionalCheckFailedException` (`:522`–`:537`, raises a
  409 "out of stock"). There are **no soft reservations** — stock is only ever
  consumed at the moment of purchase. Idempotency is keyed via
  `_cart_purchase_idempotency_key` and the `cart_purchase:{user}:{cart}:{order}`
  trigger (`:597`). Order creation is delegated to
  `commerce_order_service.create_order_from_line_items` (`:581`).
- **Billing ledger (single-entry).** `new_ledger_entry`
  (`app/services/billing_shared.py:224`) writes one row per money event:
  `{type, amount_cents, state ∈ {pending,settled,reversed}, reason, provider,
  ledger_date}`. Account balances are four running counters in `BAL_FIELDS`
  (`:15`) — `owed_pending/settled_cents`, `payments_pending/settled_cents` —
  mutated by `apply_balance_delta` (`:83`). `compute_due` (`:158`) derives amounts
  due from those counters. **This is single-entry**: there is no contra-account,
  no debit/credit pair, no chart of accounts, no trial balance. FIN-013 added the
  `ledger_date` denorm (`:253`) + `GSI_LEDGER_DATE` index so the platform financial
  dashboard (`app/services/platform_financial_dashboard.py:136` `_query_ledger_by_date`)
  can bucket entries by day without scanning.
- **Refunds.** `refund_payment` (`app/routers/billing.py:1286`) calls the provider,
  writes a `type="adjustment", reason="refund", state="settled"` ledger entry
  (`:1306`) carrying `provider` (FIN-013/GAP-0203), reverses the balance counters
  (`:1318`–`:1321`), and flips the original ledger row to `reversed` via
  `settle_or_reverse_ledger` (`:1323`). **There is exactly one refund mechanism —
  any RMA refund must reuse it.**
- **Promotions (flat).** `promo_codes.py` supports only
  `VALID_DISCOUNT_TYPES = {percentage, fixed_amount, free_trial}` (`:26`).
  `_calculate_discount` (`:376`) is flat per-code math; `redeem_promo_code` (`:398`)
  does an atomic `current_uses` increment with a `< max_uses` condition. **No
  tiered / bulk / conditional / scoped rules.**
- **Accounting export.** `app/services/audit_export_accounting.py` already maps
  ledger rows to QuickBooks/Xero CSV columns — a downstream consumer the GL work
  must stay compatible with.
- **Invoices.** `app/services/invoices.py` is the existing invoice entity (refund
  marking, etc.) — the AR derivation must reconcile to it.

### What is missing (the gap)

No warehouse/location model · no soft reservations (only decrement-at-purchase) ·
no returns/RMA entity · no double-entry GL / chart of accounts / journal entries /
AR / AP / trial balance / financial statements · no rules-based pricing.

---

## Decision drivers

1. **Reuse over rewrite.** The ledger, refund path, order service, and promo
   redemption already encode hard-won correctness (idempotency, provider
   attribution, atomic counters). Replacing them risks regressions in live money
   flows for no functional gain.
2. **SECOPS-007 dev/prod parity.** Per CLAUDE.md, every new path must run the same
   code in dev (moto/local DDB) and prod (real AWS) — no `dev_mode` branch in
   business logic. OFBiz's Java/entity-engine/screen-widget stack cannot satisfy
   this; it would introduce a second runtime, a second persistence layer, and a
   second auth model.
3. **Flag-gated, incremental rollout.** New behavior must default **off** behind a
   `*_ENABLED` flag (the `app/core/settings.py` pattern, e.g. `:389`
   `billing_reconcile_enabled`) so a milestone can ship dark and activate per env.
4. **DynamoDB single-table conventions.** New tables must follow the
   `_resolve_table_name(S.<name>, "<default>")` + `attr_types` numeric-GSI rule
   (CLAUDE.md gotcha) and wire through `app/core/tables.py` (`T.*`).
5. **Hermetic, frozen-S/T testability.** New services must be unit-testable
   offline by patching frozen `S`/`T` via `object.__setattr__` (the house pattern).
6. **Financial correctness must be derivable, not duplicated.** The GL must derive
   from the existing ledger as the single source of truth, so the two can never
   diverge and a reconciliation test can tie them out.

---

## Options considered

### Option A — Adopt Apache OFBiz wholesale (integrate the OFBiz application)

Stand up OFBiz (Java + its OFBiz Entity Engine on a relational DB + screen-widget
UI) as the system of record for inventory, orders, accounting, and pricing, and
sync to/from testlogon.

- **Pros:** Mature, battle-tested ERP semantics out of the box; full GL/AR/AP, MRP,
  warehouse, pricing engine already implemented; large feature surface "for free".
- **Cons:** Violates **every** decision driver. Second runtime (JVM) and second
  datastore (relational, not DynamoDB) → no dev/prod parity, no frozen-S/T tests,
  no flag-gating of individual behaviors. Bidirectional sync between OFBiz orders
  and `commerce_order_service`/`billing_shared` is a permanent, brittle reconciliation
  surface. Auth/role model (`require_ui_session`/`require_admin_session`/ROOT) does
  not map onto OFBiz's security. Enormous integration + operational cost for a
  platform that already has working orders/cart/ledger. **Rejected.**

### Option B — Port OFBiz schema/algorithms verbatim into testlogon

Re-create OFBiz's relational entity set (InventoryItem, ItemIssuance,
OrderItemShipGrpInvRes, GlAccount, AcctgTrans/AcctgTransEntry, ProductPrice/
ProductPriceRule, ReturnHeader/ReturnItem) one-for-one as DynamoDB tables and
re-implement its services in Python.

- **Pros:** Inherits a known-correct conceptual model; less novel design risk than
  greenfield.
- **Cons:** OFBiz's schema is normalized-relational and assumes joins/transactions
  DynamoDB doesn't offer cheaply; a verbatim port produces dozens of tiny tables
  and N+1 access patterns. It would create a **parallel** accounting world
  (AcctgTrans) disconnected from our `billing_shared` ledger — exactly the
  divergence driver #6 forbids — requiring a separate reconciliation between
  AcctgTrans and our ledger. Over-scoped: pulls in MRP/manufacturing concepts we
  explicitly defer. **Rejected** as too literal.

### Option C — Cherry-pick four OFBiz *domains*, re-model them natively, derive the GL from the existing ledger (RECOMMENDED)

Take the **concepts** from four OFBiz domains — (1) inventory + soft reservations,
(2) returns/RMA, (3) double-entry GL/AR/AP, (4) advanced pricing/promotions — and
implement them as native testlogon services on DynamoDB, mapped onto the existing
cart/order/ledger/promo subsystems. Crucially, the GL is **posted from** the
existing single-entry ledger rather than replacing it. Explicitly defer OFBiz MRP,
manufacturing, shipment routing, and multi-warehouse transfer orders.

- **Pros:** Satisfies all decision drivers — same Python/DynamoDB runtime, dev/prod
  parity, flag-gated, frozen-S/T tests. Reuses `refund_payment`/`new_ledger_entry`/
  `create_order_from_line_items`/`redeem_promo_code` (no parallel money mechanisms).
  GL derives from the ledger (single source of truth → tie-out testable).
  Incremental: each domain is its own milestone behind its own flag. Matches the
  ticket backlog 1:1.
- **Cons:** We re-implement (not inherit) the reservation lifecycle, GL posting
  rules, aging, and pricing-rule evaluation — real engineering effort and the risk
  of subtle financial bugs (mitigated by the balanced-entry and tie-out invariants
  in OFB-014/015/016). Soft reservations add a TTL-release background loop and a
  new oversell-race surface (mitigated by single-writer conditional updates).

### Option D — Minimal "good-enough" extensions, no GL

Add only soft reservations + a returns entity + a couple of new promo discount
types, skip double-entry accounting entirely (keep relying on the single-entry
ledger + the existing CSV mapper for accountants).

- **Pros:** Smallest effort; avoids the riskiest, highest-effort milestone (GL).
- **Cons:** Leaves the single biggest enterprise gap (auditable double-entry
  books, trial balance, AR/AP aging, financial statements) unaddressed — the
  primary reason to look at an ERP at all. The CSV mapper is a flat dump, not a
  balanced ledger. **Rejected** as under-delivering on the mandate, though it is
  effectively the "stop after Milestone 2–3" fallback if the GL milestone is
  descoped.

---

## Decision

Adopt **Option C** — cherry-pick the four domains and re-model them natively,
deriving the GL from the existing billing ledger.

### Per-domain mapping (cherry-pick vs. adopt vs. defer)

| OFBiz domain | testlogon today | Decision | Where it lands |
|---|---|---|---|
| Inventory items + on-hand/reserved/available + reorder point | `stock_count` scalar (`catalog.py:94`) | **Cherry-pick, re-model** | new `app/services/inventory.py`; catalog `stock_count` becomes a denormalized read-through mirror (OFB-003) |
| Soft reservations (reserve → issue → release) | decrement-at-purchase only (`shoppingcart.py:515`) | **Cherry-pick, re-model** | reservation lifecycle + TTL-release loop in `inventory.py`/`shoppingcart.py` (OFB-004) |
| Multi-warehouse / location, transfer orders | none | **Defer** (schema carries an optional `location_id`, single default "warehouse") | OFB-003 schema only |
| Returns / RMA (ReturnHeader/ReturnItem lifecycle) | none | **Cherry-pick, re-model** | new `app/services/returns_rma.py` + router (OFB-008..012) |
| RMA refund | reuse `refund_payment`/`settle_or_reverse_ledger` (`billing.py:1286`) | **Adopt existing path** | OFB-010 (no parallel refund) |
| Double-entry GL + chart of accounts | single-entry ledger (`billing_shared.py:224`) | **Cherry-pick, derive from ledger** | `gl_accounts.py` + `gl_posting.py`, posted from `GSI_LEDGER_DATE` buckets (OFB-013/014) |
| AR / AP subledgers + aging | `BAL_FIELDS`/`compute_due` + `invoices.py` | **Cherry-pick, derive** | `gl_posting.py`/new AR-AP module reconciling to GL control accounts (OFB-015) |
| Trial balance / P&L / balance sheet | none (only CSV mapper) | **Cherry-pick** | statement generators over the GL (OFB-016) |
| MRP / manufacturing | none | **Defer (explicitly out)** | — |
| Advanced pricing (tiered/bulk/conditional, scope, stacking) | flat promo codes (`promo_codes.py:26`) | **Cherry-pick, re-model** | new `app/services/pricing_rules.py`, integrated with `validate_promo_code` (OFB-019/020) |

### Rationale

Option C is the only option that preserves the existing money-flow code as the
authoritative source while adding the missing enterprise depth. The decisive design
choice is that **the GL is a projection of the billing ledger, not a replacement
for it** — every journal entry is derived idempotently (one per source `entry_id`)
from a ledger row, so the books can always be tied back to the ledger and the
platform financial dashboard. This avoids the dual-source-of-truth trap that sinks
both Option A and Option B, and it keeps the entire feature set inside the one
runtime/datastore/auth model the codebase and SECOPS-007 require.

---

## Consequences

**Positive**

- No second runtime, datastore, or auth model; everything stays Python/FastAPI/DynamoDB.
- Refunds, order creation, and promo redemption keep their single, tested
  implementations; provider attribution (FIN-013) and the financial dashboard stay
  correct automatically.
- Each domain ships behind its own flag, defaulting off — zero behavior change on
  deploy until explicitly enabled per env.
- The GL is reconcilable to the ledger by construction (tie-out test in OFB-015/016).

**Negative / risks**

- **Oversell race.** Moving from decrement-at-purchase to reserve-then-commit adds a
  new concurrency surface. Mitigation: keep the existing single-writer conditional-update
  guarantee (`ConditionExpression` on available qty), so exactly one reservation of
  the last unit wins and the loser gets the existing 409 path (OFB-004 AC).
- **Stranded reservations.** TTL-release loop must be reliable. Mitigation: reuse the
  cart-abandonment loop pattern (`shoppingcart.py` `start_cart_abandonment_task`).
- **Double-counting catalog stock.** During OFB-003/004, catalog `stock_count` and
  the new inventory record coexist. Mitigation: catalog becomes a strict read-through
  mirror written only by the inventory service.
- **GL mapping correctness.** A wrong type→account mapping silently mis-states the
  books. Mitigation: hard invariant that Σdebits == Σcredits per entry (unbalanced →
  fail loudly, never persist) + a reconciliation test against the dashboard.
- **Migration window for `GSI_LEDGER_DATE`-driven posting.** Historical ledger rows
  need a one-shot backfill (OFB-014 AC) — idempotent per `entry_id` so re-runs are safe.

**Neutral**

- Net-new admin/ROOT UI surfaces (inventory, RMA queue, accounting, pricing rules).
- MRP/manufacturing remain out of scope; revisiting them is a future ADR.

---

## Security & dev/prod-parity model (SECOPS-007)

- **No `dev_mode` branches in business logic.** Inventory, reservations, RMA, GL
  posting, and pricing all run identical code in dev (in-process moto / local DDB on
  :8001) and prod (real DynamoDB) — same as the audit-export and KYC-partner-API
  patterns in CLAUDE.md.
- **Role gating.** Customer-facing endpoints (request a return, cart total) use
  `Depends(require_ui_session)` with CSRF on non-GET. Inventory/RMA admin actions use
  `require_admin_session`; chart-of-accounts, journal browser, AR/AP, and financial
  statements are **ROOT-only** (`require_root_session`) — books are root-privileged.
- **Ownership enforcement.** Returns validate the order line belongs to the requester
  (foreign order → 403/404), mirroring the per-partition isolation pattern used across
  the codebase.
- **Audit everything.** Inventory adjustments, RMA transitions, GL postings, and rule
  changes emit `app/services/alerts.audit_event` (as `commerce_order_service.py:106`).
- **Money paths reuse the gated provider/fraud machinery.** RMA refunds go through
  `refund_payment`, inheriting `_require_provider_enabled` / fraud gating (GAP-0206/0207).
- **Frozen-S/T hermetic tests.** Every new service is unit-tested offline by patching
  frozen `S`/`T` via `object.__setattr__` and binding moto in-memory tables to the exact
  frozen handles (the house pattern), with no real AWS/network.

---

## New settings / flags

All added to `app/core/settings.py` following the
`os.environ.get("X", "false").lower() == "true"` pattern, **defaulting off**, and read
through the `S` singleton. Table names follow `_resolve_table_name(S.<name>, "<default>")`.

| Setting (env) | Default | Purpose |
|---|---|---|
| `INVENTORY_RESERVATIONS_ENABLED` | `false` | Master switch for inventory records + soft reservations (OFB-003/004) |
| `INVENTORY_RESERVATION_TTL_SECONDS` | e.g. `1800` | TTL before a stranded reservation auto-releases (OFB-004) |
| `INVENTORY_LOW_STOCK_ALERTS_ENABLED` | `false` | Reorder-point alert emission + de-dup (OFB-005) |
| `RETURNS_RMA_ENABLED` | `false` | Returns/RMA entity + endpoints (OFB-008..012) |
| `GL_DOUBLE_ENTRY_ENABLED` | `false` | Background GL poster from `GSI_LEDGER_DATE` buckets (OFB-014) |
| `GL_AR_AP_ENABLED` | `false` | AR/AP subledger derivation + aging (OFB-015) |
| `PRICING_RULES_ENABLED` | `false` | Tiered/bulk/conditional pricing engine (OFB-019/020) |

Existing reused config: `S.catalog_default_low_stock_threshold` (`:833`) as the
per-SKU reorder-point default; `GSI_LEDGER_DATE` + `ledger_date` denorm as the GL
derivation source.

### New tables (OFB-002 scaffolding; exact PK/SK/GSIs finalized in OFB-002)

| Table (`S.<name>`, default) | PK | SK | GSIs (numeric → `attr_types`) | Notes |
|---|---|---|---|---|
| `inventory` | `sku` | `LOC#{location_id}` | `GSI_AVAILABLE` (status / `available` N) for low-stock filter | on_hand/reserved/available/reorder_point; single default location |
| `reservations` | `RES#{reservation_id}` | `META` | `GSI_SKU` (sku / `created_at` N); `GSI_EXPIRY` (`SCHED#ACTIVE` / `expires_at` N) for TTL-release | reserve→commit→release lifecycle |
| `returns` (RMA) | `return_id` | `META` / `ITEM#{n}` | `GSI_ORDER` (order_id / `created_at` N); `GSI_STATUS` (status / `created_at` N) | references existing `orders`/`order_items` |
| `gl_accounts` | `account_id` | `META` | `GSI_CLASS` (account_class / account_id) | chart of accounts; class + normal-balance side |
| `gl_journal` | `JE#{journal_id}` | `META` / `LINE#{n}` | `GSI_SOURCE` (`source_entry_id` / `posted_at` N) idempotency; `GSI_DATE` (`gl_date` / `posted_at` N) | one balanced JE per source ledger `entry_id` |
| `pricing_rules` | `RULE#{rule_id}` | `META` | `GSI_SCOPE` (scope_key / priority N); `GSI_CREATOR` (creator_id / `created_at` N) | tiered/bulk/conditional; may link a promo code |

(AR/AP are *derived* from balances/invoices + GL control accounts, not a new base
table — OFB-015.) All numeric GSI sort keys (`available`, `created_at`, `expires_at`,
`posted_at`, `priority`, `gl_date` if numeric) must be declared with `attr_types` in
`scripts/local-ddb-init.py` per the CLAUDE.md gotcha, or queries 500 with
`ValidationException`. Table handles wired in `app/core/tables.py` as
`T.inventory`, `T.reservations`, `T.returns`, `T.gl_accounts`, `T.gl_journal`,
`T.pricing_rules`.

---

## High-level implementation plan (mapped to ticket IDs)

**Milestone 1 — Scoping**
- **OFB-001** (this ADR): module mapping + data-model delta + phasing + sign-off.
- **OFB-002**: land the six new tables in `scripts/local-ddb-init.py` (with
  `attr_types`), add the seven flags to `settings.py` (off), wire `T.*` handles,
  smoke test `just restart` + handle resolution.

**Milestone 2 — Inventory & reservations** (gated by `INVENTORY_RESERVATIONS_ENABLED`)
- **OFB-003**: `inventory.py` — `get_inventory`/`set_on_hand`/`adjust` with atomic
  conditional updates + audit; catalog `stock_count` becomes a read-through mirror.
- **OFB-004**: reservation lifecycle in `purchase_cart` (`shoppingcart.py:474`) —
  reserve at checkout-begin, commit on purchase, release on abandon/expiry/fail;
  TTL-release background loop; preserve idempotency (`:597`) + `create_order_from_line_items`.
- **OFB-005**: reorder-point/low-stock alerts with crossing de-dup.
- **OFB-006**: admin inventory UI under `frontend/src/pages/shop/admin/`.
- **OFB-007**: `frontend/e2e/inventory.spec.ts`.

**Milestone 3 — Returns / RMA** (gated by `RETURNS_RMA_ENABLED`)
- **OFB-008**: `returns_rma.py` + router (request flow, ownership + qty validation,
  validated status transitions), registered in `app/main.py` under `require_ui_session`.
- **OFB-009**: admin approve/reject/receive; on `received`, restock via
  `inventory.adjust(sku, +qty, "rma_restock")` (guarded by the inventory flag).
- **OFB-010**: refund via the existing `refund_payment`/`settle_or_reverse_ledger`
  path (`billing.py:1286`) — one refund ledger entry, provider-attributed, idempotent;
  mark invoice `refunded` (`invoices.py`).
- **OFB-011**: customer "My Returns" + admin RMA queue UI.
- **OFB-012**: `frontend/e2e/returns-rma.spec.ts`.

**Milestone 4 — Double-entry GL / AR / AP** (gated by `GL_DOUBLE_ENTRY_ENABLED`, `GL_AR_AP_ENABLED`)
- **OFB-013**: `gl_accounts.py` — seedable chart of accounts (Cash, AR, AP, Sales
  Revenue, Refunds contra, Sales Tax Payable, Processor Fees), ROOT CRUD.
- **OFB-014**: `gl_posting.py` — derive a balanced JE per ledger row from
  `GSI_LEDGER_DATE` day buckets; idempotent per source `entry_id`; backfill command.
- **OFB-015**: AR (from `BAL_FIELDS`/`compute_due` + `invoices.py`) and AP subledgers
  with aging; reconcile to GL control accounts.
- **OFB-016**: trial balance / income statement / balance sheet over the GL;
  reconcile revenue to `platform_financial_dashboard.py`.
- **OFB-017**: ROOT-only accounting UI; export via `audit_export_accounting.py`.
- **OFB-018**: GL/AR/AP pytest + `frontend/e2e/accounting.spec.ts` smoke.

**Milestone 5 — Advanced pricing / promotions** (gated by `PRICING_RULES_ENABLED`)
- **OFB-019**: `pricing_rules.py` — tiered/bulk/conditional engine with scope +
  stacking/precedence; integrate with `validate_promo_code` (`promo_codes.py:239`);
  flat codes unchanged.
- **OFB-020**: apply rules at cart total (`shoppingcart.py:474`, total endpoint
  `app/routers/shoppingcart.py:169`); persist applied-rule refs on order line items;
  keep `redeem_promo_code` (`:398`) caps for code-bound rules.
- **OFB-021**: admin rule builder UI with live discount preview.
- **OFB-022**: pricing pytest + `frontend/e2e/pricing-rules.spec.ts`.

---

## Effort estimate

Summed from the backlog estimates (developer-days):

| Milestone | Tickets | Days |
|---|---|---|
| M1 Scoping | OFB-001, 002 | 6 |
| M2 Inventory & reservations | OFB-003..007 | 16 |
| M3 Returns / RMA | OFB-008..012 | 16 |
| M4 GL / AR / AP | OFB-013..018 | 25 |
| M5 Advanced pricing | OFB-019..022 | 14 |
| **Total** | **22 tickets** | **≈77 dev-days (~15–16 weeks for one engineer; ~6–8 calendar weeks with 2–3 in parallel respecting deps)** |

Milestone 4 (GL) is the largest and highest-risk; M2 and M3/M5 are independent
after M2's inventory primitives exist (M3's restock depends on M2-OFB-003), so M3
and M5 can run in parallel with M4. If the GL milestone is descoped, Option D
(M2 + M3 + M5, ~46 days) is the natural fallback line.

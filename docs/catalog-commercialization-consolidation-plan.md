# Catalog Commercialization Consolidation Plan

## Objective

Consolidate commercialization entitlement grant flows so they run through:

1. the existing shopping cart + checkout experience, and
2. the existing subscriptions system,

while preserving deterministic entitlement lifecycle behavior, payment reconciliation, and rollback safety.

---

## Current-state summary

Today there are parallel paths:

- Shopping cart purchase flow records cart purchase history but does not consistently create commercialization order/item records used by entitlement grants.
- Commercialization checkout creates dedicated `orders`/`order_items` records directly.
- Subscription flows use the subscriptions subsystem with limited native bridging into commercialization order + entitlement templates.

This plan unifies those surfaces into a single commercial order/event model with phased migration.

---

## Guiding principles

- **No big-bang migration**: use feature flags and compatibility adapters.
- **One canonical order/item contract** across cart, direct checkout, and subscription renewals.
- **Deterministic entitlement behavior** using existing state machine and policy contracts.
- **Full auditability** for support, billing, and incident response.
- **Rollback without data loss** (disable source-family flags and fallback to previous path).

---

## Epic G — Unified commerce model

### CCE-060: Define canonical commercial line-item schema
**Goal**: unify billable payloads across cart, direct checkout, and subscriptions.

**Scope**
- Define `commercial_line_item` schema with: `sku`, `product_type`, `billing_model`, `source_system`, `quantity`, `scope`, `pricing_ref`.
- Add adapters:
  - shopping cart item -> commercial line item,
  - direct commercialization checkout request -> commercial line item,
  - subscription plan -> recurring commercial line item template.
- Version schema and publish examples.

**Acceptance criteria**
- One validator accepts all three source variants.
- Contract test fixtures exist for file bundle, API package, internal API package, and subscription renewal line items.

**Dependencies**
- CCE-001, CCE-002.

---

### CCE-061: Build unified commerce order orchestration service
**Goal**: all purchase sources write the same canonical order + order_items records.

**Scope**
- Introduce `CommerceOrderService.create_order(...)` and `create_order_from_line_items(...)`.
- Persist source metadata: `source_system` (`shopping_cart`, `commercial_direct`, `subscription_cycle`) and correlation IDs.
- Keep compatibility outputs for existing consumers.

**Acceptance criteria**
- Cart/direct/subscription-cycle all produce canonical `orders` + `order_items`.
- Audit events include source + correlation IDs.

**Dependencies**
- CCE-060, CCE-010.

---

## Epic H — Shopping cart + checkout consolidation

### CCE-062: Add commercialization-aware SKU/cart item support
**Goal**: support commercialization products as first-class cart line items.

**Scope**
- Extend cart item model for `product_type`, `scope`, `access_mode`, rental metadata, and entitlement template metadata.
- Validate cart item payloads against catalog schema by product type.
- Support mixed carts (legacy items + commercialization items).

**Acceptance criteria**
- Invalid scope/config is rejected at cart add/update time.
- Mixed-cart totals and item listing remain stable.

**Dependencies**
- CCE-060, CCE-001.

---

### CCE-063: Route cart purchase through unified commercial order + checkout
**Goal**: shopping cart purchase becomes a canonical commercialization checkout source.

**Scope**
- Refactor cart purchase execution to call unified order orchestration.
- Preserve existing purchase history writes for backward compatibility.
- Add idempotent cart-purchase keying to avoid duplicate orders.

**Acceptance criteria**
- Cart purchases create canonical order/item records.
- Commercialization entitlements can be granted from cart purchases via existing payment reconciliation path.

**Dependencies**
- CCE-061, CCE-062, CCE-012.

---

### CCE-064: Build unified checkout session API
**Goal**: one checkout entrypoint for cart-based and direct SKU purchases.

**Scope**
- Add `POST /ui/checkout/session` with `source` (`cart`, `direct`, `subscription_action`).
- Keep existing specialized routes as compatibility wrappers.
- Normalize response payload: `order_id`, `checkout_session_id`, `line_items`, `source`.

**Acceptance criteria**
- Existing clients continue working via wrappers.
- New UI flow uses unified endpoint and identical payment orchestration.

**Dependencies**
- CCE-061, CCE-063.

---

## Epic I — Subscription system consolidation

### CCE-065: Map subscription plans to entitlement templates
**Goal**: subscription plans produce standardized entitlement definitions.

**Scope**
- Define plan->template mapping for access, limits, credits, duration/window behavior.
- Add plan version compatibility checks.
- Include policy for renewals, pauses, cancel-at-period-end, and resumptions.

**Acceptance criteria**
- Active subscription state deterministically maps to active entitlement state.
- Plan changes update future entitlement template behavior correctly.

**Dependencies**
- CCE-060, CCE-002.

---

### CCE-066: Emit canonical recurring orders from subscription lifecycle
**Goal**: make subscription billing cycles first-class canonical commercial orders.

**Scope**
- On subscription renewal/charge events, write canonical `orders` + `order_items` with `source_system=subscription_cycle`.
- Link recurring orders to subscription IDs and invoice IDs.
- Reuse existing payment reconciliation hooks.

**Acceptance criteria**
- Subscription charges are represented in the same order stream as cart/direct purchases.
- Entitlement grant/revoke audit traces reference recurring order IDs.

**Dependencies**
- CCE-061, CCE-065, CCE-012.

---

### CCE-067: Backfill active subscriptions into standardized entitlements
**Goal**: ensure current subscribers are aligned before full cutover.

**Scope**
- Build dry-run/apply backfill job for active subscriptions -> entitlement records.
- Produce ownership-tagged drift report and reconciliation summary.
- Provide rollback script/runbook section.

**Acceptance criteria**
- Dry-run output reviewed by product, billing, support.
- Apply mode validated in staging with deterministic reruns.

**Dependencies**
- CCE-065, CCE-050.

---

## Epic J — Visibility, reconciliation, and operations

### CCE-068: Unified entitlement visibility with source attribution
**Goal**: users/support can see where entitlements came from.

**Scope**
- Extend `GET /v1/entitlements` with: `source_system`, `order_id`, optional `subscription_id`, billing metadata pointers.
- Add filters by source and lifecycle status.

**Acceptance criteria**
- Support can explain access outcomes from a single entitlement response.
- Subscription-derived entitlements are clearly identified.

**Dependencies**
- CCE-066, CCE-022.

---

### CCE-069: Cross-system billing/entitlement reconciliation invariants
**Goal**: detect and repair drift between billed units, orders, and entitlements.

**Scope**
- Add reconciliation checks:
  - billed units == canonical order items,
  - canonical order items == entitlement grants/updates,
  - subscription renewal events == recurring order stream.
- Alert with ownership metadata and remediation hints.

**Acceptance criteria**
- Reconciliation reports produce actionable drift rows.
- Replay/repair flows tested in staging game-day.

**Dependencies**
- CCE-050, CCE-063, CCE-066.

---

## Epic K — Phased rollout and cutover safety

### CCE-070: Introduce consolidation migration feature flags
**Goal**: migrate each source path independently with safe rollback.

**Scope**
- Add flags:
  - `CART_USE_UNIFIED_COMMERCE_ORDER`
  - `SUBSCRIPTIONS_EMIT_COMMERCE_ORDERS`
  - `CHECKOUT_USE_UNIFIED_ENDPOINT`
- Add shadow-mode metrics comparing old/new path outputs before full enablement.

**Acceptance criteria**
- Source-level canary rollout with independent rollback.
- No data loss when toggling flags off.

**Dependencies**
- CCE-063, CCE-064, CCE-066, CCE-052.

---

### CCE-071: Cutover go/no-go and support readiness gates
**Goal**: formalize launch governance across engineering/product/support.

**Scope**
- Define go/no-go checklist for cart/direct/subscription migration stages.
- Require support runbook validation for manual corrections and escalations.
- Add on-call incident drill specific to entitlement grant regressions.

**Acceptance criteria**
- Checklist approved by engineering, product, support, billing.
- Staging game-day evidence attached before production expansion.

**Dependencies**
- CCE-070, CCE-069, CCE-051.

---

## Recommended execution sequence

1. CCE-060, CCE-061 (contract + orchestrator foundation)
2. CCE-062, CCE-063, CCE-064 (cart + checkout consolidation)
3. CCE-065, CCE-066, CCE-067 (subscription integration)
4. CCE-068, CCE-069 (visibility + reconciliation)
5. CCE-070, CCE-071 (migration flags + final cutover governance)

---

## Deliverables expected at completion

- A single canonical commerce order pipeline across cart/direct/subscription paths.
- Entitlement grants sourced from unified order events.
- Subscription charges represented in the same canonical order stream.
- Consolidated observability + reconciliation with ownership metadata.
- Fully staged, reversible cutover with documented support workflows.

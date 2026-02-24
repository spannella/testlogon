# Shopping Cart Entitlement Reconciliation Unification Plan

## Problem Statement
The current shopping cart purchase flow is unified with commercialization at the **order creation** layer (`commerce_order_service.create_order_from_line_items` with `source_system="shopping_cart"`), but it does not directly trigger entitlement grant/reconciliation within `purchase_cart`. As a result, entitlement issuance for non-subscription cart purchases depends on broader asynchronous payment/reconciliation paths, which can create visibility lag and ambiguity in ownership of the grant step.

## Goals
1. Make entitlement grant semantics for shopping-cart purchases explicit and deterministic.
2. Preserve payment-state correctness (no grant before successful payment where required).
3. Keep idempotency guarantees across retries/replays and process restarts.
4. Ensure support/API entitlement reads (`/v1/entitlements`) observe cart-driven grants through the same `T.entitlements` surface.
5. Minimize regression risk in existing subscription-cycle reconciliation and dead-letter/replay behavior.

## Non-Goals
- Replacing the existing subscription-cycle reconciliation flow.
- Changing entitlement policy semantics (scope/limit rules) beyond orchestration.
- Migrating historical data in this phase (backfill can be a follow-up ticket if needed).

---

## Proposed Target Architecture

### A) Introduce a commerce entitlement orchestration service
Create a dedicated orchestrator (e.g., `CommerceEntitlementOrchestrator`) responsible for:
- deriving entitlement actions from order + order_items,
- invoking the existing `EntitlementsService` via table-backed repository,
- applying idempotency keys derived from stable business identity (`order_id:item_id[:action]`),
- recording audit events for each grant/revoke/no-op.

This service should be provider-agnostic and callable by both:
- shopping-cart purchase completion,
- unified checkout completion hooks,
- payment reconciliation replay paths.

### B) Wire cart purchase completion to orchestration
Update `purchase_cart` completion path to emit an explicit post-purchase orchestration trigger with a deterministic event identity. Two implementation-compatible options:
1. **Inline trigger** immediately after cart transitions to PURCHASED and order is known.
2. **Outbox/event trigger** written transactionally (preferred for scale/reliability), consumed by worker that calls orchestrator.

Recommended: start with inline + idempotency guard, then evolve to outbox if throughput demands.

### C) Keep payment-state invariant explicit
For billable items, grant only when payment is successful by requiring one of:
- payment status on order metadata indicates success, or
- reconciliation service confirms success event for that order.

For free/zero-value items, allow immediate grant path.

### D) Unify dead-letter and replay for cart entitlement failures
Persist cart entitlement failures in a durable dead-letter store with:
- `order_id`, `cart_id`, `user_id`, `source_system`, `owner_team`, `remediation_hint`, `failure_reason`, `attempt_count`, timestamps.

Provide replay helpers by:
- order id,
- cart id,
- time window.

---

## Implementation Work Breakdown

### Ticket SC-EU-1: Add commerce entitlement orchestrator abstraction
**Scope**
- New service module with methods:
  - `process_order_entitlements(order_id, *, trigger_event_id, source_system)`
  - `replay_failed_order(order_id)`
- Use table-backed entitlements repository and existing entitlement policy/service contracts.

**Acceptance Criteria**
- Given canonical order/order_items, orchestrator can grant expected entitlements.
- Duplicate calls with same trigger event are no-op/idempotent.

---

### Ticket SC-EU-2: Integrate shopping cart purchase completion with orchestrator
**Scope**
- Update `purchase_cart` to invoke orchestrator (inline) after successful purchase transition.
- Add deterministic trigger id: `cart_purchase:{user_sub}:{cart_id}:{order_id}`.
- Preserve existing cart idempotency behavior and return payload.

**Acceptance Criteria**
- Successful cart purchase triggers entitlement processing exactly once.
- Repeated purchase calls do not duplicate entitlements.

---

### Ticket SC-EU-3: Payment-state gating and source-specific rules
**Scope**
- Encode gating rules for billable vs non-billable line items.
- If payment not yet terminal-success, record deferred/no-op with traceable status.
- Ensure subsequent reconciliation can complete the grant.

**Acceptance Criteria**
- No entitlement granted before required payment success.
- Entitlements are granted when payment success arrives, without duplicate rows.

---

### Ticket SC-EU-4: Durable dead-letter + replay for cart entitlement failures
**Scope**
- Add persisted dead-letter records for orchestrator failures.
- Add replay APIs/helpers for order/cart/time windows.
- Add owner/remediation metadata for operator actionability.

**Acceptance Criteria**
- Operators can query and replay failed cart entitlement actions without payload reconstruction.
- Replay success leads to active entitlement visibility.

---

### Ticket SC-EU-5: End-to-end and regression tests
**Scope**
- Add/extend tests validating:
  1. cart purchase success -> entitlement visible via `list_user_entitlements`,
  2. duplicate purchase invocation -> no duplicate entitlement row,
  3. payment delayed then success -> deferred then granted,
  4. orchestrator failure -> dead-letter -> replay -> active entitlement,
  5. no regression in subscription-cycle reconciliation and charge-path routing.

**Acceptance Criteria**
- All new E2E scenarios pass.
- Existing related suites remain green.

---

## Data Model & Idempotency Details

### Deterministic entitlement identity
Use stable IDs for cart-driven grants, e.g.:
- `sha256("order_entitlement:{order_id}:{item_id}:{sku}:{product_type}")[:32]`

### Write protection
- Use conditional insert (`attribute_not_exists(entitlement_id)`) on `T.entitlements`.
- Treat conditional check failures as duplicate/no-op and return deterministic status.

### Event idempotency registry
Record processed orchestrator trigger events keyed by:
- `source_system + trigger_event_id`.

Store outcome/status/timestamp for observability and replay behavior.

---

## Rollout Plan
1. **Dark launch** orchestrator behind feature flag (`ENABLE_CART_ENTITLEMENT_ORCHESTRATION`).
2. Enable for low-risk cohorts/tenants.
3. Monitor dead-letter volume, duplicate suppression counts, entitlement visibility lag.
4. Enable globally after stability window.
5. Document runbook and rollback steps.

---

## Observability & Alerts
Add metrics/counters:
- `cart_entitlement_orchestration_attempt_total`
- `cart_entitlement_orchestration_success_total`
- `cart_entitlement_orchestration_dead_letter_total`
- `cart_entitlement_orchestration_duplicate_total`
- `cart_entitlement_visibility_lag_seconds` (optional histogram)

Add alert thresholds:
- dead-letter rate spike,
- replay backlog age,
- sustained visibility lag.

---

## Risks & Mitigations
- **Risk:** Double-grants during retries.  
  **Mitigation:** deterministic entitlement ID + conditional write + trigger idempotency.
- **Risk:** Granting before payment finalization.  
  **Mitigation:** explicit payment-state gate for billable items.
- **Risk:** New synchronous latency in `purchase_cart`.  
  **Mitigation:** keep orchestration lightweight, use timeout + dead-letter fallback, move to outbox worker if needed.

---

## Definition of Done
- Shopping-cart purchase path has explicit entitlement orchestration trigger.
- Entitlement writes are durable in `T.entitlements` and visible via `list_user_entitlements`.
- Idempotency verified across retries/replays and process restarts.
- Dead-letter records are actionable and replayable.
- E2E + regression tests pass for cart + subscription flows.

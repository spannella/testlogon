# Subscription Entitlement Persistence Unification — Implementation Tickets

## Context
Current recurring reconciliation can read canonical `orders`/`order_items`, but entitlement writes are still in-memory in the gateway repository lineage. This creates a persistence mismatch with visibility/API reads that query `T.entitlements`.

---

## CCE-069E-1 — Add table-backed entitlement repository adapter for reconciliation

**Goal**
Create a production repository adapter for `EntitlementsService` that persists grants into DynamoDB-backed entitlements, while still reading canonical order/order_item data.

**Scope**
- Add `TableBackedEntitlementsRepository` (or equivalent) with methods used by `EntitlementsService`:
  - `get_order(order_id)` from `T.orders`
  - `get_order_items(order_id)` from `T.order_items`
  - `put_entitlement(record)` to `T.entitlements`
  - `get_entitlement(entitlement_id)` from `T.entitlements`
  - `list_entitlements_for_subject(user_id)` from `T.entitlements`
- Preserve compatibility with current `EntitlementsService` contracts.

**Acceptance Criteria**
- Reconciliation-driven grants are written to `T.entitlements`.
- `GET /v1/entitlements` can observe those grants without auxiliary sync steps.

**Dependencies**
- None.

---

## CCE-069E-2 — Wire subscription-cycle reconciliation gateway to table-backed persistence

**Goal**
Replace in-memory entitlement persistence in `SubscriptionCycleReconciliationGateway` with the table-backed adapter.

**Scope**
- Update gateway initialization to use table-backed entitlements repository.
- Keep canonical order presence invariant checks (`missing_order`, `missing_order_items`).
- Keep existing dead-letter metadata and audit events.

**Acceptance Criteria**
- Successful recurring reconciliation persists entitlements in DynamoDB.
- No behavior regression in dead-letter/replay and audit chains.

**Dependencies**
- CCE-069E-1.

---

## CCE-069E-3 — Enforce idempotent grant writes across retries/replays

**Goal**
Guarantee duplicate webhook deliveries/replays do not create duplicate entitlement rows.

**Scope**
- Introduce deterministic grant identity per order item (e.g., `order_id:item_id` or stable hash).
- Use conditional write/upsert guard (`attribute_not_exists` or equivalent) in `put_entitlement`.
- Ensure duplicate event processing returns duplicate/no-op semantics consistently.

**Acceptance Criteria**
- Repeated processing of the same `subscription_charge:<invoice_id>` does not increase entitlement row count.
- Idempotency survives process restarts (not memory-bound).

**Dependencies**
- CCE-069E-1, CCE-069E-2.

---

## CCE-069E-4 — Persist replay/dead-letter operational metadata

**Goal**
Make failed recurring grants fully actionable by preserving ownership and replay pointers in dead-letter records.

**Scope**
- Ensure dead-letter rows include:
  - `order_id`, `invoice_id`, `subscription_id`, `provider_event_id`
  - `owner_team`, `remediation_hint`
- Ensure replay-by-invoice-range helper operates against persisted, queryable metadata.

**Acceptance Criteria**
- Operators can query and replay failures by invoice window without manual payload reconstruction.
- Dead-letter alerts map directly to replay actions.

**Dependencies**
- CCE-069E-2.

---

## CCE-069E-5 — End-to-end integration tests for persistence unification

**Goal**
Prove that recurring subscription reconciliation writes are visible in the same entitlement surface used by support/API.

**Scope**
- Add tests validating:
  1. renewal → recurring order → reconciliation success → entitlement row in `T.entitlements` → visible via `list_user_entitlements`
  2. duplicate invoice event → no duplicate entitlement row
  3. transient reconciliation failure → dead-letter → replay → entitlement row active
  4. all five subscription charge paths still route shared emit/reconcile helper
- Add regression assertions for audit event chains.

**Acceptance Criteria**
- All above tests pass against table-backed path.
- Existing reconciliation and subscription route tests continue to pass.

**Dependencies**
- CCE-069E-2, CCE-069E-3, CCE-069E-4.

---

## CCE-069E-6 — Rollout flag + staging game-day + runbook updates

**Goal**
Roll out safely with staged validation and clear operational guidance.

**Scope**
- Add feature flag to toggle reconciliation entitlements repository mode (`in_memory` vs `table_backed`) for controlled rollout.
- Document game-day checklist:
  - replay by invoice range
  - duplicate suppression checks
  - entitlement visibility verification from API/support surfaces
- Update recurring orders runbook with troubleshooting matrix.

**Acceptance Criteria**
- Staging game-day confirms deterministic reruns and correct visibility.
- Production rollout plan includes observability metrics and rollback switch.

**Dependencies**
- CCE-069E-1 through CCE-069E-5.

---

## Suggested Delivery Order
1. CCE-069E-1
2. CCE-069E-2
3. CCE-069E-3
4. CCE-069E-4
5. CCE-069E-5
6. CCE-069E-6

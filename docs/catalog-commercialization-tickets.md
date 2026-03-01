# Catalog Commercialization & Entitlements — Implementation Ticket Backlog

This backlog translates `docs/catalog-commercialization-plan.md` into dependency-ordered implementation tickets for delivery.

---

## Epic A — Contracts, product modeling, and governance

### CCE-001: Define canonical catalog schema for `product_type` and versioning
**Goal**: Extend catalog contracts so file bundles, external API packages, and internal API packages share one typed schema.

**Scope**
- Add `product_type` enum support: `file_bundle`, `api_package`, `internal_api_package`.
- Add common fields: `sku`, `display_name`, `billing_model`, `effective_at`, optional `sunset_at`, pricing metadata.
- Add product-specific config sections:
  - file bundle scope (`selection_type`, `date_start`, `date_end`, rental config),
  - API access/limit/credit definitions,
  - internal namespace definitions.
- Publish JSON examples and schema validation rules.

**Acceptance criteria**
- Catalog validation rejects invalid/missing required fields by product type.
- Existing catalog readers remain backward compatible when feature flags are off.
- Product and billing owners approve schema and examples.

**Dependencies**
- None.

---

### CCE-002: Define entitlement domain model and state machine contract
**Goal**: Standardize entitlement semantics across all monetized product families.

**Scope**
- Finalize entitlement states: `pending_payment`, `active`, `expired`, `revoked`, `consumed`.
- Define required fields (`entitlement_id`, `user_id`, `sku`, `product_type`, `scope`, `starts_at`, `ends_at`, usage counters, audit fields).
- Define state transition rules and forbidden transitions.
- Define clock/timezone rules (UTC) and expiration semantics.

**Acceptance criteria**
- Written transition matrix published and approved.
- Domain model represented in application models and API contracts.
- Unit tests cover allowed/denied transitions.

**Dependencies**
- CCE-001.

---

### CCE-003: Publish policy contract for access checks and usage consumption
**Goal**: Prevent service-by-service authorization drift with one policy contract.

**Scope**
- Define `check_access(subject, action, resource)` contract and response shape.
- Define `consume_usage(subject, meter, amount, idempotency_key)` contract.
- Define error taxonomy for denied/expired/exhausted entitlements.
- Define idempotency and replay behavior expectations.

**Acceptance criteria**
- Contract examples exist for file download, external API call, and internal API call.
- API, Messaging, and File Manager owners sign off.

**Dependencies**
- CCE-002.

---

## Epic B — Persistence and service foundations

### CCE-010: Add database/storage migrations for orders, payments, entitlements, usage events
**Goal**: Provision durable storage primitives needed for checkout, entitlement, and usage tracking.

**Scope**
- Create/extend entities:
  - `catalog_products`, `catalog_product_versions`
  - `orders`, `order_items`, `payments`
  - `entitlements`, `entitlement_usage_events`
- Add indexes for entitlement lookups and usage queries.
- Add idempotency uniqueness constraints for payment webhooks and usage consumption.

**Acceptance criteria**
- Migrations are forward/backward safe per repository migration policy.
- Query plans for critical paths meet latency targets in staging.
- Schema docs updated.

**Dependencies**
- CCE-001, CCE-002.

---

### CCE-011: Build Entitlements Service read/write core
**Goal**: Centralize entitlement grant/revoke/check/consume operations.

**Scope**
- Implement service methods:
  - `grant_entitlement(order_id)`
  - `revoke_entitlement(entitlement_id, reason)`
  - `check_access(subject, action, resource)`
  - `consume_usage(subject, meter, amount, idempotency_key)`
- Enforce state machine and idempotency constraints.
- Add structured audit logging for entitlement mutations.

**Acceptance criteria**
- Service supports all three product types in integration tests.
- Concurrent consume requests remain consistent (no double-consumption).
- Denial reasons map to standardized error contract.

**Dependencies**
- CCE-003, CCE-010.

---

### CCE-012: Integrate payment webhook reconciliation to entitlement activation/revocation
**Goal**: Activate or revoke entitlements from payment lifecycle events deterministically.

**Scope**
- Normalize provider webhook events into internal payment state transitions.
- Trigger entitlement grants only on terminal successful payment events.
- Revoke or mark pending entitlements on failed/refunded/chargeback states (policy-defined).
- Add dead-letter/replay handling for failed webhook processing.

**Acceptance criteria**
- Duplicate webhook deliveries are idempotent.
- Replay from dead-letter queue produces deterministic final state.
- Audit trail links payment events to entitlement changes.

**Dependencies**
- CCE-010, CCE-011.

---

## Epic C — File bundle purchase/rental MVP

### CCE-020: Implement file bundle SKU creation and checkout support
**Goal**: Enable purchasing and renting date-range file bundle products.

**Scope**
- Add catalog authoring support for `file_bundle` products with date window scope.
- Extend checkout endpoint/session creation to accept file bundle SKU(s).
- Validate requested bundle parameters against catalog constraints.

**Acceptance criteria**
- Checkout session creation succeeds for valid purchase/rental bundle SKUs.
- Invalid date ranges or rental configs are rejected with clear errors.

**Dependencies**
- CCE-001, CCE-012.

---

### CCE-021: Enforce file bundle entitlements on file preview/download routes
**Goal**: Gate file access based on active entitlement and in-scope file date ranges.

**Scope**
- Integrate entitlement checks into file preview/download handlers.
- Validate both entitlement validity window and file-scope match.
- Return consistent authorization payload for expired/out-of-scope access attempts.

**Acceptance criteria**
- Purchased bundles provide access without expiration.
- Rental bundles expire at configured `ends_at` and deny further access.
- Out-of-scope files are denied even with active entitlement.

**Dependencies**
- CCE-011, CCE-020.

---

### CCE-022: Add user entitlement visibility for file bundles
**Goal**: Make purchased/rented file bundle access transparent to users.

**Scope**
- Add `GET /v1/entitlements` support for file-bundle-specific scope metadata.
- Surface active/upcoming/expired status and expiration timestamps.
- Add tests for account-level entitlement listing and filtering.

**Acceptance criteria**
- Users can discover all file bundle entitlements and status via API.
- Response includes enough metadata to explain access denial reasons.

**Dependencies**
- CCE-021.

---

## Epic D — External API packages (credits/limits/access)

### CCE-030: Implement external API package SKU types and entitlement templates
**Goal**: Model credit packs, limit upgrades, and access-tier products in catalog.

**Scope**
- Define catalog template fields for:
  - credit bucket grants,
  - per-period limit overrides,
  - route allowlists/feature unlocks.
- Add server-side validation and compatibility checks.

**Acceptance criteria**
- API package SKUs are creatable and versioned with schema validation.
- Incompatible template combinations are rejected (e.g., conflicting limit definitions).

**Dependencies**
- CCE-001, CCE-011.

---

### CCE-031: Enforce external API entitlement checks in gateway/middleware
**Goal**: Block unauthorized API usage and apply purchased limits/credits at request time.

**Scope**
- Resolve active API package entitlements per caller/key.
- Enforce route access, quota overrides, and credit sufficiency.
- Consume credits/usage atomically with idempotency protections.

**Acceptance criteria**
- Unauthorized routes are denied with deterministic error contract.
- Credit exhaustion and cap exceedance are enforced without significant race leakage.
- Observability includes denial reason and entitlement context.

**Dependencies**
- CCE-003, CCE-030.

---

### CCE-032: Add API package usage burn-down and low-balance alerting
**Goal**: Give users and ops visibility into credit/cap consumption.

**Scope**
- Add usage endpoint(s) tied to entitlement usage events.
- Add configurable low-balance/near-cap thresholds.
- Emit alerts/notifications for threshold crossings.

**Acceptance criteria**
- Usage balances reconcile with entitlement consumption ledger.
- Alerting triggers once per threshold crossing policy.

**Dependencies**
- CCE-031.

---

## Epic E — Internal API package rollout (Messaging + File Manager)

### CCE-040: Define internal namespace metering contract for `messaging.*` and `filemanager.*`
**Goal**: Treat internal service APIs as first-class billable surfaces.

**Scope**
- Publish namespace/action taxonomy for billable internal operations.
- Map service operations to entitlement meters.
- Define identity propagation requirements for service calls.

**Acceptance criteria**
- Messaging and File Manager operations map deterministically to meters.
- Contract approved by both service owners.

**Dependencies**
- CCE-003.

---

### CCE-041: Integrate entitlement enforcement in Messaging routes
**Goal**: Apply internal API package entitlements to messaging operations.

**Scope**
- Add middleware/hooks for entitlement checks on targeted messaging endpoints.
- Consume internal usage meters for covered actions.
- Add end-to-end tests for allowed/denied/exhausted scenarios.

**Acceptance criteria**
- Messaging operations enforce entitlement checks for enabled namespaces.
- Usage consumption events are emitted and queryable.

**Dependencies**
- CCE-040, CCE-011.

---

### CCE-042: Integrate entitlement enforcement in File Manager internal APIs
**Goal**: Apply internal API package entitlements to file-manager service operations.

**Scope**
- Add middleware/hooks for entitlement checks on selected file-manager internal routes.
- Consume usage meters for storage/file operation actions in scope.
- Add end-to-end tests for allow/deny/limit scenarios.

**Acceptance criteria**
- File-manager internal operations enforce entitlement policy consistently.
- Metered usage is attached to relevant entitlement IDs.

**Dependencies**
- CCE-040, CCE-011.

---

## Epic F — Reliability, reconciliation, and operations

### CCE-050: Build entitlement and billing reconciliation jobs
**Goal**: Ensure invoicing and entitlement usage remain auditably correct.

**Scope**
- Add jobs to reconcile request/service logs with entitlement usage events.
- Add drift reports for consumed usage versus billed units.
- Add repair tooling for replay/recompute from source events.

**Acceptance criteria**
- Reconciliation job produces actionable diffs with ownership metadata.
- Replay/repair workflow is documented and tested in staging.

**Dependencies**
- CCE-031, CCE-041, CCE-042.

---

### CCE-051: Add admin operations for manual adjustments and support workflows
**Goal**: Provide safe operator tools for corrections and customer support.

**Scope**
- Add admin APIs/UI actions for entitlement revoke/extend/credit adjustment.
- Require reason codes and audit comments.
- Add RBAC checks for privileged operations.

**Acceptance criteria**
- All manual adjustments are fully auditable.
- Unauthorized operator attempts are denied and logged.

**Dependencies**
- CCE-011, CCE-050.

---

### CCE-052: Production readiness, feature-flag rollout, and cutover runbook
**Goal**: Ship with low risk and clear rollback paths.

**Scope**
- Define flag rollout sequencing for file bundles, external API packages, and internal API packages.
- Add SLOs/alerts for entitlement check latency and error rates.
- Document cutover, rollback, and incident-response procedures.

**Acceptance criteria**
- Runbook validated in staging game-day.
- Flags can be disabled per product family without data loss.
- Go/no-go checklist approved by engineering, product, and support.

**Dependencies**
- CCE-022, CCE-032, CCE-051.

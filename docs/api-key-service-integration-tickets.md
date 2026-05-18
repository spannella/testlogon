# API Key Service Integration — Implementation Ticket Backlog

This backlog translates `docs/api-key-service-integration-plan.md` into actionable, dependency-ordered tickets for enabling API-key-backed access across File Manager, Newsfeed, Ticket Management, Shopping, and Messager.

---

## Epic A — Capability contract and policy foundation

### AKI-001: Finalize API key capability namespace and ownership model
**Status**: ✅ Implemented (2026-03-25) via `docs/api-key-capability-policy.md`, `docs/api-key-capability-contract-v1.json`, and `app/services/api_key_capabilities.py`.

**Goal**: Freeze a canonical capability naming standard and assignment model used across product APIs.

**Scope**
- Confirm capability set:
  - `filemanager:read|write|share|admin`
  - `newsfeed:read|write|moderate`
  - `tickets:read|write|admin`
  - `shopping:catalog:read|cart:write|checkout:write|orders:read`
  - `messager:read|write|manage`
- Define inheritance/aggregation semantics for broader scopes (if any).
- Define deny-by-default behavior for unspecified routes.

**Acceptance criteria**
- Capability namespace approved by backend/security/product owners.
- Policy reference doc updated and linked in implementation tickets.
- No route in initial rollout relies on ambiguous scope semantics.

**Dependencies**
- None.

---

### AKI-002: Extend API key data model to persist scope grants
**Status**: ✅ Implemented (2026-03-25) via API key create/update/read scope persistence, `POST /ui/api_keys/scopes`, and legacy backfill support (`scripts/backfill_api_key_capabilities.py`).

**Goal**: Persist API key scope grants in key metadata with backward compatibility.

**Scope**
- Add API key metadata fields for allowed capabilities.
- Ensure legacy keys without scopes follow explicit migration/default policy.
- Add validation constraints for unknown/invalid scopes.

**Acceptance criteria**
- Key create/update/read operations support scope metadata.
- Existing keys remain functional according to migration policy.
- Tests cover valid/invalid scope persistence and retrieval.

**Dependencies**
- AKI-001.

---

### AKI-003: Build shared `requires_scope(...)` evaluator with entitlement gate hooks
**Status**: ✅ Implemented (2026-03-25) via `app/services/api_key_authorization.py` including route+method scope resolution and entitlement-deny differentiation.

**Goal**: Centralize authorization logic for API key requests.

**Scope**
- Implement reusable scope evaluation helper(s).
- Integrate entitlement checks per product area.
- Return deterministic authorization failure reasons for observability.

**Acceptance criteria**
- Evaluator supports route + method + requested capability checks.
- Missing scope and missing entitlement are distinguishable outcomes.
- Unit tests cover allow/deny matrix across products.

**Dependencies**
- AKI-001, AKI-002.

---

## Epic B — Request pipeline integration

### AKI-010: Implement shared API key auth dependency for service routers
**Status**: ✅ Implemented (2026-03-25) via `app/services/api_key_auth_dependency.py`.

**Goal**: Provide one composable request dependency for API-key-authenticated API access.

**Scope**
- Parse key from `Authorization: ApiKey ...` and `x-api-key`.
- Validate key format, status, revocation, expiry.
- Resolve principal (`user_sub`, `api_key_id`) and attach normalized context to request state.

**Acceptance criteria**
- Shared dependency is reusable by all target product routers.
- 401 contract is consistent for invalid/revoked/expired keys.
- Tests cover extraction precedence and principal normalization.

**Dependencies**
- AKI-002.

---

### AKI-011: Enforce API key IP allow/deny and origin policy in shared dependency
**Status**: ✅ Implemented (2026-03-25) via normalized 403 origin-deny contract in `app/services/api_key_auth_dependency.py`.

**Goal**: Apply key-level network restrictions before product handler execution.

**Scope**
- Validate request source IP against key allow/deny CIDR rules.
- Normalize error handling for denied origins.
- Add coverage for IPv4/IPv6 edge cases where supported.

**Acceptance criteria**
- Disallowed IPs are rejected with deterministic 403 payload.
- Allowed paths pass through unchanged.
- Security tests validate bypass-resistant policy behavior.

**Dependencies**
- AKI-010.

---

### AKI-012: Integrate usage metering dimensions for product API key traffic
**Status**: ✅ Implemented (2026-03-26) via `app/services/api_usage_metering.py` product dimensions + secret-safe event tests.

**Goal**: Ensure API-key product requests emit the required usage dimensions.

**Scope**
- Emit `product`, `route_id`, `api_key_id`, `status_code`, and billable dimensions.
- Guarantee raw secret material is never logged/stored.
- Confirm compatibility with existing usage aggregation jobs.

**Acceptance criteria**
- Events emitted for eligible API-key product requests.
- Metrics/dashboards can segment by product and key.
- Tests verify no raw key secret appears in telemetry payloads.

**Dependencies**
- AKI-010.

---

## Epic C — Route-to-scope registry and enforcement

### AKI-020: Create route-to-scope registry for initial product API endpoints
**Status**: ✅ Implemented (2026-03-26) via `app/services/api_key_route_scope_registry.py` and registry completeness tests.

**Goal**: Define a single source of truth mapping endpoint operations to required scopes.

**Scope**
- Enumerate initial endpoints for all five product surfaces.
- Register required scope(s) and entitlement requirement per route.
- Include explicit exemptions (if any) with rationale.

**Acceptance criteria**
- Registry covers all initial rollout endpoints.
- Unknown routes default to deny (or explicit legacy path behavior, documented).
- CI test asserts registry completeness for tagged endpoints.

**Dependencies**
- AKI-003, AKI-010.

---

### AKI-021: Add enforcement wiring from registry into router handlers
**Status**: ✅ Implemented (2026-03-26) via shared router dependency `maybe_enforce_api_key_route_policy` applied across product routers.

**Goal**: Enforce scope policy consistently without duplicating logic per endpoint.

**Scope**
- Attach scope checks via dependency/decorator/policy wrapper.
- Standardize 403 response body for missing scope/entitlement.
- Add audit metadata for deny outcomes.

**Acceptance criteria**
- Protected routes cannot be invoked without mapped scope.
- 403 payload includes machine-readable denial reason.
- Contract tests cover allow/deny permutations for representative endpoints.

**Dependencies**
- AKI-020.

---

## Epic D — Product integrations

### AKI-030: Integrate API key auth for File Manager endpoints
**Status**: ✅ Implemented (2026-03-26) via filemanager router policy wiring, API-key principal actor resolution, and filemanager route registry mappings.

**Goal**: Enable API-key access to file operations with object-level authorization intact.

**Scope**
- Cover list/read/upload/download/folder/share operations in initial surface.
- Validate ownership/project constraints on every request.
- Meter high-cost routes for volume/bytes where applicable.

**Acceptance criteria**
- File Manager API-key flows pass integration tests.
- Cross-user object access attempts are denied.
- Metering shows File Manager route usage by key.

**Dependencies**
- AKI-021, AKI-012.

---

### AKI-031: Integrate API key auth for Newsfeed endpoints
**Goal**: Enable API-key read/write operations for Newsfeed with moderation controls.

**Scope**
- Cover feed read and post write/edit/delete routes in rollout set.
- Require elevated scope for moderation-sensitive operations.
- Add anti-abuse throttles and payload validation checks.

**Acceptance criteria**
- Newsfeed API-key routes enforce correct scopes.
- Moderation actions denied without elevated scope.
- Integration tests verify expected read/write behavior.

**Dependencies**
- AKI-021, AKI-012.

---

### AKI-032: Integrate API key auth for Ticket Management endpoints
**Goal**: Enable API-key ticket workflows with admin gating and actor auditability.

**Scope**
- Cover ticket CRUD, comments, assignments, and status transitions.
- Require `tickets:admin` for administrative/privileged operations.
- Ensure audit events include API key actor metadata.

**Acceptance criteria**
- Ticket routes enforce `read/write/admin` scopes correctly.
- Audit logs show actor linkage (`api_key_id`, key owner context).
- Integration tests cover end-to-end ticket lifecycle with API key auth.

**Dependencies**
- AKI-021, AKI-012.

---

### AKI-033: Integrate API key auth for Messager endpoints
**Goal**: Enable API-key messaging workflows while preserving participant/visibility constraints.

**Scope**
- Cover conversation list/read/send and moderation-adjacent message controls in initial set.
- Enforce participant membership and hidden/visibility rules.
- Meter media-heavy endpoints separately.

**Acceptance criteria**
- Non-participants cannot access conversation content via API key.
- Message write operations enforce scope and visibility policy.
- Integration tests validate hidden/archived visibility behavior.

**Dependencies**
- AKI-021, AKI-012.

---

### AKI-034: Integrate API key auth for Shopping endpoints with idempotent checkout
**Goal**: Enable product/catalog/cart/checkout/order flows through API keys safely.

**Scope**
- Scope-gate catalog read, cart mutation, checkout, and order retrieval.
- Require idempotency key for checkout/order-creation operations.
- Validate entitlement/purchase policy gates before order finalization.

**Acceptance criteria**
- Checkout/order creation rejects missing idempotency key.
- Replay attempts do not create duplicate orders.
- Integration tests pass for cart-to-order lifecycle under API key auth.

**Dependencies**
- AKI-021, AKI-012.

---

## Epic E — API management surface and documentation

### AKI-040: Extend API key management endpoints/UI for scope assignment
**Goal**: Let users assign and manage product scopes on API keys.

**Scope**
- Add create/update API surfaces for scope grants.
- Validate user cannot assign disallowed/out-of-plan scopes.
- Update UX/API error messaging for scope validation failures.

**Acceptance criteria**
- Users can assign/revoke scopes on keys.
- Invalid scope submissions are rejected with clear contract.
- API docs include scope field behavior and examples.

**Dependencies**
- AKI-002, AKI-001.

---

### AKI-041: Publish OpenAPI scope annotations for all integrated endpoints
**Goal**: Make required API key scopes discoverable to integrators.

**Scope**
- Annotate endpoint docs with required scope(s) and entitlement notes.
- Group product tags for external API consumers.
- Generate examples for header usage and authorization failures.

**Acceptance criteria**
- OpenAPI output includes scope requirements per integrated route.
- Docs review sign-off from developer experience stakeholders.
- Contract snapshots updated.

**Dependencies**
- AKI-030, AKI-031, AKI-032, AKI-033, AKI-034.

---

## Epic F — Observability, controls, and rollout

### AKI-050: Build product/key usage dashboards and alerting rules
**Goal**: Monitor adoption, denial spikes, and anomalous key behavior.

**Scope**
- Add dashboards segmented by product, route, key, and status class.
- Alert on abnormal 401/403 trends and suspicious key activity patterns.
- Document on-call investigation runbook entries.

**Acceptance criteria**
- Dashboards available in staging/prod observability stack.
- Alerts trigger correctly in simulated error scenarios.
- Runbook includes triage + rollback guidance.

**Dependencies**
- AKI-012.

---

### AKI-051: Add per-key and per-account throttling policy for product APIs
**Goal**: Reduce abuse risk and protect service reliability under API-key traffic.

**Scope**
- Define default burst/sustained limits by product criticality.
- Enforce runtime throttles with deterministic 429 payload.
- Add configurable overrides for trusted/internal cohorts.

**Acceptance criteria**
- Throttles apply consistently across integrated product routes.
- 429 responses include machine-readable retry metadata.
- Load tests validate behavior under burst traffic.

**Dependencies**
- AKI-010, AKI-020.

---

### AKI-052: Execute phased rollout (shadow -> canary -> GA) with feature flags
**Goal**: Release safely while preserving fast rollback.

**Scope**
- Add per-product flags (`api_key_filemanager`, `api_key_newsfeed`, etc.).
- Run shadow evaluation before hard enforcement.
- Progressively expand cohort and monitor SLO/error regressions.

**Acceptance criteria**
- Shadow mode metrics demonstrate policy correctness before enforcement.
- Canary rollout checklist completed for each product.
- Flags provide immediate rollback path without session-auth regression.

**Dependencies**
- AKI-030, AKI-031, AKI-032, AKI-033, AKI-034, AKI-050.

---

## Suggested delivery sequence
1. **Foundation**: AKI-001 → AKI-002 → AKI-003 → AKI-010/011/012.
2. **Policy wiring**: AKI-020 → AKI-021.
3. **Product rollout**: AKI-030 and AKI-031 first, then AKI-032 and AKI-033, then AKI-034.
4. **DX/docs**: AKI-040 → AKI-041.
5. **Operations/GA**: AKI-050 → AKI-051 → AKI-052.

## Definition of done (program level)
- Initial endpoint set across all five products supports API key auth with scope + entitlement enforcement.
- Security regression suite passes for cross-user access, revoked/expired keys, IP policy, and checkout idempotency.
- OpenAPI/docs are updated with endpoint-level scope requirements.
- Dashboards and alerts are live; rollout completed to GA cohort.

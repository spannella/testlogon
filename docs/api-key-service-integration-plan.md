# API Key–Backed Service API Integration Plan

## Goal
Enable users to call core product APIs using existing API keys, with consistent authorization, entitlement enforcement, usage metering, and auditability across:
- File Manager
- Newsfeed
- Ticket Management
- Shopping System
- Messager

## Current baseline (already present)
- API key lifecycle and validation exists (create/revoke/expiry/IP rules).
- API usage metering infrastructure exists.
- Service routers already exist for each product area.

This plan focuses on layering **API key authn/authz contracts** on top of existing service routes without regressing session/JWT flows.

## Non-goals
- Replacing interactive user session auth.
- Rewriting domain services.
- Introducing cross-tenant access models.

## Architecture approach
1. Keep existing user-session auth paths unchanged.
2. Add a shared API-key request dependency/middleware that:
   - validates key and origin policy,
   - resolves principal (`user_sub`, `api_key_id`),
   - applies scope + entitlement checks,
   - emits standardized usage events.
3. Add per-route API-key capability declarations and policy checks.
4. Expose product-scoped API endpoints/documentation for external callers.

## Workstream 1: Capability model and policy contract
Define a canonical capability namespace used by all service APIs.

### Proposed capability scopes
- `filemanager:read`, `filemanager:write`, `filemanager:share`, `filemanager:admin`
- `newsfeed:read`, `newsfeed:write`, `newsfeed:moderate`
- `tickets:read`, `tickets:write`, `tickets:admin`
- `shopping:catalog:read`, `shopping:cart:write`, `shopping:checkout:write`, `shopping:orders:read`
- `messager:read`, `messager:write`, `messager:manage`

### Deliverables
- API key metadata extension for scope grants.
- Shared policy evaluator: `requires_scope(...)` + entitlement gates.
- Mapping table from HTTP route -> required scopes.

## Workstream 2: Shared request auth dependency
Implement a composable dependency (or middleware + dependency pair) for service routers.

### Behavior contract
1. Extract API key (`Authorization: ApiKey ...` and `x-api-key`).
2. Validate key status, expiry, IP allow/deny.
3. Resolve owning user context and API key id.
4. Validate requested capability scopes.
5. Validate feature entitlements for target product.
6. Attach normalized principal to request state.
7. Emit usage meter event with route + product + api key id (no secret).

### Failure modes
- 401 invalid/expired/revoked key
- 403 IP denied, missing scope, or missing entitlement
- 429 key/account rate limit exceeded

## Workstream 3: Service-by-service rollout
Roll out behind feature flags with canary cohorts.

### File Manager
- Cover file listing, upload/download, folder ops, share links.
- Enforce object-level ownership/project access checks.
- Meter high-cost routes (upload/download/preview).

### Newsfeed
- Cover post CRUD, feed read, reactions/comments (if exposed).
- Enforce moderation-sensitive operations via elevated scopes.
- Add payload validation and anti-abuse throttles.

### Ticket Management
- Cover ticket CRUD, assignment, comments, status transitions.
- Gate admin operations (`tickets:admin`) distinctly.
- Ensure audit log captures API-key actor metadata.

### Shopping System
- Catalog read via read scope; cart/checkout/order operations via write scopes.
- Enforce entitlement/purchase policy checks before checkout.
- Add idempotency-key requirement for checkout/order creation.

### Messager
- Cover conversation list/read/send/edit/delete/hide flows as applicable.
- Enforce participant and visibility constraints on every operation.
- Meter media/attachment heavy endpoints separately.

## Workstream 4: API surface and docs
- Publish external endpoint contracts (OpenAPI tags grouped by product).
- Document required scopes + entitlement prerequisites per endpoint.
- Provide API key onboarding guide with examples in curl/SDK snippets.
- Add migration notes for existing session-auth clients.

## Workstream 5: Observability, abuse controls, and billing hooks
- Dashboard slices by `product`, `route`, `api_key_id`, `status_code`.
- Alerts for 401/403 spikes and anomalous key usage patterns.
- Per-key and per-account throttles with configurable burst windows.
- Ensure billable event taxonomy maps cleanly to product capabilities.

## Workstream 6: Security and compliance hardening
- Structured audit events for all write operations with actor = api key id + owner.
- Optional key rotation policy reminders and forced expiry settings.
- Key-scoped IP restrictions and optional environment restrictions.
- Validate message/file/ticket access paths against horizontal privilege escalation.

## Delivery phases

### Phase 0: Design and contract freeze (1 week)
- Finalize capability namespace.
- Freeze route-to-scope mapping for initial endpoints.
- Review security and abuse controls.

### Phase 1: Shared auth/policy foundation (1-2 weeks)
- Implement shared dependency and policy evaluator.
- Add API key scope metadata support.
- Integrate metering fields needed for product attribution.

### Phase 2: Product integrations (2-4 weeks)
- File Manager + Newsfeed first (lower transactional risk).
- Ticket Management + Messager second.
- Shopping checkout/order endpoints last with strict idempotency and reconciliation tests.

### Phase 3: Hardening and GA (1-2 weeks)
- Soak testing, abuse simulations, rollback drills.
- Documentation finalization and customer onboarding assets.
- Feature flag ramp to GA.

## Testing strategy
- Unit tests for scope evaluator and dependency behavior.
- Contract tests per endpoint for allowed/denied scope matrix.
- Integration tests for per-product critical workflows using API key auth.
- Security regression tests:
  - cross-user resource access attempts,
  - IP policy enforcement,
  - revoked/expired key behavior,
  - idempotency replay for checkout.
- Metering assertions to ensure billable dimensions are emitted.

## Rollout safeguards
- Feature flags per product (`api_key_filemanager`, `api_key_newsfeed`, etc.).
- Shadow mode to evaluate policy decisions before enforcement.
- Canary by user cohort and key cohort.
- Fast rollback: disable product flag, preserve existing session-auth paths.

## AKI-052 phased rollout execution checklist

| Product | Shadow complete | Canary complete | GA complete | Rollback validated |
| --- | --- | --- | --- | --- |
| filemanager | ☐ | ☐ | ☐ | ☐ |
| newsfeed | ☐ | ☐ | ☐ | ☐ |
| tickets | ☐ | ☐ | ☐ | ☐ |
| shopping | ☐ | ☐ | ☐ | ☐ |
| messager | ☐ | ☐ | ☐ | ☐ |

Operational notes:
- Set `API_KEY_<PRODUCT>_PHASE=shadow` first and review `api_key_policy_shadow_eval` outcomes.
- Promote to `canary` with `API_KEY_<PRODUCT>_CANARY_PERCENT` and/or `API_KEY_<PRODUCT>_CANARY_SUBJECTS`.
- Promote to `ga` only after SLO/error checks pass for at least one full business cycle.
- Roll back instantly with `API_KEY_<PRODUCT>=0` (session-auth paths remain unchanged).

## Success metrics
- % of targeted endpoints supporting API key auth.
- Auth failure rate (401/403) after initial adoption window.
- P95/P99 auth dependency latency overhead.
- Zero critical authz regressions in penetration/regression testing.
- Adoption: number of active API keys invoking each product surface.

## Suggested initial implementation tickets
1. Add API key scope schema + persistence updates.
2. Build shared API key auth dependency for service routers.
3. Add route-to-scope registry and enforcement hooks.
4. Integrate File Manager endpoints.
5. Integrate Newsfeed endpoints.
6. Integrate Ticket endpoints.
7. Integrate Messager endpoints.
8. Integrate Shopping endpoints (checkout idempotency required).
9. Extend OpenAPI docs with scope requirements.
10. Build dashboards/alerts for API key product usage.

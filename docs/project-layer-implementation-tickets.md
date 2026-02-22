# Project Layer Implementation Tickets

This ticket set turns `docs/project-layer-plan.md` into an execution-ready backlog.

## Epic 0 — Foundations

### PL-001: Add persistence models for Project and TrackedFile
**Type:** Backend  
**Priority:** P0  
**Estimate:** 3 points  
**Depends on:** None

**Scope**
- Add DB schema/models for `Project` and `TrackedFile`.
- Include extensibility fields (`settings`, `metadata`) and basic indexes.
- Add soft-delete/archive strategy for tracked files.

**Acceptance Criteria**
- Tables/models exist and can be migrated in a clean environment.
- `TrackedFile` has provider + provider_ref uniqueness per project.
- Unit tests cover model constraints and serialization.

---

### PL-002: Add project repository/service primitives
**Type:** Backend  
**Priority:** P0  
**Estimate:** 3 points  
**Depends on:** PL-001

**Scope**
- Add service methods: create/get/list/update/delete project.
- Validate required fields and normalize tags/settings.

**Acceptance Criteria**
- Service methods return deterministic error types.
- Pagination/filtering works for list endpoint internals.
- Tests cover happy path + validation failures.

---

### PL-003: Provider interface and LocalFileProvider implementation
**Type:** Backend  
**Priority:** P0  
**Estimate:** 5 points  
**Depends on:** PL-001

**Scope**
- Add provider abstraction: `resolve`, `exists`, `get_metadata`, optional `list_children`.
- Implement LocalFileProvider bridging to existing file manager identity/path semantics.
- Add provider registry/factory for future GitHub/GitLab support.

**Acceptance Criteria**
- Local provider can validate and canonicalize file refs.
- Service code can call provider via interface (not hardcoded local class).
- Unit tests cover canonicalization and missing-file behavior.

---

## Epic 1 — Project CRUD + Tracking API (MVP)

### PL-004: Add project CRUD API routes
**Type:** Backend API  
**Priority:** P0  
**Estimate:** 3 points  
**Depends on:** PL-002

**Scope**
- Add API endpoints for create/get/list/update/delete projects.
- Reuse existing auth context; enforce project-scoped authorization hooks.

**Acceptance Criteria**
- OpenAPI/docs updated.
- Endpoint tests for auth, validation, and not-found behavior.
- API returns stable schema for frontend integration.

---

### PL-005: Add tracked file API routes
**Type:** Backend API  
**Priority:** P0  
**Estimate:** 5 points  
**Depends on:** PL-003, PL-004

**Scope**
- Add API endpoints for add/remove/list tracked files under a project.
- Validate refs via provider before persisting.
- Store status and last-seen metadata on add.

**Acceptance Criteria**
- Cannot add duplicate provider_ref entries in same project.
- Removing tracked files is idempotent.
- Endpoint tests include missing-file and forbidden-project scenarios.

---

### PL-006: Integrate file manager service with project tracking lookups
**Type:** Backend integration  
**Priority:** P1  
**Estimate:** 3 points  
**Depends on:** PL-005

**Scope**
- Expose a read path for project detail hydration using existing file manager metadata.
- Ensure tracked-file references map correctly to file manager identifiers.

**Acceptance Criteria**
- Project detail response includes display-ready file rows.
- Integration tests verify metadata hydration and fallback on missing files.

---

## Epic 2 — Frontend MVP

### PL-007: Add Projects list page + creation flow
**Type:** Frontend  
**Priority:** P1  
**Estimate:** 5 points  
**Depends on:** PL-004

**Scope**
- Add projects list route/page with empty/loading/error states.
- Add create project dialog/form.

**Acceptance Criteria**
- Users can create a project and see it in the list without reload.
- Form validation mirrors backend contract.
- Frontend tests cover list render + create flow.

---

### PL-008: Add Project detail page with tracked files table
**Type:** Frontend  
**Priority:** P1  
**Estimate:** 5 points  
**Depends on:** PL-005, PL-007

**Scope**
- Build detail view with tracked file table (path, provider, status, last seen).
- Show missing-file warnings and empty states.

**Acceptance Criteria**
- Detail page fetches and renders tracked files.
- Missing files are visibly differentiated.
- Frontend tests cover table states and warnings.

---

### PL-009: Add tracked-file add/remove interactions
**Type:** Frontend  
**Priority:** P1  
**Estimate:** 3 points  
**Depends on:** PL-008

**Scope**
- Add add-file action from file manager context or typed ref input.
- Add remove tracked-file action with confirmation.

**Acceptance Criteria**
- Add/remove updates table state optimistically with rollback on error.
- Toast/error messaging is consistent with existing UX patterns.

---

## Epic 3 — Reliability, Observability, and Scale

### PL-010: Background reconciliation job for tracked files
**Type:** Backend jobs  
**Priority:** P1  
**Estimate:** 5 points  
**Depends on:** PL-005

**Scope**
- Add periodic reconciliation to refresh existence + metadata.
- Mark files missing/active and update timestamps.

**Acceptance Criteria**
- Job runs safely across multiple projects.
- Retry/backoff implemented for transient provider errors.
- Tests cover status transitions and error handling.

---

### PL-011: Add project activity events (optional model enabled)
**Type:** Backend  
**Priority:** P2  
**Estimate:** 3 points  
**Depends on:** PL-010

**Scope**
- Persist key events: file_added/file_removed/sync_ran/provider_error.
- Add read endpoint for recent project events.

**Acceptance Criteria**
- Events are emitted for all tracking mutations.
- Event list endpoint supports pagination.

---

### PL-012: Add project metrics + dashboards
**Type:** Observability  
**Priority:** P2  
**Estimate:** 3 points  
**Depends on:** PL-010

**Scope**
- Add counters and timers: project_count, tracked_file_count, reconcile_failures, provider_latency.
- Add alert thresholds for repeated provider failures.

**Acceptance Criteria**
- Metrics exposed in existing telemetry pipeline.
- Dashboard panels and alerts documented.

---

## Epic 4 — External Providers (GitHub/GitLab)

### PL-013: Add credential plumbing for external providers
**Type:** Backend/Auth  
**Priority:** P2  
**Estimate:** 5 points  
**Depends on:** PL-003

**Scope**
- Add secure storage and retrieval for provider tokens per user/org.
- Add permission scopes and token validation checks.

**Acceptance Criteria**
- Tokens encrypted at rest.
- Token scope/validity errors surface actionable API responses.

---

### PL-014: Implement GitHubProvider (read-only refs)
**Type:** Backend integration  
**Priority:** P2  
**Estimate:** 5 points  
**Depends on:** PL-013

**Scope**
- Implement provider interface for GitHub repo/path/ref references.
- Support existence + metadata retrieval.

**Acceptance Criteria**
- Can add/list GitHub-backed tracked files in a project.
- Rate-limit and API error handling tested.

---

### PL-015: Implement GitLabProvider (read-only refs)
**Type:** Backend integration  
**Priority:** P2  
**Estimate:** 5 points  
**Depends on:** PL-013

**Scope**
- Implement provider interface for GitLab repo/path/ref references.
- Match GitHub provider behavior/contracts.

**Acceptance Criteria**
- Can add/list GitLab-backed tracked files in a project.
- Contract tests pass across local/GitHub/GitLab providers.

---

## Cross-Cutting Tickets

### PL-016: Authorization hardening and policy tests
**Type:** Security  
**Priority:** P0  
**Estimate:** 3 points  
**Depends on:** PL-004, PL-005

**Scope**
- Enforce project-scoped auth for all endpoints and background reads.
- Add policy tests for ownership and forbidden access.

**Acceptance Criteria**
- Unauthorized access blocked on all project APIs.
- Security tests included in CI suite.

---

### PL-017: API contract documentation and frontend client generation updates
**Type:** DX/API  
**Priority:** P1  
**Estimate:** 2 points  
**Depends on:** PL-004, PL-005

**Scope**
- Update API contract docs and examples.
- Ensure frontend API client types stay aligned.

**Acceptance Criteria**
- Contract artifacts updated.
- Frontend builds without type regressions.

---

### PL-018: Release plan + feature flag rollout
**Type:** Release  
**Priority:** P1  
**Estimate:** 2 points  
**Depends on:** PL-007, PL-008, PL-009

**Scope**
- Gate project features behind flags.
- Define staged rollout cohorts and rollback playbook.

**Acceptance Criteria**
- Feature can be toggled on/off safely.
- Rollback steps documented and tested in staging.

---

## Suggested Milestones
- **Milestone A (MVP Backend):** PL-001 to PL-006 + PL-016
- **Milestone B (MVP UX):** PL-007 to PL-009 + PL-017 + PL-018
- **Milestone C (Reliability):** PL-010 to PL-012
- **Milestone D (External Sources):** PL-013 to PL-015

## Definition of Done (for each ticket)
- Code merged with tests.
- Docs/contract updated (if API/UI changed).
- Metrics/logging included for new runtime paths.
- Security/privacy review completed for new data flows.

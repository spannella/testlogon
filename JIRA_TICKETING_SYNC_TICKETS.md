# Jira ↔ Internal Ticketing Sync — Implementation Tickets

This ticket set converts `JIRA_TICKETING_SYNC_PLAN.md` into executable engineering work. Tickets are grouped by epic and include scope, deliverables, and acceptance criteria.

## Epic 1: Discovery, Contracts, and Foundations

### JIRA-SYNC-001 — Discovery + architecture decision record
**Type:** Feature  
**Priority:** P0  
**Dependencies:** None  
**Status:** Implemented (2026-03-24)

**Scope**
- Audit the current internal ticketing domain model, lifecycle states, and API constraints.
- Confirm Jira auth mode for phase 1 (user OAuth only vs hybrid service account).
- Publish architecture decision record (ADR) covering sync directionality, source-of-truth boundaries, and conflict ownership.

**Deliverables**
- Discovery notes and current-state model map.
- Signed ADR with explicit non-goals.
- Delivery sequencing confirmation for all epics.

**Acceptance Criteria**
- ADR approved by backend, frontend, and security owners.
- Phase 1 auth model finalized and documented.
- Unknowns and risks are tracked with named owners.

---

### JIRA-SYNC-002 — Schema migrations for integration persistence
**Type:** Feature  
**Priority:** P0  
**Dependencies:** JIRA-SYNC-001  
**Status:** Implemented (2026-03-24)

**Scope**
- Add persistence structures for:
  - `jira_connections`
  - `ticket_external_links`
  - `jira_issue_mirror`
  - `ticket_sync_events`
- Add indices for lookup by workspace/user, issue key/id, ticket id, and sync state.
- Add migration rollback plan and data retention policy for audit events.

**Deliverables**
- Forward/rollback migrations.
- Data access abstractions and model definitions.
- Migration runbook notes.

**Acceptance Criteria**
- Migrations apply cleanly in dev/stage.
- Query latency for primary list/detail access stays within agreed SLOs.
- Sync event table supports immutable append-only writes.

---

### JIRA-SYNC-003 — Feature flags and rollout guardrails
**Type:** Feature  
**Priority:** P0  
**Dependencies:** JIRA-SYNC-001  
**Status:** Implemented (2026-03-24)

**Scope**
- Add feature flags for Jira integration modules (read-only listing, outbound sync, inbound webhook apply).
- Add workspace allowlist and global kill switch for outbound writes.
- Add per-environment configuration validation at startup.

**Deliverables**
- Flags/config docs.
- Startup health checks for integration config.
- Admin-level toggle controls.

**Acceptance Criteria**
- Integration can be enabled for pilot workspaces only.
- Outbound writes can be disabled instantly without code deploy.
- Missing critical config causes explicit startup failure.

---

## Epic 2: Jira Connectivity and Authentication

### JIRA-SYNC-004 — Jira OAuth connect/disconnect and token lifecycle
**Type:** Feature  
**Priority:** P0  
**Dependencies:** JIRA-SYNC-002

**Scope**
- Implement connect start endpoint and callback handling.
- Persist token references in secrets manager and connection metadata in DB.
- Implement token refresh and revoked-token handling.

**Deliverables**
- `POST /integrations/jira/connect`
- `GET /integrations/jira/callback`
- `DELETE /integrations/jira/connection` (or equivalent disconnect endpoint)

**Acceptance Criteria**
- Users can connect/disconnect Jira successfully.
- Expired access token refreshes without user intervention when refresh token is valid.
- Token values never appear in application logs.

---

### JIRA-SYNC-005 — Jira API client with retries, pagination, and rate-limit control
**Type:** Feature  
**Priority:** P0  
**Dependencies:** JIRA-SYNC-004

**Scope**
- Build typed Jira client wrapper for issue, project, and comment operations.
- Add retry policy with exponential backoff for transient failures and 429 handling.
- Normalize Jira errors to internal integration error codes.

**Deliverables**
- Jira client library/service.
- Unified error mapping layer.
- Instrumented request metrics (latency, status classes, retry counts).

**Acceptance Criteria**
- Pagination works for large issue sets without duplication.
- 429 responses trigger bounded retries and backoff.
- Non-retryable Jira errors are surfaced with stable internal error codes.

---

### JIRA-SYNC-006 — Jira project discovery and connection settings API
**Type:** Feature  
**Priority:** P1  
**Dependencies:** JIRA-SYNC-004, JIRA-SYNC-005

**Scope**
- Expose connection metadata and available Jira projects.
- Persist per-user/per-workspace defaults for project and sync mode.
- Validate site URL allowlist and selected project permissions.

**Deliverables**
- `GET /integrations/jira/projects`
- `GET/PUT /integrations/jira/settings` (or equivalent)

**Acceptance Criteria**
- Connected users can load and save default Jira project preferences.
- Attempting to use unauthorized project/site returns 4xx with actionable messaging.
- Settings updates are audited.

---

## Epic 3: Read-Only Jira Visibility in Ticketing

### JIRA-SYNC-007 — Mirror ingestion job (initial pull + incremental poll)
**Type:** Feature  
**Priority:** P0  
**Dependencies:** JIRA-SYNC-005, JIRA-SYNC-002

**Scope**
- Build ingestion worker that pulls Jira issues into `jira_issue_mirror`.
- Support first-time backfill and incremental polling by updated timestamp.
- Track staleness, ingest cursors, and partial-failure resume behavior.

**Deliverables**
- Queue worker / scheduler job.
- Ingestion state store and resume logic.
- Mirror write path with idempotent upsert.

**Acceptance Criteria**
- First sync imports all scoped issues for configured projects.
- Incremental sync only fetches changed issues.
- Worker recovers from transient failure without reprocessing all history.

---

### JIRA-SYNC-008 — Unified ticket listing API with source filters
**Type:** Feature  
**Priority:** P0  
**Dependencies:** JIRA-SYNC-007

**Scope**
- Extend ticket list endpoint to support `source=internal|jira|unified`.
- Add filters for assignee/reporter/project for Jira-backed rows.
- Return source metadata and sync-health indicators.

**Deliverables**
- Updated `GET /tickets` contract.
- Serialization layer for unified list items.
- API contract tests for filter combinations.

**Acceptance Criteria**
- Jira-only and unified modes return deterministic pagination.
- Each row includes source badge and last-sync freshness data.
- Existing internal-only behavior remains backward compatible.

---

### JIRA-SYNC-009 — Frontend ticket list support for Jira and unified views
**Type:** Feature  
**Priority:** P1  
**Dependencies:** JIRA-SYNC-008

**Scope**
- Add source tabs/filters (Internal, Jira, Unified) in ticketing UI.
- Render origin badges and staleness/sync-health indicators.
- Add empty/loading/error states specific to Jira visibility.

**Deliverables**
- UI components + state management updates.
- UX copy for connection required / stale data scenarios.

**Acceptance Criteria**
- Users can switch sources without full-page reload.
- Jira rows render key fields consistently with internal rows.
- Error states explain recovery action (reconnect, retry, contact admin).

---

## Epic 4: Linking and Outbound Sync (Internal → Jira)

### JIRA-SYNC-010 — Link model APIs: create Jira issue / link existing / unlink
**Type:** Feature  
**Priority:** P0  
**Dependencies:** JIRA-SYNC-002, JIRA-SYNC-005

**Scope**
- Implement APIs to create Jira issues from internal tickets.
- Support linking an existing Jira issue key/id.
- Support unlink operation with audit trail and safety checks.

**Deliverables**
- `POST /tickets/{id}/external-links/jira`
- `POST /tickets/{id}/external-links/jira/link-existing`
- `DELETE /tickets/{id}/external-links/{linkId}`

**Acceptance Criteria**
- Link creation enforces single-active-link rules per ticket (or documented multi-link behavior).
- Linking validates external issue existence + permissions.
- Unlink preserves historical sync event audit records.

---

### JIRA-SYNC-011 — Field mapping engine + status mapping configuration
**Type:** Feature  
**Priority:** P0  
**Dependencies:** JIRA-SYNC-010

**Scope**
- Implement canonical mapping for summary/description/status/assignee/priority/labels/comments.
- Add configurable status mapping table by project/workspace.
- Build Jira ADF conversion adapter for description/comments.

**Deliverables**
- Mapping library and config schema.
- Validation endpoint/utility for mapping completeness.

**Acceptance Criteria**
- All mapped fields round-trip with deterministic transforms.
- Missing status mappings fail fast with actionable validation errors.
- ADF conversion handles supported formatting without data loss for baseline cases.

---

### JIRA-SYNC-012 — Outbound sync worker and idempotency controls
**Type:** Feature  
**Priority:** P0  
**Dependencies:** JIRA-SYNC-011

**Scope**
- Emit outbound sync events from internal ticket mutations.
- Process queue jobs to push changes to Jira.
- Add idempotency keys, origin markers, and replay-safe behavior.

**Deliverables**
- Domain event publishers for ticket changes.
- Outbound worker + retry policy.
- Sync event logging for each attempt/result.

**Acceptance Criteria**
- Ticket updates produce outbound jobs only for linked tickets.
- Duplicate deliveries do not create duplicate Jira writes.
- Failures are captured with retryable vs terminal classification.

---

## Epic 5: Inbound Sync (Jira → Internal), Conflict Handling, and Webhooks

### JIRA-SYNC-013 — Jira webhook receiver and signature verification
**Type:** Feature  
**Priority:** P0  
**Dependencies:** JIRA-SYNC-005, JIRA-SYNC-003

**Scope**
- Implement webhook endpoint and event normalization.
- Verify webhook authenticity (shared secret/signature) and replay protection.
- Route supported event types to inbound apply queue.

**Deliverables**
- `POST /integrations/jira/webhook`
- Signature verification and replay cache.
- Event schema fixtures for contract tests.

**Acceptance Criteria**
- Invalid signature events are rejected and audited.
- Duplicate webhook deliveries are deduplicated safely.
- Supported event types are accepted and queued within latency SLO.

---

### JIRA-SYNC-014 — Inbound apply engine with loop prevention
**Type:** Feature  
**Priority:** P0  
**Dependencies:** JIRA-SYNC-013, JIRA-SYNC-011

**Scope**
- Apply inbound Jira deltas to linked internal tickets.
- Prevent echo loops by tracking origin metadata and remote update identifiers.
- Update mirror and internal state atomically where required.

**Deliverables**
- Inbound apply worker.
- Loop-prevention markers and duplicate suppression logic.
- Sync state transitions (`in_sync`, `degraded`, `conflict`, etc.).

**Acceptance Criteria**
- Jira updates propagate to linked internal tickets for mapped fields.
- Echoed updates from outbound writes are ignored correctly.
- Partial apply failures are recoverable via retry without data corruption.

---

### JIRA-SYNC-015 — Conflict detection + resolution API
**Type:** Feature  
**Priority:** P1  
**Dependencies:** JIRA-SYNC-014

**Scope**
- Detect same-field concurrent edits based on local/remote update windows.
- Persist conflict payloads with both candidate values.
- Expose resolve actions (`keep_jira`, `keep_internal`) and re-sync.

**Deliverables**
- `GET /tickets/{id}/sync-status`
- `POST /tickets/{id}/sync-conflicts/{conflictId}/resolve`
- Conflict event audit logging.

**Acceptance Criteria**
- Conflicts are flagged with enough context for user decision.
- Resolution action clears conflict state and reestablishes sync.
- Conflict lifecycle is fully auditable.

---

## Epic 6: UI Integration, Observability, and Operations

### JIRA-SYNC-016 — Integrations settings UI for Jira connection/preferences
**Type:** Feature  
**Priority:** P1  
**Dependencies:** JIRA-SYNC-004, JIRA-SYNC-006

**Scope**
- Build settings page/section to connect Jira and configure defaults.
- Show connection status, scopes, selected projects, and last sync metadata.
- Support reconnect/disconnect and permission error guidance.

**Deliverables**
- Integration settings UI components.
- Client-side state + API wiring for settings.

**Acceptance Criteria**
- User can connect, configure defaults, and disconnect from UI.
- Settings reflect backend connection state accurately.
- UX communicates remediation steps for auth failures.

---

### JIRA-SYNC-017 — Ticket details UI for link state and sync activity
**Type:** Feature  
**Priority:** P1  
**Dependencies:** JIRA-SYNC-010, JIRA-SYNC-012, JIRA-SYNC-015

**Scope**
- Show linked Jira issue key/status and link actions in ticket detail view.
- Add sync timeline entries (pushed, pulled, failed, conflict).
- Add conflict banner/modal and resolution controls.

**Deliverables**
- Ticket detail UI enhancements.
- Timeline rendering tied to sync event feed.
- Conflict resolution modal UX.

**Acceptance Criteria**
- Linked ticket detail clearly indicates current Jira relationship.
- Users can resolve conflicts from UI without manual API calls.
- Sync timeline includes direction, timestamp, and result.

---

### JIRA-SYNC-018 — Observability, DLQ/replay tooling, and runbooks
**Type:** Feature  
**Priority:** P0  
**Dependencies:** JIRA-SYNC-012, JIRA-SYNC-014

**Scope**
- Add metrics dashboards (throughput, latency, failure rate, conflict rate).
- Add dead-letter queue handling and replay tooling.
- Publish operational runbooks and alert thresholds.

**Deliverables**
- Dashboards + alerts.
- DLQ inspection/replay utility.
- On-call runbook + incident playbook.

**Acceptance Criteria**
- Alerting triggers on sustained failure/error budgets.
- Operators can replay failed sync jobs safely.
- Runbook includes mitigation steps for token failures, Jira outages, and drift.

---

## Epic 7: Quality, Security, and Rollout

### JIRA-SYNC-019 — Test suite for mapper/client/webhook/sync flows
**Type:** Feature  
**Priority:** P0  
**Dependencies:** JIRA-SYNC-011, JIRA-SYNC-012, JIRA-SYNC-014

**Scope**
- Add unit tests for mapping, ADF transforms, loop prevention, and conflict detection.
- Add integration tests for OAuth callback, refresh, and webhook verification.
- Add contract fixtures for Jira issue/webhook payloads.

**Deliverables**
- Expanded automated test coverage.
- CI updates for integration test execution.

**Acceptance Criteria**
- Bi-directional create/update/comment sync paths are test-covered.
- Signature verification and replay checks are test-covered.
- Regression suite passes in CI.

---

### JIRA-SYNC-020 — Staged rollout, pilot validation, and GA checklist
**Type:** Feature  
**Priority:** P1  
**Dependencies:** JIRA-SYNC-018, JIRA-SYNC-019, JIRA-SYNC-017

**Scope**
- Execute staged rollout (internal dogfood → pilot workspaces → broader rollout).
- Track success metrics against plan targets.
- Finalize GA checklist and support handoff.

**Deliverables**
- Rollout report with KPI trends.
- GA readiness checklist sign-off.
- Support/CS escalation documentation.

**Acceptance Criteria**
- Pilot meets sync latency/failure targets for agreed period.
- No unresolved P0/P1 defects blocking GA.
- GA decision and rollback criteria documented.

---

## Dependency Summary (Critical Path)
1. JIRA-SYNC-001 → JIRA-SYNC-002/003
2. JIRA-SYNC-004 → JIRA-SYNC-005 → JIRA-SYNC-007/006
3. JIRA-SYNC-007 → JIRA-SYNC-008 → JIRA-SYNC-009
4. JIRA-SYNC-010 → JIRA-SYNC-011 → JIRA-SYNC-012
5. JIRA-SYNC-013 → JIRA-SYNC-014 → JIRA-SYNC-015
6. JIRA-SYNC-012 + JIRA-SYNC-014 → JIRA-SYNC-018 → JIRA-SYNC-020
7. JIRA-SYNC-011/012/014 → JIRA-SYNC-019 → JIRA-SYNC-020

## Suggested Milestone Packaging
- **Milestone A (Read-only Jira visibility):** JIRA-SYNC-001..009
- **Milestone B (Link + outbound sync):** JIRA-SYNC-010..012
- **Milestone C (Inbound + conflict handling):** JIRA-SYNC-013..015, 017
- **Milestone D (Hardening + rollout):** JIRA-SYNC-016, 018..020

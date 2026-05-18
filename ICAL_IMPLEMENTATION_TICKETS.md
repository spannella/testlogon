# Apple Calendar (iCal) Bi-Directional Sync — Implementation Tickets

This ticket set converts `ICAL_INTEGRATION_PLAN.md` into executable engineering work. Tickets are grouped by epic and include scope, deliverables, and acceptance criteria.

## Epic 1: Foundations, Provider Adapter, and Configuration

### TKT-ICAL-001 — CalDAV integration module scaffolding
**Type:** Feature  
**Priority:** P0  
**Dependencies:** None

**Scope**
- Create `apple_caldav` integration module with clear boundaries:
  - connection/auth service
  - calendar discovery client
  - event client (CRUD/sync)
  - mapping utilities
- Add provider configuration (endpoint templates, timeouts, retry defaults).
- Add typed error model for auth/network/protocol failures.

**Deliverables**
- Provider module skeleton and interfaces wired into calendar integration registry.
- Config flags for enabling/disabling Apple integration.

**Acceptance Criteria**
- Application boots with Apple provider enabled and disabled.
- Integration registry resolves Apple adapter without conditional hacks.
- Provider errors are returned as structured codes/messages.

---

### TKT-ICAL-002 — Encrypted credential storage and secret lifecycle
**Type:** Feature  
**Priority:** P0  
**Dependencies:** TKT-ICAL-001

**Scope**
- Persist Apple credentials via secret manager reference (no plaintext in app DB).
- Implement create/read/update/delete credential reference lifecycle.
- Add credential validation state fields and rotation metadata.

**Deliverables**
- DB migration(s) for `calendar_connections` core fields.
- Secret manager adapter methods and redaction-safe logging guards.

**Acceptance Criteria**
- No plaintext Apple password appears in logs, traces, or DB columns.
- Rotating credentials updates reference and invalidates stale sync jobs.
- Credential deletion on disconnect removes secret reference safely.

---

### TKT-ICAL-003 — Connection API and basic status endpoint
**Type:** Feature  
**Priority:** P0  
**Dependencies:** TKT-ICAL-001, TKT-ICAL-002

**Scope**
- Implement endpoints:
  - `POST /calendar/integrations/apple/connect`
  - `GET /calendar/integrations/apple/status`
  - `POST /calendar/integrations/apple/disconnect`
- Add provider health/status model (`connected`, `degraded`, `disconnected`).

**Deliverables**
- API handlers with authz checks and structured validation errors.
- Connection lifecycle service methods.

**Acceptance Criteria**
- Authenticated user can connect/disconnect Apple integration.
- Status endpoint reflects latest success/error and connection state.
- Invalid credentials return user-safe remediation guidance.

---

## Epic 2: Calendar Discovery and Sync State Persistence

### TKT-ICAL-004 — CalDAV calendar discovery and selection
**Type:** Feature  
**Priority:** P0  
**Dependencies:** TKT-ICAL-003

**Scope**
- Implement CalDAV discovery flow for user calendars.
- Implement endpoints:
  - `GET /calendar/integrations/apple/calendars`
  - `POST /calendar/integrations/apple/calendars/select`
- Persist selected calendars and sync settings.

**Deliverables**
- Discovery client/report parser and normalized calendar DTO.
- Persistence for `external_calendars` records.

**Acceptance Criteria**
- User can list remote calendars and select subset for sync.
- Selected calendars persist with `sync_enabled`, direction, and timezone.
- Discovery failure scenarios return actionable error codes.

---

### TKT-ICAL-005 — Sync state schema and event link model
**Type:** Feature  
**Priority:** P0  
**Dependencies:** TKT-ICAL-004

**Scope**
- Add persistence for:
  - `sync_token`, `ctag`, `last_synced_at`
  - external link mapping (`UID`, resource URL, ETag)
- Add indexes and uniqueness constraints for high-volume sync lookups.

**Deliverables**
- DB migration(s) for `external_calendars`, `external_event_links`.
- Data access layer methods for upsert/query by UID/resource URL/internal ID.

**Acceptance Criteria**
- Link table enforces uniqueness without duplicate mappings.
- Sync state can be updated atomically within a sync run transaction.
- Query paths support expected throughput with indexed plans.

---

### TKT-ICAL-006 — Sync run/job telemetry persistence
**Type:** Feature  
**Priority:** P1  
**Dependencies:** TKT-ICAL-005

**Scope**
- Add `calendar_sync_jobs` / `calendar_sync_runs` tracking.
- Capture per-run counters (created/updated/deleted/conflicts/errors).
- Store last error snapshots and run durations.

**Deliverables**
- Migration(s), repository methods, and run lifecycle helper utilities.

**Acceptance Criteria**
- Every sync execution writes a run record with terminal status.
- Counters align with actual write operations in sample test runs.
- Support tooling can fetch last N runs by connection/calendar.

---

## Epic 3: Apple -> Internal Read Synchronization

### TKT-ICAL-007 — Initial historical import worker
**Type:** Feature  
**Priority:** P0  
**Dependencies:** TKT-ICAL-005

**Scope**
- Implement initial import workflow for selected calendars.
- Configurable historical window (default lookback/lookahead).
- Idempotent upsert behavior for repeated imports.

**Deliverables**
- Queue worker + orchestration command.
- Internal event upsert service integration with mapping layer.

**Acceptance Criteria**
- First run imports events in configured window.
- Re-running import does not create duplicates.
- Sync state and links are created for imported events.

---

### TKT-ICAL-008 — Incremental pull sync via sync token/ctag fallback
**Type:** Feature  
**Priority:** P0  
**Dependencies:** TKT-ICAL-007

**Scope**
- Implement incremental Apple-side change detection using sync tokens.
- Add fallback path when token invalid/expired (ctag + bounded scan).
- Process changed and deleted resources.

**Deliverables**
- Incremental pull worker path and shared reconciliation helper.

**Acceptance Criteria**
- Changed remote events update mapped internal events.
- New remote events create internal events and link rows.
- Remote deletions map to internal cancel/soft-delete policy.

---

### TKT-ICAL-009 — Polling scheduler and per-connection locking
**Type:** Feature  
**Priority:** P0  
**Dependencies:** TKT-ICAL-008

**Scope**
- Schedule periodic pull sync jobs with configurable intervals.
- Enforce per-connection lock to prevent overlapping runs.
- Add manual `sync-now` trigger endpoint integration.

**Deliverables**
- Scheduler config + queue lock mechanism.
- `POST /calendar/integrations/apple/sync-now` endpoint implementation.

**Acceptance Criteria**
- No concurrent pull runs for same connection.
- Sync-now request enqueues immediate run with dedupe key.
- Polling frequency honors configured limits and defaults.

---

## Epic 4: Internal -> Apple Write Synchronization

### TKT-ICAL-010 — Event serialization to iCalendar payloads
**Type:** Feature  
**Priority:** P0  
**Dependencies:** TKT-ICAL-005

**Scope**
- Build mapper from internal event model to `VEVENT` payload.
- Support title, description, location, start/end, timezone, all-day, status.
- Ensure stable UID strategy for cross-system identity.

**Deliverables**
- Serialization utility with validation and sanitization.

**Acceptance Criteria**
- Serialized payloads pass parser validation in integration tests.
- UID remains stable across updates of same internal event.
- All-day and timezone fields serialize correctly.

---

### TKT-ICAL-011 — Incremental push for create/update/delete with ETag preconditions
**Type:** Feature  
**Priority:** P0  
**Dependencies:** TKT-ICAL-010, TKT-ICAL-009

**Scope**
- Trigger push sync on internal event mutations for linked calendars.
- For updates, send conditional `PUT` with `If-Match` ETag.
- For deletes, issue remote `DELETE` for two-way calendars.

**Deliverables**
- Event mutation hook/outbox publisher.
- Push worker with create/update/delete operations and link/ETag refresh.

**Acceptance Criteria**
- Internal creates appear in Apple calendar and create link rows.
- Internal updates refresh remote event and stored ETag.
- Internal deletes remove/cancel remote event per direction policy.

---

### TKT-ICAL-012 — Outbox and retry/backoff policy for push reliability
**Type:** Feature  
**Priority:** P1  
**Dependencies:** TKT-ICAL-011

**Scope**
- Add durable outbox queue for eventual push delivery.
- Implement retry with exponential backoff + jitter.
- Classify terminal vs transient errors.

**Deliverables**
- Outbox table/queue integration and retry policy config.

**Acceptance Criteria**
- Transient failures retry automatically without data loss.
- Terminal auth failures mark connection degraded and stop hot-loop retries.
- Replay of stuck outbox items succeeds after credential fix.

---

## Epic 5: Conflict Resolution and Recurrence

### TKT-ICAL-013 — Conflict detection and deterministic merge engine (v1)
**Type:** Feature  
**Priority:** P0  
**Dependencies:** TKT-ICAL-011

**Scope**
- Detect conflicts via ETag mismatch and changed-since checks.
- Implement deterministic merge policy:
  - latest-write-wins default for base fields
  - preserve select local metadata where safe
- Persist conflict audit artifacts.

**Deliverables**
- Conflict resolver service and audit event schema.

**Acceptance Criteria**
- Conflicting edits converge deterministically in repeated runs.
- Conflict details are queryable for support/debug.
- No silent overwrite when stale ETag is detected.

---

### TKT-ICAL-014 — Recurrence support phase 1 (simple series)
**Type:** Feature  
**Priority:** P1  
**Dependencies:** TKT-ICAL-008, TKT-ICAL-010

**Scope**
- Support simple RRULE series read/write (daily/weekly/monthly).
- Add validation guardrails for unsupported recurrence complexity.

**Deliverables**
- Recurrence parser/serializer module and compatibility checks.

**Acceptance Criteria**
- Supported simple recurring events round-trip across both systems.
- Unsupported patterns are safely flagged without sync corruption.

---

### TKT-ICAL-015 — Recurrence exceptions (phase 2)
**Type:** Feature  
**Priority:** P2  
**Dependencies:** TKT-ICAL-014, TKT-ICAL-013

**Scope**
- Add support for `RECURRENCE-ID`, detached instances, and `EXDATE` handling.
- Implement exception-aware diffing and conflict paths.

**Deliverables**
- Exception mapping layer and targeted reconciliation routines.

**Acceptance Criteria**
- Detached instance edits sync correctly both directions.
- Exception deletions and moved instances preserve series integrity.
- Regression suite covers DST boundary exception scenarios.

---

## Epic 6: Product UX, Operations, and Support

### TKT-ICAL-016 — Integration settings UI (connect/manage/disconnect)
**Type:** Feature  
**Priority:** P0  
**Dependencies:** TKT-ICAL-003, TKT-ICAL-004

**Scope**
- Build Apple integration settings page:
  - connect form with app-specific password instructions
  - calendar selection controls
  - sync direction and interval settings
  - disconnect action

**Deliverables**
- Frontend screens/components + backend API wiring.

**Acceptance Criteria**
- User can complete full connect-to-select flow in UI.
- Validation and provider errors are clearly shown.
- Disconnect removes active sync behavior immediately.

---

### TKT-ICAL-017 — Sync status, health, and conflict center UI
**Type:** Feature  
**Priority:** P1  
**Dependencies:** TKT-ICAL-006, TKT-ICAL-013

**Scope**
- Show last sync time, connection health, recent errors, and conflict indicators.
- Add user-facing “sync now” and lightweight conflict messaging.

**Deliverables**
- Status cards and run history table in settings UX.

**Acceptance Criteria**
- Users can see current health and latest successful run.
- Conflicts are surfaced with clear non-technical guidance.
- Sync-now action reflects run progress and result.

---

### TKT-ICAL-018 — Admin/support troubleshooting tooling
**Type:** Feature  
**Priority:** P1  
**Dependencies:** TKT-ICAL-006, TKT-ICAL-013

**Scope**
- Add support views/actions for:
  - connection diagnostics
  - run inspection
  - safe relink/repair operations for UID mismatches

**Deliverables**
- Internal admin endpoints or dashboard components (role-gated).

**Acceptance Criteria**
- Support can identify root cause for degraded connection within one screen.
- Relink operation is audited and reversible.
- Unauthorized users cannot access tooling.

---

## Epic 7: Security, Compliance, and Observability Hardening

### TKT-ICAL-019 — Logging redaction, consent text, and audit events
**Type:** Feature  
**Priority:** P0  
**Dependencies:** TKT-ICAL-002, TKT-ICAL-003

**Scope**
- Add log redaction for auth headers and sensitive calendar payload fragments.
- Implement explicit user consent copy and capture acceptance timestamp.
- Emit audit events for connect/disconnect/credential rotation.

**Deliverables**
- Redaction middleware/filter updates and consent persistence fields.

**Acceptance Criteria**
- Security test confirms no sensitive credential leakage in logs.
- Consent is required before enabling two-way sync.
- Audit events are generated for all integration lifecycle actions.

---

### TKT-ICAL-020 — Metrics, dashboards, and alerting for sync SLOs
**Type:** Feature  
**Priority:** P1  
**Dependencies:** TKT-ICAL-006, TKT-ICAL-009, TKT-ICAL-012

**Scope**
- Emit metrics for run success/failure, latency, conflict rate, and backlog depth.
- Build dashboards and alerts for auth failure spikes and queue buildup.

**Deliverables**
- Metrics instrumentation + dashboard JSON/config + alert rules.

**Acceptance Criteria**
- On-call can observe end-to-end sync health from dashboard.
- Alerts fire for sustained auth failures and elevated error ratios.
- SLO indicators are reportable by environment and provider.

---

## Epic 8: Test Strategy and Rollout Execution

### TKT-ICAL-021 — CalDAV contract and integration test suite
**Type:** Feature  
**Priority:** P0  
**Dependencies:** TKT-ICAL-008, TKT-ICAL-011

**Scope**
- Build integration tests for discovery, sync tokens, CRUD, ETag mismatch, deletions.
- Include provider-compatibility fixtures for iCloud-specific behavior.

**Deliverables**
- CI-runnable integration suite for Apple adapter.

**Acceptance Criteria**
- CI fails on protocol regressions in adapter behavior.
- ETag collision and token invalidation scenarios are covered.
- Test reports include operation-level diagnostics.

---

### TKT-ICAL-022 — End-to-end sync convergence test coverage
**Type:** Feature  
**Priority:** P1  
**Dependencies:** TKT-ICAL-016, TKT-ICAL-017, TKT-ICAL-021

**Scope**
- Automate E2E flows:
  - connect -> import -> internal edit -> Apple reflect
  - Apple edit -> pull sync -> internal reflect
  - disconnect/reconnect + credential rotation

**Deliverables**
- E2E test scenarios and reusable test account harness docs.

**Acceptance Criteria**
- Core bidirectional scenarios pass consistently in CI/staging.
- Flaky tests are below agreed threshold.
- Failures provide actionable traces/screenshots/log links.

---

### TKT-ICAL-023 — Beta rollout plan and feature-flagged release controls
**Type:** Feature  
**Priority:** P1  
**Dependencies:** TKT-ICAL-020, TKT-ICAL-022

**Scope**
- Implement progressive rollout with feature flags and cohort controls.
- Define runbook for degrade/rollback and customer communication templates.

**Deliverables**
- Rollout checklist, runbook, and launch gates.

**Acceptance Criteria**
- Apple integration can be enabled by cohort and environment.
- Rollback can disable new connections without data corruption.
- Launch gate review includes SLO, support readiness, and known limitations.

---

## Suggested milestone mapping

- **Milestone A (MVP Read Sync):** TKT-ICAL-001..009, 016, 019, 021
- **Milestone B (Bi-Directional GA Core):** TKT-ICAL-010..013, 017, 020, 022
- **Milestone C (Hardening + Advanced Recurrence):** TKT-ICAL-014, 015, 018, 023

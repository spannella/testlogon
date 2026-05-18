# Google Calendar Integration — Implementation Tickets

This ticket set converts `docs/google-calendar-integration-plan.md` into executable engineering work. Tickets are grouped by epic and include scope, deliverables, and acceptance criteria.

## Epic 1: Platform Foundations & Feature Flagging

### GCAL-001 ✅ — Add integration feature flags and rollout controls
**Type:** Feature  
**Priority:** P0  
**Dependencies:** None

**Scope**
- Introduce backend/frontend feature flag gates for Google Calendar integration.
- Add per-environment and cohort-based rollout support.
- Define kill switch behavior for sync writes.

**Deliverables**
- `google_calendar_sync_enabled` and `google_calendar_writeback_enabled` flags.
- Documentation for staged rollout policy.

**Acceptance Criteria**
- Integration UI and API endpoints are hidden/disabled when flags are off.
- Writeback can be disabled independently from read sync.
- Flags can be toggled without redeploy.

---

### GCAL-002 ✅ — Provision encrypted secrets/token storage primitives
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-001

**Scope**
- Add secure storage abstraction for OAuth tokens (refresh/access metadata).
- Implement envelope encryption and key rotation support.
- Add redaction guardrails for logs.

**Deliverables**
- Token vault helper/service.
- Security controls checklist entries for token handling.

**Acceptance Criteria**
- Refresh tokens are encrypted at rest.
- Logs and traces never emit raw token values.
- Rotation path tested for non-breaking decrypt/encrypt migration.

---

## Epic 2: OAuth Connection Lifecycle

### GCAL-003 ✅ — Implement Google OAuth connect start endpoint
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-002

**Scope**
- Add `POST /ui/calendar/integrations/google/connect/start`.
- Generate secure `state` and `nonce` with expiry.
- Return provider authorization URL with required scopes.

**Deliverables**
- Endpoint and state persistence mechanism.
- Unit tests for malformed/expired state generation paths.

**Acceptance Criteria**
- Endpoint returns valid Google OAuth URL and server-tracked state.
- Scope list is least-privilege and configurable.
- Replayed/expired state values are rejected.

---

### GCAL-004 ✅ — Implement OAuth callback token exchange and account linking
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-003

**Scope**
- Add `GET /ui/calendar/integrations/google/connect/callback`.
- Exchange auth code for tokens; persist provider connection record.
- Link Google account identity to app user.

**Deliverables**
- Callback endpoint with error path handling.
- `calendar_provider_connection` persistence implementation.

**Acceptance Criteria**
- Successful callback stores encrypted refresh token and expiry metadata.
- Invalid code/state returns user-safe error and no partial link.
- Duplicate connect reuses/upgrades existing connection cleanly.

---

### GCAL-005 ✅ — Implement disconnect and provider token revocation
**Type:** Feature  
**Priority:** P1  
**Dependencies:** GCAL-004

**Scope**
- Add `POST /ui/calendar/integrations/google/disconnect`.
- Revoke provider token and mark mappings inactive.
- Record audit event for disconnect action.

**Deliverables**
- Disconnect endpoint and revocation client call.
- Audit payload contract for connect/disconnect events.

**Acceptance Criteria**
- Disconnected users can no longer sync.
- Revocation failures are surfaced with retry-safe semantics.
- Audit stream includes actor, account, and outcome.

---

## Epic 3: Calendar & Event Mapping Data Model

### GCAL-006 ✅ — Add calendar provider connection model/table
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-002

**Scope**
- Create storage model for provider connections.
- Track sync health, cursor metadata, and reauth state.

**Deliverables**
- Schema/migration (or Dynamo item contract) for connection entities.
- Repository/service methods for CRUD + status updates.

**Acceptance Criteria**
- Model supports one user to many provider connections safely.
- Connection health/status updates are idempotent.
- Data access is covered by unit tests.

---

### GCAL-007 — Add internal↔Google calendar mapping model
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-006

**Scope**
- Create mapping model for app `calendar_id` to Google `calendarId`.
- Add ownership/permission validation before mapping write.

**Deliverables**
- Mapping schema and service API.
- Validation for duplicate/invalid mapping attempts.

**Acceptance Criteria**
- Same internal calendar cannot be mapped twice to active targets.
- Unmapping preserves historical sync auditability.
- Permission checks prevent cross-tenant mapping.

---

### GCAL-008 ✅ — Add internal↔Google event mapping model and tombstones
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-007

**Scope**
- Create event mapping store for IDs, etag, sync fingerprint, timestamps.
- Add tombstone records for delete propagation.

**Deliverables**
- Event mapping schema/repo methods.
- Tombstone lifecycle logic and retention policy.

**Acceptance Criteria**
- Mapping uniquely identifies bi-directional event identity.
- Delete propagation uses tombstones and avoids accidental recreation.
- Retention policy documented and implemented.

---

## Epic 4: Google API Client & Data Transformation

### GCAL-009 ✅ — Build Google Calendar API client wrapper
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-004

**Scope**
- Implement typed client for calendars/events/list/watch/token refresh.
- Normalize error responses and retryable conditions.

**Deliverables**
- Google client module with auth middleware.
- Contract tests for key endpoint wrappers.

**Acceptance Criteria**
- Client refreshes access token on expiry without data loss.
- Retryable failures are classified and surfaced.
- Non-retryable auth errors drive reauth-required state.

---

### GCAL-010 ✅ — Implement internal↔Google event transformation layer
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-009, GCAL-008

**Scope**
- Build deterministic mappers for datetime/all-day/recurrence/status fields.
- Preserve source metadata for sync decisions.

**Deliverables**
- Mapper utilities with schema validation.
- Edge-case fixtures (timezone boundaries, recurrence exceptions).

**Acceptance Criteria**
- Mapping is deterministic for identical inputs.
- Recurrence and timezone conversions pass fixture tests.
- Unsupported fields degrade gracefully with tracked warnings.

---

## Epic 5: Inbound Sync (Google → App)

### GCAL-011 ✅ — Implement initial full import sync job
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-010

**Scope**
- Build first-run backfill job from mapped Google calendars.
- Upsert app events and create mapping records.

**Deliverables**
- Queue job handler for full import.
- Progress metrics and partial failure reporting.

**Acceptance Criteria**
- Initial sync imports all events in configured window.
- Re-running full import is idempotent.
- Job telemetry includes counts for created/updated/skipped/errors.

---

### GCAL-012 ✅ — Implement incremental sync with syncToken handling
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-011

**Scope**
- Store and reuse Google incremental `syncToken`.
- Handle token invalidation by triggering full re-sync fallback.

**Deliverables**
- Incremental poll job and token lifecycle manager.
- Failure/recovery playbook entry for invalid sync token.

**Acceptance Criteria**
- Incremental runs process only changed resources.
- Invalid token path auto-recovers via full sync.
- Cursor/token updates are atomic with successful job completion.

---

### GCAL-013 ✅ — Inbound delete/cancelled event propagation
**Type:** Feature  
**Priority:** P1  
**Dependencies:** GCAL-012, GCAL-008

**Scope**
- Interpret Google cancelled/deleted events correctly.
- Apply internal delete or tombstone state update.

**Deliverables**
- Delete handling logic with mapping/tombstone updates.
- Regression tests for delete + restore edge cases.

**Acceptance Criteria**
- Cancelled provider events no longer appear in app view.
- Deletes are idempotent when duplicate notifications arrive.
- Tombstone state prevents accidental recreation loops.

---

## Epic 6: Outbound Sync (App → Google)

### GCAL-014 ✅ — Emit outbound sync jobs from event CRUD operations
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-008, GCAL-001

**Scope**
- Hook existing app event create/update/delete routes to enqueue jobs.
- Include stable dedup/idempotency keys in payload.

**Deliverables**
- Event-write integration hooks and queue payload contracts.
- Unit tests for enqueue behavior per CRUD action.

**Acceptance Criteria**
- All relevant event writes enqueue exactly one logical sync job.
- Duplicate producer attempts collapse via dedup key.
- Queue payload includes mapping and actor context.

---

### GCAL-015 ✅ — Implement outbound create/update/delete handlers with etag checks
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-014, GCAL-010

**Scope**
- Implement writeback logic to Google events endpoints.
- Use etag/version checks to avoid blind overwrite.

**Deliverables**
- Outbound worker handlers for create, patch, delete.
- Retry matrix and conflict classification logic.

**Acceptance Criteria**
- App-originated CRUD changes are reflected in Google.
- etag mismatch routes to conflict state, not silent overwrite.
- Successful writes update event mapping metadata.

---

### GCAL-016 ✅ — Implement conflict detection and state surfacing
**Type:** Feature  
**Priority:** P1  
**Dependencies:** GCAL-015

**Scope**
- Detect concurrent modifications since last synced timestamp.
- Mark events `sync_state=conflict` and preserve snapshots.

**Deliverables**
- Conflict detector utility and persistence updates.
- API exposure of conflict metadata for frontend badges.

**Acceptance Criteria**
- Concurrent edits are flagged deterministically.
- Conflict details are queryable for UI/admin diagnostics.
- Normal non-conflicting writes remain fast path.

---

## Epic 7: Integration API Surface & Frontend UX

### GCAL-017 ✅ — Add integration status/mapping/manual sync endpoints
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-007, GCAL-012

**Scope**
- Implement:
  - `GET /ui/calendar/integrations/google/status`
  - `GET /ui/calendar/integrations/google/calendars`
  - `POST /ui/calendar/integrations/google/mappings`
  - `POST /ui/calendar/integrations/google/sync/run`

**Deliverables**
- Endpoint handlers + authz checks + response models.
- API tests for success/failure/permission paths.

**Acceptance Criteria**
- Users can view health, pick calendars, create mappings, and trigger sync.
- Unauthorized access is denied consistently.
- Manual sync trigger is rate-limited and audit-logged.

---

### GCAL-018 — Build frontend integration card and connect flow UX
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-004, GCAL-017

**Scope**
- Add Google integration section in Calendar settings.
- Implement connect/disconnect actions and status display.

**Deliverables**
- Frontend components for connection lifecycle.
- Error messaging for reauth-required and disconnect failures.

**Acceptance Criteria**
- Users can connect/disconnect from UI without manual API calls.
- Connection status reflects backend truth on page refresh.
- UX includes clear reauth call-to-action.

---

### GCAL-019 — Add calendar mapping UI and merged event rendering
**Type:** Feature  
**Priority:** P1  
**Dependencies:** GCAL-018, GCAL-017

**Scope**
- Allow selecting internal calendar ↔ Google calendar mapping in UI.
- Render provider source badges in calendar event listings.

**Deliverables**
- Mapping management UI and persisted selections.
- Calendar view updates for source and sync-state indicators.

**Acceptance Criteria**
- Mapped calendars show provider-linked events in standard view.
- Source/sync badges are visible and accessible.
- Unmapped calendars are unaffected.

---

## Epic 8: Reliability, Observability, and Compliance

### GCAL-020 — Add queue retries, backoff, and dead-letter handling
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-011, GCAL-015

**Scope**
- Implement retry policy with jittered exponential backoff.
- Route exhausted failures to DLQ with replay tooling.

**Deliverables**
- Queue configuration updates.
- Replay script/runbook for DLQ processing.

**Acceptance Criteria**
- Transient failures retry automatically and succeed when recoverable.
- Poison messages end in DLQ with actionable context.
- Replay path is documented and tested.

---

### GCAL-021 — Add sync metrics, structured logs, and alerts
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-011, GCAL-015

**Scope**
- Emit metrics for job counts, latency, conflicts, token refresh failures.
- Add structured logs with correlation IDs and mapping identifiers.
- Define alert thresholds for backlog/auth failure/conflict spikes.

**Deliverables**
- Metrics instrumentation and dashboards.
- Alert policies and on-call runbook updates.

**Acceptance Criteria**
- Dashboard surfaces real-time sync health for inbound/outbound flows.
- Alerts fire on configured thresholds in staging simulations.
- Logs support tracing a single event across sync pipeline.

---

### GCAL-022 — Add audit/compliance events for integration lifecycle
**Type:** Feature  
**Priority:** P1  
**Dependencies:** GCAL-005, GCAL-017

**Scope**
- Emit structured audit events for connect/disconnect, mapping changes, manual sync, sync errors, and conflicts.
- Ensure audit payload excludes secrets and includes actor/outcome context.

**Deliverables**
- Audit event schema updates and documentation.
- Compliance validation tests.

**Acceptance Criteria**
- All integration lifecycle actions generate auditable records.
- Audit events include actor, target, outcome, and timestamp.
- No token/secret material appears in audit payloads.

---

## Epic 9: Verification, Rollout, and GA

### GCAL-023 — Implement automated test suite (unit/integration/e2e)
**Type:** Feature  
**Priority:** P0  
**Dependencies:** GCAL-012, GCAL-015, GCAL-019

**Scope**
- Add unit tests for OAuth/token/mapper/conflict logic.
- Add integration tests with mocked Google API flows.
- Add e2e tests for connect, map, import, writeback, conflict visibility.

**Deliverables**
- Test modules and CI jobs.
- Mock fixtures for token expiry and sync token invalidation scenarios.

**Acceptance Criteria**
- CI includes regression coverage for all critical sync paths.
- Failing Google API conditions are covered by deterministic tests.
- e2e test proves two-way sync behavior from user perspective.

---

### GCAL-024 — Staged rollout and post-launch validation
**Type:** Feature  
**Priority:** P1  
**Dependencies:** GCAL-021, GCAL-023

**Scope**
- Roll out to internal users, pilot cohort, then broader population.
- Run migration/backfill and monitor quality SLOs.
- Capture launch report with defects, incident notes, and follow-up items.

**Deliverables**
- Rollout checklist and go/no-go criteria.
- Post-launch validation report.

**Acceptance Criteria**
- Pilot cohort meets sync SLA and error budget targets.
- No Sev1/Sev2 unresolved issues before wider rollout.
- GA approval documented with stakeholder sign-off.

---

## Suggested Milestones
- **M1 (Foundation):** GCAL-001 to GCAL-010
- **M2 (Read-only Sync):** GCAL-011 to GCAL-013 + GCAL-017 + GCAL-018
- **M3 (Two-way Sync):** GCAL-014 to GCAL-016 + GCAL-019
- **M4 (Production Hardening):** GCAL-020 to GCAL-024

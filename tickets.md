# Apple Calendar (CalDAV) Integration — Implementation Tickets

### CAL-001: Add calendar integration connection tables and indexes
**Description:** Create database migrations for calendar connection persistence (`calendar_connections`, `external_calendars`, `external_event_links`, `calendar_sync_runs`). Add indexes for user/provider lookup, remote UID uniqueness, and connection status filtering.
**Acceptance criteria:**
- Migration creates all required tables with rollback support.
- Unique constraints prevent duplicate external link mappings.

### CAL-002: Add encrypted credential reference fields and lifecycle columns
**Description:** Extend connection schema to include `credential_ref`, `credential_validation_status`, `credential_last_validated_at`, and `credential_rotated_at`. Ensure only references (not plaintext secrets) are persisted.
**Acceptance criteria:**
- Schema includes all credential lifecycle columns.
- No plaintext credential fields exist in persistent schemas.

### CAL-003: Add application config flags for Apple CalDAV provider
**Description:** Add and document environment-backed settings for global calendar integration enablement, Apple provider enablement, base URL, timeouts, retry policy, and polling interval defaults.
**Acceptance criteria:**
- Settings load with safe defaults in all environments.
- Feature can be globally disabled and provider-specific disabled independently.

### CAL-004: Implement provider registry bootstrap and runtime wiring
**Description:** Wire provider registry initialization into service startup so provider adapters can be registered/discovered by provider key. Ensure Apple adapter wiring can be toggled by feature flags.
**Acceptance criteria:**
- Registry exposes provider lookup by stable key.
- App startup succeeds with provider enabled or disabled.

### CAL-005: Implement secret manager adapter for calendar credentials
**Description:** Implement a secret adapter for storing and reading encrypted Apple credentials by `credential_ref`, including create/update/delete semantics and metadata tagging.
**Acceptance criteria:**
- Secret write returns stable reference identifier.
- Secret delete removes secret and invalidates old references.

### CAL-006: Implement credential redaction guardrails for logs
**Description:** Add centralized redaction of credential-like fields (password, auth header, token, iCal auth payload) across logger and error surfaces used by calendar integration code paths.
**Acceptance criteria:**
- Structured logs redact sensitive keys by default.
- Security regression tests confirm no secret leakage in emitted logs.

### CAL-007: Build Apple connect endpoint
**Description:** Add `POST /calendar/integrations/apple/connect` endpoint to validate input, store credential reference, create/update connection record, and return redacted connection status.
**Acceptance criteria:**
- Authenticated user can connect Apple integration successfully.
- Endpoint response never includes plaintext app-specific password.

### CAL-008: Build Apple status endpoint
**Description:** Add `GET /calendar/integrations/apple/status` to return current connection state, last successful sync, last error snapshot, and selected calendar count.
**Acceptance criteria:**
- Endpoint returns consistent status model for connected/degraded/disconnected.
- Missing connection returns a clear empty/not-connected response.

### CAL-009: Build Apple disconnect endpoint
**Description:** Add `POST /calendar/integrations/apple/disconnect` to disable sync, delete secret reference, and mark connection as disconnected while preserving audit trail.
**Acceptance criteria:**
- Disconnect removes active credential reference.
- Future sync jobs for disconnected connection are rejected/skipped.

### CAL-010: Implement CalDAV credential validation probe
**Description:** Implement Apple credential validation call flow in provider adapter with clear mapping for auth failures, network errors, and protocol errors.
**Acceptance criteria:**
- Invalid credentials surface actionable auth error codes.
- Timeouts/network errors are marked retriable.

### CAL-011: Implement CalDAV calendar discovery service
**Description:** Implement discovery of remote calendar collections for authenticated Apple user and normalize discovery output to internal DTOs.
**Acceptance criteria:**
- Discovery returns calendar IDs/URLs and display names.
- Empty or inaccessible discovery result is handled gracefully.

### CAL-012: Build calendar selection endpoints
**Description:** Add `GET /calendar/integrations/apple/calendars` and `POST /calendar/integrations/apple/calendars/select` to list discovered calendars and persist sync settings (enabled, direction, timezone).
**Acceptance criteria:**
- User can select/deselect calendars idempotently.
- Selections persist and are reflected in status endpoint.

### CAL-013: Implement initial import job orchestration
**Description:** Create initial import workflow that enqueues per-calendar import jobs, tracks run state, and supports configurable historical window.
**Acceptance criteria:**
- Initial sync creates a run record per calendar.
- Re-running initial import does not duplicate linked events.

### CAL-014: Implement Apple->internal event mapper (read path)
**Description:** Implement iCalendar parsing for VEVENT fields (summary, description, location, start/end, timezone, all-day, UID, status) and map to internal event model.
**Acceptance criteria:**
- Supported fields are mapped deterministically.
- Invalid/unsupported payload fragments are captured as structured parse errors.

### CAL-015: Persist sync state tokens and remote ETags
**Description:** Implement storage/update logic for per-calendar sync token/ctag and per-event remote metadata (`remote_uid`, `resource_url`, `etag`) during import/pull.
**Acceptance criteria:**
- Sync token/ctag are persisted after successful runs.
- Event links include remote UID and latest ETag.

### CAL-016: Implement incremental pull sync engine
**Description:** Add scheduled pull path using sync-token first and ctag/time-window fallback. Reconcile created/updated/deleted remote resources into internal event records.
**Acceptance criteria:**
- Pull sync updates internal events for remote edits.
- Remote deletions correctly apply internal cancel/soft-delete policy.

### CAL-017: Add pull scheduler and per-connection lock
**Description:** Add recurring scheduler for pull sync with per-connection distributed lock and duplicate job suppression.
**Acceptance criteria:**
- Same connection cannot run overlapping pull jobs.
- Polling interval is configurable and enforced.

### CAL-018: Implement internal->Apple iCalendar serializer
**Description:** Build serializer from internal event model to CalDAV-compatible VEVENT payloads including UID handling and timezone/all-day normalization.
**Acceptance criteria:**
- Serializer output passes parser round-trip tests.
- UID remains stable across updates of the same event.

### CAL-019: Implement push sync worker with conditional writes
**Description:** Implement create/update/delete push operations to Apple with ETag precondition (`If-Match`) and external link updates.
**Acceptance criteria:**
- Internal create/update/delete operations propagate to Apple for selected calendars.
- ETag mismatches trigger conflict flow instead of blind overwrite.

### CAL-020: Implement outbox for reliable push delivery
**Description:** Add durable outbox for pending push operations with retry/backoff/jitter and dead-letter handling for repeated failures.
**Acceptance criteria:**
- Transient push failures are retried automatically.
- Terminal failures are surfaced in sync status and preserved for support inspection.

### CAL-021: Implement conflict detection and merge policy (v1)
**Description:** Add conflict resolver for concurrent edits with deterministic policy (latest-write-wins baseline plus protected local metadata handling) and conflict audit records.
**Acceptance criteria:**
- Conflict resolution is deterministic for same input states.
- Conflict audit entries are queryable for debugging/support.

### CAL-022: Implement recurrence support phase 1
**Description:** Add read/write support for simple RRULE recurrence series (daily/weekly/monthly) without detached exceptions.
**Acceptance criteria:**
- Supported recurrence rules round-trip correctly across systems.
- Unsupported recurrence patterns are rejected with clear user-facing reason.

### CAL-023: Implement recurrence exceptions phase 2
**Description:** Add `RECURRENCE-ID`/`EXDATE` handling for detached instance edits/deletes and recurring series exception reconciliation.
**Acceptance criteria:**
- Detached instance updates sync correctly in both directions.
- Exception operations do not corrupt parent series state.

### CAL-024: Add integration settings UI shell
**Description:** Build frontend settings page for Apple integration with connect form, feature state, and entry points to calendar selection.
**Acceptance criteria:**
- User can access Apple integration settings from calendar settings UI.
- Form handles validation and inline error states.

### CAL-025: Add calendar selection UI
**Description:** Build UI for discovered calendar list with selection toggles, sync direction controls, and save/apply behavior.
**Acceptance criteria:**
- User selections persist and reload accurately.
- UI prevents selecting invalid combinations (e.g., disabled connection).

### CAL-026: Add sync status and health UI
**Description:** Build status widgets showing last run, current connection health, error summary, and manual "sync now" trigger.
**Acceptance criteria:**
- UI reflects latest backend status values.
- Manual sync action provides pending/success/error feedback.

### CAL-027: Add conflict notification UX
**Description:** Add UI surfaces for conflict counts and per-event conflict messages with guidance for resolution behavior.
**Acceptance criteria:**
- Users can identify which events had conflicts.
- Conflict messaging is understandable and non-technical.

### CAL-028: Add backend API/integration tests for connection lifecycle
**Description:** Add automated tests for connect/status/disconnect and calendar selection endpoints including authz, redaction, and failure cases.
**Acceptance criteria:**
- Tests cover happy path and major validation/error branches.
- CI includes these tests in standard backend suite.

### CAL-029: Add CalDAV adapter contract tests
**Description:** Add integration tests for discovery, token-based pull, ctag fallback, ETag collision handling, and delete propagation.
**Acceptance criteria:**
- Contract tests detect protocol regressions.
- Test fixtures cover Apple-specific interoperability edge cases.

### CAL-030: Add end-to-end sync convergence tests
**Description:** Add E2E tests for connect/import/pull/push/rotate/disconnect workflows to verify eventual consistency across internal and Apple calendars.
**Acceptance criteria:**
- Core two-way scenarios pass reliably in CI/staging.
- Test artifacts capture diagnostics on failure.

### CAL-031: Add operational dashboards and alerts
**Description:** Implement metrics instrumentation and dashboards for run success rate, sync latency, conflict rate, queue backlog, and auth failures; configure alerts.
**Acceptance criteria:**
- Dashboard visualizes key sync SLO indicators.
- Alerts trigger on sustained auth failures and high error rates.

### CAL-032: Add support/admin troubleshooting tooling
**Description:** Add admin-only tools for viewing connection health, last errors, run history, and safe relink/repair actions.
**Acceptance criteria:**
- Role-gated access enforced for support/admin tooling.
- Troubleshooting view includes enough data to triage without direct DB access.

### CAL-033: Add deployment runbook and rollout controls
**Description:** Create deployment runbook with feature flag rollout plan, canary cohorts, rollback actions, and known limitations. Include environment config checklist.
**Acceptance criteria:**
- Runbook documents step-by-step rollout and rollback procedures.
- Launch checklist includes security, observability, and support readiness gates.

### CAL-034: Add data migration/backfill utilities for existing events
**Description:** Build one-time and repeatable backfill scripts for linking pre-existing internal events to remote Apple UIDs when possible, with dry-run mode and audit output.
**Acceptance criteria:**
- Backfill supports dry-run and apply modes.
- Backfill writes audit/report summary with changed/skipped/error counts.

### CAL-035: Add post-launch hardening and load validation
**Description:** Execute resilience/load testing for high-volume calendars, long-run polling stability, timeout behavior, and retry pressure; tune thresholds and limits.
**Acceptance criteria:**
- Load tests meet defined sync throughput/latency targets.
- Hardening changes are documented with before/after metrics.

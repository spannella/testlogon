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
# Jira ↔ Internal Ticketing Sync — Implementation Tickets

### JTS-001: Finalize Jira integration API contract
**Description:** Define and freeze request/response schemas for Jira connect, callback, project discovery, link/unlink, sync status, and webhook endpoints.
**Acceptance criteria:**
- OpenAPI spec is updated with all Jira integration endpoints and error codes.
- API contract includes pagination, filtering, and idempotency semantics.

### JTS-002: Define Jira field mapping specification
**Description:** Document canonical mapping between internal ticket fields and Jira fields (summary, description, status, assignee, priority, labels, comments).
**Status:** Implemented (2026-04-05) via `docs/jira-field-mapping-spec.md`.
**Acceptance criteria:**
- Mapping spec includes data types, required/optional flags, and null-handling rules.
- Status and priority mapping strategy is explicitly defined per workspace/project.

### JTS-003: Create DB migration plan for Jira entities
**Description:** Author migration design for `jira_connections`, `ticket_external_links`, `jira_issue_mirror`, and `ticket_sync_events` entities using current storage strategy.
**Status:** Implemented (2026-04-05) via `docs/jira-db-migration-plan.md`.
**Acceptance criteria:**
- Migration plan includes forward and rollback procedures.
- Retention and archival policy for sync event history is documented.

### JTS-004: Add migration scripts for Jira persistence keys/indexes
**Description:** Implement migration scripts (or infra updates) needed to provision Jira-related indexes and entity keys in all environments.
**Status:** Implemented (2026-04-05) via `scripts/migrations/20260405_jira_ticket_indexes_migration.py` and `scripts/verify_jira_ticket_indexes.py`.
**Acceptance criteria:**
- Migrations apply cleanly in local, staging, and production dry-run.
- Migration verification script confirms required indexes exist.

### JTS-005: Implement Jira integration health startup checks
**Description:** Add startup checks that validate required Jira integration environment configuration when feature flags are enabled.
**Status:** Implemented (2026-04-05) via `app/services/jira_feature_flags.py` + `tests/test_jira_feature_flags.py`.
**Acceptance criteria:**
- Service fails fast on invalid Jira integration config with actionable error messages.
- Startup checks are covered by unit tests.

### JTS-006: Build OAuth connect initiation endpoint
**Description:** Implement endpoint that starts Jira OAuth flow and safely stores correlation state.
**Status:** Implemented (2026-04-05) via `app/routers/jira_integrations.py` + `app/services/jira_oauth.py`.
**Acceptance criteria:**
- Endpoint returns redirect URL with CSRF-safe state value.
- Invalid/missing OAuth config returns structured 4xx/5xx errors.

### JTS-007: Implement OAuth callback and token exchange
**Description:** Implement callback handler that exchanges code for token and persists secure references.
**Status:** Implemented (2026-04-05) via `app/routers/jira_integrations.py` + `app/services/jira_oauth_exchange.py`.
**Acceptance criteria:**
- Successful callback creates/updates Jira connection metadata.
- Expired/invalid codes return deterministic error responses.

### JTS-008: Implement token refresh and revocation handling
**Description:** Add token refresh flow and revoke/disconnect behavior for broken credentials.
**Status:** Implemented (2026-04-05) via `app/services/jira_token_lifecycle.py` + `app/services/jira_oauth_exchange.py`.
**Acceptance criteria:**
- Access token refresh occurs transparently when expired.
- Invalid refresh token transitions connection state to degraded/disconnected.

### JTS-009: Add Jira site/project discovery endpoint
**Description:** Implement endpoint to list available Jira projects for connected user/site.
**Status:** Implemented (2026-04-05) via `app/services/jira_projects.py` + `app/routers/jira_integrations.py`.
**Acceptance criteria:**
- Endpoint supports pagination and permission-aware filtering.
- Errors from Jira API are normalized to internal error model.

### JTS-010: Implement Jira API client with retries and rate-limit handling
**Description:** Build typed Jira client wrapper with timeout, retry, and 429 backoff policies.
**Status:** Implemented (2026-04-05) via `app/services/jira_api_client.py` and integration in `app/services/jira_projects.py`.
**Acceptance criteria:**
- Retry behavior is bounded and configurable.
- Metrics for request count, latency, retries, and failures are emitted.

### JTS-011: Add connection storage repository methods
**Description:** Implement repository methods for creating, reading, and listing Jira connection records.
**Status:** Implemented (2026-04-05) via `app/services/jira_ticket_sync_store.py` + `tests/test_jira_ticket_sync_store.py`.
**Acceptance criteria:**
- Repository supports lookup by workspace and user.
- CRUD behavior is covered by unit tests.

### JTS-012: Add external link repository methods
**Description:** Implement repository methods for creating, listing, and deleting links between internal tickets and Jira issues.
**Status:** Implemented (2026-04-05) via `app/services/jira_ticket_sync_store.py` + `tests/test_jira_ticket_sync_store.py`.
**Acceptance criteria:**
- Links can be queried by internal ticket and external issue key/id.
- Duplicate active link constraints are enforced.

### JTS-013: Add Jira issue mirror repository methods
**Description:** Implement repository methods for storing and retrieving mirrored Jira issue snapshots.
**Status:** Implemented (2026-04-05) via `app/services/jira_ticket_sync_store.py` + `tests/test_jira_ticket_sync_store.py`.
**Acceptance criteria:**
- Mirror upsert is idempotent by external issue id.
- Mirror records include remote update timestamp and ingestion timestamp.

### JTS-014: Add immutable sync event repository methods
**Description:** Implement append-only sync event persistence for inbound/outbound operations.
**Status:** Implemented (2026-04-05) via `app/services/jira_ticket_sync_store.py` + `tests/test_jira_ticket_sync_store.py`.
**Acceptance criteria:**
- Events are immutable and queryable by ticket/workspace/time.
- Event records include direction, outcome, trace id, and error code.

### JTS-015: Implement Jira webhook endpoint skeleton
**Description:** Add webhook endpoint for Jira events with payload validation and dispatch to processing queue.
**Status:** Implemented (2026-04-05) via `app/routers/jira_integrations.py`, `app/services/jira_webhook.py`, and `tests/test_jira_webhook.py`.
**Acceptance criteria:**
- Unsupported event types are acknowledged and logged safely.
- Valid events are enqueued with trace metadata.

### JTS-016: Add webhook signature verification and replay protection
**Description:** Validate webhook signatures/secrets and reject replayed payloads.
**Status:** Implemented (2026-04-05) via `app/services/jira_webhook.py`, `app/routers/jira_integrations.py`, and `tests/test_jira_webhook.py`.
**Acceptance criteria:**
- Invalid signatures return 401/403 and are audited.
- Duplicate webhook deliveries are deduplicated by replay protection keys.

### JTS-017: Build mirror ingestion worker (initial backfill)
**Description:** Implement worker that performs initial Jira issue import for selected projects.
**Status:** Implemented (2026-04-05) via `app/services/jira_mirror_backfill.py`, `app/services/jira_ticket_sync_store.py`, and tests.
**Acceptance criteria:**
- Worker imports all pages for configured projects.
- Progress checkpoints allow resume after failure.

### JTS-018: Build mirror ingestion worker (incremental sync)
**Description:** Implement incremental polling based on Jira updated timestamp.
**Status:** Implemented (2026-04-05) via `app/services/jira_mirror_incremental.py`, `app/services/jira_ticket_sync_store.py`, and tests.
**Acceptance criteria:**
- Incremental sync fetches only changed issues since last checkpoint.
- Polling cadence is configurable and observable.

### JTS-019: Implement ticket link creation API (create Jira issue)
**Description:** Add endpoint to create a new Jira issue from an internal ticket and persist link metadata.
**Status:** Implemented (2026-04-05) via `app/routers/jira_integrations.py`, `app/services/jira_link_creation.py`, and tests.
**Acceptance criteria:**
- Endpoint creates Jira issue and local link atomically or compensates on failure.
- Returned payload includes Jira key/id and sync status.

### JTS-020: Implement ticket link creation API (link existing Jira issue)
**Description:** Add endpoint to link an existing Jira issue to an internal ticket.
**Status:** Implemented (2026-04-05) via `app/routers/jira_integrations.py`, `app/services/jira_link_creation.py`, and tests.
**Acceptance criteria:**
- Endpoint validates external issue existence and permissions.
- Link operation is idempotent for repeated requests.

### JTS-021: Implement unlink API and historical audit retention
**Description:** Add endpoint to unlink Jira issue from internal ticket while retaining audit history.
**Status:** Implemented (2026-04-05) via `app/routers/jira_integrations.py`, `app/services/jira_link_creation.py`, and `app/services/jira_ticket_sync_store.py`.
**Acceptance criteria:**
- Unlink deactivates sync without deleting historical events.
- Unlink action is captured in audit trail.

### JTS-022: Implement outbound sync producer on ticket mutations
**Description:** Emit outbound sync tasks for mapped field changes on linked tickets.
**Status:** Implemented (2026-04-05) via `app/services/jira_outbound_sync.py` + `tests/test_jira_outbound_sync.py`.
**Acceptance criteria:**
- Producer emits tasks for create/update/status/comment changes.
- Producer skips non-linked tickets and unchanged mapped fields.

### JTS-023: Implement outbound sync worker with idempotency
**Description:** Process outbound tasks and update Jira with dedupe safeguards.
**Status:** Implemented (2026-04-05) via `app/services/jira_outbound_worker.py` + `tests/test_jira_outbound_worker.py`.
**Acceptance criteria:**
- Worker applies idempotency keys to prevent duplicate updates.
- Retryable and terminal failures are classified and logged.

### JTS-024: Implement inbound sync apply engine
**Description:** Apply inbound Jira deltas to linked internal tickets based on mapping rules.
**Status:** Implemented (2026-04-05) via `app/services/jira_inbound_apply.py`, `app/services/jira_ticket_sync_store.py`, and tests.
**Acceptance criteria:**
- Inbound updates modify mapped internal fields correctly.
- Apply engine updates sync status and last-synced metadata.

### JTS-025: Implement sync loop prevention metadata handling
**Description:** Add origin/update token tracking to ignore webhook echoes of local outbound writes.
**Status:** Implemented (2026-04-05) via `app/services/jira_outbound_worker.py`, `app/services/jira_inbound_apply.py`, and `app/services/jira_ticket_sync_store.py`.
**Acceptance criteria:**
- Echoed updates are skipped deterministically.
- Non-echo updates continue through apply pipeline.

### JTS-026: Implement conflict detection and persistence model
**Description:** Detect concurrent edits to same mapped field and persist conflict payload.
**Status:** Implemented (2026-04-05) via `app/services/jira_inbound_apply.py`, `app/services/jira_ticket_sync_store.py`, and tests.
**Acceptance criteria:**
- Conflict records include both local and remote candidate values.
- Ticket/link state transitions to conflict when detected.

### JTS-027: Implement conflict resolution API actions
**Description:** Add API endpoints/actions to resolve conflicts by choosing internal or Jira value.
**Status:** Implemented (2026-04-05) via `app/routers/jira_integrations.py`, `app/services/jira_conflict_resolution.py`, and tests.
**Acceptance criteria:**
- `keep_internal` and `keep_jira` actions are both supported.
- Conflict resolution triggers follow-up sync and clears conflict state.

### JTS-028: Extend ticket list API for source filtering
**Description:** Add `source=internal|jira|unified` and Jira-specific filters to ticket list endpoint.
**Status:** Implemented (2026-04-05) via `app/routers/tickets.py` and route tests.
**Acceptance criteria:**
- Unified listing supports stable sorting and pagination.
- Response includes source marker and sync freshness metadata.

### JTS-029: Add sync status endpoint for ticket details
**Description:** Implement endpoint returning link state, last sync info, and active conflict details.
**Acceptance criteria:**
- Endpoint returns normalized sync-state enum.
- Missing linkage returns explicit not-linked status.

### JTS-030: Build frontend Jira integration settings page
**Description:** Implement UI for connect/disconnect, project preferences, and integration status.
**Status:** Implemented (2026-04-05) via Jira integration settings UI, Jira settings API endpoints, and persistence for project preferences.
**Acceptance criteria:**
- Users can initiate OAuth and view connection state from settings UI.
- Validation and error states are clearly surfaced.

### JTS-031: Add frontend ticket source filters and badges
**Description:** Update ticket list UI with Internal/Jira/Unified filters and source badges.
**Acceptance criteria:**
- Source filter state persists across navigation.
- Jira and unified rows render consistently and accessibly.

### JTS-032: Add frontend linked Jira panel on ticket detail
**Description:** Display linked Jira issue metadata and sync status in ticket details.
**Status:** Implemented (2026-04-05) via `frontend/src/pages/tickets/JiraLinkedPanel.tsx`, ticket detail wiring, and sync-status enrichment in `app/routers/jira_integrations.py`.
**Acceptance criteria:**
- Detail panel shows Jira key, status, and last sync timestamp.
- Link/unlink actions are available with confirmation flows.

### JTS-033: Add frontend conflict resolution modal
**Description:** Implement UI modal for reviewing and resolving sync conflicts.
**Status:** Implemented (2026-04-05) via conflict-resolution modal in Jira ticket panel and sync-status conflict payload exposure.
**Acceptance criteria:**
- Modal presents both internal and Jira values for conflicting fields.
- Resolution action updates UI state without full-page reload.

### JTS-034: Add backend unit tests for Jira client and mapping logic
**Description:** Add focused unit coverage for Jira client retries, mapping transforms, and validation helpers.
**Status:** Implemented (2026-04-05) via expanded unit coverage in Jira API client, mapping helpers, and link validation tests.
**Acceptance criteria:**
- Tests cover success, timeout, 429, and non-retryable error paths.
- Mapping tests cover empty/null/edge-case values.

### JTS-035: Add backend integration tests for OAuth + webhook flows
**Description:** Add integration tests for OAuth callback lifecycle and webhook verification/apply behavior.
**Status:** Implemented (2026-04-05) via integration tests for callback persistence, webhook signature+replay handling, and inbound apply/link metadata updates.
**Acceptance criteria:**
- Tests validate signature verification and replay rejection.
- End-to-end inbound path updates mirrored/linked records as expected.

### JTS-036: Add backend integration tests for bidirectional sync lifecycle
**Description:** Add tests for create link, outbound updates, inbound updates, and conflict transitions.
**Status:** Implemented (2026-04-05) via lifecycle integration tests covering create-link, outbound worker, inbound apply, conflict detect, and conflict resolve.
**Acceptance criteria:**
- Test suite verifies both outbound and inbound direction correctness.
- Conflict detection and resolution paths are covered.

### JTS-037: Add frontend tests for Jira settings and list/detail UX
**Description:** Add component/integration tests for settings page, source filters, linked panel, and conflict modal.
**Status:** Implemented (2026-04-05) via new frontend component tests for Jira settings and ticket detail linked panel/conflict modal UX.
**Acceptance criteria:**
- Tests cover loading, empty, success, and error states.
- Key flows pass in CI test environment.

### JTS-038: Add migration/deployment runbook for Jira sync rollout
**Description:** Create runbook describing migration sequence, feature-flag rollout, and rollback steps.
**Status:** Implemented (2026-04-05) via `docs/jira-sync-rollout-runbook.md` with preflight, rollout, rollback, and incident response playbooks.
**Acceptance criteria:**
- Runbook includes preflight checks and rollback procedures.
- On-call/operator playbook includes incident actions.

### JTS-039: Add observability dashboards and alerts for sync pipeline
**Description:** Add dashboards and alerts for webhook throughput, sync latency, failures, conflicts, and queue depth.
**Status:** Implemented (2026-04-05) via `docs/jira-observability-dashboards-and-alerts.md` and `ops/monitoring/jira_sync_alerts.yaml`.
**Acceptance criteria:**
- Alert thresholds align with agreed SLO/error budget.
- Dashboards include drill-down dimensions by workspace and direction.

### JTS-040: Execute staged rollout and GA readiness review
**Description:** Roll out by environment/workspace cohorts and perform GA decision review using defined success metrics.
**Status:** Implemented (2026-04-05) via staged rollout success gates in `docs/jira-sync-rollout-runbook.md` and GA sign-off template in `docs/jira-ga-readiness-review.md`.
**Acceptance criteria:**
- Pilot cohort meets sync latency and failure rate targets.
- GA checklist is signed off by engineering, security, and support owners.
### THR-001: Thread domain model and constants
**Description:** Define the canonical thread domain contract in backend code (field names, thread states, and helper constants). Include clear semantics for `thread_id`, `thread_root_message_id`, and `parent_message_id` so all services and APIs use the same vocabulary.
**Acceptance criteria:**
- Thread linkage field semantics are documented in code comments and shared constants.
- No duplicate ad-hoc field-name strings remain in core message/thread service paths.

### THR-002: Create threads persistence schema
**Description:** Add persistence schema for thread records with required fields (`id`, `conversation_id`, `root_message_id`, `created_at`, `created_by`) and query indexes needed by thread listing and lookup.
**Acceptance criteria:**
- A threads table/model exists and supports lookups by conversation and root message.
- Schema is backward-compatible with existing environments and does not impact current message writes.

### THR-003: Add message linkage fields and indexes
**Description:** Ensure message records support nullable linkage fields (`thread_id`, `thread_root_message_id`, `parent_message_id`) and add indexes for conversation chronology, parent lookup, thread chronology, and root lookup.
**Acceptance criteria:**
- Message writes succeed when new linkage fields are absent.
- Required indexes exist for `(conversation_id, created_at)`, `(parent_message_id)`, `(thread_id, created_at)`, and `(thread_root_message_id)` access patterns.

### THR-004: Migration apply and rollback scripts
**Description:** Implement migration scripts to create thread schema and add message indexes in existing environments, plus safe rollback behavior for the new thread table.
**Acceptance criteria:**
- Migration apply is idempotent and can run repeatedly without failure.
- Rollback safely handles already-removed resources without failing.

### THR-005: Reply write-path linkage plumbing
**Description:** Update all message creation paths (text, media, forwards, system-supported reply paths) so reply targets set both compatibility and normalized linkage fields, preserving current behavior.
**Acceptance criteria:**
- All reply-capable send endpoints write `parent_message_id` consistently when replying.
- Existing `reply_to_message_id` behavior remains intact for clients that still use it.

### THR-006: Thread promotion service logic
**Description:** Implement backend service logic to promote replies into a thread when either (a) more than one direct reply exists for the same root message or (b) a reply targets another reply.
**Acceptance criteria:**
- Promotion occurs automatically according to the defined rules.
- A single, stable `thread_id` is assigned to all messages in the promoted subtree.

### THR-007: Backfill and subtree reconciliation job
**Description:** Create a repair/backfill job that scans conversation messages, identifies eligible historical reply trees, creates missing thread records, and links descendants consistently.
**Acceptance criteria:**
- Job is idempotent and can be resumed safely.
- Running the job on already-correct data causes no destructive changes.

### THR-008: Concurrency-safe thread creation
**Description:** Add transaction/conditional-write protections so simultaneous replies cannot create duplicate threads or inconsistent linkage when promotion happens under race conditions.
**Acceptance criteria:**
- Competing promotion attempts for the same root produce exactly one thread.
- Conflict/retry behavior is deterministic and covered by tests.

### THR-009: Thread-aware read APIs
**Description:** Extend backend APIs to expose thread metadata in conversation timelines and add endpoints/query modes to fetch thread messages efficiently.
**Acceptance criteria:**
- Timeline responses include thread summary metadata when applicable.
- A thread fetch API returns ordered thread messages with pagination support.

### THR-010: Thread validation and authorization
**Description:** Add server-side validation to ensure thread and parent references are in the same conversation, target messages exist, and users are authorized to read/write in thread contexts.
**Acceptance criteria:**
- Invalid cross-conversation references are rejected with clear errors.
- Authorization behavior matches existing conversation membership rules.

### THR-011: Frontend thread entry points in timeline
**Description:** Update message timeline UI to display thread indicators and entry points (e.g., “View thread”, reply counts, last activity) without regressing current message rendering.
**Acceptance criteria:**
- Messages with threads show a clear thread affordance and count.
- Non-threaded messages render unchanged from current UX.

### THR-012: Frontend thread panel/page implementation
**Description:** Build the thread view UI (drawer, panel, or dedicated route) that shows thread history, participants, and reply composer tied to thread context.
**Acceptance criteria:**
- Users can open a thread from timeline and read all thread messages.
- Sending from thread UI posts to the correct thread context.

### THR-013: Reply composer behavior updates
**Description:** Update composer interaction rules so reply-to-reply actions route into thread context, and direct replies correctly resolve parent/root/thread linkage in payloads.
**Acceptance criteria:**
- Reply-to-reply always attaches to the expected thread context.
- Composer payloads include required linkage fields for backend processing.

### THR-014: Notifications and unread semantics for threads
**Description:** Define and implement notification/unread behavior for thread activity (root author, participants, followers/watchers if supported) and avoid duplicate alerts between timeline and thread surfaces.
**Acceptance criteria:**
- Thread events generate expected notifications without duplicates.
- Unread counters remain consistent between conversation and thread views.

### THR-015: API contract and type generation updates
**Description:** Update OpenAPI/schema artifacts and frontend generated types to include thread fields and thread endpoints, preserving backward compatibility.
**Acceptance criteria:**
- API contract artifacts include all thread fields/endpoints.
- Frontend type checks pass with updated contract types.

### THR-016: Backend unit and integration test suite
**Description:** Add comprehensive tests for schema behavior, promotion rules, linkage writes, API reads, auth validation, and failure scenarios.
**Acceptance criteria:**
- Tests cover no-promotion, second-reply promotion, and reply-to-reply promotion.
- Negative tests cover invalid references, unauthorized access, and rollback paths.

### THR-017: Concurrency and load test coverage
**Description:** Add targeted concurrency tests and representative load scenarios to validate thread promotion correctness and performance under parallel message sends.
**Acceptance criteria:**
- Parallel reply tests confirm single-thread creation per root.
- Performance baselines for thread queries are captured and within agreed thresholds.

### THR-018: Frontend E2E thread scenarios
**Description:** Add end-to-end tests validating timeline-to-thread navigation, thread creation triggers, reply-to-reply behavior, and cross-device/session consistency.
**Acceptance criteria:**
- E2E tests verify promotion behavior from user workflows.
- Thread UI and timeline metadata remain consistent after refresh/reconnect.

### THR-019: Observability and operational metrics
**Description:** Add metrics, logs, and dashboards for thread creation, promotion outcomes, index query latency, and reconciliation anomalies.
**Acceptance criteria:**
- Metrics for promotions, failures, and retries are emitted.
- Dashboard panels and alert thresholds are documented for operations.

### THR-020: Feature flag, rollout, and deployment runbook
**Description:** Introduce a controlled rollout plan (feature flags, staged enablement, rollback steps) and deployment checklist covering migrations, backfills, and monitoring gates.
**Acceptance criteria:**
- Feature flag controls thread behavior by environment/tenant cohort.
- Runbook documents deploy order, verification checks, rollback steps, and post-deploy validation.
### MSGD-001: Product requirements and scope lock for messaging drafts
**Description:** Finalize the feature contract for draft messages, including data model, lifecycle behavior, retention policy, cross-device expectations, and rollout constraints. Define in-scope (text drafts, save/load/remove) and out-of-scope (attachments, scheduled payloads, encrypted payload persistence) behavior.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- Product spec documents exact user behavior for save, load, remove, overwrite/replace semantics, and empty-draft handling.
- Spec includes platform behavior (desktop/mobile), privacy constraints, and explicit non-goals for v1.

### MSGD-002: UX wireframes and interaction states for composer drafts
**Description:** Deliver UX for draft controls in the composer: Save Draft trigger, saved-drafts list, load/remove actions, empty state, loading/error states, and accessibility annotations.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- Final wireframes include default, empty, populated, and error states for the draft panel.
- Accessibility notes include keyboard traversal, ARIA labels, focus management, and screen-reader text.

### MSGD-003: Backend API contract for server-synced conversation drafts
**Description:** Define OpenAPI contract for draft endpoints under messaging conversations. Include create/update, list, fetch, and delete semantics; idempotency; pagination strategy; and error formats.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- API contract includes `GET/POST/PATCH/DELETE /messaging/conversations/{conversation_id}/drafts` with request/response schemas.
- Contract defines authz failures, validation errors, and versioning strategy.

### MSGD-004: DynamoDB schema and migration plan for drafts
**Description:** Design and implement storage schema for conversation drafts in DynamoDB (or existing store), including keys, GSIs, TTL/retention fields, created/updated metadata, and tenancy/user scoping.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- Migration script creates required table/indexes and is idempotent across environments.
- Schema supports fast list-by-conversation and secure user-scoped reads/writes.

### MSGD-005: Backend repository/service layer for draft CRUD
**Description:** Implement service/repository methods for draft CRUD with validation, deterministic ordering, row size limits, and safe handling of malformed legacy rows.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- Service supports create, update, list, get-by-id, and delete with stable ordering and strict ownership checks.
- Unit tests cover validation, ordering, and defensive handling of malformed records.

### MSGD-006: Messaging router endpoints for draft operations
**Description:** Add FastAPI messaging routes for draft CRUD operations and hook them to auth, policy checks, and service layer methods.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- Endpoints return contract-compliant payloads and status codes for all success/failure paths.
- Route tests validate authn/authz, schema validation, and error response parity.

### MSGD-007: Frontend API client methods for server draft endpoints
**Description:** Add typed client methods in frontend API layer for list/save/load/remove draft operations and adapt DTOs to UI-safe models.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- API client exposes strongly typed methods consumed by UI hooks/components.
- Unit tests verify request shapes, path params, and response adaptation.

### MSGD-008: Frontend draft data hook with local fallback strategy
**Description:** Build/extend draft hook to support server-backed drafts with localStorage fallback for offline mode. Add sync/reconcile behavior between local and server states.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- Hook supports online CRUD via API and local fallback when offline or API unavailable.
- Reconciliation policy is documented and tested (e.g., last-write-wins with timestamp).

### MSGD-009: Composer UI integration for save/load/remove drafts
**Description:** Integrate draft hook into `ComposeBar` with user controls, list rendering, load/remove actions, and optimistic UX feedback. Preserve existing send behavior and compose state handling.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- Users can save, load, and remove drafts without breaking message send, reply, and attachment flows.
- UI updates are immediate and remain correct after conversation switches and page refresh.

### MSGD-010: Conversation-scoping and prop contract hardening
**Description:** Enforce conversation-scoped draft behavior end-to-end by requiring conversation context and validating all callsites that instantiate composer/draft logic.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- All composer entrypoints provide `conversationId` and pass type checks.
- Tests prove no cross-conversation draft leakage.

### MSGD-011: Backend integration tests for draft endpoints
**Description:** Add integration tests covering full draft lifecycle via HTTP API, including ownership checks, malformed input rejection, and pagination/list order behavior.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- Integration suite validates create/list/load/update/delete end-to-end against local test backend.
- Negative tests cover unauthorized access and cross-user data isolation.

### MSGD-012: Frontend unit/integration tests for draft UX
**Description:** Expand frontend tests for draft panel and composer interactions, including keyboard accessibility, focus behavior, and toast/error handling.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- Tests cover empty-save rejection, load-replaces-text behavior, remove behavior, and focus restoration.
- Tests verify draft state across rerenders and conversation changes.

### MSGD-013: E2E draft lifecycle scenarios
**Description:** Add robust Playwright scenarios for save/reload/load/isolation/remove across multiple conversations and sessions, with deterministic fixtures and cleanup.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- E2E tests pass in CI with stable selectors and no flaky timing dependencies.
- Scenarios include at least one negative path (e.g., session expiry or auth failure during draft operation).

### MSGD-014: Observability and analytics instrumentation
**Description:** Emit metrics/events for draft operations (save/load/remove/failure), backend latency/error rates, and fallback usage (server vs local).
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- Dashboards/alerts include draft endpoint errors, latency percentiles, and operation volumes.
- Event schema documented and validated for privacy-safe payloads.

### MSGD-015: Security and privacy hardening for draft content
**Description:** Review draft storage and transmission for sensitive data exposure risks. Add safeguards for logging, retention, and encryption-at-rest/in-transit assumptions.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- Security review completed with no plaintext draft content in logs/telemetry.
- Retention/deletion behavior is documented and validated in test environments.

### MSGD-016: Release strategy, feature flagging, and rollout plan
**Description:** Add feature flag gates and phased rollout plan (internal, beta, GA), plus rollback steps and operational readiness checklist.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- Feature can be toggled per environment/tenant without redeploy.
- Rollout doc includes rollback procedure, owner on-call notes, and success criteria.

### MSGD-017: Deployment and migration execution checklist
**Description:** Prepare and execute deployment checklist covering migration ordering, compatibility windows, smoke tests, and post-deploy verification.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- Deployment runbook includes preflight checks, migration sequencing, and post-deploy verification commands.
- Production rollout completes with no data-loss incidents and verified draft CRUD functionality.

### MSGD-018: Documentation and support enablement
**Description:** Update developer docs, user-facing release notes, QA test plans, and support troubleshooting guides for draft behavior.
**Status:** ✅ Implemented (2026-04-05)
**Acceptance criteria:**
- Documentation covers known limitations, offline behavior, and cross-device expectations.
- Support playbook includes troubleshooting for missing drafts, stale drafts, and sync conflicts.

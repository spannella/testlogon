### ICLOUD-101: Provider capability contract schema
**Description:** Define a versioned capability schema shared by backend and frontend for provider features, limits, and temporary restrictions.
**Acceptance criteria:**
- Capability schema is published as typed models and validated at API boundaries.
- Backward compatibility policy is documented with schema versioning rules.

### ICLOUD-102: Capability resolver in dispatcher
**Description:** Integrate capability checks directly into dispatcher routing for every operation.
**Acceptance criteria:**
- Unsupported operations are blocked before provider invocation.
- Contract tests verify capability enforcement across S3 and iCloud paths.

### ICLOUD-103: Capability endpoint for UI action gating
**Description:** Expose effective capabilities per mount and path to the Files UI.
**Acceptance criteria:**
- Endpoint includes operation allow/deny plus machine-readable deny reason.
- Files UI uses endpoint response to render disabled states/tooltips.

### ICLOUD-104: Canonical path utility extraction
**Description:** Extract and centralize canonical path normalization used by routes, mount service, and dispatcher.
**Acceptance criteria:**
- All path-normalization call sites use the shared utility.
- Fuzz tests confirm equivalent normalization for edge-case path variants.

### ICLOUD-105: Mount path overlap validator (create)
**Description:** Add overlap protection in mount creation to prevent ambiguous parent/child mounts.
**Acceptance criteria:**
- Create flow rejects overlaps with deterministic conflict code.
- Unit tests cover exact, prefix, and trailing-slash overlap cases.

### ICLOUD-106: Mount path overlap validator (update)
**Description:** Enforce overlap validation in mount updates and status transitions that re-enable mounts.
**Acceptance criteria:**
- Updates cannot introduce overlap after initial creation.
- Route tests verify overlap checks for all update entry points.

### ICLOUD-107: Tenant boundary assertions in resolver
**Description:** Add explicit tenant ownership assertions when resolving mounts to provider contexts.
**Acceptance criteria:**
- Resolver rejects cross-tenant mount references with stable auth errors.
- Security tests cover forged mount IDs and mixed-tenant path probes.

### ICLOUD-108: Idempotency ledger for mutating calls
**Description:** Persist idempotency keys and outcomes for write/move/delete provider operations.
**Acceptance criteria:**
- Duplicate keys return stored outcomes without additional provider side effects.
- TTL cleanup and replay semantics are configurable and documented.

### ICLOUD-109: Multi-step compensation orchestration
**Description:** Add compensation orchestration when remote mutation succeeds but local metadata write/audit fails.
**Acceptance criteria:**
- Compensation tasks capture correlation IDs and original operation context.
- Integration tests prove eventual consistency after injected partial failures.

### ICLOUD-110: Reconcile cursor-loop detector
**Description:** Detect repetitive reconcile cursors/pages and abort safely to avoid infinite batch loops.
**Acceptance criteria:**
- Reconcile stops after configurable loop threshold and surfaces explicit reason.
- Metrics and audit events are emitted for loop-detection incidents.

### ICLOUD-111: Reconcile retry budget per mount
**Description:** Implement per-mount retry budgets for reconcile failures with cooldown windows.
**Acceptance criteria:**
- Budget exhaustion pauses reconcile attempts for affected mount.
- Dashboard panels expose retry budget usage and exhaustion counts.

### ICLOUD-112: Reconcile stale-delete blast-radius guard
**Description:** Limit maximum stale-local deletions per run and switch to dry-run above threshold.
**Acceptance criteria:**
- Threshold breach prevents destructive apply operations in that run.
- Alerts fire when blast-radius guard is triggered.

### ICLOUD-113: Reconcile mismatch quarantine automation
**Description:** Automatically quarantine mounts with repeated high mismatch rates.
**Acceptance criteria:**
- Quarantine state blocks mutating operations until operator action.
- Quarantine/unquarantine transitions are audited and tested.

### ICLOUD-114: Reconcile dead-letter queue integration
**Description:** Route repeated reconcile failures to a DLQ with replay tooling.
**Acceptance criteria:**
- Failed reconcile jobs are persisted with error class and retry metadata.
- Replay CLI/API can re-run DLQ items with bounded retries.

### ICLOUD-115: Provider throttle backpressure bridge
**Description:** Feed provider throttle/error signals into rate-limit service for adaptive request shaping.
**Acceptance criteria:**
- Sustained 429/503 responses reduce mount-level admission rate.
- Recovery logic restores limits after healthy windows.

### ICLOUD-116: Adaptive concurrency control by mount
**Description:** Add mount-level adaptive concurrency using rolling latency/error windows.
**Acceptance criteria:**
- Concurrency contracts on degradation and expands on recovery.
- Controller decisions are observable via dedicated metrics.

### ICLOUD-117: Provider timeout policy matrix
**Description:** Define per-operation timeout budgets and enforce them in provider adapters.
**Acceptance criteria:**
- Distinct timeout profiles exist for list/read/write/move/delete.
- Unit tests validate timeout policy application per operation.

### ICLOUD-118: Retry policy matrix by error class
**Description:** Implement retries based on error class with jitter strategy and max-attempt controls.
**Acceptance criteria:**
- Auth/validation errors are non-retryable by default.
- Throttle/server errors use bounded exponential backoff with jitter.

### ICLOUD-119: iCloud cache invalidation correctness
**Description:** Ensure cache invalidation for object and parent listing keys on every mutation path.
**Acceptance criteria:**
- Rename/move/delete/update flows invalidate affected cache entries deterministically.
- Tests verify no stale listing/object reads post-mutation.

### ICLOUD-120: Cache single-flight miss coalescing
**Description:** Implement single-flight coalescing for identical cache misses to reduce provider load.
**Acceptance criteria:**
- Concurrent miss bursts generate one upstream fetch per key.
- Load tests show reduced upstream call amplification.

### ICLOUD-121: Cache TTL tuning by object class
**Description:** Add configurable TTL profiles for metadata/listing/content cache classes.
**Acceptance criteria:**
- TTLs are environment-configurable with sane defaults.
- Metrics track hit ratio and stale-read avoidance by cache class.

### ICLOUD-122: End-to-end trace propagation standard
**Description:** Propagate trace/correlation IDs from API entry through dispatcher/provider/reconcile/audit.
**Acceptance criteria:**
- Single trace ID links logs, metrics exemplars, and audit events.
- Integration tests verify propagation across mounted and default providers.

### ICLOUD-123: Provider error taxonomy normalization
**Description:** Normalize provider errors into stable API categories and machine-readable codes.
**Acceptance criteria:**
- All mount/provider endpoints return `code`, `category`, and `retryable`.
- API docs include mapping table from provider-native errors.

### ICLOUD-124: OpenAPI expansion for mount endpoints
**Description:** Document all `/v1/fs/mounts*` endpoints with complete request/response/error models.
**Acceptance criteria:**
- OpenAPI includes examples for initiate/verify/rotate/revoke/status override.
- Contract tests fail when docs drift from runtime schemas.

### ICLOUD-125: Secrets access anomaly alert pack
**Description:** Add anomaly alerts for secret read spikes, repeated failures, and unusual tenant patterns.
**Acceptance criteria:**
- Alerts include runbook links and actionable labels.
- Observability tests validate alert definitions and expressions.

### ICLOUD-126: Secret redaction enforcement tests
**Description:** Add tests that scan logs/audits/traces/metrics for leaked credential patterns.
**Acceptance criteria:**
- CI fails on high-confidence secret leakage patterns.
- Allowlist process is explicit and security-reviewed.

### ICLOUD-127: IAM least-privilege simulation suite
**Description:** Add IAM policy simulation tests for create/read/rotate/revoke secret operations.
**Acceptance criteria:**
- Negative tests verify unauthorized actions are denied.
- Documentation maps required IAM actions per endpoint.

### ICLOUD-128: KMS key policy validation checks
**Description:** Validate KMS key policies used by mount secrets for least privilege and correct principals.
**Acceptance criteria:**
- CI check rejects overly permissive key policy statements.
- Security docs include approved policy patterns.

### ICLOUD-129: Onboarding nonce replay protection
**Description:** Enforce one-time nonce semantics for onboarding verification callbacks.
**Acceptance criteria:**
- Replayed nonce requests are rejected with explicit replay code.
- Tests cover duplicate callback and delayed replay attacks.

### ICLOUD-130: Onboarding session expiry semantics
**Description:** Standardize expiration behavior for onboarding sessions and retries.
**Acceptance criteria:**
- Expired sessions cannot be verified, rotated, or resumed.
- UI receives deterministic expiry reason and restart guidance.

### ICLOUD-131: Rotation rollback transaction workflow
**Description:** Add transaction-safe rollback when rotate verify fails after partial cutover.
**Acceptance criteria:**
- Previous secret version pointer is stored before cutover.
- Rollback path is idempotent and integration-tested.

### ICLOUD-132: Revoke completion verifier job
**Description:** Add background verification that revoked credentials are unusable and mount is locked.
**Acceptance criteria:**
- Revoke marked complete only after verification succeeds.
- Failure emits alert and remediation guidance.

### ICLOUD-133: Mount health transition policy engine
**Description:** Centralize allowed mount status transitions with reason codes and operator override paths.
**Acceptance criteria:**
- Invalid transitions are rejected consistently across services/routes.
- Policy matrix tests cover all statuses and override combinations.

### ICLOUD-134: Manual override expiration controls
**Description:** Add TTL and auto-expiry behavior for manual mount status overrides.
**Acceptance criteria:**
- Overrides auto-expire at configured deadline with audit record.
- UI/API show override expiry metadata.

### ICLOUD-135: Rollout cohort automation controller
**Description:** Automate cohort promotions based on SLO/alert health with pause and rollback controls.
**Acceptance criteria:**
- Controller supports internal→beta→ga staged promotions.
- Automatic rollback triggers on configured burn-rate thresholds.

### ICLOUD-136: Rollout decision explainability endpoint
**Description:** Provide endpoint returning evaluated rollout decision inputs and final reason.
**Acceptance criteria:**
- Endpoint reports cohort, mode, kill-switch, tenant overrides, and decision reason.
- Tests verify explainability output matches runtime decision path.

### ICLOUD-137: Browser E2E mount happy-path suite
**Description:** Add browser E2E tests for connect, verify, list, upload, move, and delete operations.
**Acceptance criteria:**
- Tests run in CI with deterministic fixtures.
- Failure artifacts (video/screenshots/logs) are retained in CI.

### ICLOUD-138: Browser E2E failure-path suite
**Description:** Add E2E coverage for auth failure, throttle backoff, expired session, and revoked mount behavior.
**Acceptance criteria:**
- Each critical failure path has a deterministic UI assertion.
- Tests validate user-facing remediation messaging.

### ICLOUD-139: Chaos pack for provider outage simulation
**Description:** Create staging chaos scenarios for latency spikes, auth outages, and throttling storms.
**Acceptance criteria:**
- Chaos scenarios are runnable on-demand and scheduled.
- Results produce machine-readable pass/fail reports.

### ICLOUD-140: Production readiness report generator
**Description:** Build automated report aggregating SLO health, security checks, test gates, and rollout readiness.
**Acceptance criteria:**
- Report includes mandatory readiness sections with pass/fail state.
- Release pipeline blocks promotion when required checks fail.
### PDM-101: Provider adapter conformance test harness
**Description:** Build a shared conformance harness that each provider adapter must pass (verify, parse, retry, response-submit, and error mapping).
**Acceptance criteria:**
- Harness runs against Stripe/PayPal/CCBill adapters in CI.
- Failing conformance blocks adapter changes from merging.

### PDM-102: Webhook failure DLQ ingestion
**Description:** Persist all non-recoverable webhook failures into a dedicated DLQ table with canonical failure taxonomy.
**Acceptance criteria:**
- Verification/parse/transition terminal failures are captured with provider and reason code.
- DLQ schema includes replay metadata and source payload reference.

### PDM-103: Replay worker with shard-aware throttling
**Description:** Implement DLQ replay worker with shard-aware rate limits and exponential backoff to avoid provider/API overload.
**Acceptance criteria:**
- Replay throughput and backoff behavior are configurable per provider.
- Worker reports replay success/failure/skip counts per shard.

### PDM-104: Replay dry-run diff endpoint
**Description:** Add admin API to preview replay impact (state transition diffs) without mutating incident records.
**Acceptance criteria:**
- Dry-run returns deterministic before/after transition preview.
- Apply mode requires explicit confirmation token and privileged scope.

### PDM-105: Incident-store consistency auditor
**Description:** Add scheduled auditor to verify incident/event/evidence/retry/ticket-link referential consistency.
**Acceptance criteria:**
- Auditor emits machine-readable inconsistency report with severity.
- Critical inconsistencies raise alerts and create remediation tasks.

### PDM-106: Queue query path optimization
**Description:** Optimize queue filtering/sorting query paths and indexes for large-volume tenants.
**Acceptance criteria:**
- p95 and p99 list latency improvements are measured against baseline.
- Query correctness remains unchanged for all existing filters.

### PDM-107: Cursor token integrity signing
**Description:** Sign admin queue cursor tokens to prevent tampering and enforce token expiration semantics.
**Acceptance criteria:**
- Invalid or expired cursors are rejected with documented error codes.
- Token signing keys are rotatable without downtime.

### PDM-108: Retry race-condition locking
**Description:** Add lock/lease semantics around retry operations to prevent concurrent duplicate retry attempts.
**Acceptance criteria:**
- Concurrent retry requests result in single-winner execution.
- Loser requests receive deterministic retry-in-progress response.

### PDM-109: Provider outage fallback policy
**Description:** Add provider health-aware fallback behavior for retry and response-submit APIs when upstream is degraded.
**Acceptance criteria:**
- APIs return user-safe fallback responses with actionable reason codes.
- Fallback decisions are logged with provider health snapshot metadata.

### PDM-110: Evidence object checksum verification
**Description:** Record and verify cryptographic checksums for evidence uploads to detect corruption or tampering.
**Acceptance criteria:**
- Upload pipeline stores checksum and verifies on read/submit.
- Checksum mismatch marks evidence unusable and raises alert.

### PDM-111: Evidence access audit trail hardening
**Description:** Capture immutable audit events for every evidence read/download/submit action with actor and context.
**Acceptance criteria:**
- Audit events include actor identity, scope, incident ID, and action outcome.
- Audit logs are queryable by incident and actor for investigations.

### PDM-112: Scoped RBAC matrix enforcement tests
**Description:** Add comprehensive authorization matrix tests for all payment-incident admin/customer routes.
**Acceptance criteria:**
- Tests cover allowed/denied behavior for each role and scope combination.
- CI fails on any route missing explicit auth expectations.

### PDM-113: Metrics cardinality budget enforcement
**Description:** Add runtime safeguards and CI checks to prevent unbounded payment-incident metrics label cardinality.
**Acceptance criteria:**
- Dynamic labels are normalized/capped under configured budgets.
- Budget violations emit warnings and fail metrics-contract checks.

### PDM-114: Alert routing policy by provider/severity
**Description:** Define explicit alert routing and escalation policy for payment incidents by provider and severity.
**Acceptance criteria:**
- Alerts route to provider-specific on-call targets with override support.
- Escalation policy is tested for duplicate suppression and re-page intervals.

### PDM-115: Lifecycle SLO scoreboard automation
**Description:** Automate SLO scoreboard generation for ingest success, transition latency, replay backlog, and recovery outcomes.
**Acceptance criteria:**
- Scoreboard updates on schedule and exports machine-readable status.
- SLO breaches include links to impacted providers/incidents.

### PDM-116: API error catalog and client handling guide
**Description:** Publish complete payment-incident API error catalog with recommended client handling strategies.
**Acceptance criteria:**
- Catalog includes code, HTTP status, semantics, retryability, and UX guidance.
- Contract tests verify server responses match documented error codes.

### PDM-117: Runbook drill orchestration pipeline
**Description:** Create repeatable drill automation for webhook outage, replay backlog surge, and ticket-sync drift scenarios.
**Acceptance criteria:**
- Drill pipeline captures timeline, commands, outputs, and pass/fail rubric.
- Drill artifacts are retained and linked in operational runbooks.

### PDM-118: Provider sandbox negative-path E2E expansion
**Description:** Expand sandbox E2E matrix with negative-path scenarios (invalid signatures, out-of-order events, retry failures).
**Acceptance criteria:**
- Matrix covers at least one critical negative path per provider feature family.
- Failures include deterministic repro details and classification tags.

### PDM-119: Deployment canary and rollback gate
**Description:** Add pre-production canary checks and automatic rollback gates for payment-incident deployments.
**Acceptance criteria:**
- Canary validates webhook health, queue latency, and DLQ growth before promotion.
- Rollback is auto-triggered when critical gate thresholds are breached.
### GCAL-201: Webhook endpoint for Google push notifications
**Description:** Implement a secure webhook endpoint to receive Google Calendar channel notifications and route them into tenant-scoped incremental sync triggers.
**Acceptance criteria:**
- Webhook endpoint accepts Google channel notifications and maps them to the correct tenant connection.
- Invalid or unrecognized channel notifications are rejected and audited.

### GCAL-202: Channel token verification and replay defense
**Description:** Add signed channel token validation and replay-window checks for incoming webhook requests to prevent spoofing and replay attacks.
**Acceptance criteria:**
- Requests with missing/invalid channel token are rejected with structured security audit events.
- Duplicate notifications within replay window are ignored idempotently.

### GCAL-203: Watch channel lifecycle manager
**Description:** Build a lifecycle manager to create, renew, and clean up Google watch channels per mapped calendar.
**Acceptance criteria:**
- Channels are renewed before expiration with configurable lead time.
- Expired or invalid channels are recreated automatically and tracked in metrics.

### GCAL-204: Per-calendar sync scheduling priorities
**Description:** Add configurable scheduling priorities across mapped calendars so critical calendars receive lower-latency sync execution.
**Acceptance criteria:**
- Priority can be configured per mapping without code deployment.
- Scheduler consistently executes higher-priority calendars first under load.

### GCAL-205: Bootstrap import checkpoint resume
**Description:** Make first-time full import resumable with durable checkpoints to recover from worker crashes mid-import.
**Acceptance criteria:**
- Interrupted imports resume from last successful page/checkpoint.
- Resume flow avoids duplicate event materialization and duplicate mappings.

### GCAL-206: Recurring series split and merge handling
**Description:** Extend sync transform logic for recurring event split/merge operations (e.g., “this and following”) with lineage-safe mapping.
**Acceptance criteria:**
- Split/merge operations preserve recurrence integrity after round-trip sync.
- Tests cover parent/child mapping consistency across updates and deletes.

### GCAL-207: Timezone and DST regression pack
**Description:** Introduce dedicated timezone/DST edge-case fixtures and automated regression tests for all-day and timed events.
**Acceptance criteria:**
- Events crossing DST boundaries retain intended local times after sync.
- Fixture suite covers at least three timezone families and DST transitions.

### GCAL-208: Outbound mutation coalescing window
**Description:** Add short-window coalescing for rapid consecutive local mutations to reduce redundant provider writes.
**Acceptance criteria:**
- Multiple updates to the same event within window collapse into one outbound action.
- Final provider state matches latest local event version.

### GCAL-209: Backpressure controls for outbound queue
**Description:** Implement backpressure controls and adaptive concurrency for outbound workers based on retry rates and quota signals.
**Acceptance criteria:**
- Worker concurrency scales down automatically during quota pressure.
- Queue lag and dropped/deferred work are exposed in metrics.

### GCAL-210: Sync freshness SLO dashboard primitives
**Description:** Add metrics and labels required to compute sync freshness SLOs per tenant, connection, and calendar mapping.
**Acceptance criteria:**
- Freshness lag metric is emitted for inbound and outbound pipelines.
- Dashboards can filter and alert by tenant and mapping.

### GCAL-211: Burn-rate alert rules for integration SLOs
**Description:** Define and implement burn-rate alerting for sync freshness and failure-rate objectives.
**Acceptance criteria:**
- Alerts support fast-burn and slow-burn windows.
- Alert payload includes tenant, connection, and flow context.

### GCAL-212: Dead-letter taxonomy normalization
**Description:** Normalize DLQ error categories and reason codes across inbound and outbound sync processors.
**Acceptance criteria:**
- Each DLQ item includes standardized error class, reason code, and retry recommendation.
- Existing DLQ inspection tooling can filter by normalized taxonomy.

### GCAL-213: Safe bulk DLQ replay orchestration
**Description:** Implement controlled bulk replay orchestration with dry-run mode, tenant quotas, and circuit breaker protection.
**Acceptance criteria:**
- Replay can execute in dry-run and apply modes with summary output.
- Replay halts automatically when failure-rate threshold is exceeded.

### GCAL-214: Strict token access authorization checks
**Description:** Enforce service-role and tenant-bound authorization checks before token decrypt/use in all integration flows.
**Acceptance criteria:**
- Unauthorized token access attempts fail closed and are audited.
- Integration tests verify tenant isolation around token operations.

### GCAL-215: Envelope key rotation migration runner
**Description:** Build a resumable background runner to rotate encrypted token payloads to a new KMS key version.
**Acceptance criteria:**
- Rotation supports pause/resume and idempotent retries.
- Migration report includes processed, migrated, skipped, and failed counts.

### GCAL-216: Telemetry sensitive-data guardrails
**Description:** Add centralized telemetry guardrails that block sensitive Google token/calendar content from logs, traces, and metrics labels.
**Acceptance criteria:**
- Guardrail middleware redacts or rejects sensitive fields before emission.
- Automated tests fail on known secret leakage patterns.

### GCAL-217: Conflict resolution policy engine
**Description:** Add tenant-configurable conflict policies (app-wins, provider-wins, manual-review) used consistently by outbound and inbound flows.
**Acceptance criteria:**
- Policy selection is persisted per tenant and applied at runtime.
- Conflict decisions include explicit resolution source and rationale.

### GCAL-218: Manual conflict triage queue API
**Description:** Implement API support for manual conflict triage, assignment, resolution notes, and resolution SLA tracking.
**Acceptance criteria:**
- Operators can list/filter/assign/resolve conflicts via API.
- Queue supports pagination, age filters, and assignee filters.

### GCAL-219: End-to-end trace correlation propagation
**Description:** Propagate a single correlation ID from API request through queue jobs, provider calls, and webhook processing.
**Acceptance criteria:**
- End-to-end flow is traceable with one correlation ID across services.
- Correlation fields are present in structured logs and audit events.

### GCAL-220: Multi-tenant fairness scheduler for backfills
**Description:** Implement weighted fairness in scheduling to prevent large-tenant backfills from starving incremental sync work for others.
**Acceptance criteria:**
- Scheduler enforces tenant fairness constraints under sustained load.
- Observability exposes wait time by tenant and job class.

### GCAL-221: Integration incident runbook consolidation
**Description:** Consolidate operational docs into incident-oriented runbooks with triage, mitigation, rollback, and validation steps.
**Acceptance criteria:**
- Runbooks cover auth failures, lag spikes, DLQ growth, and webhook failures.
- Diagnostics endpoints and alerts link directly to relevant runbook sections.

### GCAL-222: Deployment preflight and rollback automation
**Description:** Add deployment preflight checks and automated rollback hooks tied to core integration health indicators.
**Acceptance criteria:**
- Rollout blocks when preflight checks fail required health thresholds.
- Rollback can be triggered automatically and records an audit trail.

### GCAL-223: Full tenant lifecycle e2e scenario suite
**Description:** Build deterministic end-to-end scenarios covering connect, import, edit both systems, conflicts, disconnect, reconnect, and recovery.
**Acceptance criteria:**
- E2E suite runs in CI with deterministic fixtures/mocks.
- Failing runs output timeline/state artifacts for diagnosis.

### GCAL-224: Chaos and outage resilience test matrix
**Description:** Add chaos tests for provider outages, network partitions, queue delays, and worker restarts to validate eventual consistency.
**Acceptance criteria:**
- System behavior under faults is measured against defined recovery objectives.
- Tests verify no duplicate writes and bounded recovery lag after restoration.

### CAL-101: Implement production sync-token REPORT client
**Description:** Replace placeholder incremental pull path with RFC 6578 `sync-collection` REPORT requests and robust response parsing.
**Acceptance criteria:**
- Pull uses persisted sync-token values for incremental fetch.
- Parser emits created/updated/deleted resources with deterministic UID mapping.

### CAL-102: Add sync-token reset recovery automation
**Description:** Handle token invalidation responses by transparently resetting sync state and entering fallback sync mode.
**Acceptance criteria:**
- 409/410/invalid-token responses trigger automated recovery flow.
- Run metadata includes fallback reason and recovered state details.

### CAL-103: Add ctag-based no-op optimization
**Description:** Skip expensive pull scans when ctag has not changed.
**Acceptance criteria:**
- Unchanged ctag exits early with no-op outcome.
- Changed ctag triggers deep scan and persists updated ctag.

### CAL-104: Add chunked pull pagination
**Description:** Process remote resources in bounded batches to control memory/latency on large calendars.
**Acceptance criteria:**
- Pull processes resources in configurable batch sizes.
- Large-calendar imports complete without memory spikes.

### CAL-105: Add resumable pull checkpoints
**Description:** Persist progress checkpoints so interrupted pull runs can continue from last known point.
**Acceptance criteria:**
- Interrupted pull resumes from latest checkpoint.
- Resume flow is idempotent and avoids duplicate writes.

### CAL-106: Implement real CalDAV PUT for upsert
**Description:** Replace scaffolded push write with actual conditional PUT behavior.
**Acceptance criteria:**
- Create uses `If-None-Match`; update uses `If-Match` when etag exists.
- Response etag/resource URL updates are persisted to links.

### CAL-107: Implement real CalDAV DELETE semantics
**Description:** Replace scaffolded delete with conditional DELETE handling.
**Acceptance criteria:**
- DELETE honors etag preconditions when known.
- 404/410 are treated as idempotent successful deletes.

### CAL-108: Persist pulled entities in internal event store
**Description:** Replace placeholder internal ID generation with durable event persistence.
**Acceptance criteria:**
- Pulled creates/updates persist to internal calendar event table.
- Event links always reference existing internal IDs.

### CAL-109: Implement internal soft-delete policy for remote deletes
**Description:** Apply configurable cancel/archive semantics when remote deletions are observed.
**Acceptance criteria:**
- Policy is configurable and environment-aware.
- Delete behavior is covered in integration tests.

### CAL-110: Support detached recurrence instance mapping
**Description:** Handle RECURRENCE-ID overrides/deletes as first-class sync entities.
**Acceptance criteria:**
- Detached instances persist with parent-series association.
- Instance delete does not remove parent recurrence series.

### CAL-111: Expand recurrence compatibility coverage
**Description:** Improve import/export parity for supported recurrence rule fields.
**Acceptance criteria:**
- Supported RRULE components round-trip without semantic drift.
- Unsupported RRULE fields generate structured parse errors.

### CAL-112: Add all-day + DST edge-case fixtures
**Description:** Add explicit timezone boundary fixtures for all-day and DST transitions.
**Acceptance criteria:**
- All-day date integrity is preserved across timezone conversions.
- DST transition tests pass for pull and push serializers.

### CAL-113: Add per-connection runtime budget guard
**Description:** Bound sync execution time per connection and defer remaining work.
**Acceptance criteria:**
- Runs exceeding budget checkpoint and reschedule continuation.
- Low-volume connections are not starved by large tenants.

### CAL-114: Add adaptive polling/backoff policy
**Description:** Dynamically tune polling intervals using connection health and error history.
**Acceptance criteria:**
- Poll intervals increase during sustained errors and recover on stability.
- Poll state changes are observable in metrics/logs.

### CAL-115: Add outbox per-connection throughput caps
**Description:** Introduce fair-share limits and jitter for outbound push queue processing.
**Acceptance criteria:**
- Outbox enforces per-connection push limits.
- Throughput smoothing reduces burst-induced retry storms.

### CAL-116: Add dead-letter replay support endpoint
**Description:** Allow authorized operators to replay dead-lettered push items.
**Acceptance criteria:**
- Replay endpoint is role-gated and audit logged.
- Replay path is idempotent and preserves traceability.

### CAL-117: Add sync-now idempotency keys
**Description:** Protect manual sync trigger against duplicated requests.
**Acceptance criteria:**
- Duplicate idempotency keys return existing run reference.
- Duplicate execution is prevented server-side.

### CAL-118: Add explicit connection health model
**Description:** Compute and persist health states (healthy/degraded/unhealthy/quarantined).
**Acceptance criteria:**
- Health transitions follow deterministic rules.
- Health state is surfaced in user and admin APIs.

### CAL-119: Add automatic quarantine policy
**Description:** Quarantine connections with repeated terminal failures to protect global reliability.
**Acceptance criteria:**
- Quarantine threshold is configurable per environment.
- Admin override/unquarantine actions are available and audited.

### CAL-120: Add tenant-aware remote call rate limiting
**Description:** Enforce fairness limits for outbound CalDAV calls.
**Acceptance criteria:**
- One noisy tenant cannot saturate shared sync capacity.
- Rate-limit outcomes are recorded in metrics/logs.

### CAL-121: Add credential-age lifecycle policy
**Description:** Track credential age and enforce rotation signals for stale secrets.
**Acceptance criteria:**
- Status includes credential age and rotation warnings.
- Alerts trigger for credentials exceeding policy threshold.

### CAL-122: Add secret re-encryption maintenance job
**Description:** Support key policy/version rotations without plaintext exposure.
**Acceptance criteria:**
- Re-encryption job is resumable and auditable.
- Secret material is never persisted unencrypted.

### CAL-123: Expand redaction policy enforcement
**Description:** Harden redaction for logs, audits, and diagnostics exports.
**Acceptance criteria:**
- Sensitive fields (auth headers, secrets, attendee identifiers) are always redacted.
- Redaction regression tests fail on leakage.

### CAL-124: Add redirect-safe SSRF protections
**Description:** Block unsafe redirect chains and private-target resolution during outbound requests.
**Acceptance criteria:**
- Redirects to private/loopback/link-local targets are denied.
- DNS rebinding + redirect edge cases are covered in tests.

### CAL-125: Add TLS failure classification telemetry
**Description:** Distinguish cert-expired/hostname-mismatch/trust-chain failures for operator triage.
**Acceptance criteria:**
- TLS failure class is recorded in run diagnostics.
- User-safe error message and admin-actionable detail are separated.

### CAL-126: Add end-to-end correlation IDs
**Description:** Thread correlation IDs across scheduler, pull/push, outbox, and admin diagnostics.
**Acceptance criteria:**
- Correlation IDs appear in logs/run records/audit rows.
- Admin tools can retrieve run timelines by correlation ID.

### CAL-127: Reduce metrics cardinality risk
**Description:** Refactor labels to bounded dimensions suitable for Prometheus at scale.
**Acceptance criteria:**
- Unbounded identifiers are removed from metric labels.
- Dashboards and alerts are updated to new label model.

### CAL-128: Add sync phase latency dashboards
**Description:** Track p50/p95/p99 latency by fetch/parse/reconcile/write phases.
**Acceptance criteria:**
- Dashboards show phase-level latency by outcome.
- Alerting is configured for p95 latency regressions.

### CAL-129: Add burn-rate SLO alerts
**Description:** Introduce multi-window burn-rate alerts for sync success SLO.
**Acceptance criteria:**
- Fast and slow burn windows are configured.
- Alert annotations include links to triage runbook sections.

### CAL-130: Add stale-connection freshness alerts
**Description:** Alert when successful sync freshness exceeds configured SLA window.
**Acceptance criteria:**
- Freshness threshold is configurable by environment/tier.
- Alert payload includes last-success timestamp and failure context.

### CAL-131: Extend status API diagnostics
**Description:** Add last-failure categories, retry counters, and next-action hints to status response.
**Acceptance criteria:**
- Status response includes actionable troubleshooting fields.
- Contract tests enforce backward-compatible schema changes.

### CAL-132: Add admin sync-state reset operation
**Description:** Allow targeted reset of per-calendar sync token/ctag for recovery.
**Acceptance criteria:**
- Operation is permission-checked and audited.
- Next run enters deterministic bootstrap mode.

### CAL-133: Publish integration API reference docs
**Description:** Document lifecycle APIs (connect, discover, select, import, sync-now, disconnect, admin tools).
**Acceptance criteria:**
- Docs include request/response examples and error taxonomy.
- Retry/idempotency behavior is explicitly documented.

### CAL-134: Publish operator conflict runbook
**Description:** Add decision tree for etag conflicts, dead letters, and replay failure handling.
**Acceptance criteria:**
- Runbook maps symptoms to concrete remediation steps.
- Escalation checklist and evidence requirements are defined.

### CAL-135: Add deployment preflight validation command
**Description:** Validate schema, indexes, flags, and secret dependencies before rollout.
**Acceptance criteria:**
- Preflight fails fast with actionable remediation output.
- Deploy pipeline can gate on preflight result.

### CAL-136: Add automated canary rollout orchestration
**Description:** Manage progressive cohort rollout with automated guardrail checks.
**Acceptance criteria:**
- Cohort percentages are configurable and observable.
- Rollout auto-pauses on alert/SLO breaches.

### CAL-137: Add migration verification + rollback drills
**Description:** Validate migration invariants and exercise rollback in staging.
**Acceptance criteria:**
- Post-migration invariants are automatically checked.
- Rollback drill runbook is executed and validated.

### CAL-138: Add deterministic staging E2E harness
**Description:** Build stable E2E suite using mock CalDAV fixtures for full lifecycle paths.
**Acceptance criteria:**
- E2E covers connect/import/pull/push/delete/recovery scenarios.
- Suite runs in CI without external iCloud dependencies.

### CAL-139: Add chaos testing for transient failures
**Description:** Inject timeout/5xx/reset/malformed payload scenarios into sync flows.
**Acceptance criteria:**
- Retry/backoff/dead-letter behavior is validated under chaos faults.
- Chaos tests confirm no duplicate link corruption.

### CAL-140: Add scale validation for high-volume calendars
**Description:** Expand load testing to large event sets and mixed pull/push traffic.
**Acceptance criteria:**
- Reports include throughput, queue depth, latency, and failure percentiles.
- Performance regression thresholds are enforced in CI gates.

### CAL-141: Add drift detection job
**Description:** Periodically detect divergence across remote state, event links, and internal event store.
**Acceptance criteria:**
- Drift classes include orphan links, stale etags, and missing internal records.
- Drift results can be consumed by automated repair workflows.

### CAL-142: Add orphan-link repair job
**Description:** Build idempotent repair workflow for invalid/missing internal event references.
**Acceptance criteria:**
- Repair supports relink, recreate, or tombstone actions.
- All repair actions are audit logged.

### CAL-143: Add retention policy enforcement job
**Description:** Enforce retention/archival rules for sync runs, conflicts, and dead-letter artifacts.
**Acceptance criteria:**
- Expired artifacts are purged or archived according to policy.
- Compliance exceptions are configurable and documented.

### CAL-144: Add redacted support diagnostics export
**Description:** Generate downloadable incident bundles with sanitized operational context.
**Acceptance criteria:**
- Bundle generation is permission-gated and audited.
- Bundle includes run timeline, health snapshots, and redacted errors.

### CAL-145: Improve end-user troubleshooting UI
**Description:** Add state-specific remediation guidance in calendar integration settings.
**Acceptance criteria:**
- UI provides clear next steps for common failure states.
- Guidance links to public support documentation.

### CAL-146: Add admin safe-mode (pull-only) control
**Description:** Allow temporary push suppression while preserving pull visibility.
**Acceptance criteria:**
- Safe mode toggles are per-connection and audit logged.
- Scheduler/outbox immediately respect safe mode.

### CAL-147: Add rollout cohort operations dashboard
**Description:** Build canary/beta/GA cohort dashboards for success, freshness, conflicts, and dead letters.
**Acceptance criteria:**
- Dashboard breaks down key SLO indicators by rollout cohort.
- Operators can quickly identify highest-risk cohorts.

### CAL-148: Add mixed-version compatibility matrix
**Description:** Validate rolling deploy behavior across old/new worker versions.
**Acceptance criteria:**
- Mixed-version tests pass for pull, push, scheduler, and outbox paths.
- Compatibility constraints are documented for releases.

### CAL-149: Add disaster-recovery restore drills
**Description:** Script and validate restoration of integration tables/secrets in staging.
**Acceptance criteria:**
- Restore drill meets defined RPO/RTO objectives.
- Post-restore checks confirm sync system readiness.

### CAL-150: Add GA readiness sign-off workflow
**Description:** Define measurable go-live gates across reliability, security, support, and rollback readiness.
**Acceptance criteria:**
- Scorecard includes explicit metrics and owner approvals.
- GA enablement requires completed sign-off and rollback plan reference.
### JTS-101: Add webhook policy outcome metrics and alert hooks
**Description:** Instrument webhook source-IP policy decisions (allow, deny, monitor, misconfigured) with labeled metrics and alert metadata.
**Acceptance criteria:**
- Metrics capture outcome and reason dimensions without high-cardinality labels.
- Alert rule examples are provided for deny and misconfigured spikes.

### JTS-102: Implement workspace-scoped webhook policy overrides
**Description:** Add workspace-level overrides for webhook policy mode and allowlist with strict validation.
**Acceptance criteria:**
- Override API validates CIDR syntax and policy mode values.
- Override changes are audited with actor, reason, and before/after values.

### JTS-103: Build effective-policy resolver for webhook security
**Description:** Implement deterministic resolution of global defaults vs workspace overrides for webhook source policy.
**Acceptance criteria:**
- Resolver behavior is unit-tested across all override combinations.
- Effective policy is exposed in diagnostics response for operators.

### JTS-104: Add webhook authentication failure taxonomy conformance tests
**Description:** Ensure all webhook auth failures map to documented error codes and response schema.
**Acceptance criteria:**
- Contract tests validate code/message pairs for each auth failure type.
- CI fails when undocumented webhook auth codes are emitted.

### JTS-105: Implement dead-letter queue replay governance controls
**Description:** Add approval workflow and replay guardrails for DLQ event reprocessing.
**Acceptance criteria:**
- Replay requires explicit scope, owner, and reason.
- Replay job emits completion report with success/failure breakdown.

### JTS-106: Add retry budget exhaustion triage flow
**Description:** Route jobs that exceed retry budgets into triage queues with actionable metadata.
**Acceptance criteria:**
- Triage records include last error family and retry history.
- Operators can filter and bulk-triage exhausted jobs by workspace.

### JTS-107: Implement mirror checkpoint consistency verifier
**Description:** Verify checkpoint monotonicity and cursor consistency before incremental runs.
**Acceptance criteria:**
- Inconsistent checkpoints are flagged and blocked from unsafe continuation.
- Recovery guidance includes nearest valid checkpoint and replay range.

### JTS-108: Add selective remirror orchestration API
**Description:** Expose API to trigger scoped remirror jobs for specific workspaces/projects/issues.
**Acceptance criteria:**
- Scoped remirror requests validate ownership and project permissions.
- Job status endpoint reports progress and reconciliation summary.

### JTS-109: Implement outbound payload diff minimization
**Description:** Build field-level diffing to send minimal outbound Jira updates and reduce update conflicts.
**Acceptance criteria:**
- Unchanged fields are omitted from outbound payloads.
- Diff logic is tested for nested field and array structures.

### JTS-110: Add idempotency-key lifecycle observability
**Description:** Track idempotency-key creation, reuse, and collision events across outbound pipeline.
**Acceptance criteria:**
- Metrics show key hit/miss/collision rates by direction.
- Collision events include traceable correlation identifiers.

### JTS-111: Implement worker fairness across workspace cohorts
**Description:** Ensure sync workers process tasks fairly across workspace cohorts under load.
**Acceptance criteria:**
- Fair scheduling policy is configurable and benchmarked.
- Saturation tests show no cohort starvation over sustained load.

### JTS-112: Add adaptive concurrency controls for sync workers
**Description:** Auto-tune worker concurrency from queue age/depth and processing latency signals.
**Acceptance criteria:**
- Concurrency scales up/down within safe configured bounds.
- Scaling decisions are logged with reason codes.

### JTS-113: Implement conflict severity scoring and routing
**Description:** Assign severity scores to conflicts and route high-severity conflicts for prioritized handling.
**Acceptance criteria:**
- Severity score is persisted with each conflict record.
- Routing rules prioritize high-severity conflicts in triage views.

### JTS-114: Add conflict resolution preview endpoint
**Description:** Provide non-mutating preview endpoint for keep-internal/keep-jira conflict outcomes.
**Acceptance criteria:**
- Preview response includes field-level before/after values.
- Preview endpoint never mutates link or ticket state.

### JTS-115: Implement optimistic-lock retry utility for sync store writes
**Description:** Centralize optimistic-lock retry behavior for concurrent link/sync metadata updates.
**Acceptance criteria:**
- Retry helper uses bounded attempts with jitter.
- Store callers adopt helper and emit lock-collision metrics.

### JTS-116: Add Jira project permission preflight cache
**Description:** Cache project permission checks to reduce repeated discovery latency during enablement.
**Acceptance criteria:**
- Cached permission checks expire safely on configurable TTL.
- Stale cache invalidation can be triggered by admin action.

### JTS-117: Implement OAuth scope drift alarms
**Description:** Detect and alert when granted Jira OAuth scopes fall below required minimum.
**Acceptance criteria:**
- Scope drift transitions connection health to degraded state.
- Alerts include missing scopes and impacted capabilities.

### JTS-118: Add token refresh jitter and backpressure
**Description:** Prevent token refresh stampedes by introducing jitter and in-flight refresh backpressure.
**Acceptance criteria:**
- Refresh jobs are distributed over configured jitter windows.
- Backpressure limits concurrent refreshes per tenant/workspace.

### JTS-119: Implement secret rotation rehearsal automation
**Description:** Automate periodic rehearsals for webhook and OAuth secret rotations.
**Acceptance criteria:**
- Rehearsals produce pass/fail artifacts and rollback timing.
- Rehearsal outcomes are stored for audit and readiness reporting.

### JTS-120: Add SIEM export mapping for Jira security events
**Description:** Normalize Jira integration security events to SIEM schema contracts.
**Acceptance criteria:**
- SIEM payload mapping is contract-tested in CI.
- Export failures are retried and surfaced on security dashboard.

### JTS-121: Implement SLO burn-rate deployment gate
**Description:** Block cohort promotions when sync SLO burn-rate exceeds policy thresholds.
**Acceptance criteria:**
- Promotion workflow enforces burn-rate checks automatically.
- Override path requires owner approval and incident linkage.

### JTS-122: Add queue anomaly early-warning detector
**Description:** Detect anomalous queue growth trends before critical backlog thresholds are breached.
**Acceptance criteria:**
- Detector emits warnings with confidence score and trend window.
- False-positive suppression strategy is documented and configurable.

### JTS-123: Implement synthetic full-path canaries
**Description:** Run synthetic canaries through webhook, outbound, inbound, and conflict flows per environment.
**Acceptance criteria:**
- Canary failures capture traces/logs and alert on-call.
- Canary health history is visible by environment and workspace cohort.

### JTS-124: Add multi-project isolation integration tests
**Description:** Validate that one Jira project’s failures do not block other projects within same workspace.
**Acceptance criteria:**
- Tests cover isolated failure and independent recovery paths.
- Health APIs surface project-scoped status independently.

### JTS-125: Implement high-cardinality pagination stress harness
**Description:** Stress-test sync history pagination under high event cardinality and concurrent writes.
**Acceptance criteria:**
- Cursor stability is maintained under concurrent ingest.
- Performance report includes p95/p99 latency for key endpoints.

### JTS-126: Add attachment quarantine and review workflow
**Description:** Quarantine risky synced attachments and provide operator review/approval actions.
**Acceptance criteria:**
- Quarantined artifacts are excluded from default user views.
- Review decisions are audited with actor and rationale.

### JTS-127: Implement sensitive-field mirror redaction policies
**Description:** Enforce field-level redaction policies for sensitive Jira data before mirror persistence.
**Acceptance criteria:**
- Redacted fields are never written to mirror storage.
- Redaction events are counted and included in audit trails.

### JTS-128: Add signed compliance audit export bundles
**Description:** Export sync audit logs in signed, tamper-evident bundles for compliance workflows.
**Acceptance criteria:**
- Export supports workspace/time-range/event filters.
- Integrity verification utility validates bundle signatures and manifest hashes.

### JTS-129: Implement support triage console views
**Description:** Build support-focused views for recent failures, conflict queues, and replay actions.
**Acceptance criteria:**
- Views support filter by workspace, error family, and severity.
- Each failure row links to runbook remediation guidance.

### JTS-130: Add customer-facing integration diagnostics summary
**Description:** Provide redacted diagnostics summary endpoint for workspace admins.
**Acceptance criteria:**
- Endpoint enforces scoped permissions and strict rate limits.
- Response includes actionable health hints without leaking sensitive data.

### JTS-131: Implement deployment preflight verifier for Jira dependencies
**Description:** Verify required queues, indexes, secrets, and feature flags before deployment proceeds.
**Acceptance criteria:**
- Deploy pipeline fails with actionable diagnostics when checks fail.
- Preflight results include owner mapping for each failed dependency.

### JTS-132: Add blue/green worker traffic shift automation
**Description:** Automate progressive traffic shifting between old/new worker pools with rollback triggers.
**Acceptance criteria:**
- Shift supports cohort-based ramp percentages.
- Rollback restores prior pool without event loss.

### JTS-133: Implement migration rollback simulation suite
**Description:** Simulate partial index migration failures and verify rollback playbook correctness.
**Acceptance criteria:**
- Simulations cover interrupted migration and mixed index state.
- Verified rollback steps are reflected in runbook docs.

### JTS-134: Add OpenAPI webhook error examples
**Description:** Document concrete webhook auth/replay/source-policy error examples in OpenAPI.
**Acceptance criteria:**
- Examples cover all documented webhook auth error codes.
- Contract tests validate example payload schema conformance.

### JTS-135: Implement error catalog drift checker
**Description:** Add CI checker to ensure runtime Jira error codes match documented taxonomy.
**Acceptance criteria:**
- CI fails for undocumented or deprecated runtime codes.
- Report identifies source module and owner for each drift.

### JTS-136: Add nightly end-to-end lifecycle regression suite
**Description:** Execute nightly end-to-end Jira lifecycle tests from connect through unlink.
**Acceptance criteria:**
- Suite runs against isolated sandbox tenants and publishes artifacts.
- Flaky scenarios are tracked with quarantine ownership.

### JTS-137: Implement chaos test matrix for Jira dependency failures
**Description:** Expand chaos tests for 429 floods, latency spikes, and intermittent Jira outages.
**Acceptance criteria:**
- Matrix validates correctness and recovery behavior per scenario.
- Results include measured recovery time and backlog drain metrics.

### JTS-138: Add long-running soak validation pipeline
**Description:** Run 24h soak pipelines to validate stability, memory trends, and convergence.
**Acceptance criteria:**
- Soak output includes trend charts for latency, errors, and queue depth.
- No sustained divergence or unbounded backlog growth is tolerated.

### JTS-139: Implement incident timeline auto-assembly
**Description:** Auto-generate incident timelines from metrics, logs, alerts, and deployment metadata.
**Acceptance criteria:**
- Timeline captures key events, mitigations, and decision points.
- Timeline artifact is consumable by postmortem templates.

### JTS-140: Add GA readiness scorecard and sign-off automation
**Description:** Automate GA readiness scoring and required owner sign-offs for final release decisions.
**Acceptance criteria:**
- Scorecard aggregates reliability, security, support, and rollout metrics.
- GA status remains blocked until all required sign-offs are recorded.
### THR-101: Cursor versioning contract and strict parser
**Description:** Introduce explicit cursor schema versioning and a strict parser for thread pagination cursors to support safe protocol evolution.
**Acceptance criteria:**
- Cursor payload includes mandatory `version` field and parser rejects unknown versions.
- Parser behavior is fully covered with tests for malformed, missing, and unsupported versions.

### THR-102: Cursor secret rotation runbook automation
**Description:** Implement automated secret rotation steps for thread cursor signing with staged rollout and rollback support.
**Acceptance criteria:**
- Rotation automation supports preflight validation, staged activation, and rollback.
- Rotation metrics and alerts are emitted and linked in runbook docs.

### THR-103: Idempotency guarantees for reply-driven promotion
**Description:** Add explicit idempotency handling for message write paths that can trigger thread promotion to avoid duplicate promotions under retries.
**Acceptance criteria:**
- Duplicate idempotency keys return consistent prior results without extra writes.
- Concurrency tests verify exactly-once thread record creation semantics.

### THR-104: Thread lifecycle event outbox implementation
**Description:** Implement transactional outbox delivery for thread lifecycle events so downstream systems observe promotion/reconciliation reliably.
**Acceptance criteria:**
- Thread write and outbox insert are atomic in the same transaction boundary.
- Dispatcher retries with backoff and dead-letter routing for exhausted retries.

### THR-105: DLQ replay tooling for thread lifecycle events
**Description:** Build operator tooling to inspect and replay dead-lettered thread lifecycle events by tenant/conversation and time range.
**Acceptance criteria:**
- Tool supports inspect, dry-run replay, and execute replay modes.
- Replay operations generate audit logs and structured outcome reports.

### THR-106: Hot-thread latency optimization (p95/p99)
**Description:** Optimize thread read path for high-volume threads via adaptive read windows and/or precomputed projections.
**Acceptance criteria:**
- Benchmark results show measurable p95/p99 latency reduction on hot threads.
- Ordering and authorization behavior remains functionally identical.

### THR-107: Thread summary projection service
**Description:** Add a projection service to maintain thread summary fields (`reply_count`, `last_reply_at`) incrementally.
**Acceptance criteria:**
- Projections update correctly on send, revoke, delete, hide/unhide operations.
- Projection drift detector and repair job are covered by tests.

### THR-108: Reconciliation checkpoint durability
**Description:** Harden backfill/reconciliation with durable checkpoints and deterministic resume behavior after interruption.
**Acceptance criteria:**
- Interrupted runs resume from persisted checkpoint without duplicate destructive updates.
- Progress, lag, and completion metrics are emitted for every run.

### THR-109: Reconciliation safety limits and blast-radius controls
**Description:** Add scoped execution controls, max-write thresholds, and mandatory dry-run previews for reconciliation jobs.
**Acceptance criteria:**
- Operators can scope by tenant/conversation/time window and preview exact planned updates.
- Jobs fail safely with clear diagnostics when safety thresholds are exceeded.

### THR-110: Policy enforcement parity across thread mutations
**Description:** Ensure retention/legal-hold checks are consistently enforced for all thread mutation paths including backfill/repair.
**Acceptance criteria:**
- Policy violations return stable, policy-specific error codes.
- Policy decisions are fully audited with actor and resource context.

### THR-111: Authorization matrix regression suite for thread APIs
**Description:** Build a complete authorization regression matrix for thread reads/writes across user roles and participant states.
**Acceptance criteria:**
- Tests cover member, removed member, moderator/admin/root, and cross-conversation misuse.
- CI gate fails on any authorization regression.

### THR-112: Unread counter convergence and repair
**Description:** Implement reconciliation between conversation unread counters and thread unread counters under race and reconnect conditions.
**Acceptance criteria:**
- Drift detection and repair logic converges counters deterministically.
- Multi-device integration tests validate convergence after repair.

### THR-113: Notification dedupe for thread/timeline fanout overlap
**Description:** Add deterministic dedupe keys to suppress duplicate notifications emitted from overlapping thread and timeline fanout paths.
**Acceptance criteria:**
- Duplicate notification rate remains below defined SLO in load tests.
- Dedupe counters and suppression reasons are visible in dashboards.

### THR-114: Fanout backpressure and circuit-breaker controls
**Description:** Add queue backpressure and circuit-breaker behavior for thread fanout when downstream dependencies degrade.
**Acceptance criteria:**
- Circuit breaker opens/closes based on configurable error thresholds.
- Backpressure/circuit events are metricized and alertable.

### THR-115: Failure-injection coverage for thread critical flows
**Description:** Add chaos/failure-injection tests for promotion, thread reads, and reconciliation under throttling and partial failure scenarios.
**Acceptance criteria:**
- Tests prove no orphaned linkage or duplicate thread records under injected faults.
- Recovery behavior meets defined error-budget thresholds.

### THR-116: Thread API contract drift gate
**Description:** Add strict CI checks for drift between runtime thread API behavior and OpenAPI schema definitions.
**Acceptance criteria:**
- CI blocks changes when runtime responses diverge from contract fixtures.
- Schema/fixture update process is documented and enforced.

### THR-117: Thread SLOs and alerting package
**Description:** Define and implement thread-specific SLOs and alert rules (latency, success rate, reconciliation health, error budget burn).
**Acceptance criteria:**
- Dashboard includes SLI panels and error-budget visualizations.
- Alerts route to on-call with linked remediation runbooks.

### THR-118: Automated rollout gate orchestration
**Description:** Automate tenant-cohort progression and rollback actions based on thread telemetry gate outcomes.
**Acceptance criteria:**
- Cohort expansion is blocked when health gates fail.
- Gate decisions and rollback actions are logged with auditable metadata.

### THR-119: Production-like canary E2E for threaded messaging
**Description:** Add scheduled and deploy-triggered canary E2E tests for thread creation, promotion, pagination, notifications, and rollback toggles.
**Acceptance criteria:**
- Canary results feed release gates and surface actionable diagnostics on failure.
- Failure artifacts include request IDs, logs, traces, and screenshots where applicable.

### THR-120: Thread operations handbook and incident drills
**Description:** Publish a comprehensive threaded messaging operations handbook and run recurring incident drills.
**Acceptance criteria:**
- Handbook contains deployment, rollback, reconciliation recovery, and incident response SOPs.
- Staging drill outcomes are recorded with remediation follow-ups and owners.
### MSGD-101: Autosave debounce core utility
**Description:** Implement a reusable debounce utility in the draft hook layer for autosave scheduling and cancellation.
**Acceptance criteria:**
- Utility supports schedule, cancel, flush-now semantics.
- Unit tests verify no duplicate invocation under rapid input.

### MSGD-102: Composer autosave integration flag
**Description:** Integrate autosave into `ComposeBar` behind a dedicated feature flag and configurable idle delay.
**Acceptance criteria:**
- Autosave triggers only when text changed and idle threshold elapsed.
- Flag-off mode keeps current manual save behavior unchanged.

### MSGD-103: Unsaved state indicator
**Description:** Add composer UI state showing “Unsaved” vs “Saved” draft status.
**Acceptance criteria:**
- Indicator updates on manual save, autosave success, and send/clear.
- Screen reader announcement is emitted on status changes.

### MSGD-104: Route transition guard for unsaved text
**Description:** Add confirmation dialog when leaving conversation with unsaved draft edits.
**Acceptance criteria:**
- Dialog appears only when unsaved delta exists.
- Confirming leave preserves latest local snapshot.

### MSGD-105: Browser unload protection
**Description:** Persist unsaved composer text on tab close/refresh via unload lifecycle handling.
**Acceptance criteria:**
- Local draft snapshot is saved before unload when text is dirty.
- No unload listener remains attached when drafts feature is disabled.

### MSGD-106: Cross-tab draft event sync
**Description:** Synchronize draft create/update/delete events across tabs using BroadcastChannel with storage fallback.
**Acceptance criteria:**
- Draft changes in one tab are reflected in another within a bounded delay.
- Integration test validates cross-tab consistency.

### MSGD-107: Reconnect-triggered draft refresh
**Description:** On network reconnection, trigger bounded background refresh of conversation drafts.
**Acceptance criteria:**
- Exactly one refresh per reconnect event per active conversation.
- Local unsent edits are never overwritten without conflict handling.

### MSGD-108: Create endpoint idempotency persistence
**Description:** Add backend idempotency record storage for draft `POST` to prevent duplicate creates on retries.
**Acceptance criteria:**
- Reusing same idempotency key returns original response.
- Idempotency records are scoped by user+conversation and TTL-cleaned.

### MSGD-109: Patch version precondition
**Description:** Require version precondition for draft updates to detect stale concurrent writes.
**Acceptance criteria:**
- Stale updates return conflict response with stable error code.
- Service and route tests cover stale and non-stale update paths.

### MSGD-110: Conflict response contract documentation
**Description:** Extend API contract and frontend types for conflict payloads and retry guidance.
**Acceptance criteria:**
- Docs include example 409/412 payloads and recovery semantics.
- Frontend type definitions compile against updated contract.

### MSGD-111: Conflict resolution composer flow
**Description:** Add conflict resolution UI actions: keep local, use server, merge manually.
**Acceptance criteria:**
- User can complete each path without losing original local text.
- UI tests cover all branches and resulting composer content.

### MSGD-112: Mutation retry/backoff policy
**Description:** Implement bounded exponential backoff for retryable draft mutation failures.
**Acceptance criteria:**
- Non-retryable classes (auth/validation) skip retries.
- Retry attempts and terminal outcomes are observable.

### MSGD-113: Draft API rate limiting
**Description:** Add per-user/per-conversation rate limits for draft mutation endpoints.
**Acceptance criteria:**
- Exceeding limit returns structured 429 with retry metadata.
- Prometheus counters include throttled request dimensions.

### MSGD-114: Pagination cursor hardening
**Description:** Validate and sign list cursors to prevent tampering and decode faults.
**Acceptance criteria:**
- Invalid cursor yields safe 400 error, never 500.
- Tests cover tampered, expired, and malformed cursors.

### MSGD-115: Performance benchmark for high-cardinality threads
**Description:** Add benchmark harness for list/get latency under high draft counts.
**Acceptance criteria:**
- Benchmark reports p50/p95/p99 latency artifacts.
- CI/perf job fails on configured regression threshold.

### MSGD-116: Draft fallback SLO and alert policy
**Description:** Define SLOs for availability/latency/fallback ratio with burn-rate alerts.
**Acceptance criteria:**
- SLO definitions are checked into repo with targets/windows.
- Alert runbook maps each SLO breach to mitigation actions.

### MSGD-117: Draft observability dashboard pack
**Description:** Create dashboard panels for operation volume, error classes, fallback rates, and latency.
**Acceptance criteria:**
- Panels support environment and endpoint filtering.
- Dashboard links directly to incident runbook sections.

### MSGD-118: End-to-end tracing across draft lifecycle
**Description:** Instrument traces from frontend action through API/router/service/storage spans.
**Acceptance criteria:**
- Trace graph includes correlation ID and phase timings.
- No span attributes include raw draft content.

### MSGD-119: Telemetry redaction CI guardrails
**Description:** Add CI assertions to block raw draft text from logs/metrics/events/traces fixtures.
**Acceptance criteria:**
- CI fails on forbidden field/value patterns.
- Allowlist exceptions require explicit review and justification.

### MSGD-120: Security threat model refresh for drafts
**Description:** Update threat model with replay, abuse, authz bypass, and data leakage scenarios.
**Acceptance criteria:**
- Model includes mitigations and owners for each threat.
- Review outcomes tracked in security review docs.

### MSGD-121: DSAR export integration for draft data
**Description:** Include conversation-scoped draft records in user export workflow.
**Acceptance criteria:**
- Export includes only user-owned drafts.
- Integration tests verify no cross-user leakage.

### MSGD-122: Account deletion draft purge verification
**Description:** Ensure deletion pipeline purges all user drafts and records verifiable completion.
**Acceptance criteria:**
- Purge job emits deleted-count metric and completion status.
- Post-purge verifier confirms zero residual user drafts.

### MSGD-123: Mobile draft lifecycle E2E suite
**Description:** Expand Playwright coverage for save/load/remove/autosave on mobile viewports.
**Acceptance criteria:**
- Tests pass on iOS/Android-sized viewport matrix.
- Keyboard/focus interactions are deterministic and non-flaky.

### MSGD-124: Draft docs and QA matrix phase-2 refresh
**Description:** Update API/developer/QA docs for autosave, conflicts, retries, and rate-limiting behaviors.
**Acceptance criteria:**
- Docs include sequence diagrams and error matrix for new flows.
- QA matrix maps each phase-2 behavior to explicit test scenarios.
# Newsfeed Drafts — Phase 2 Backlog (Production Readiness)

### NFD-101: Add idempotency key support for draft create
**Description:** Implement idempotency-key handling for draft creation to make client retries safe during network instability.
**Acceptance criteria:**
- Replayed create requests with identical key/payload return the same draft identity.
- Reused keys with conflicting payloads fail with deterministic conflict errors.

### NFD-102: Add idempotency key support for draft update
**Description:** Extend idempotency handling to draft updates so autosave retries do not produce divergent state.
**Acceptance criteria:**
- Replayed update requests with same key/payload return stable responses.
- Metrics differentiate idempotent replay from true version-conflict failures.

### NFD-103: Add draft read-after-write consistency checks
**Description:** Add integration tests validating immediate list/get consistency after create/update/delete operations across pagination boundaries.
**Acceptance criteria:**
- Tests verify no stale reads in common read-after-write paths.
- Regression suite catches duplicate/missing items after rapid mutations.

### NFD-104: Add publish transaction rollback hardening
**Description:** Harden publish-from-draft flow to guarantee deterministic behavior on partial failure between post creation and draft cleanup.
**Acceptance criteria:**
- keep-copy and delete-copy modes are explicitly validated under injected failures.
- Failure telemetry reports stage-specific error codes for triage.

### NFD-105: Add attachment reconciliation preflight API
**Description:** Implement a draft preflight endpoint that validates attachment ownership/existence and returns remediation details.
**Acceptance criteria:**
- Endpoint returns per-reference status and remediation hints.
- Composer can invoke preflight without losing unsaved editor state.

### NFD-106: Add orphaned draft attachment cleanup worker
**Description:** Introduce scheduled cleanup for attachment objects no longer referenced by active drafts or published posts.
**Acceptance criteria:**
- Worker emits scanned/deleted/skipped/failure counters.
- Safety windows prevent deleting recently uploaded or still-referenced objects.

### NFD-107: Add quota race-condition stress tests
**Description:** Add concurrency stress coverage for create/update/delete operations to validate quota accounting under contention.
**Acceptance criteria:**
- Quota is never exceeded under concurrent mutation races.
- Quota error payload values remain accurate and stable.

### NFD-108: Add retention boundary + clock skew integration tests
**Description:** Build time-travel tests for retention expiration with simulated clock skew across API callers and backend.
**Acceptance criteria:**
- Expiry semantics are correct at exact boundary timestamps.
- Skew scenarios do not cause premature expiration or ghost retrieval.

### NFD-109: Add pagination token tamper-resistance tests
**Description:** Expand pagination tests to include token tampering, replay, and invalid-shape handling.
**Acceptance criteria:**
- Tampered tokens are rejected with deterministic typed errors.
- Legitimate pagination traversal remains duplicate-free and gap-free.

### NFD-110: Add high-cardinality account performance benchmarks
**Description:** Benchmark draft list/get/update for large draft counts and near-limit payload sizes.
**Acceptance criteria:**
- Benchmark report includes p50/p95/p99 latency and read/write cost indicators.
- Performance thresholds are enforced in perf CI jobs.

### NFD-111: Add autosave circuit-breaker policy
**Description:** Add adaptive circuit-breaker behavior to autosave to prevent retry storms during backend degradation.
**Acceptance criteria:**
- Autosave pauses after configurable transient-failure threshold.
- Recovery resumes safely without duplicate writes or stale overwrites.

### NFD-112: Add offline mutation queue and replay ordering
**Description:** Implement offline queueing for draft mutations with deterministic replay order on reconnect.
**Acceptance criteria:**
- Offline edits replay in-order and preserve user-intended final content.
- Replay conflicts surface clear merge/retry guidance in UI.

### NFD-113: Add cross-device conflict end-to-end scenario
**Description:** Add E2E tests for multi-session editing where one client becomes stale and must recover.
**Acceptance criteria:**
- Test validates conflict response and guided recovery flow.
- Final server draft reflects explicit user conflict resolution.

### NFD-114: Add publish parity differential suite
**Description:** Create differential tests comparing direct post publish and publish-from-draft outputs across content permutations.
**Acceptance criteria:**
- Assertions cover format fields, attachment metadata, lock settings, and visibility.
- Any intentional parity deviations are documented and asserted.

### NFD-115: Add telemetry schema governance + versioning
**Description:** Enforce versioned telemetry contracts for draft lifecycle events across client and server emitters.
**Acceptance criteria:**
- Invalid event shapes are rejected or normalized with diagnostics.
- Schema/version drift triggers CI failures with actionable output.

### NFD-116: Add production observability dashboard pack
**Description:** Build dashboards for draft funnel conversion, conflict rates, retry behavior, and top failure reasons.
**Acceptance criteria:**
- Dashboards support cohort/flag dimensions for rollout analysis.
- Ownership, runbook links, and maintenance expectations are documented.

### NFD-117: Add SLOs and alert routing for drafts
**Description:** Define draft subsystem SLOs and configure alerts for latency, error rate, and telemetry ingestion health.
**Acceptance criteria:**
- SLO targets and alert thresholds are codified in monitoring config.
- Alerts link to remediation runbooks and escalation paths.

### NFD-118: Add security fuzzing for draft payload parser
**Description:** Add fuzz corpus for rich-text structures, encoded URL edge cases, and boundary-size payload fragments.
**Acceptance criteria:**
- Fuzz suite runs in CI and fails on parser/validator regressions.
- Error responses avoid leaking sensitive internals.

### NFD-119: Add cross-tenant authorization regression matrix
**Description:** Expand route-level negative tests to ensure drafts cannot be read/updated/deleted/published across account boundaries.
**Acceptance criteria:**
- Unauthorized access attempts consistently fail with non-disclosing errors.
- Denied requests produce zero write side effects.

### NFD-120: Add structured audit logging for draft lifecycle actions
**Description:** Emit structured audit events for create/update/delete/publish actions with actor/resource/outcome metadata.
**Acceptance criteria:**
- Audit events include stable fields required for investigations.
- Sensitive content fields are redacted in all audit sinks.

### NFD-121: Add API error-code handbook for drafts
**Description:** Publish a versioned draft error-code reference with retry semantics and client handling recommendations.
**Acceptance criteria:**
- Handbook includes all draft route-specific errors and sample responses.
- Each error documents retryability and expected UX handling.

### NFD-122: Add rollout automation guardrails
**Description:** Add pre-deploy checks for draft feature flags, cohort config, kill-switch readiness, and rollback gating.
**Acceptance criteria:**
- Misconfigured rollout settings block promotion.
- Rollback checklist is executable and linked from deployment docs.

### NFD-123: Add incident response runbook + tabletop checklist
**Description:** Create operations runbooks for quota spikes, conflict surges, publish failures, and telemetry drops.
**Acceptance criteria:**
- Runbook includes concrete queries/commands and decision trees.
- Tabletop drill checklist is documented for on-call readiness.

### NFD-124: Add launch-readiness load and soak testing suite
**Description:** Define and automate normal/burst/soak traffic tests for draft CRUD and publish-from-draft paths.
**Acceptance criteria:**
- Suite reports throughput, saturation, and error-budget burn metrics.
- Launch signoff requires meeting documented pass thresholds.
# Mass Messaging — Phase 2 Follow-up Implementation Tickets

### MSG-101: Replace thread kickoff with durable queue publish
**Description:** Move campaign dispatch from in-process threads to durable queue enqueue so jobs survive API restarts.
**Acceptance criteria:**
- API only returns success after campaign enqueue metadata is durably persisted.
- Enqueue failure leaves campaign in non-processing state with explicit error code.

### MSG-102: Add dedicated queue consumer worker service
**Description:** Implement standalone worker process to consume queued campaign jobs and run fanout outside API pods.
**Acceptance criteria:**
- Worker runtime can scale independently from API deployment.
- Worker startup/readiness/health behavior is documented and test covered.

### MSG-103: Add distributed campaign lease lock
**Description:** Introduce campaign lease records so only one worker instance can process a campaign at a time.
**Acceptance criteria:**
- Concurrent workers cannot process the same campaign simultaneously.
- Lease expiry and takeover behavior is validated by race-condition tests.

### MSG-104: Implement worker heartbeat and stale recovery
**Description:** Persist periodic worker heartbeat and requeue campaigns whose lease holder disappears.
**Acceptance criteria:**
- Stale in-progress campaigns are detected and requeued automatically.
- Recovery logic guarantees already-sent destinations are not resent.

### MSG-105: Add campaign cancellation endpoint
**Description:** Provide API to cancel scheduled/pending/processing campaigns with deterministic transition rules.
**Acceptance criteria:**
- Cancellation prevents future destination sends after acknowledgment.
- Response includes sent vs prevented destination counts.

### MSG-106: Add replay endpoint for failed destinations
**Description:** Support replaying failed destinations from completed campaigns without duplicating successful sends.
**Acceptance criteria:**
- Replay references source campaign in audit trail.
- Replay path respects destination idempotency keys.

### MSG-107: Add scheduled campaign edit window
**Description:** Allow editing scheduled campaigns before lock-in while preserving immutable change history.
**Acceptance criteria:**
- Edit operations are blocked once campaign enters processing.
- Audit events include before/after payload and schedule values.

### MSG-108: Persist rate-limit counters in shared store
**Description:** Replace in-memory create throttles with shared backend counters for multi-node correctness.
**Acceptance criteria:**
- Rate limits are enforced consistently across all API replicas.
- Existing blocked error contracts remain backward compatible.

### MSG-109: Add tenant-specific quota overrides
**Description:** Support per-tenant configuration for campaigns/hour, destinations/campaign, and worker concurrency.
**Acceptance criteria:**
- Override precedence and defaults are deterministic and documented.
- Effective quota source is exposed in admin diagnostics.

### MSG-110: Add destination dedupe fingerprint checks
**Description:** Persist campaign+destination+payload fingerprint to suppress duplicate send attempts.
**Acceptance criteria:**
- Duplicate attempts resolve to explicit no-op outcomes.
- Deduplication behavior is validated in retry/recovery tests.

### MSG-111: Add dead-letter queue for terminal failures
**Description:** Route irrecoverable destination failures to DLQ with replay tooling.
**Acceptance criteria:**
- DLQ records include canonical error metadata and campaign references.
- Replay from DLQ preserves idempotency guarantees.

### MSG-112: Add retry jitter and retry budget policy
**Description:** Introduce randomized backoff jitter and per-campaign retry budget caps.
**Acceptance criteria:**
- Retry intervals include jitter and are runtime configurable.
- Processing halts retries when budget threshold is exceeded.

### MSG-113: Add dependency circuit breaker controls
**Description:** Add circuit-breaker handling for repeated downstream failures (DDB/archive/metering).
**Acceptance criteria:**
- Circuit open/half-open/closed states are observable via metrics.
- Worker behavior during open circuit is deterministic and documented.

### MSG-114: Add campaign max-runtime timeout guard
**Description:** Enforce campaign processing timeout with controlled terminal status and reason code.
**Acceptance criteria:**
- Long-running campaigns transition to timeout terminal state.
- Timeout reason is visible in API and audit records.

### MSG-115: Add campaign list/search endpoint
**Description:** Provide paginated campaign list API with filter/sort support for sender/status/mode/time range.
**Acceptance criteria:**
- Endpoint supports stable pagination and deterministic sorting.
- OpenAPI docs include filter examples and response shape.

### MSG-116: Add admin diagnostics endpoint
**Description:** Expose privileged diagnostics for worker attempts, retries, failure buckets, and lease events.
**Acceptance criteria:**
- Endpoint enforces admin scope checks and audit logging.
- Diagnostics payload is sufficient for triage without raw log scraping.

### MSG-117: Expand structured audit lifecycle coverage
**Description:** Emit structured audit events for every campaign lifecycle mutation and operator action.
**Acceptance criteria:**
- All state transitions emit a canonical audit event.
- Audit schema compatibility is enforced by contract tests.

### MSG-118: Harden payload redaction in logs
**Description:** Enforce centralized redaction of campaign content across API/worker error paths.
**Acceptance criteria:**
- Message payload text never appears in plaintext logs.
- Redaction behavior is covered by regression tests.

### MSG-119: Add moderation/policy pre-check integration
**Description:** Execute policy checks at create-time and pre-send time to block disallowed content.
**Acceptance criteria:**
- Policy failures return machine-readable codes and guidance.
- Policy outcomes are emitted to audit and metrics streams.

### MSG-120: Split campaign permission scopes
**Description:** Add fine-grained scopes for create/read/cancel/replay/diagnostics operations.
**Acceptance criteria:**
- Route-level scope enforcement is consistent across all campaign endpoints.
- Unauthorized access attempts are audit-logged and metrically counted.

### MSG-121: Validate legal hold/export interoperability
**Description:** Ensure campaign-originated messages are fully represented in legal-hold and export flows.
**Acceptance criteria:**
- Export payload includes campaign metadata and destination context.
- Integration tests verify hold-on and hold-off scenarios.

### MSG-122: Add queue lag and backlog age metrics
**Description:** Emit queue-depth, lag, and backlog-age metrics keyed by tenant and mode.
**Acceptance criteria:**
- Dashboards display lag and age with environment dimensions.
- Alerting thresholds can trigger directly from emitted series.

### MSG-123: Add multi-window SLO burn-rate alerts
**Description:** Define burn-rate alerts for destination failures and worker latency SLOs.
**Acceptance criteria:**
- Alerts include severity mapping for page vs ticket.
- Alert annotations link to owner and runbook sections.

### MSG-124: Add campaign anomaly detector jobs
**Description:** Run periodic checks for stuck campaigns, retry spikes, and status/counter anomalies.
**Acceptance criteria:**
- Detector outputs machine-readable findings with severity.
- Findings can trigger notifications/webhooks for ops workflows.

### MSG-125: Add counter reconciliation repair job
**Description:** Implement recompute/repair job that rebuilds campaign counters from destination truth.
**Acceptance criteria:**
- Job supports dry-run and apply modes.
- Repair actions are idempotent and audit tracked.

### MSG-126: Add queue-backed integration harness
**Description:** Build integration tests for create→enqueue→worker→status flows using queue semantics.
**Acceptance criteria:**
- Harness covers immediate and scheduled campaigns.
- Tests verify duplicate queue deliveries do not duplicate sends.

### MSG-127: Add worker crash-recovery tests
**Description:** Simulate worker termination mid-campaign and verify reprocessing correctness.
**Acceptance criteria:**
- Completed destinations are not resent after recovery.
- Campaign reaches correct terminal status after restart.

### MSG-128: Add high-volume load/performance suite
**Description:** Benchmark throughput, latency, and retry amplification for campaigns with large destination counts.
**Acceptance criteria:**
- Suite reports throughput plus p95/p99 latencies.
- Capacity thresholds and bottlenecks are documented.

### MSG-129: Add chaos fault-injection tests
**Description:** Inject DDB throttling/network/archive outages to validate retry and circuit-breaker behavior.
**Acceptance criteria:**
- Worker behavior under faults matches documented failure policy.
- Recovery path avoids duplicate delivery side effects.

### MSG-130: Add frontend real-time progress stream
**Description:** Implement SSE/WebSocket campaign progress updates with automatic polling fallback.
**Acceptance criteria:**
- Active campaign progress updates in near real-time.
- Polling fallback activates seamlessly when stream fails.

### MSG-131: Virtualize large destination status tables
**Description:** Optimize frontend rendering for campaigns with thousands of destinations.
**Acceptance criteria:**
- UI remains responsive for 5k+ destination rows.
- Frontend tests validate virtualization behavior and pagination.

### MSG-132: Add CSV bulk destination import UX
**Description:** Allow destination import via CSV with dedupe preview and row-level validation errors.
**Acceptance criteria:**
- Invalid rows are surfaced before submission.
- Imported rows merge safely with manual destination selection.

### MSG-133: Run accessibility hardening pass
**Description:** Improve keyboard navigation, ARIA semantics, and screen-reader support in mass-message UI.
**Acceptance criteria:**
- Automated accessibility checks pass for compose/status flows.
- Keyboard-only e2e coverage is added for primary actions.

### MSG-134: Expand operational runbook with drills
**Description:** Add response playbooks for queue outages, stuck campaigns, replay operations, and rollback.
**Acceptance criteria:**
- Runbook includes command-level remediation procedures.
- Drill evidence captures outcomes and owners.

### MSG-135: Add release gate automation for rollout readiness
**Description:** Create pre-rollout gate that validates schema, queue health, worker health, alerts, and smoke flow.
**Acceptance criteria:**
- Gate fails fast on missing readiness prerequisites.
- Output includes actionable remediation instructions.

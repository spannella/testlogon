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

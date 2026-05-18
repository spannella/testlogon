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

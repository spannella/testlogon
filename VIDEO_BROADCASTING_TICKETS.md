# Video Broadcasting — Implementation Tickets

This ticket set converts `VIDEO_BROADCASTING_PLAN.md` into executable engineering work. Tickets are grouped by epic and include scope, deliverables, and acceptance criteria.

## Epic 1: Architecture, ADRs, and Platform Readiness

### BRD-001 — Architecture Decision Record and system boundaries
**Type:** Feature  
**Priority:** P0  
**Dependencies:** None
**Status:** ✅ Implemented (2026-03-25 via `docs/adr/ADR-0003-brd001-broadcast-system-boundaries.md`)

**Scope**
- Produce ADR documenting end-to-end broadcast architecture:
  - RTMP ingest
  - MediaLive processing + watermarking
  - MediaPackage DRM packaging
  - S3 archive output
  - CloudFront distribution
- Define service ownership boundaries (app control plane vs infra automation).
- Document non-goals for MVP.

**Deliverables**
- ADR markdown in repository docs.
- Sequence diagrams for create/start/stop lifecycle.

**Acceptance Criteria**
- ADR explicitly selects initial DRM strategy and key provider approach.
- Lifecycle diagrams include success and failure paths.
- Stakeholder signoff recorded.

---

### BRD-002 — AWS quotas, cost model, and account bootstrap
**Type:** Feature  
**Priority:** P0  
**Dependencies:** BRD-001
**Status:** ✅ Implemented (2026-03-25 via runbook + cost sheet + readiness script)

**Scope**
- Validate/raise service quotas for MediaLive/MediaPackage/CloudFront.
- Define cost model assumptions by channel profile and concurrency.
- Create bootstrap checklist for required IAM roles, KMS keys, S3 buckets, and tagging policy.

**Deliverables**
- Quota request matrix.
- Cost estimation sheet.
- Bootstrap runbook.

**Acceptance Criteria**
- Required quotas are approved in target region(s) or explicit fallback exists.
- Cost per-hour estimate is available for each rendition preset.
- Bootstrap runbook is executable in a clean account.

---

## Epic 2: Data Model and Control-Plane APIs

### BRD-003 — Broadcast schema and migrations
**Type:** Feature  
**Priority:** P0  
**Dependencies:** BRD-001
**Status:** ✅ Implemented (2026-03-25 via migration+rollback, models defaults, and store query indexes)

**Scope**
- Add persistent entities:
  - `broadcast_profile`
  - `broadcast_session`
  - `broadcast_output`
- Add indexes for status, creator, and time-window queries.
- Add migration and rollback script.

**Deliverables**
- DB migration files.
- Model definitions and repository access layer.

**Acceptance Criteria**
- Migration applies cleanly on empty and populated DB.
- Backward-compatible defaults are set for newly added fields.
- Query performance meets baseline for session listing.

---

### BRD-004 — Session lifecycle state machine and transition guardrails
**Type:** Feature  
**Priority:** P0  
**Dependencies:** BRD-003
**Status:** ✅ Implemented (2026-03-25 via state machine module + transition audit persistence)

**Scope**
- Implement lifecycle states: `draft -> provisioning -> ready -> live -> stopping -> stopped -> error`.
- Enforce legal transitions server-side.
- Capture transition reasons and timestamps.

**Deliverables**
- State machine module and tests.
- Standardized error codes for invalid transitions.

**Acceptance Criteria**
- Invalid transition attempts are rejected with stable error code.
- Transition audit records are persisted.
- Unit tests cover all legal/illegal transitions.

---

### BRD-005 — Broadcast profile/session API endpoints
**Type:** Feature  
**Priority:** P0  
**Dependencies:** BRD-003, BRD-004
**Status:** ✅ Implemented (2026-03-25 via `/broadcast` router + role checks + route contract tests)

**Scope**
- Implement endpoints:
  - `POST /broadcast/profiles`
  - `POST /broadcast/sessions`
  - `POST /broadcast/sessions/{id}/start`
  - `POST /broadcast/sessions/{id}/stop`
  - `GET /broadcast/sessions/{id}`
- Add request/response contracts and validation.
- Add role-based authorization checks.

**Deliverables**
- Router handlers and service methods.
- OpenAPI contract updates.

**Acceptance Criteria**
- Endpoints return deterministic schema and status codes.
- Unauthorized roles cannot start/stop sessions.
- Contract tests pass for all endpoints.

---

## Epic 3: Secrets, Security, and Compliance

### BRD-006 — Stream key and DRM credential secret management
**Type:** Feature  
**Priority:** P0  
**Dependencies:** BRD-003
**Status:** ✅ Implemented (2026-03-26 via secret service abstraction + reference-only validation + metadata migration)

**Scope**
- Integrate Secrets Manager (or SSM+KMS fallback) for stream keys and DRM credentials.
- Persist only secret references in DB.
- Add rotation metadata fields and retrieval policy.

**Deliverables**
- Secret service abstraction.
- Secret reference model and migration update.

**Acceptance Criteria**
- Raw secret values are never persisted in DB.
- Secret retrieval failures are surfaced with non-sensitive errors.
- Audit logs include secret reference IDs only.

---

### BRD-007 — IAM least-privilege policies and security guardrails
**Type:** Feature  
**Priority:** P0  
**Dependencies:** BRD-002

**Scope**
- Create minimal IAM policies for app orchestration role.
- Add deny-by-default boundary and resource-level constraints.
- Add security checks to CI for policy drift (lint/static check).

**Deliverables**
- IAM policy documents/templates.
- CI policy validation script.

**Acceptance Criteria**
- Orchestration operations succeed with least-privilege role.
- Policy checks fail CI when broadened permissions are introduced.
- Security review signoff is recorded.

---

### BRD-008 — Broadcast action audit logging
**Type:** Feature  
**Priority:** P1  
**Dependencies:** BRD-005
**Status:** ✅ Implemented (2026-03-26 via broadcast audit service + admin query endpoint + correlation IDs)

**Scope**
- Log create/start/stop/delete actions with actor + correlation ID.
- Add immutable audit event shape.
- Provide admin query endpoint/filter for audit records.

**Deliverables**
- Audit logging middleware/service integration.
- Admin API endpoint for audit queries.

**Acceptance Criteria**
- Every mutating broadcast action writes an audit record.
- Audit records include request correlation ID and actor identity.
- Admin query endpoint supports time and actor filters.

---

## Epic 4: Local Provider and Host-Local Development Stack

### BRD-009 — Provider abstraction (`local|aws`) and interface contracts
**Type:** Feature  
**Priority:** P0  
**Dependencies:** BRD-005
**Status:** ✅ Implemented (2026-03-26 via provider interface/factory, local+aws stubs, and contract tests)

**Scope**
- Introduce `BROADCAST_PROVIDER` switch.
- Define provider interface for provision/start/stop/status/teardown.
- Implement provider selection wiring in service layer.

**Deliverables**
- Provider interface and factory.
- Local and AWS provider stubs with contract tests.

**Acceptance Criteria**
- Provider can be swapped by configuration only.
- Contract tests run against both providers.
- No endpoint contract changes required between providers.

---

### BRD-010 — Local RTMP ingest + ffmpeg watermark pipeline
**Type:** Feature  
**Priority:** P0  
**Dependencies:** BRD-009
**Status:** ✅ Implemented (2026-03-26 via local compose stack + nginx-rtmp config + ffmpeg ABR watermark worker)

**Scope**
- Add Docker Compose services for RTMP ingest (`nginx-rtmp` or SRS).
- Add `ffmpeg` worker for ABR output and watermark overlay.
- Map stream key to local ingest route and output directory.

**Deliverables**
- Compose config and local service configs.
- Watermark asset loading and scaling rules for local pipeline.

**Acceptance Criteria**
- OBS can publish RTMP stream to localhost ingest.
- Local HLS outputs are generated with visible watermark.
- Pipeline restart does not require manual state repair.

---

### BRD-011 — Local DRM simulation and mock key service
**Type:** Feature  
**Priority:** P1  
**Dependencies:** BRD-010

**Scope**
- Implement AES-128 HLS encryption for local output.
- Build mock key service endpoint and token validation.
- Keep request/response contracts aligned with future SPEKE adapter.

**Deliverables**
- Mock key service and local auth middleware.
- Developer docs for encrypted local playback.

**Acceptance Criteria**
- Encrypted local playlist plays only with valid token/key fetch.
- Key server endpoints are test-covered.
- Provider contract remains compatible with AWS pathway.

---

### BRD-012 — Local S3/CDN equivalents (MinIO + cache proxy)
**Type:** Feature  
**Priority:** P1  
**Dependencies:** BRD-010

**Scope**
- Add MinIO for archive storage.
- Add reverse proxy cache to emulate CloudFront behavior.
- Add signed URL/token verification path in local proxy.

**Deliverables**
- Compose services and initialization scripts.
- Local playback URL generation compatible with app API.

**Acceptance Criteria**
- Archive outputs are persisted in MinIO with session prefixing.
- Playback through local cache proxy succeeds with auth token.
- Cache headers and behavior are observable in logs.

---

### BRD-013 — Local debug/ops developer page
**Type:** Feature  
**Priority:** P2  
**Dependencies:** BRD-010, BRD-012

**Scope**
- Add internal debug UI page showing:
  - ingest status
  - transcoder logs
  - manifest URL
  - archive object listing
- Restrict page to dev/internal environments.

**Deliverables**
- Frontend page and backend debug endpoints.
- Feature flag and auth guard.

**Acceptance Criteria**
- Devs can verify full local pipeline without shelling into containers.
- Debug routes are inaccessible in production mode.
- Page renders updates within expected polling interval.

---

## Epic 5: AWS Orchestration MVP

### BRD-014 — MediaLive input/channel provisioning workflows
**Type:** Feature  
**Priority:** P0  
**Dependencies:** BRD-009, BRD-007

**Scope**
- Implement AWS provider logic for MediaLive input + channel create/update.
- Support idempotency keys and correlation IDs.
- Persist ARNs and channel state snapshots.

**Deliverables**
- MediaLive orchestration module.
- Retry/backoff behavior for transient AWS errors.

**Acceptance Criteria**
- Repeated create requests do not create duplicate channels.
- Provisioning status is reflected in session state.
- Error path sets session to `error` with actionable reason.

---

### BRD-015 — MediaPackage channel/endpoint creation with DRM hooks
**Type:** Feature  
**Priority:** P0  
**Dependencies:** BRD-014, BRD-006

**Scope**
- Provision MediaPackage channel and HLS endpoint.
- Configure DRM parameters and key provider linkage placeholders.
- Persist endpoint URLs and packaging metadata.

**Deliverables**
- MediaPackage orchestration module.
- Config mapping from profile to package endpoint settings.

**Acceptance Criteria**
- Session start yields a valid playback origin endpoint.
- DRM configuration is attached for DRM-enabled profiles.
- Endpoint metadata is stored and queryable from session API.

---

### BRD-016 — S3 archive output and retention policy automation
**Type:** Feature  
**Priority:** P1  
**Dependencies:** BRD-014

**Scope**
- Configure parallel archive output group to S3.
- Apply retention/lifecycle tags and bucket policy checks.
- Store archive prefix in `broadcast_output`.

**Deliverables**
- Archive output configuration builder.
- Retention policy automation scripts/config.

**Acceptance Criteria**
- Started sessions write archive segments to expected S3 prefix.
- Lifecycle policies are attached and validated.
- Archive location is exposed in session details.

---

### BRD-017 — CloudFront playback URL generation and auth model
**Type:** Feature  
**Priority:** P1  
**Dependencies:** BRD-015

**Scope**
- Integrate CloudFront distribution mapping for MediaPackage origins.
- Implement signed playback URL or cookie issuance.
- Add optional geo/WAF policy attachment points.

**Deliverables**
- CloudFront mapping service.
- Auth token signing utilities and API integration.

**Acceptance Criteria**
- Session API returns CloudFront playback URL.
- Playback denied when signature/token invalid.
- Security headers and cache policy defaults are applied.

---

## Epic 6: Reliability, Monitoring, and Operations

### BRD-018 — Broadcast health polling and drift detection
**Type:** Feature  
**Priority:** P1  
**Dependencies:** BRD-014, BRD-015

**Scope**
- Poll provider state (local/AWS) and reconcile to session state.
- Detect desired-vs-actual drift and flag incidents.
- Add stale-session recovery jobs.

**Deliverables**
- Health reconciler worker.
- Drift detection rules and alert events.

**Acceptance Criteria**
- Drift conditions are detected within defined SLA window.
- Reconciler updates persisted status reliably.
- Recovery behavior is documented and tested.

---

### BRD-019 — Metrics, dashboards, and alerting
**Type:** Feature  
**Priority:** P1  
**Dependencies:** BRD-018

**Scope**
- Emit metrics for:
  - provisioning latency
  - start/stop success rates
  - input loss/output error counts
- Build operational dashboards.
- Configure critical alert thresholds and routing.

**Deliverables**
- Metrics instrumentation.
- Dashboard templates and alarm configs.

**Acceptance Criteria**
- Dashboards expose key KPIs for on-call diagnosis.
- Alert routing verified in non-prod smoke test.
- Metrics include provider dimension (`local|aws`).

---

### BRD-020 — Runbooks and incident response for live broadcast failures
**Type:** Feature  
**Priority:** P2  
**Dependencies:** BRD-018, BRD-019

**Scope**
- Create runbooks for common incidents:
  - ingest failure
  - no output playback
  - DRM key issues
  - watermark misconfiguration
- Add triage checklist and escalation matrix.

**Deliverables**
- On-call runbook documents.
- Incident template for postmortems.

**Acceptance Criteria**
- On-call engineers can execute runbook without author assistance.
- Each incident class has rollback or mitigation procedure.
- Postmortem template includes prevention action tracking.

---

## Epic 7: Quality, Validation, and Release Gating

### BRD-021 — Contract/integration test suite for broadcast APIs
**Type:** Feature  
**Priority:** P0  
**Dependencies:** BRD-005, BRD-009

**Scope**
- Add API contract tests for profile/session lifecycle endpoints.
- Add provider contract tests for local and AWS adapters.
- Add snapshot tests for session status and output payloads.

**Deliverables**
- Automated test suite in CI.
- Test fixtures for both provider modes.

**Acceptance Criteria**
- CI fails on breaking API contract changes.
- Provider implementations pass shared contract test suite.
- Test coverage includes all lifecycle transitions.

---

### BRD-022 — End-to-end local pipeline test harness
**Type:** Feature  
**Priority:** P1  
**Dependencies:** BRD-010, BRD-011, BRD-012

**Scope**
- Add automated E2E that:
  - starts local stack
  - pushes synthetic RTMP input
  - validates watermark in generated output
  - verifies encrypted HLS and archive persistence
- Integrate into optional CI job or nightly workflow.

**Deliverables**
- E2E script/harness and assertions.
- Synthetic input media assets and expected outputs.

**Acceptance Criteria**
- E2E flow completes successfully on clean environment.
- Failures provide actionable logs/artifacts.
- Harness execution time meets agreed CI budget.

---

### BRD-023 — Release gate for broadcast feature rollout
**Type:** Feature  
**Priority:** P1  
**Dependencies:** BRD-021, BRD-022, BRD-019

**Scope**
- Add release-gate script validating:
  - required metrics wired
  - critical alerts configured
  - API contracts passing
  - security checks passing
- Integrate gate into deployment pipeline.

**Deliverables**
- Release gate script and CI/CD integration.
- Gate exceptions policy.

**Acceptance Criteria**
- Production deploy is blocked when any critical gate fails.
- Exception process is documented and auditable.
- Gate output clearly identifies failed controls.

---

## Suggested Delivery Sequence
1. **Foundation:** BRD-001 → BRD-005
2. **Security and provider abstraction:** BRD-006, BRD-007, BRD-009
3. **Local developer parity:** BRD-010 → BRD-013
4. **AWS MVP path:** BRD-014 → BRD-017
5. **Operations and hardening:** BRD-018 → BRD-023

## Milestone Mapping
- **Milestone A (Control Plane Ready):** BRD-001..BRD-009
- **Milestone B (Local E2E Ready):** BRD-010..BRD-013 + BRD-021
- **Milestone C (AWS MVP Ready):** BRD-014..BRD-017 + BRD-019
- **Milestone D (Production Hardening):** BRD-018..BRD-023

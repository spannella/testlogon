# KYC System — Implementation Ticket Backlog

This backlog translates `docs/kyc-implementation-plan.md` into implementation-ready engineering tickets with scope, dependencies, and acceptance criteria.

## Milestone 1 — Foundation (data model + base case lifecycle)

### KYC-001: Define KYC case persistence schema and repository
**Goal**: Introduce a first-class KYC aggregate with stable cross-system references.
**Status**: ✅ Implemented (current branch)

**Scope**
- Create KYC persistence model with fields from plan:
  - identity: `kyc_case_id`, `user_sub`
  - lifecycle: `status`, `created_at`, `updated_at`, `version`
  - linked refs: questionnaire session/version, file paths, signature packet, review ticket
  - decision metadata: reviewer, reason codes, timestamps
- Add repository methods for create/get/update/list with optimistic concurrency.
- Add status and owner access patterns (GSIs if required).

**Dependencies**
- None.

**Acceptance criteria**
- KYC case can be created/read/updated with conditional version checks.
- Repository returns deterministic conflict semantics on stale writes.
- Access patterns support: lookup by case id, list by user, list by status.

---

### KYC-002: Add API contracts and error taxonomy for KYC routes
**Goal**: Establish stable request/response contracts before endpoint expansion.
**Status**: ✅ Implemented (current branch)

**Scope**
- Add Pydantic contracts for applicant and admin KYC endpoints.
- Define reusable error codes (`kyc_case_not_found`, `kyc_invalid_transition`, `kyc_submit_prereq_failed`, etc.).
- Ensure responses include enough state for clients (`status`, `missing_requirements`, links/ids).

**Dependencies**
- KYC-001.

**Acceptance criteria**
- Contract models exist for all planned route families.
- Error envelopes are consistent across KYC endpoints.
- Validation failures produce deterministic error codes.

---

### KYC-003: Implement applicant draft lifecycle endpoints
**Goal**: Allow users to create and manage draft KYC cases.
**Status**: ✅ Implemented (current branch)

**Scope**
- Add applicant endpoints:
  - `POST /v1/kyc/cases`
  - `GET /v1/kyc/cases`
  - `GET /v1/kyc/cases/{id}`
  - `PATCH /v1/kyc/cases/{id}` (draft-only mutable fields)
- Enforce ownership checks and draft-state edit guards.
- Emit audit events for create/update/read-denied actions.

**Dependencies**
- KYC-001, KYC-002.

**Acceptance criteria**
- Authenticated user can create/list/get their own draft cases.
- Cross-user access is forbidden.
- Non-draft case edits are blocked with `kyc_invalid_transition`.

---

## Milestone 2 — Artifact integration (questionnaire + files + signature)

### KYC-004: Link questionnaire sessions to KYC cases
**Goal**: Reuse existing published questionnaire flow as KYC declaration intake.
**Status**: ✅ Implemented (current branch)

**Scope**
- Add endpoint to start questionnaire session from KYC case context.
- Persist `{questionnaire_id, version_id, response_session_id}` on case.
- Add resolver to compute questionnaire completion state for submit gate.
- Optionally store generated response PDF reference when available.

**Dependencies**
- KYC-003.

**Acceptance criteria**
- Case can start and bind exactly one active questionnaire session per attempt.
- Questionnaire linkage survives retries idempotently.
- Completion status can be evaluated from linked response session.

---

### KYC-005: Implement file attachment policy and required document validator
**Goal**: Reuse file manager for KYC evidence while enforcing required document classes.
**Status**: ✅ Implemented (current branch)

**Scope**
- Define KYC-required file types (selfie, ID front/back; optional address proof by policy).
- Add API to attach canonical file-manager paths to case with type labels.
- Validate ownership/access for attached paths.
- Add validator returning missing/invalid document requirements.

**Dependencies**
- KYC-003.

**Acceptance criteria**
- Applicant can attach uploaded file-manager paths to a case.
- Required-document validator returns deterministic missing list.
- Invalid/unowned file paths are rejected.

---

### KYC-006: Add signature packet linkage and completion verifier
**Goal**: Reuse existing signature packet flow for policy/consent acknowledgement.
**Status**: ✅ Implemented (current branch)

**Scope**
- Add endpoint to create/link signature packet from policy PDF source.
- Persist packet reference + status on case.
- Add verifier that checks signer completion + final PDF availability.
- Capture legal notice version accepted for compliance traceability.

**Dependencies**
- KYC-003.

**Acceptance criteria**
- Case can create/link a signature packet idempotently.
- Completion verifier blocks submit until packet is completed.
- Final artifact reference is retrievable for reviewer context.

---

### KYC-007: Build KYC readiness endpoint
**Goal**: Give clients a single place to see what is still missing before submission.
**Status**: ✅ Implemented (current branch)

**Scope**
- Add `GET /v1/kyc/cases/{id}/readiness`.
- Aggregate questionnaire, files, and signature checks into one payload.
- Include machine-readable missing requirements + human-readable hints.

**Dependencies**
- KYC-004, KYC-005, KYC-006.

**Acceptance criteria**
- Readiness payload accurately reflects current linked artifacts.
- Missing list updates immediately after completing each requirement.
- Endpoint does not expose private artifact content; references only.

---

## Milestone 3 — Submission orchestration + ticket bootstrap

### KYC-008: Implement atomic `submit` transition with guards
**Goal**: Move case from draft to submitted only when all prerequisites are satisfied.
**Status**: ✅ Implemented (current branch)

**Scope**
- Add `POST /v1/kyc/cases/{id}/submit`.
- Validate all submit guards:
  - questionnaire session submitted,
  - required files present,
  - signature packet completed.
- Perform conditional transition `draft|needs_more_info -> submitted`.
- Persist immutable evidence snapshot/hash manifest on submission.

**Dependencies**
- KYC-007.

**Acceptance criteria**
- Submit fails with explicit missing requirements when incomplete.
- Successful submit writes immutable evidence references.
- Concurrent submit attempts produce deterministic idempotent or conflict outcomes.

---

### KYC-009: Auto-create review ticket on successful submission
**Goal**: Route submitted cases to admin review queue using existing ticket system.
**Status**: ✅ Implemented (current branch)

**Scope**
- Create ticket exactly once per submitted case.
- Use dedicated ticket space/category for KYC operations.
- Include evidence links/IDs in ticket body/metadata.
- Persist `ticket_id` back onto case.

**Dependencies**
- KYC-008.

**Acceptance criteria**
- Every successfully submitted case has exactly one linked ticket.
- Ticket includes references to questionnaire PDF/session, files, and signature final PDF.
- Retry/replay cannot create duplicate tickets.

---

### KYC-010: Build KYC↔ticket synchronization hooks
**Goal**: Keep KYC status and review thread actions consistent.
**Status**: ✅ Implemented (current branch)

**Scope**
- Sync assignment and key status changes between ticket and KYC case.
- Mirror admin request-for-info actions into ticket messages and case state.
- Record synchronization failures with retry-safe handling.

**Dependencies**
- KYC-009.

**Acceptance criteria**
- Assignment/status changes are reflected in both systems.
- Sync retries are idempotent and do not corrupt state.
- Failures are observable via logs/metrics.

---

## Milestone 4 — Admin review workflows

### KYC-011: Implement admin KYC queue/list endpoint
**Goal**: Give admins an operational queue for KYC review.
**Status**: ✅ Implemented (current branch)

**Scope**
- Add `GET /v1/kyc/admin/queue` with filters:
  - status, assignee, age/staleness, risk tier.
- Support cursor pagination and stable ordering.
- Include lightweight summary fields for triage.

**Dependencies**
- KYC-001, KYC-009.

**Acceptance criteria**
- Admins can query queue without table scans.
- Non-admin access is denied.
- Filters and pagination are deterministic.

---

### KYC-012: Implement admin KYC case detail endpoint
**Goal**: Provide a joined reviewer view of all KYC evidence references and timeline.
**Status**: ✅ Implemented (current branch)

**Scope**
- Add `GET /v1/kyc/admin/cases/{id}`.
- Return linked evidence references (questionnaire, files, signature, ticket).
- Return review timeline/events and current decision state.

**Dependencies**
- KYC-011.

**Acceptance criteria**
- Admin detail payload includes all references needed for decisioning.
- Sensitive data is scoped to authorized admin users only.
- Missing link states are explicit (not silently dropped).

---

### KYC-013: Implement admin request-more-info action
**Goal**: Let reviewers send actionable remediation requests to applicants.
**Status**: ✅ Implemented (current branch)

**Scope**
- Add `POST /v1/kyc/admin/cases/{id}/request-info`.
- Transition `under_review -> needs_more_info`.
- Post standardized follow-up message to linked ticket.
- Capture requested items in structured metadata.

**Dependencies**
- KYC-012.

**Acceptance criteria**
- Request-info action updates case state and ticket thread atomically (or with compensating retry).
- Applicant-visible required follow-ups are retrievable.
- Duplicate request submissions are idempotent.

---

### KYC-014: Implement approve/reject decision endpoints
**Goal**: Complete KYC lifecycle with auditable terminal decisions.
**Status**: ✅ Implemented (current branch)

**Scope**
- Add:
  - `POST /v1/kyc/admin/cases/{id}/approve`
  - `POST /v1/kyc/admin/cases/{id}/reject`
- Require reason codes and reviewer notes policy.
- Transition from `under_review` only.
- Mirror outcome into ticket status and activity timeline.

**Dependencies**
- KYC-012.

**Acceptance criteria**
- Only authorized admins can approve/reject.
- Invalid transitions are blocked.
- Decision reason codes and actor/timestamps are immutable once terminal.

---

## Milestone 5 — Security, observability, and operations

### KYC-015: Enforce KYC artifact authorization boundaries
**Goal**: Prevent unauthorized access to sensitive KYC evidence.
**Status**: ✅ Implemented (current branch)

**Scope**
- Add policy checks for owner vs scoped-admin access.
- Ensure non-reviewers cannot read evidence references/content.
- Add negative tests for horizontal/vertical privilege escalation paths.

**Dependencies**
- KYC-003, KYC-012.

**Acceptance criteria**
- Unauthorized reads/writes are denied with stable error codes.
- Policy behavior is covered by security-focused tests.
- Access checks are consistent across applicant/admin endpoints.

---

### KYC-016: Add audit events for all KYC state transitions and admin actions
**Goal**: Meet traceability/compliance expectations.
**Status**: ✅ Implemented (current branch)

**Scope**
- Emit structured audit events for case create/update/submit/review/decision.
- Include actor, target case, transition, and correlation IDs.
- Ensure ticket/sync actions include correlation links.

**Dependencies**
- KYC-008, KYC-014.

**Acceptance criteria**
- Every state change is represented in audit trail.
- Audits are queryable for a full case timeline reconstruction.
- Missing-audit conditions are detectable in monitoring.

---

### KYC-017: Implement KYC metrics and dashboards
**Goal**: Provide visibility into throughput, quality, and latency.
**Status**: ✅ Implemented (current branch)

**Scope**
- Track funnel metrics: draft/submitted/approved/rejected/needs_more_info.
- Track review latency percentiles and stale queue counts.
- Track submit guard failures by reason category.
- Add dashboard + baseline alerts.
  - See `docs/kyc-metrics-dashboard.md`.

**Dependencies**
- KYC-011, KYC-014.

**Acceptance criteria**
- Metrics are emitted for all key lifecycle transitions.
- Dashboard supports day-1 operational monitoring.
- Alert thresholds are documented and actionable.

---

### KYC-018: Add retention, purge, and expiration workflows
**Goal**: Enforce data lifecycle and minimize retained sensitive evidence.
**Status**: ✅ Implemented (current branch)

**Scope**
- Define per-status retention policy (rejected/expired/etc.).
- Add scheduled purge/expiration job(s).
- Ensure purge updates case/ticket references safely and audibly.
  - See `docs/kyc-retention-policy.md`.

**Dependencies**
- KYC-001, KYC-016.

**Acceptance criteria**
- Expired/rejected cases are purged per policy window.
- Purge operations are idempotent and logged.
- Post-purge reads behave predictably (tombstone/not-found semantics).

---

## Milestone 6 — Test coverage and release readiness

### KYC-019: Unit and integration tests for state machine, guards, and idempotency
**Goal**: Prove correctness of lifecycle transitions and retry behavior.
**Status**: ✅ Implemented (current branch)

**Scope**
- Unit tests for legal transitions/guards.
- Integration tests for submit + ticket creation + sync.
- Concurrency tests for conflicting admin decisions.

**Dependencies**
- KYC-008 through KYC-014.

**Acceptance criteria**
- Guard failures and transition errors are comprehensively tested.
- Idempotent retries behave correctly.
- Race conditions produce safe conflict behavior.

---

### KYC-020: End-to-end KYC happy/edge-path scenarios
**Goal**: Validate complete user/admin journeys before rollout.

**Scope**
- E2E happy path: questionnaire + files + signature + submit + approve.
- E2E reject and needs-more-info loops.
- E2E negative cases: missing files, unsigned packet, stale admin action.

**Dependencies**
- KYC-019.

**Acceptance criteria**
- Core KYC journeys pass in CI/staging.
- Critical edge failures have deterministic UX-visible errors.
- Release gate includes KYC-specific checklist and signoff.

---

## Suggested dependency order
1. KYC-001 → KYC-003 (foundation)
2. KYC-004/KYC-005/KYC-006 → KYC-007 (artifact readiness)
3. KYC-008 → KYC-009 → KYC-010 (submit and ticket bootstrap)
4. KYC-011 → KYC-014 (admin workflows)
5. KYC-015 → KYC-018 (security/ops hardening)
6. KYC-019 → KYC-020 (test and release)

# SFTP Mount Integration — Ticket Breakdown

This ticket set maps directly to `docs/sftp-mount-integration-plan.md` and decomposes the work into implementation-ready milestones for secure SFTP mount support with read/write operations.

---

## Milestone 0 — Contracts, threat model, and guardrails

### SFTP-001: Finalize SFTP mount product/API contract
**Scope**
- Define canonical mounted path namespace (`/mounts/{mount_id}/...`) and path resolution rules.
- Define mount state model (`healthy|degraded|auth_failed|unreachable|disabled`).
- Document backend behavior for mounted paths across list/download/upload/delete/move.

**Implementation artifact**
- `docs/sftp-mount-api-contract.md`

**Acceptance criteria**
- API contract and path semantics are documented and reviewed by backend + frontend.
- Mounted-path behavior is deterministic and backward compatible for existing non-mounted paths.

**Dependencies**
- None.

---

### SFTP-002: Threat model and security baseline for user-provided SFTP credentials
**Scope**
- Produce threat model for credential ingestion, storage, access, and rotation.
- Define mandatory controls: encryption approach, secret redaction, IAM boundaries, host restrictions.
- Define abuse controls (egress limits, connection timeouts, retry caps).

**Implementation artifact**
- `docs/sftp-mount-threat-model.md`

**Acceptance criteria**
- Security review sign-off exists with explicit “must-have” controls.
- Risks are mapped to concrete engineering tasks in this ticket set.

**Dependencies**
- SFTP-001.

---

### SFTP-003: Add feature flags and rollout controls for SFTP mounts
**Scope**
- Introduce service-level flag for SFTP mount functionality.
- Add optional sub-flags for write operations and share behavior on mounted paths.
- Ensure disabled path returns explicit, stable error codes.

**Acceptance criteria**
- SFTP mount feature can be enabled by environment/config only.
- Disabled paths fail safely without affecting core file-manager APIs.

**Dependencies**
- SFTP-001.

---

## Milestone 1 — Credentials and mount lifecycle

### SFTP-010: Implement encrypted credential store for SFTP connection material
**Scope**
- Create dedicated persistence model/table for SFTP credentials (separate from file nodes).
- Support auth modes:
  - username + password
  - username + private key (+ optional passphrase)
- Encrypt secrets with KMS envelope encryption.

**Acceptance criteria**
- No raw credentials are stored in plaintext at rest.
- Secret reads/writes are auditable and constrained by least-privilege IAM.

**Dependencies**
- SFTP-002.

---

### SFTP-011: Build mount metadata model and repository layer
**Scope**
- Add mount record schema: owner, host, port, auth reference, remote root, policy, status timestamps.
- Add indexes for owner-scoped listing and mount lookup.
- Add validation rules for host/port/root inputs.

**Acceptance criteria**
- Mount records can be created/read/updated/deleted independently of file node records.
- Invalid mount payloads return clear validation errors.

**Dependencies**
- SFTP-001, SFTP-010.

---

### SFTP-012: Add SFTP mount lifecycle API endpoints
**Scope**
- Implement:
  - `POST /v1/fs/mounts/sftp`
  - `GET /v1/fs/mounts`
  - `PATCH /v1/fs/mounts/{id}`
  - `DELETE /v1/fs/mounts/{id}`
  - `POST /v1/fs/mounts/{id}/test`
- Enforce owner authorization and admin visibility policy where required.

**Acceptance criteria**
- Endpoints support create/list/update/delete/test workflows end-to-end.
- Status payloads include mount health and actionable error reason where applicable.

**Dependencies**
- SFTP-011.

---

### SFTP-013: Implement credential rotation and revocation workflow
**Scope**
- Allow credential replacement without changing mount ID/path mapping.
- Support mount disable/revoke semantics.
- Add audit events for rotate/revoke actions.

**Acceptance criteria**
- Rotating credentials updates subsequent connection attempts without remounting.
- Revoked/disabled mounts are blocked for all read/write operations.

**Dependencies**
- SFTP-010, SFTP-012.

---

## Milestone 2 — Provider abstraction and read path

### SFTP-020: Introduce storage-provider abstraction in file-manager service
**Scope**
- Define provider contract for file operations (`list_dir`, `stat`, `read_stream`, `write_stream`, `mkdir`, `delete`, `move`).
- Implement/adapter for existing S3-backed behavior as baseline provider.
- Add provider resolver based on normalized path.

**Acceptance criteria**
- Existing non-mounted behavior remains unchanged through S3 provider.
- Provider dispatch is test-covered for mounted vs non-mounted paths.

**Dependencies**
- SFTP-001.

---

### SFTP-021: Implement SFTP client module with connection lifecycle management
**Scope**
- Build SFTP connectivity client with bounded connection pooling/reuse.
- Implement host key verification strategy from approved policy.
- Map low-level connection/auth errors to stable domain error codes.

**Acceptance criteria**
- Connection/auth/network errors are categorized and surfaced consistently.
- Connection lifecycle is observable (active sessions, failures, latency).

**Dependencies**
- SFTP-002, SFTP-010.

---

### SFTP-022: Implement `SFTPProvider` read operations
**Scope**
- Implement `list_dir`, `stat`, `read_stream` against remote SFTP paths.
- Enforce mount root scoping to prevent path escape.
- Normalize metadata (size, modified time, type) into file-manager format.

**Acceptance criteria**
- Users can browse mounted folders and download files through existing file-manager routes.
- Path traversal attempts are rejected deterministically.

**Dependencies**
- SFTP-020, SFTP-021.

---

### SFTP-023: Wire mounted-path routing into file-manager list/info/download routes
**Scope**
- Extend path resolution logic to detect `/mounts/{id}/...` and resolve mount ownership.
- Route mounted paths through `SFTPProvider` while preserving existing ACL/auth checks.
- Add mount-aware error mapping in API responses.

**Acceptance criteria**
- Mounted paths work with list/info/download APIs without regressions for native paths.
- Unauthorized access to mounts or mounted content returns correct HTTP status.

**Dependencies**
- SFTP-022.

---

## Milestone 3 — Write path and operational resilience

### SFTP-030: Implement `SFTPProvider` write operations
**Scope**
- Implement `write_stream`, `mkdir`, `delete`, and `move/rename`.
- Support overwrite behavior with explicit policy.
- Enforce read-only vs read-write mount policy.

**Acceptance criteria**
- Upload/create/delete/rename flows succeed for read-write mounts.
- Read-only mounts reject mutating operations with stable error codes.

**Dependencies**
- SFTP-022.

---

### SFTP-031: Integrate mounted write flows into file-manager upload/delete/move routes
**Scope**
- Route mounted upload/delete/move APIs through provider abstraction.
- Preserve existing input validation, auth checks, and audit behavior.
- Ensure mutating operations include mount context in audit metadata.

**Acceptance criteria**
- Existing routes perform mounted mutations safely without changing external API shape.
- Native S3-backed file flows remain unaffected.

**Dependencies**
- SFTP-030, SFTP-023.

---

### SFTP-032: Add retry/timeouts/circuit-breaker controls for SFTP operations
**Scope**
- Add per-operation timeout budgets and bounded retries for transient failures.
- Add circuit-breaker or degradation mechanism for repeatedly failing mounts/hosts.
- Surface health status updates on repeated failures.

**Acceptance criteria**
- Repeated remote failures do not exhaust service resources.
- API returns actionable transient/permanent failure signals.

**Dependencies**
- SFTP-021, SFTP-022, SFTP-030.

---

### SFTP-033: Implement mount health checks and background status refresh
**Scope**
- Implement active test endpoint behavior and optional periodic background probes.
- Persist latest status, failure reason, and timestamp in mount metadata.
- Expose status in mount listing and mount detail responses.

**Acceptance criteria**
- Health state is visible and updated without requiring file operations.
- Status transitions are audited and observable.

**Dependencies**
- SFTP-012, SFTP-032.

---

## Milestone 4 — Metering, audit, and policy controls

### SFTP-040: Extend usage metering for mounted read/write bytes and operation counts
**Scope**
- Integrate mounted download/upload byte accounting into existing usage system.
- Add operation counters for list/read/write/delete/move on mounts.
- Tag usage records by backend type (`s3|sftp`).

**Acceptance criteria**
- Usage reporting distinguishes mounted SFTP activity from native storage activity.
- Quota enforcement remains consistent for mounted operations.

**Dependencies**
- SFTP-023, SFTP-031.

---

### SFTP-041: Add mount-specific audit event taxonomy
**Scope**
- Add audit events for mount lifecycle + credential events + data operations.
- Ensure all events redact secret material and include mount/user/path context.
- Document expected audit payload shape.

**Acceptance criteria**
- Security-sensitive mount operations are fully auditable.
- No credential material appears in logs or audit events.

**Dependencies**
- SFTP-010, SFTP-012, SFTP-031.

---

### SFTP-042: Enforce outbound destination policy and host allowlist controls
**Scope**
- Add configuration for allowed SFTP destinations (hostname/domain/IP policy).
- Enforce policy at mount creation/update and connection time.
- Add explicit policy violation error codes.

**Acceptance criteria**
- Disallowed destinations cannot be mounted or connected.
- Policy decisions are logged/audited for incident review.

**Dependencies**
- SFTP-002, SFTP-012.

---

## Milestone 5 — UX integration and launch readiness

### SFTP-050: File-manager UI for mount management and health states
**Scope**
- Add UI for create/edit/delete/test mount workflows.
- Add health/status presentation and troubleshooting messaging.
- Add clear copy for read-only/read-write behavior.

**Acceptance criteria**
- Users can self-serve mount setup and diagnostics without backend tooling.
- Error states are understandable and actionable.

**Dependencies**
- SFTP-012, SFTP-033.

---

### SFTP-051: File browser UX for mounted directories/files
**Scope**
- Show mounted roots under an “External” grouping.
- Ensure browse/upload/download/delete/rename actions behave consistently for mounted paths.
- Add affordances for unsupported actions where applicable.

**Acceptance criteria**
- Mounted content is clearly distinguishable and fully navigable.
- Unsupported operations are visible before failure where possible.

**Dependencies**
- SFTP-023, SFTP-031, SFTP-050.

---

### SFTP-052: Define and implement initial share-policy for mounted content
**Scope**
- Implement initial policy from plan recommendation (default: do not allow sharing mounted files).
- Return explicit API error if share is attempted for mounted paths.
- Add UI messaging and docs for this limitation.

**Acceptance criteria**
- Sharing behavior for mounted content is deterministic and policy-aligned.
- Existing share flows for native files are unaffected.

**Dependencies**
- SFTP-023, SFTP-051.

---

### SFTP-053: End-to-end validation suite and launch checklist
**Scope**
- Add integration tests for mount CRUD, auth failures, browse, upload, delete, rename, and status transitions.
- Add non-functional checks for large files, latency spikes, and remote host outages.
- Create launch checklist with rollback and kill-switch procedures.

**Acceptance criteria**
- Test suite covers critical happy path + failure path scenarios.
- Launch readiness review completed with rollback plan.

**Dependencies**
- SFTP-033, SFTP-040, SFTP-041, SFTP-042, SFTP-051, SFTP-052.

---

## Suggested execution order
1. Milestone 0 (SFTP-001..003)
2. Milestone 1 (SFTP-010..013)
3. Milestone 2 (SFTP-020..023)
4. Milestone 3 (SFTP-030..033)
5. Milestone 4 (SFTP-040..042)
6. Milestone 5 (SFTP-050..053)

This ordering keeps security and lifecycle primitives ahead of data-path integration, then completes launch hardening and UX.

---

## Milestone 6 — Dev tool UX for mock remote host inspection

### SFTP-054: Add mock remote host browser endpoint contract hardening
**Scope**
- Formalize `GET /v1/fs/mounts/{id}/mock-files` contract for dev inspection.
- Add cursor/limit response shape for large directories (even if initially optional).
- Standardize error payloads for mock backend disabled, bad path, not found, not directory.

**Acceptance criteria**
- Endpoint behavior is deterministic and documented with request/response examples.
- Errors are actionable and stable for UI handling.

**Dependencies**
- SFTP-053.

---

### SFTP-055: Dev UI modal navigation for mock remote filesystem
**Scope**
- Extend File Manager mount panel “Mock files” action to support:
  - breadcrumb navigation,
  - folder drill-down,
  - parent/up navigation,
  - refresh in current path.
- Preserve existing mount panel behavior for non-mock backends.

**Acceptance criteria**
- Developers can navigate nested mock directories from the Dev UI without API tooling.
- Navigation state and path rendering remain consistent across repeated reloads.

**Dependencies**
- SFTP-054.

---

### SFTP-056: Mock file browser usability and diagnostics improvements
**Scope**
- Add sort/filter affordances in modal (name/type/size/mtime).
- Add contextual remediation copy for common errors:
  - `sftp_mock_backend_disabled`
  - `mock_path_not_found`
  - `mock_path_not_directory`
- Add copy helpers for mount-relative path and filesystem path where safe.

**Acceptance criteria**
- Error states are understandable and actionable for developers.
- Listing large folders remains usable in UI.

**Dependencies**
- SFTP-055.

---

### SFTP-057: Security and observability for mock inspection flows
**Scope**
- Add audit events for mock-inspection endpoint usage with owner/mount/path context.
- Ensure owner/admin authorization behavior is explicit and tested.
- Add rate/size guardrails to prevent expensive directory scans.

**Acceptance criteria**
- Mock inspection usage is observable and bounded.
- Authorization for owner-scoped vs admin-scoped access is deterministic.

**Dependencies**
- SFTP-054.

---

### SFTP-058: Validation and rollout checklist for mock inspection UX
**Scope**
- Add backend tests for:
  - traversal/path-escape protection,
  - nested folder navigation,
  - pagination/limits,
  - auth/admin access behavior.
- Add frontend tests for modal navigation, sorting/filtering, and error remediation copy.
- Extend launch checklist with dev-tool-specific readiness/rollback notes.

**Acceptance criteria**
- Critical happy-path + failure-path scenarios for mock inspection are automated.
- Dev-tool rollout has explicit rollback and kill-switch guidance.

**Dependencies**
- SFTP-055, SFTP-056, SFTP-057.

---

## Updated recommended sequencing

1. Milestone 0 (SFTP-001..003)
2. Milestone 1 (SFTP-010..013)
3. Milestone 2 (SFTP-020..023)
4. Milestone 3 (SFTP-030..033)
5. Milestone 4 (SFTP-040..042)
6. Milestone 5 (SFTP-050..053)
7. Milestone 6 (SFTP-054..058)

# File Manager S3 Mounts — Implementation Tickets

This ticket set operationalizes the architecture in `docs/filemanager-s3-mount-plan.md` into executable engineering work.

---

## Epic FM-S3-0: S3 Mounts Program Setup

### FM-S3-0.1 — Define feature flags and rollout defaults
**Goal**: Gate S3 mount functionality behind flags for controlled rollout.

**Scope**
- Add settings:
  - `filemgr_s3_mounts_enabled` (default `false`)
  - `filemgr_s3_mounts_write_enabled` (default `false`)
  - `filemgr_s3_mounts_allowed_bucket_patterns` (optional list)
- Document defaults in `.env.example` and ops docs.

**Acceptance criteria**
- When disabled, `/v1/fs/mounts/*` returns 404 or 403 consistently.
- Existing `/v1/fs/*` behavior unchanged.

**Dependencies**: none.

---

## Epic FM-S3-1: Credentials & Security Foundation

### FM-S3-1.1 — Extend provider credential model for S3
**Goal**: Support `provider=s3` in existing credential lifecycle.

**Scope**
- Update `ProviderCredentialModel` enum to include `s3`.
- Define metadata schema for non-secret config:
  - `region`, `endpoint_url`, `path_style`, `auth_mode`.
- Keep secrets encrypted only (`access_key_id`, `secret_access_key`, optional `session_token`).

**Acceptance criteria**
- S3 credentials can be created/retrieved/deleted via projects provider credential routes.
- Responses never include plaintext secret material.

**Dependencies**: FM-S3-0.1.

### FM-S3-1.2 — Implement S3 credential validation service
**Goal**: Validate credentials before persistence.

**Scope**
- Add provider validation path in `provider_credentials`:
  - Check auth works (`HeadBucket` and minimal permission probe).
  - Normalize region and endpoint handling.
  - Map AWS errors to stable API errors (`401/403/400/502`).

**Acceptance criteria**
- Invalid keys/bucket permissions fail with actionable messages.
- Valid credentials store with encrypted secret payload.

**Dependencies**: FM-S3-1.1.

### FM-S3-1.3 — Redaction and audit for credential flows
**Goal**: Prevent leakage and improve traceability.

**Scope**
- Ensure logs redact credential fields.
- Emit audit events for create/update/delete credential operations.

**Acceptance criteria**
- Security test confirms no secret data in logs or API responses.
- Audit events include actor, provider, org/context, timestamp.

**Dependencies**: FM-S3-1.1.

---

## Epic FM-S3-2: Mount Data Model & CRUD

### FM-S3-2.1 — Add file mount model and table mapping
**Goal**: Persist mount metadata cleanly.

**Scope**
- Add `FileMountModel` with fields:
  - `id`, `owner`, `provider`, `mount_path`, `bucket`, `prefix`, `mode`, `auth_ref`, `status`, timestamps.
- Add DynamoDB serialization/deserialization helpers.

**Acceptance criteria**
- Mount records round-trip with validation.
- Invalid `mount_path` or `mode` rejected.

**Dependencies**: FM-S3-0.1.

### FM-S3-2.2 — Build mount service CRUD + conflict validation
**Goal**: Add robust lifecycle for mounts.

**Scope**
- Create `file_mounts` service module:
  - create/get/list/update/delete mounts
  - enforce owner scoping
  - reject path overlaps/conflicts (mount vs mount, mount vs local node)

**Acceptance criteria**
- Overlapping mounts fail with 409.
- Create/update/delete operations are idempotent-safe and audited.

**Dependencies**: FM-S3-2.1, FM-S3-1.2.

### FM-S3-2.3 — Add `/v1/fs/mounts` API routes
**Goal**: Expose mount management endpoints.

**Scope**
- Add endpoints:
  - `POST /v1/fs/mounts`
  - `GET /v1/fs/mounts`
  - `GET /v1/fs/mounts/{id}`
  - `PATCH /v1/fs/mounts/{id}`
  - `DELETE /v1/fs/mounts/{id}`
  - `POST /v1/fs/mounts/{id}/validate`
- Reuse existing session/auth dependency model.

**Acceptance criteria**
- Full OpenAPI schema and error responses documented.
- Access is owner-scoped with admin behavior matching existing policy.

**Dependencies**: FM-S3-2.2.

---

## Epic FM-S3-3: Mounted S3 Read Path (MVP)

### FM-S3-3.1 — Implement S3 mount adapter (list/stat/read)
**Goal**: Core mounted read primitives.

**Scope**
- Build adapter methods:
  - `list_dir`
  - `stat`
  - `read_file`
- Add safe path translation virtual -> bucket key (with prefix).

**Acceptance criteria**
- Directory listings support pagination.
- File reads stream content without loading full object in memory.

**Dependencies**: FM-S3-1.2, FM-S3-2.2.

### FM-S3-3.2 — Add mount-aware dispatch for list/download
**Goal**: Route existing filemanager read ops to mounted backend when needed.

**Scope**
- In filemanager service, resolve target path:
  - local behavior for non-mounted paths
  - mounted adapter for mounted paths
- Integrate into:
  - `GET /v1/fs/list`
  - `GET /v1/fs/download`

**Acceptance criteria**
- Existing local-path tests still pass.
- Mounted path list/download works with normalized response shape.

**Dependencies**: FM-S3-3.1.

### FM-S3-3.3 — Error mapping and UX consistency for mounted reads
**Goal**: Consistent API contract regardless of backing store.

**Scope**
- Map S3 SDK/service errors to existing HTTP semantics.
- Ensure response fields (`type`, `name`, `size`, etc.) match local format.

**Acceptance criteria**
- Clients do not need provider-specific handling for list/download.

**Dependencies**: FM-S3-3.2.

---

## Epic FM-S3-4: Mounted S3 Write Path

### FM-S3-4.1 — Implement write/delete primitives in adapter
**Goal**: Enable object mutation for read-write mounts.

**Scope**
- Add:
  - `write_file` (small object put + multipart pathway)
  - `delete_file`
- Preserve content type and metadata handling.

**Acceptance criteria**
- Upload + delete work for mounted paths.
- Large file upload path uses multipart where configured threshold exceeded.

**Dependencies**: FM-S3-3.1, FM-S3-0.1.

### FM-S3-4.2 — Enforce mount mode policy (`read_only` vs `read_write`)
**Goal**: Guarantee write safety.

**Scope**
- Block mounted writes/deletes when mount is read-only.
- Add clear error code/message (`mount_read_only`).

**Acceptance criteria**
- Write/delete on read-only mount returns deterministic 403/409 policy response.

**Dependencies**: FM-S3-4.1, FM-S3-2.2.

### FM-S3-4.3 — Route upload/delete endpoints for mounted paths
**Goal**: Full file-manager read/write on mount roots.

**Scope**
- Integrate mounted dispatch into:
  - `POST /v1/fs/upload` (and/or presign flow)
  - `DELETE /v1/fs`

**Acceptance criteria**
- Mounted upload/delete e2e works.
- Non-mounted behavior unchanged.

**Dependencies**: FM-S3-4.2.

---

## Epic FM-S3-5: Observability, Health, and Ops Hardening

### FM-S3-5.1 — Add mount metrics and structured logging
**Goal**: Observe performance and errors by provider/mode/op.

**Scope**
- Metrics:
  - op latency (`list/read/write/delete`)
  - bytes in/out
  - error totals by AWS error code
- Add mount context labels (provider, mode, mount_id hash).

**Acceptance criteria**
- Dashboard queries can separate local vs mounted traffic and failures.

**Dependencies**: FM-S3-3.2, FM-S3-4.3.

### FM-S3-5.2 — Implement mount health check worker
**Goal**: Detect degraded mounts proactively.

**Scope**
- Periodic check (`HeadBucket` + lightweight list probe).
- Persist `last_check_at`, `status`, `last_error`.

**Acceptance criteria**
- Degraded mounts are visible from mount list endpoint.
- Health failures do not block healthy mounts.

**Dependencies**: FM-S3-2.2.

### FM-S3-5.3 — Production guardrails (allowlist + limits)
**Goal**: Reduce blast radius.

**Scope**
- Enforce optional bucket allowlist pattern.
- Upload/download size limits and rate limits for mounted paths.

**Acceptance criteria**
- Non-allowlisted bucket mount creation blocked when policy enabled.
- Oversized requests fail fast with clear errors.

**Dependencies**: FM-S3-0.1, FM-S3-4.3.

---

## Epic FM-S3-6: Testing & Release

### FM-S3-6.1 — Unit test coverage for credentials/mount service/adapter
**Goal**: Validate core logic and error paths.

**Scope**
- Tests for:
  - S3 credential validation success/failure
  - mount path conflict detection
  - path traversal rejection
  - read-only policy enforcement
  - AWS error mapping

**Acceptance criteria**
- New unit test suite passes in CI.

**Dependencies**: FM-S3-1.x, FM-S3-2.x, FM-S3-3.x, FM-S3-4.x.

### FM-S3-6.2 — Integration tests using localstack/moto
**Goal**: Verify end-to-end mounted behavior.

**Scope**
- Scenario tests:
  - create mount -> list/read
  - upload/write -> read back
  - delete
  - read-only mount denies writes

**Acceptance criteria**
- Integration tests pass in dedicated CI job or gated test command.

**Dependencies**: FM-S3-3.x, FM-S3-4.x.

### FM-S3-6.3 — Rollout runbook + launch checklist
**Goal**: Operationally safe launch.

**Scope**
- Create runbook:
  - enable flags by environment
  - monitor dashboards/alerts
  - rollback procedure
- Add launch checklist with go/no-go criteria.

**Acceptance criteria**
- On-call and backend owners sign off on runbook.

**Dependencies**: FM-S3-5.x.

**Implementation notes**
- Runbook: `docs/filemanager-s3-mount-rollout-runbook.md`
- Checklist: `docs/filemanager-s3-mount-launch-checklist.md`

---

## Suggested Sprint Sequencing

### Sprint A (Foundations)
- FM-S3-0.1
- FM-S3-1.1
- FM-S3-1.2
- FM-S3-2.1
- FM-S3-2.2
- FM-S3-2.3

### Sprint B (Read MVP)
- FM-S3-3.1
- FM-S3-3.2
- FM-S3-3.3
- FM-S3-5.1 (read metrics subset)
- FM-S3-6.1 (for completed scope)

### Sprint C (Write + hardening)
- FM-S3-4.1
- FM-S3-4.2
- FM-S3-4.3
- FM-S3-5.2
- FM-S3-5.3
- FM-S3-6.2
- FM-S3-6.3

---

## Definition of Done (Program-level)

- Users can securely register S3 credentials and create mounts.
- Mounted paths support list/download/upload/delete per mount mode.
- Existing local file manager behavior remains backward compatible.
- Security controls (encryption/redaction/authz) and observability are in place.
- Tests and rollout docs are complete, and feature flags allow safe incremental rollout.

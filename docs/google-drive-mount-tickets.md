# Google Drive Mount Plan — Ticket Breakdown

This ticket set maps directly to `docs/google-drive-mount-plan.md` and is ordered to minimize security and dependency risk.

---

## Milestone 0 — OAuth and credential foundation

### GDM-001: Extend provider model to support `google_drive`
**Scope**
- Extend `ProviderCredentialModel.provider` union to include `google_drive`.
- Update provider normalization/validation paths to accept `google_drive`.
- Keep backward compatibility for existing `github`/`gitlab` credentials.

**Acceptance criteria**
- Credential create/get/delete routes accept `google_drive`.
- Existing provider credential tests pass unchanged.
- New tests validate model and route-level acceptance.

**Dependencies**
- None.

---

### GDM-002: Implement Google OAuth start endpoint
**Scope**
- Add `POST /v1/projects/providers/google_drive/oauth/start`.
- Generate signed one-time `state` tied to user/session with TTL.
- Return provider authorization URL with configured scopes and redirect URI.

**Acceptance criteria**
- Endpoint returns valid Google consent URL.
- State replay is rejected.
- State expires correctly.

**Dependencies**
- GDM-001.

---

### GDM-003: Implement OAuth callback/token exchange + secure credential storage
**Scope**
- Add `POST /v1/projects/providers/google_drive/oauth/callback`.
- Exchange auth code for access/refresh token.
- Encrypt stored secrets with existing KMS helpers.
- Persist scope list + token expiry metadata.

**Acceptance criteria**
- Successful callback stores encrypted credential.
- Invalid/expired code paths produce deterministic 4xx responses.
- Metadata includes granted scopes and expiry.

**Dependencies**
- GDM-002.

---

### GDM-004: Add Google token refresh helper + failure taxonomy
**Scope**
- Add shared helper to refresh access token using refresh token.
- Auto-refresh on provider 401 where appropriate.
- Normalize auth failures into explicit reason codes:
  - `revoked`
  - `insufficient_scope`
  - `access_removed`

**Acceptance criteria**
- Refresh updates stored expiry metadata.
- Invalid refresh token marks credential unusable and surfaces reconnect action.
- Unit tests cover refresh success/failure.

**Dependencies**
- GDM-003.

---

## Milestone 1 — Provider adapter and reference semantics

### GDM-010: Add `GoogleDriveProvider` read primitives
**Scope**
- Implement provider class in `app/services/file_providers.py`.
- Support canonical refs for My Drive + Shared Drive roots.
- Implement `resolve`, `exists`, `get_metadata`, `list_children`.

**Acceptance criteria**
- Canonical ref parser rejects malformed refs.
- Metadata/listing work for folder + file refs.
- Provider is registered in default registry.

**Dependencies**
- GDM-004.

---

### GDM-011: Add Drive API client abstraction with retry/backoff
**Scope**
- Centralize Drive requests behind helper (timeouts, retries, jitter).
- Standardize translation of Drive API errors to API errors.
- Include 429/5xx retry behavior with cap.

**Acceptance criteria**
- Retry policy is configurable and bounded.
- 429 response includes retry hint.
- Tests verify retry behavior and non-retryable failures.

**Dependencies**
- GDM-010.

---

## Milestone 2 — Mount model and APIs

### GDM-020: Add mount persistence model and storage helpers
**Scope**
- Introduce mount entity with fields:
  - `mount_id`, `owner`, `provider`, `mount_path`, `provider_root_ref`, `mode`, timestamps.
- Add create/get/list/update/delete helpers.

**Acceptance criteria**
- Mount path uniqueness enforced per owner.
- Overlapping mounts rejected.
- Data model documented with key patterns.

**Dependencies**
- GDM-001.

---

### GDM-021: Mount CRUD API endpoints
**Scope**
- Add endpoints under `/v1/fs/mounts`:
  - create, list, patch, delete.
- Validate mount_path normalization and provider root existence at creation.

**Acceptance criteria**
- API supports full mount lifecycle.
- Invalid mount conflicts return 409/400 with clear detail.
- Authorization matches existing file manager session rules.

**Dependencies**
- GDM-020, GDM-010.

---

### GDM-022: Feature flag and rollout guardrails
**Scope**
- Add `filemgr_google_drive_mounts_enabled` setting.
- Gate mount CRUD and mounted FS dispatch behind flag.
- Add startup/config diagnostics for missing OAuth config.

**Acceptance criteria**
- Disabled flag returns clear unsupported response.
- Enabling flag in configured env activates endpoints.

**Dependencies**
- GDM-021.

---

## Milestone 3 — Read-only mounted filesystem

### GDM-030: Add mounted-path resolver in file manager
**Scope**
- Add path dispatcher that determines local vs mounted path.
- Resolve mounted relative path to provider item ID/path.

**Acceptance criteria**
- Existing local `/v1/fs` behavior unchanged for non-mounted paths.
- Mounted path lookup is deterministic and owner-scoped.

**Dependencies**
- GDM-021.

---

### GDM-031: Route list/download through mounted adapter (read-only)
**Scope**
- Wire `/v1/fs/list` and download flows to Drive adapter for mounted paths.
- Stream reads from Drive without full in-memory buffering.

**Acceptance criteria**
- Users can list directories and download files under mount path.
- Content-type and size metadata are surfaced consistently.

**Dependencies**
- GDM-030, GDM-011.

---

### GDM-032: Read-only mount mode enforcement
**Scope**
- Enforce `read_only` mode for mounted roots.
- Return 403/409 for write attempts under read-only mount.

**Acceptance criteria**
- Write endpoints blocked for read-only mounts.
- Errors are explicit and documented.

**Dependencies**
- GDM-031.

---

## Milestone 4 — Read/write mounted filesystem

### GDM-040: Implement write operations (create/update/delete/mkdir)
**Scope**
- Add mounted write support for:
  - upload/create
  - overwrite/update
  - delete
  - mkdir

**Acceptance criteria**
- CRUD roundtrip works under mounted paths.
- Name conflict behavior is deterministic (configurable overwrite or conflict).

**Dependencies**
- GDM-031.

---

### GDM-041: Add resumable upload path for large files
**Scope**
- Use Drive resumable uploads above configurable threshold.
- Keep small-file path on single request.

**Acceptance criteria**
- Files above threshold upload successfully and recover from transient failures.
- Metrics differentiate simple vs resumable upload usage.

**Dependencies**
- GDM-040, GDM-011.

---

### GDM-042: Move semantics for mounted paths
**Scope**
- Support rename/move within same mount root.
- Reject cross-provider or cross-mount move in MVP with clear errors.

**Acceptance criteria**
- Same-mount move works for files/folders where Drive API permits.
- Unsupported cross-mount moves return deterministic error.

**Dependencies**
- GDM-040.

---

## Milestone 5 — Security, observability, and operations

### GDM-050: OAuth and secret-handling security hardening
**Scope**
- CSRF/state integrity checks for OAuth flow.
- Redirect URI allowlist enforcement.
- Audit events for connect/disconnect/token refresh failures.

**Acceptance criteria**
- Security checklist items verified in tests.
- Audit events include provider and failure reason dimensions.

**Dependencies**
- GDM-003, GDM-004.

---

### GDM-051: Metrics, dashboards, and alerts for mounted operations
**Scope**
- Add metrics for mounted fs operation latency, bytes in/out, API errors, refresh attempts.
- Add dashboard and alerts for:
  - elevated 401/403/429 rates
  - p95 latency regressions
  - upload failure spikes

**Acceptance criteria**
- Dashboard JSON + runbook committed.
- Alerts have owner + thresholds documented.

**Dependencies**
- GDM-031, GDM-040.

---

### GDM-052: Reconciliation/admin tooling for stale mounts and revoked credentials
**Scope**
- Add admin tooling/endpoint/job to detect:
  - revoked creds
  - inaccessible shared drives
  - orphaned mount roots
- Provide remediation actions (disable mount, prompt reconnect).

**Acceptance criteria**
- Tool reports stale mounts with actionable state.
- Recovery action updates mount status safely.

**Dependencies**
- GDM-050.

---

## Milestone 6 — Test matrix and rollout

### GDM-060: End-to-end integration test coverage
**Scope**
- Add integration tests for:
  - OAuth connect flow (mocked token exchange)
  - mount lifecycle
  - list/download/write/delete under mount
  - read-only enforcement
  - token refresh and revoked token behavior

**Acceptance criteria**
- CI exercises core mounted-path scenarios.
- Regressions in local FS behavior are explicitly guarded.

**Dependencies**
- GDM-031, GDM-040, GDM-050.

---

### GDM-061: Progressive rollout + kill switch plan
**Scope**
- Define staged rollout:
  - internal users
  - beta cohort
  - general availability
- Include kill switch and rollback steps.

**Acceptance criteria**
- Rollout checklist and rollback steps documented.
- On-call can disable feature without deploy.

**Dependencies**
- GDM-022, GDM-051, GDM-060.

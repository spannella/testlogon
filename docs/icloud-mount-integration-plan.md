# iCloud Mount Integration Plan (Credentials → Mounted Directory)

## 1) Current file management system review

Based on the current codebase, the file manager is implemented as an API-backed virtual filesystem rather than an OS-level mount:

- API surface is in `app/routers/filemanager.py` under `/v1/fs/*` (list, upload, download, move, share, etc.).
- Core storage logic lives in `app/services/filemanager.py`.
- Metadata is stored in DynamoDB (`_table()`), and file bytes are stored in S3 (`_bucket()`, `_s3`).
- Paths are canonicalized with `norm_path`, and operations are user-scoped.
- Upload already supports server-mediated and presigned flows (`presign_upload` + `register_presigned_upload`).

Implication: adding “iCloud as a directory” should be modeled as a **new storage backend/provider** behind the existing file-manager APIs, not as a direct replacement of the current S3+Dynamo design.

---

## 2) Key feasibility constraint (important)

There is no stable, officially supported public API for mounting a user’s full iCloud Drive in a third-party backend service with just Apple ID credentials.

Practical options are therefore:

1. **Recommended:** user installs a connector/agent on a device where iCloud Drive is already mounted by Apple (typically macOS), and our platform talks to that agent.
2. **High risk / not recommended for production:** rely on unofficial reverse-engineered iCloud APIs/tools in the server backend.
3. **Alternative product direction:** use Apple-supported CloudKit for app-specific containers (not full user iCloud Drive filesystem semantics).

Because your request is explicitly “users give us credentials and we mount iCloud as a directory,” this plan includes a credentials flow, but with guardrails and fallback to agent-based access where possible.

---

## 3) Target architecture

## 3.1 Add a storage provider abstraction

Introduce a provider layer in filemanager service:

- `LocalS3Provider` (existing behavior)
- `ICloudProvider` (new)

Common interface (conceptual):

- `list(path, cursor, limit)`
- `stat(path)`
- `read(path, byte_range)`
- `write(path, stream, content_type)`
- `delete(path)`
- `mkdir(path)`
- `move(src, dst)`

Keep current API contract in `/v1/fs/*`; route requests by mount.

## 3.2 Mount table and path routing

Create mount metadata records (new DDB table or partition):

- `mount_id`
- `owner_user_sub`
- `provider` (`s3`, `icloud`)
- `mount_path` (e.g. `/icloud/`)
- `status` (`pending`, `active`, `degraded`, `revoked`)
- provider config reference (no raw secrets in this table)

At request time:

- Resolve path prefix to mount.
- Delegate operation to provider.
- Preserve audit + metering events with provider dimension tags.

## 3.3 Credentials + secrets handling

New secure credential flow:

- Endpoint: `POST /v1/fs/mounts/icloud/initiate`
- Endpoint: `POST /v1/fs/mounts/icloud/verify`
- Endpoint: `POST /v1/fs/mounts/icloud/rotate`
- Endpoint: `DELETE /v1/fs/mounts/{mount_id}`

Security requirements:

- Store credentials only in a secrets manager (AWS Secrets Manager), encrypted with KMS.
- Never log Apple ID, app-specific password, session cookies, or MFA material.
- Use short-lived session tokens when possible; avoid storing reusable password after session bootstrap.
- Force re-verification on auth failures, suspicious activity, or long inactivity.

## 3.4 Data flow for read/write

Reads:

- `download` checks mount provider.
- For iCloud: stream from provider to client; optional temporary cache in S3 for large hot files.

Writes:

- `upload` sends bytes to provider.
- For iCloud: stage upload with temporary object + commit to remote path; return etag/version when available.

Consistency:

- Treat iCloud provider as eventually consistent.
- Add conflict policy settings per mount: `fail`, `rename`, `last_write_wins`.

---

## 4) Phased implementation plan

## Phase 0 — Product/security decision checkpoint (1 week)

- Confirm acceptable trust model for handling Apple credentials.
- Decide between:
  - server-side credential login, or
  - connector agent model (preferred for compliance and reliability).
- Produce legal/compliance review (PII handling, account takeover risk, credential retention policy).

Exit criteria:

- Approved security design and threat model.
- Decision record on supported iCloud access method.

## Phase 1 — Internal mount framework (1–2 sprints)

- Add mount model + APIs for create/list/delete mounts.
- Refactor filemanager service to route by mount provider while preserving existing S3 behavior.
- Add provider-aware audit/metrics.

Exit criteria:

- Existing `/v1/fs/*` works unchanged for default S3 root.
- Test mount prefix dispatch with a mock provider.

## Phase 2 — iCloud provider skeleton (1 sprint)

- Implement `ICloudProvider` adapter with feature-flag.
- Read-only first: list/stat/read.
- Add explicit error mapping:
  - auth expired
  - MFA required
  - throttled
  - path not found

Exit criteria:

- Can browse mounted iCloud directory tree in `/icloud/` for pilot accounts.

## Phase 3 — Write support (1 sprint)

- Implement write/delete/move semantics.
- Add conflict resolution behavior and retries/backoff.
- Add idempotency keys for write operations to avoid duplicate uploads.

Exit criteria:

- End-to-end upload/edit/delete in mounted iCloud path.

## Phase 4 — Hardening & operations (1 sprint)

- Observability dashboards and alerts for provider health.
- Background reconciliation job to detect drift between cached metadata and remote state.
- Circuit breaker: automatically degrade mount to read-only or unavailable on repeated auth failures.

Exit criteria:

- SLOs established (availability, p95 list/read latency, write success rate).

---

## 5) API/UI changes

Backend additions:

- `GET /v1/fs/mounts`
- `POST /v1/fs/mounts/icloud/initiate`
- `POST /v1/fs/mounts/icloud/verify`
- `POST /v1/fs/mounts/{mount_id}/status`
- `DELETE /v1/fs/mounts/{mount_id}`

Frontend (Files page):

- “Connect iCloud” wizard.
- Mount status badge (active/degraded/re-auth required).
- Provider badge on files/folders under mount.

No breaking changes to existing `/v1/fs` file operations.

---

## 6) Security/threat model checklist

- Credential theft risk (mitigations: secret manager, strict RBAC, redaction, no plaintext logs).
- MFA/session hijack risk (mitigations: step-up verification, device binding where possible).
- Excessive data access risk (mitigations: least privilege, user-visible access logs, per-mount revoke).
- Data exfiltration via shares/downloads (mitigations: existing entitlement + audit hooks extended to provider dimension).
- Abuse/rate-limit risk (mitigations: per-user and per-mount throttles; provider-specific backoff).

---

## 7) Testing strategy

- Unit tests:
  - mount path resolution and provider dispatch
  - secret redaction and auth error classification
  - conflict resolution logic
- Integration tests:
  - mock iCloud provider contract tests
  - end-to-end list/read/write under `/icloud/`
- Failure injection:
  - expired auth token, MFA challenge, provider 429/5xx, partial upload failure

---

## 8) Rollout strategy

1. Feature flag: `filemgr_icloud_mount_enabled`.
2. Internal dogfood accounts.
3. Limited beta cohort with read-only.
4. Enable write for beta after error budget stability.
5. Gradual GA by tenant/org.

---

## 9) Recommended immediate next steps

1. Build Phase 0 decision memo confirming acceptable iCloud access method.
2. Implement Phase 1 mount framework with a `MockRemoteProvider`.
3. Add mount management APIs and UI scaffolding before real iCloud auth integration.

This sequence de-risks the project: the platform becomes provider-ready even if iCloud auth details evolve.

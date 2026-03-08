# SFTP Mounts Launch Checklist (SFTP-053)

This checklist gates production launch readiness for SFTP mounts.

## 1) Functional validation (must pass)

- [ ] Mount CRUD lifecycle
  - [ ] Create mount (`POST /v1/fs/mounts/sftp`)
  - [ ] List mounts (`GET /v1/fs/mounts`)
  - [ ] Update mount (`PATCH /v1/fs/mounts/{id}`)
  - [ ] Delete mount (`DELETE /v1/fs/mounts/{id}`)
- [ ] Mount health/state workflows
  - [ ] Active test endpoint (`POST /v1/fs/mounts/{id}/test`)
  - [ ] Status transition to `healthy` on successful probe
  - [ ] Status transition to `auth_failed` on credential failure
  - [ ] Status transition to `unreachable|degraded` on transport failures
- [ ] Mounted data operations
  - [ ] Browse/list mounted directory
  - [ ] Download mounted file
  - [ ] Upload/write mounted file (read-write mount)
  - [ ] Delete mounted file/folder (read-write mount)
  - [ ] Rename/move mounted file/folder (read-write mount)
- [ ] Policy enforcement
  - [ ] Share attempts on mounted paths return `403 sftp_mount_share_not_allowed`
  - [ ] Destination allowlist violations return `403 sftp_destination_not_allowed`
  - [ ] Read-only mount rejects mutating operations with `mount_read_only`

## 2) Non-functional validation (must pass)

- [ ] Large-object transfer checks
  - [ ] Upload large file representative of expected 95th percentile object size
  - [ ] Verify no memory growth regressions and bounded stream behavior
- [ ] Latency spike resilience
  - [ ] Inject transient network timeout spikes
  - [ ] Confirm retry budget and backoff are honored
  - [ ] Confirm eventual success path remains available
- [ ] Remote outage resilience
  - [ ] Simulate persistent host outage
  - [ ] Confirm circuit breaker opens and short-circuits repeated attempts
  - [ ] Confirm mount status and error code update are observable
- [ ] Usage/audit observability
  - [ ] Verify mounted bytes + operation counts are emitted with backend tag `sftp`
  - [ ] Verify mount lifecycle and data events appear in audit stream
  - [ ] Verify no secret material appears in logs/audits

## 3) Rollout controls and kill switches

Feature flags (immediate kill switches):

- `filemgr_sftp_mounts_enabled=false` -> disable all mounted-path access.
- `filemgr_sftp_mounts_write_enabled=false` -> disable write/mutate operations.
- `filemgr_sftp_mounts_share_enabled=false` -> keep share flows disabled (policy-aligned).

Operational controls:

- Raise circuit sensitivity by lowering failure threshold / increasing open duration.
- Reduce retry attempts and timeout budget during incident containment.
- Disable background health refresh if probe traffic amplifies outage.

## 4) Rollback plan

1. **Immediate containment**
   - Set `filemgr_sftp_mounts_enabled=false` in runtime config.
   - Verify mounted routes return disabled policy errors.
2. **Stabilize service**
   - Drain/expire existing SFTP sessions from connection pool.
   - Confirm no sustained elevated error-rate from SFTP backend paths.
3. **Data/control integrity checks**
   - Verify native S3 flows are unaffected.
   - Confirm usage and audit pipelines remain healthy.
4. **Post-incident follow-up**
   - Capture failed destination/mount IDs and dominant error codes.
   - Patch policy/config/client behavior and re-run SFTP-053 validation suite.

## 5) Launch readiness sign-off

- [ ] Backend engineering owner sign-off
- [ ] SRE/on-call owner sign-off
- [ ] Security owner sign-off
- [ ] Product owner sign-off
- [ ] Rollback drill completed and recorded



## 6) Dev mock-inspection rollout checks (SFTP-058)

- [ ] Authorization behavior validated
  - [ ] Owner can only inspect own mount unless role is `admin|root`
  - [ ] Admin/root owner-scoped inspection (`owner` query param) behaves deterministically
- [ ] Guardrails validated
  - [ ] Path traversal and max-depth violations return stable `mock_path_invalid`
  - [ ] Oversized directory scans are bounded with `mock_path_scan_limit_exceeded`
  - [ ] Rate limiting returns stable `sftp_mock_rate_limited`
- [ ] Observability validated
  - [ ] `filemgr_sftp_mock_inspection` audit events emitted on success/failure
  - [ ] Audit payload includes `owner`, `mount_id`, `path`, `owner_scope`, and error `code` on failures

Dev-tool rollback / kill-switch guidance:

1. **Immediate kill switch**
   - Set `FILEMGR_SFTP_BACKEND=paramiko` (or any non-`mock` backend) to disable mock inspection endpoint behavior (`sftp_mock_backend_disabled`).
2. **Bounded-usage containment**
   - Reduce `FILEMGR_SFTP_MOCK_SCAN_MAX_ENTRIES` and `FILEMGR_SFTP_MOCK_RATE_LIMIT_PER_MINUTE` during incident mitigation.
3. **Full feature containment**
   - Set `filemgr_sftp_mounts_enabled=false` to disable all mounted-path and mock-inspection APIs.


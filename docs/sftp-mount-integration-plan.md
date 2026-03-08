# SFTP Mount Integration Plan for File Manager

## Objective
Enable users to provide SFTP credentials so their remote SFTP space appears under a virtual directory in our file manager and supports read/write operations.

## Contract reference
- Canonical API/path/state contract for SFTP-001 is defined in `docs/sftp-mount-api-contract.md`.
- Threat model and security baseline for SFTP-002 is defined in `docs/sftp-mount-threat-model.md`.

## Current System Review (from code)

### What exists today
- The file-manager API is exposed under `/v1/fs` and already supports list/upload/download/share/search operations. The router is in `app/routers/filemanager.py`. 
- File metadata is stored in DynamoDB through a single table abstraction (`_table()`), with node records keyed by user and normalized path.
- File bytes are stored in S3 (per-node `s3_bucket` + `s3_key`) and uploaded either directly (`upload_file`) or via presigned URL flow (`presign_upload` + `register_presigned_upload`).
- Reads (`download_file`) currently fetch from S3, not an arbitrary backend.
- The service already has robust path normalization (`norm_path`) and permission/sharing patterns we can reuse for SFTP-backed paths.

### Architectural implication
The current model is **metadata + object-store pointer** (DynamoDB + S3), not a native POSIX mounted filesystem. So “mount SFTP as a directory” should be implemented as a **virtual mounted namespace** in the file-manager service, not an OS-level mount inside app containers.

## Recommended Approach

### 1) Introduce a virtual mount namespace
Represent mounted SFTP roots as special folder nodes, e.g.:
- `/mounts/<mount_id>/...`

Each mount has config metadata:
- owner user id
- host, port, auth method
- remote root path
- policy flags (read-only/read-write)
- health/status and last successful probe

This keeps UX consistent with the existing `/v1/fs` path model and avoids introducing host-level mount dependencies.

### 2) Add SFTP credential model with secure storage
Do **not** store raw credentials in current file-node rows. Add a dedicated credential record type/table:
- encrypted at rest via KMS envelope encryption
- redact secrets from logs/audit payloads
- support at least:
  - username + password
  - username + private key (+ optional passphrase)

Also add credential rotation and revocation endpoints.

### 3) Add mount-management APIs
New endpoints under `/v1/fs/mounts`:
- `POST /v1/fs/mounts/sftp` (create mount)
- `GET /v1/fs/mounts` (list mounts)
- `PATCH /v1/fs/mounts/{id}` (update creds/root/policy)
- `DELETE /v1/fs/mounts/{id}` (unmount)
- `POST /v1/fs/mounts/{id}/test` (connectivity check)

Response payload should include `status` (`healthy`, `degraded`, `auth_failed`, etc.) for UI.

### 4) Extend filemanager service with a storage-provider abstraction
Introduce an interface layer (e.g., `StorageProvider`) so path operations dispatch by backend:
- Existing `S3Provider` for current behavior
- New `SFTPProvider` for mounted path trees

Core operations to implement:
- `list_dir`
- `stat`
- `read_stream`
- `write_stream`
- `mkdir`
- `delete`
- `move/rename`

This avoids forking route logic and keeps ACL/share code centralized.

### 5) Route mounted paths through SFTP provider
When a path resolves under `/mounts/<id>/`, resolve mount metadata and execute provider operations against SFTP.

Two implementation modes:
- **Pass-through mode (phase 1):** reads/writes go directly to SFTP; optional lightweight metadata cache.
- **Mirrored mode (phase 2 optional):** copy-on-read/write to S3 for previews/search/indexing and consistent performance.

Start with pass-through for fastest delivery and least storage duplication.

### 6) Define consistency + concurrency rules
SFTP is mutable by external actors, so define:
- last-write-wins behavior
- optimistic concurrency via mtime/size checks where possible
- explicit refresh endpoint to invalidate cached listings
- operation-level retries with bounded timeout budgets

### 7) Security and compliance controls
- Host allowlist or DNS policy for outbound SFTP destinations
- Optional SSH host key pinning (recommended)
- Secret encryption with strict IAM separation
- Per-operation audit events (mount create/update/test, read/write/delete)
- Egress rate limiting and byte-metering integrated with existing usage model

### 8) Product/UX decisions
- Mounts visible as top-level “External” entries in file browser
- Show health badges and reconnect action
- Show clear error states: auth failure, host unreachable, permission denied
- For share links: choose policy intentionally
  - Option A: disallow sharing mounted files initially
  - Option B: allow only if backend can enforce authorization and stable access

Recommend Option A initially to reduce security complexity.

## Suggested Delivery Phases

### Phase 0 — Design + threat model (1 week)
- Data model and API schema
- Security review for credential handling
- Decide host-key verification policy

### Phase 1 — Foundations (1–2 weeks)
- Credential vaulting + mount CRUD + test endpoint
- SFTP connectivity client with pooled connections
- Basic health telemetry

### Phase 2 — Read path (1–2 weeks)
- List/stat/read for mounted paths
- UI listing + basic download
- Metrics and audit events

### Phase 3 — Write path (1–2 weeks)
- Create/upload/overwrite/delete/move
- Retry + error mapping
- Quota + metering integration

### Phase 4 — Hardening (1–2 weeks)
- Host key pinning
- Rate limits and circuit breakers
- Chaos/failure tests, large-file and latency tests

## Key Risks and Mitigations
- **Credential leakage risk** → dedicated encrypted secret store + strict redaction.
- **Unreliable remote hosts** → health checks, timeouts, retries, degraded-state UX.
- **Performance variability** → async streaming, connection pooling, optional caching.
- **Feature mismatch with existing preview/search** → mark unsupported for mounted paths initially, then add async ingest if needed.

## Minimal Viable Scope (recommended)
1. Create SFTP mount with password or key auth.
2. Browse directories and download files.
3. Upload and overwrite files.
4. Delete and rename files.
5. Health status + reconnect test.
6. Audit + metrics + quota accounting.

This scope delivers real mounted read/write capability while minimizing high-risk extras (sharing/indexing/full-text preview on external files).

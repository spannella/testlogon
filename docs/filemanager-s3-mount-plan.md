# File Manager Review: S3 Credentialed Mount Plan

## Goal

Allow a user to connect their own S3 bucket using credentials we store securely, then expose that bucket as a mounted directory inside the existing file manager namespace with read and write support.

## Current state review

### 1) File Manager storage model today

- The file manager currently stores metadata in DynamoDB and object bytes in a single configured service bucket via `S.filemgr_bucket` + `s3_client()`.  
- Core file operations (`list`, `upload`, `download`, `delete`, sharing, previews) are implemented against the local metadata/object model in `app/services/filemanager.py` and surfaced via `/v1/fs/*` routes in `app/routers/filemanager.py`.

### 2) Existing provider abstraction is read-oriented and project-scoped

- The project system already has a provider abstraction (`FileProvider`) for `local`, `github`, and `gitlab` in `app/services/file_providers.py`.
- Tracked files can reference provider resources and hydrate metadata through provider clients in `app/services/projects_store.py`.
- This path is currently focused on metadata existence/read use-cases for project tracking, not full POSIX-like read/write file-manager mounts.

### 3) Credential management foundation exists

- The app already supports secure credential storage with KMS encrypt/decrypt in `app/services/provider_credentials.py` and exposes management routes under `/v1/projects/providers/{provider}/credentials` in `app/routers/projects.py`.
- The current credential model (`ProviderCredentialModel`) only allows `github`/`gitlab`, but the lifecycle (validate → encrypt → store → resolve for provider use) is a strong base for S3 credentials.

## Recommended architecture

Implement S3 bucket mounts as a **new file-manager mount subsystem** rather than shoehorning into tracked files.

### Why this direction

- Users asked for “mount bucket as directory” and read/write behavior in file manager itself.
- `/v1/fs/*` already defines the interactive filesystem experience; adding a mount layer here minimizes UX/API fragmentation.
- Project tracked files can remain a separate feature for external references.

## Design proposal

## 1) Introduce mount records

Add a new DynamoDB entity (in the existing table is acceptable initially):

- `entity_type = "file_mount"`
- keys scoped by owner + mount id
- fields:
  - `id`, `owner`, `provider = "s3"`
  - `mount_path` (e.g. `/mounts/acme-prod`)
  - `bucket`, optional `region`, optional `endpoint_url`
  - `prefix` (optional subpath in bucket)
  - `auth_ref` (points to encrypted credential record)
  - `mode` (`read_only` / `read_write`)
  - health metadata (`last_check_at`, `last_error`, `status`)
  - timestamps

Validation rules:
- mount path must be a folder path and cannot overlap another mount root.
- mount path should not conflict with existing local file/folder nodes.
- only one active mount per exact path.

## 2) Extend credential model for S3

Extend provider credentials to support `provider = "s3"` and support one of these auth modes:

- Access key mode: `access_key_id` + `secret_access_key` (+ optional session token)
- Role mode (future): external ID + role ARN via STS assume-role

Store encrypted secret material with existing KMS helpers. Keep non-secret connection metadata in `metadata`:

- `bucket`, `region`, `endpoint_url`, `path_style`, `kms_key_id(optional)`

Important: never store plaintext secrets in mount records or logs.

## 3) Add an S3 mount client adapter

Create a provider adapter dedicated to mounted I/O (separate from project tracked-file providers):

- `list_dir(mount, rel_path)` → mapped to `ListObjectsV2` with delimiter
- `read_file(mount, rel_path)` → `GetObject`
- `write_file(mount, rel_path, bytes|stream, content_type)` → `PutObject` or multipart
- `delete_file(mount, rel_path)` → `DeleteObject`
- `stat(mount, rel_path)` via `HeadObject` / prefix probe

Path mapping:

`virtual /mounts/acme/docs/a.txt` -> `s3://{bucket}/{prefix}/docs/a.txt`

Normalize and reject traversal/absolute escapes before joining.

## 4) Route local vs mounted paths in filemanager service

Add mount-aware path resolution in `app/services/filemanager.py`:

- If path is under a mounted root, dispatch operation to mount adapter.
- Else use existing local metadata + service bucket behavior.

Minimal initial support for mounted paths:

- `GET /v1/fs/list`
- `GET /v1/fs/download`
- `POST /v1/fs/upload` and/or presign flow
- `DELETE /v1/fs`

Return normalized metadata shape so frontend does not need provider-specific rendering.

## 5) New mount management API

Add endpoints (suggested under `/v1/fs/mounts`):

- `POST /v1/fs/mounts` create mount
- `GET /v1/fs/mounts` list mounts
- `GET /v1/fs/mounts/{id}` get mount
- `PATCH /v1/fs/mounts/{id}` update mode/prefix/label
- `DELETE /v1/fs/mounts/{id}` delete mount
- `POST /v1/fs/mounts/{id}/validate` run connectivity + permissions check

Creation flow:
1. submit credential payload (or credential reference)
2. perform validation (`HeadBucket`, optional test list/put/delete in temp key)
3. persist encrypted creds + mount record atomically

## 6) Permissions and safety guardrails

Required controls:

- Per-user authorization: mount records only accessible by owner (plus existing admin paths if needed).
- Optional allowlist for bucket ARN patterns in production.
- Optional block public bucket ACL operations.
- Read-only mount mode enforcement at service layer.
- Rate limiting and size limits for mounted uploads/downloads.
- Audit events for mount create/update/delete and external read/write operations.

## 7) Reliability and observability

Add metrics labeled by provider and mount mode:

- operation latency (`list/read/write/delete`)
- bytes transferred
- provider error totals by AWS error code
- mount health checks pass/fail

Add background mount health checks to mark degraded mounts and surface status in mount list.

## 8) Rollout phases

### Phase 0: Foundations

- Extend models for `s3` provider credentials.
- Add mount record schema + CRUD routes.
- Add connectivity validation endpoint.

### Phase 1: Read-only mount MVP

- Mounted `list` + `download` support.
- No write/delete yet.
- Basic observability + audit.

### Phase 2: Read-write

- Add mounted upload/write and delete.
- Add multipart upload for large files.
- Add read-only/read-write mode policy enforcement.

### Phase 3: Hardening

- Add STS assume-role option.
- Add mount health worker + retries.
- Add quotas and entitlement hooks for external-byte metering.
- Add optional object lock/version-aware behaviors.

## Implementation checklist

- [ ] Update `ProviderCredentialModel` to include `s3` and required metadata shape.
- [ ] Extend `provider_credentials` validation for S3 credential/auth checks.
- [ ] Add mount Pydantic models + DynamoDB mapping.
- [ ] Add `file_mounts` service module for CRUD + path conflict detection.
- [ ] Add S3 mounted adapter for list/read/write/delete primitives.
- [ ] Integrate mounted path dispatch into filemanager service operations.
- [ ] Add `/v1/fs/mounts/*` routes.
- [ ] Add tests for auth, validation, routing, read-only mode, and failure mapping.

## Test plan (must-have)

- Unit tests:
  - credential validation success/failure (bad keys, denied bucket).
  - mount path conflict and traversal rejection.
  - adapter operation error mapping (404/403/5xx).
- Integration tests (localstack/moto):
  - create mount, list objects, download object.
  - write object then read back.
  - read-only mount blocks write/delete.
- Regression tests:
  - existing local `/v1/fs/*` behavior unchanged for non-mounted paths.

## Risks and mitigations

- **Credential leakage risk** -> strict encryption-at-rest, redact logs, no secret echo in API responses.
- **Cross-tenant access risk** -> owner-scoped mount records + strict path-to-mount ownership checks.
- **Performance variance on large buckets** -> pagination, configurable max page size, optional prefix caching.
- **API complexity** -> keep mounted response format identical to existing file-manager node envelope.

## Suggested first deliverable

A small, low-risk milestone:

1. Add S3 credentials + mount CRUD + validation endpoint.
2. Implement read-only mounted `list` and `download`.
3. Instrument metrics and audit events.

This delivers immediate customer value while minimizing data-loss risk before enabling writes.

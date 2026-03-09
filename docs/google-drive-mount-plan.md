# Google Drive Mount Plan

## Current system review (baseline)

The file/project layer already has the right extension points for a new external provider:

- Provider abstraction exists in `app/services/file_providers.py` with provider-specific `resolve`, `exists`, `get_metadata`, and `list_children` methods plus a central `ProviderRegistry`.
- Provider credentials are encrypted-at-rest and validated before storage via `app/services/provider_credentials.py`.
- User-facing credential CRUD routes already exist at `/v1/projects/providers/{provider}/credentials` in `app/routers/projects.py`.
- The tracked file model stores provider + canonical provider_ref and rehydrates metadata through provider adapters in `app/services/projects_store.py`.

The main gap is that existing providers (GitHub/GitLab) are read-only metadata sources. There is no concept yet of mounting an external provider into `/v1/fs/*` as a writable directory.

## Goal

Allow a user to connect Google Drive using OAuth2, then mount one or more Drive roots/folders under the app file tree so `/v1/fs` can read and write content as if it were a normal directory.

## Recommended architecture

### 1) Add provider type: `google_drive`

Add a `GoogleDriveProvider` implementation in `app/services/file_providers.py` and register it in `default_provider_registry()`.

Recommended reference format:

- `gdrive://drive/{drive_id}/items/{item_id}` for Shared Drives
- `gdrive://me/items/{item_id}` for My Drive

Provider responsibilities:

- Resolve and canonicalize refs.
- Fetch metadata from Drive API (`files.get`).
- List children (`files.list` with parent query).
- Surface Drive-native metadata (`mimeType`, `size`, `modifiedTime`, parents).

### 2) Move from raw token input to OAuth authorization code flow

Current credential API expects user-supplied token strings. For Google Drive, require OAuth with refresh tokens:

- New start endpoint: `POST /v1/projects/providers/google_drive/oauth/start`.
- New callback endpoint: `POST /v1/projects/providers/google_drive/oauth/callback`.
- Store encrypted `access_token`, `refresh_token`, expiry, and granted scopes in provider credential metadata.

Minimal scopes to start:

- `https://www.googleapis.com/auth/drive.file` (recommended least privilege)
- optional upgrade path to `drive.readonly` or broader scopes for shared-drive/migration scenarios.

### 3) Introduce mount records

Create a new DynamoDB entity (in `T.projects` or dedicated table) for mounts:

- `mount_id`, `owner`, `provider=google_drive`
- `mount_path` (e.g. `/integrations/gdrive/acme`)
- `provider_root_ref` (Drive folder/file reference)
- `mode` (`read_only`/`read_write`)
- sync policy and timestamps

Mount invariants:

- `mount_path` must be unique per owner.
- No overlapping mount paths for same owner.
- Mount path cannot conflict with existing local files/folders.

### 4) Add a virtual filesystem router layer in file manager

Update `app/routers/filemanager.py` and `app/services/filemanager.py` so operations first check if path is under a mount:

- If local path -> existing behavior unchanged.
- If mounted path -> dispatch to `google_drive_fs_adapter`.

Adapter operations needed for MVP:

- `list(path)`
- `read(path)` (download stream)
- `write(path)` (create/update upload)
- `mkdir(path)`
- `delete(path)`
- `move(path_from, path_to)` within same mounted provider root

### 5) Streaming + large file handling

Use resumable uploads for files above threshold (e.g., 5–10 MB):

- Small writes: multipart upload in one request.
- Large writes: Drive resumable upload session.

For reads, stream directly from Drive to client to avoid loading entire objects in memory.

### 6) Token refresh and failure policy

Build shared auth helper for Google credentials:

- Auto-refresh access token on 401 using refresh token.
- Persist updated token expiry metadata.
- Distinguish actionable failures:
  - user revoked consent
  - insufficient scope
  - shared drive access removed

Emit structured audit events for connect/disconnect/refresh failures.

### 7) Security controls

- Encrypt all provider secrets with existing KMS helpers.
- CSRF protection and one-time state for OAuth start/callback.
- Validate redirect URI allowlist.
- Optional at-rest encryption for cached mirrored content if you add local caching.
- Limit dangerous MIME types only if product policy requires it; otherwise maintain pass-through behavior with content scanning hooks.

### 8) Product/API additions

Suggested endpoints:

- `POST /v1/fs/mounts` (create mount)
- `GET /v1/fs/mounts` (list mounts)
- `PATCH /v1/fs/mounts/{mount_id}` (mode/root updates where safe)
- `DELETE /v1/fs/mounts/{mount_id}` (unmount)

`/v1/fs/list`, `/download`, `/upload`, `/move`, `/delete` should accept mounted paths transparently.

## Rollout plan

### Phase 0 — Foundation (1 sprint)

- Extend `ProviderCredentialModel` and validation paths to support `google_drive` + refresh metadata.
- Implement OAuth start/callback and secure token storage.
- Add unit tests for credential validation and encryption/decryption flows.

### Phase 1 — Read-only mount (1 sprint)

- Add mount entity + CRUD endpoints.
- Route `/v1/fs/list` + `/download` to mounted provider.
- Ship feature flag (`filemgr_google_drive_mounts_enabled`).

### Phase 2 — Write support (1–2 sprints)

- Implement upload/create/update/delete/mkdir on mounted paths.
- Handle conflict semantics and name normalization.
- Add integration tests for roundtrip read/write.

### Phase 3 — Hardening and observability (1 sprint)

- Add retry/backoff and token refresh telemetry.
- Add metrics: mount op latency, Drive API error rate, bytes in/out.
- Add admin tooling for mount diagnostics and credential revoke cleanup.

## Key risks and mitigations

- **Drive API quotas/rate limits** → add retry with jitter, surface 429 clearly, and meter usage.
- **Token revocation drift** → detect 401 invalid_grant and force reconnect state.
- **Path semantics mismatch (Drive is ID-based, not true hierarchical FS)** → maintain stable internal ID mapping per mount and avoid path-only assumptions.
- **Cross-provider move/copy complexity** → restrict MVP moves to same mount, add copy pipeline later.

## MVP acceptance criteria

- User can connect Google Drive via OAuth and see successful credential state.
- User can create a mount at a chosen app path.
- `GET /v1/fs/list` and file downloads work under mounted path.
- User can upload/update/delete files under mounted path (Phase 2 complete).
- Audit logs and metrics exist for all mount operations.

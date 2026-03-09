# Google Drive Mount Data Model (GDM-020)

Mount records are stored in `T.projects` with owner-scoped keys.

## Entity: `fs_mount`

- `PK`: `OWNER#{owner}`
- `SK`: `MOUNT#{mount_id}`
- `entity_type`: `fs_mount`
- `mount_id`: UUID
- `owner`: user subject
- `provider`: currently `google_drive`
- `mount_path`: normalized absolute folder path (e.g. `/integrations/gdrive/team`)
- `provider_root_ref`: canonical provider root ref (e.g. `gdrive://me/items/root`)
- `mode`: `read_only` or `read_write`
- `created_at`: ISO8601 timestamp with timezone
- `updated_at`: ISO8601 timestamp with timezone

## Access patterns

- **Create mount**: write `OWNER#{owner} / MOUNT#{mount_id}` after path validation.
- **Get mount**: `GetItem` by `OWNER#{owner}` + `MOUNT#{mount_id}`.
- **List mounts**: `Query` `PK=OWNER#{owner}` with `SK begins_with MOUNT#`.
- **Update mount**: `GetItem` + `PutItem` replace after validation.
- **Delete mount**: `GetItem` then `DeleteItem`.

## Uniqueness and overlap constraints

Constraints are enforced in service logic before writes:

1. `mount_path` must be unique per owner.
2. `mount_path` cannot overlap any existing mount path for the same owner (ancestor/descendant conflicts).

Examples:

- Existing `/integrations/drive` blocks `/integrations/drive/team`.
- Existing `/integrations/drive/team` blocks `/integrations/drive`.
- Existing `/integrations/drive` blocks another `/integrations/drive`.


## Read-only mount enforcement errors (GDM-032)

Write operations under mounted paths with `mode=read_only` return explicit errors:

- HTTP `403`
- `detail.code = "mount_read_only"`
- `detail.message = "write operation is not allowed for read-only mount"`
- additional context includes `action`, `path`, `mount_id`, `mount_path`, and `mode`.


## Mounted write conflict policy (GDM-040)

Mounted uploads and creates use deterministic conflict handling:

- Default (`overwrite=false`): return HTTP `409` when target name already exists under the mounted parent.
- Overwrite mode (`overwrite=true` on upload routes): existing mounted files are updated in place; folder/file type conflicts still return HTTP `409`.


## Mounted move semantics (GDM-042)

- Same-mount moves/renames are supported for mounted items (subject to provider API permissions).
- Cross-mount or cross-provider moves are rejected in MVP with HTTP `409` and `detail.code = "mount_move_unsupported"`.
- Moving a mounted root itself is rejected in MVP.


## OAuth security hardening (GDM-050)

- OAuth `state` embeds signed integrity fields (`owner`, `nonce`, `exp`, `redirect_uri`) and is single-use via persisted consume markers.
- Callback rejects state with mismatched owner, expiry, signature, or redirect URI binding.
- Redirect URI must be explicitly allowlisted (`GOOGLE_OAUTH_REDIRECT_URI_ALLOWLIST`) and must include the configured `GOOGLE_OAUTH_REDIRECT_URI`.
- Audit events are emitted for connect/disconnect/refresh paths with `provider` and failure `reason` dimensions for operational visibility.


## Mounted observability (GDM-051)

- Metrics, dashboard, and alerts are defined in `docs/google-drive-mount-observability-runbook.md`.
- Grafana import JSON: `docs/dashboards/google-drive-mount-ops-dashboard.json`.


## Mount reconciliation + stale-state remediation (GDM-052)

- Mount records now include runtime health fields:
  - `status` (`active|disabled`)
  - `status_reason` (e.g. `revoked_credential`, `orphaned_mount_root`, `inaccessible_shared_drive`)
  - `reconnect_required` (bool)
  - `last_checked_at` (ISO-8601)
- Admin reconciliation endpoint reports stale mounts with `issues` and `recommended_actions`.
- Recovery actions disable stale mounts safely via status transition to `disabled` and preserve reason context for reconnect prompts.


## Progressive rollout + kill switch plan (GDM-061)

- Staged rollout and rollback procedures are documented in `docs/google-drive-mount-rollout-runbook.md`.
- On-call kill switch is `FILEMGR_GOOGLE_DRIVE_MOUNTS_ENABLED=0` (no deploy required).

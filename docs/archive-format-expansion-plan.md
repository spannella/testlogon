# Archive Format Expansion Plan (ZIP + TAR + TAR.GZ + RAR)

## Goal
Extend current archive ingestion so the file manager can treat these upload formats as extractable folder imports:

- `.zip` (existing)
- `.tar`
- `.tar.gz` / `.tgz`
- `.rar`

while preserving existing security guardrails, observability, and predictable API behavior.

## Current State (baseline)

- Upload extraction exists only for ZIP via `upload_zip` service and `/v1/fs/upload-zip` route.
- ZIP guardrails already exist (entry limits, total size, compression ratio, timeout).
- There is no archive-format abstraction layer; ZIP parsing, validation, and extraction are coupled.

## High-Level Design

### 1) Introduce a format-agnostic archive ingestion pipeline
Create a unified pipeline in the filemanager service with phases:

1. **Format detection** (by filename + magic bytes)
2. **Manifest scan** (enumerate entries, metadata, sizes, compression stats)
3. **Policy validation** (shared safety limits)
4. **Extraction stream** (upload extracted files to S3 + write metadata nodes)

This avoids copy/paste behavior per format and keeps policy enforcement consistent.

### 2) Add parser adapters per format
Implement an adapter interface:

- `iter_entries()` → yields normalized entry descriptors
- `open_entry(entry)` → file-like stream for extraction
- `format_name` + parser-specific metadata

Adapters:

- `ZipArchiveAdapter` (existing behavior moved behind adapter)
- `TarArchiveAdapter` (`.tar`, `.tar.gz`, `.tgz` via `tarfile`)
- `RarArchiveAdapter` (`rarfile` library, requires `unrar`/`bsdtar` backend availability)

### 3) Expand endpoint semantics
Keep current route for compatibility and add a more generic path:

- `POST /v1/fs/upload-archive` (new preferred)
- keep `POST /v1/fs/upload-zip` as alias/backward-compatible wrapper

Response shape remains consistent (`ok`, `created`, `count`) so frontend migration is low-risk.

## Security & Guardrails (all formats)

Apply the same policy model currently used for ZIP to every format:

- max entry count
- max total uncompressed bytes
- max per-entry uncompressed bytes
- extraction timeout budget
- compression ratio threshold where relevant

Additional format-specific hardening:

- reject absolute paths and path traversal (`..`) in archive entries
- ignore/deny symlinks and hardlinks by default (especially TAR/RAR)
- reject device files / special files (TAR headers)
- for `.rar`, fail closed if backend tool is unavailable

## Detailed Implementation Plan

## Phase 0 — Prework / dependency checks

1. Add feature flags/settings:
   - `FILEMGR_ARCHIVE_ENABLE_TAR`
   - `FILEMGR_ARCHIVE_ENABLE_RAR`
   - `FILEMGR_ARCHIVE_ALLOWED_FORMATS` (default: `zip,tar,targz`)
2. Decide RAR backend strategy:
   - prefer pure-python metadata + system extractor via `rarfile`
   - document required runtime binary (`unrar` or compatible)

## Phase 1 — Service refactor to common archive framework

1. Add a small internal module boundary in `filemanager.py` (or split modules if desired):
   - archive entry dataclass
   - archive adapter protocol
   - shared validation function
2. Move existing ZIP logic into `ZipArchiveAdapter` + shared extraction writer.
3. Keep behavior parity with current ZIP implementation.

## Phase 2 — TAR / TAR.GZ support

1. Implement `TarArchiveAdapter`:
   - support plain TAR and gzip-compressed TAR
   - enumerate entries through `tarfile`
2. Normalize TAR entries into same archive-entry schema.
3. Enforce path/symlink/special-file restrictions.
4. Reuse existing folder/file node creation + S3 upload path.

## Phase 3 — RAR support

1. Implement `RarArchiveAdapter` behind feature gate.
2. Validate backend availability at startup and surface clear errors.
3. Apply same guardrails and path restrictions.
4. If RAR backend missing:
   - return `415` or `501` with actionable message
   - emit metric/log for unsupported backend.

## Phase 4 — API & frontend integration

1. Add `POST /v1/fs/upload-archive` route and OpenAPI docs.
2. Keep `upload-zip` route as alias to new service.
3. Frontend changes:
   - update accepted file extensions
   - show format-specific errors (unsupported, backend unavailable, guardrail exceeded).

## Phase 5 — Observability & SLO extensions

Add labels to existing metrics for archive format:

- upload archive latency by format (`zip`, `tar`, `targz`, `rar`)
- bytes extracted/uploaded by format
- archive rejection counters by reason:
  - `too_many_entries`, `entry_too_large`, `total_too_large`, `timeout`, `path_invalid`, `unsupported_type`, `backend_unavailable`

Add structured logs per archive import with:

- `format`, `entries_total`, `bytes_total`, `duration_seconds`, `rejection_reason` (if any)

## Test Plan Expansion

### Unit tests

- parser detection:
  - valid zip/tar/targz/rar detection
  - unsupported extension/magic mismatch rejection
- guardrails per format:
  - entry count, per-entry size, total size, timeout
- path safety:
  - traversal (`../`), absolute path, symlink/hardlink rejection
- RAR backend unavailable behavior

### Behavior/failure service tests

- partial extraction interruption handling (ensuring deterministic error and no path confusion)
- duplicate output path handling across archive formats
- format-specific error mapping to HTTP status/detail

### Integration tests (local stack)

- local DynamoDB + local S3 workflow for each format:
  - upload archive
  - verify created nodes + S3 objects
  - validate counts and metadata

(For CI, RAR integration can be optional/flagged if binary availability is inconsistent.)

## Rollout Strategy

1. Ship TAR/TAR.GZ first behind feature flag.
2. Observe metrics and failure rates for 1 release window.
3. Enable RAR in environments where backend extractor is installed.
4. Keep ability to disable each format independently.

## Risks and Mitigations

- **RAR runtime dependency risk** → feature flag + startup health checks + graceful error responses.
- **Archive bombs / pathological archives** → strict shared guardrails + timeout enforcement.
- **Inconsistent behavior between formats** → single shared validation + extraction framework.

## Definition of Done

- `upload-archive` supports `.zip`, `.tar`, `.tar.gz`/`.tgz`, `.rar` (RAR gated by backend availability).
- Shared security guardrails enforced uniformly across formats.
- Metrics/logging include format + rejection reasons.
- Unit + integration coverage added for success and failure paths.
- Existing `upload-zip` behavior preserved for backward compatibility.

# File Manager Setup Review & Recommendations

This review covers the current file manager implementation in:

- `app/services/filemanager.py`
- `app/routers/filemanager.py`
- existing unit tests in `tests/test_filemanager_service.py` and `tests/test_filemanager_routes.py`

## What is working well

- The service has clear path normalization and basic traversal protection (`norm_path`) and consistently uses canonical paths.  
- Metadata and object storage responsibilities are split (DynamoDB for nodes, S3 for bytes), which is a good baseline for scalability.
- Soft-delete plus purge retention is implemented, including periodic background purging support.
- API surface is broad and practical (upload, presign flow, preview, thumbnails, ZIP, sharing, cursor pagination).

## Main improvement opportunities

## 1) Break up `filemanager.py` into focused modules

**Current state:** most behavior (path utils, CRUD, search, sharing, media probing, ZIP logic, purge jobs) lives in one very large service file.

**Why improve:** this increases coupling and makes test coverage more expensive to maintain.

**Recommendation:** split into focused modules, for example:
- `filemanager_paths.py` (path normalization / helpers)
- `filemanager_nodes.py` (metadata CRUD, folder/file operations)
- `filemanager_search.py` (prefix/text/token indexing)
- `filemanager_sharing.py`
- `filemanager_media.py` (ffmpeg/ffprobe)
- `filemanager_purge.py`

This will reduce cognitive load and make targeted tests easier.

## 2) Strengthen presigned-upload completion validation

**Current state:** `/complete-upload` trusts client-provided `key` and only performs `head_object` before registering metadata.

**Risk:** if a caller can reference another object key in the same bucket, they may register unexpected content as their own file metadata.

**Recommendation:** enforce all of the following before registration:
- key must begin with `"{user}/objects/"`
- optionally require a short-lived upload ticket ID stored server-side (path, key, content_type, expiry)
- optionally require expected object tags / metadata set at presign time

This closes key-substitution risk and gives better auditability.

## 3) Replace expensive fallback scans with explicit index-first patterns

**Current state:** some flows fall back to broader queries/scans when GSI expectations fail (e.g., list/search paths).

**Risk:** degraded latency and cost at higher object counts.

**Recommendation:**
- treat required GSIs as mandatory infra (fail fast with actionable error)
- add explicit operational checks on startup or health endpoint to verify table/index readiness
- avoid full-table scans in hot paths; keep scan-only behavior as admin/maintenance mode

## 4) Improve deletion/purge lifecycle semantics

**Current state:** purge marks metadata as `purged` and deletes S3 object; global purge relies on table scans.

**Risk:** scans can become costly; partially failed purges may require repeated rescans.

**Recommendation:**
- add a dedicated purge index (e.g., `GSI_PURGE` keyed by status/date) to avoid global scans
- include retry metadata (`purge_attempts`, `last_purge_error`) for observability
- add metrics counters for purged/skipped/error outcomes

## 5) Harden ZIP ingestion and extraction limits

**Current state:** ZIP upload extracts entries and writes to S3, with duplicate-path checks.

**Risk:** ZIP bombs or oversized archives can still overwhelm CPU/memory/storage.

**Recommendation:** enforce guardrails:
- max entry count
- max uncompressed bytes total
- max per-entry size
- reject suspicious compression ratios
- timeout budget for extraction

These checks are especially important for publicly exposed endpoints.

## 6) Add stronger transaction/recovery behavior for recursive move

**Current state:** folder move uses per-item transactions and writes a checkpoint item, but resume/repair tooling is minimal.

**Risk:** an interrupted move can leave mixed states requiring manual intervention.

**Recommendation:**
- formalize resumable move worker using checkpoint as source-of-truth
- expose admin endpoint/command to resume or rollback a move by `move_id`
- include idempotency markers so retries are safe

## 7) Expand tests from happy-path unit tests to behavior + failure coverage

**Current state:** tests mostly validate route/service happy paths with mocking.

**Recommendation:** add focused tests for:
- invalid cursor payload handling (already partially present; expand edge cases)
- presign-complete key validation failures
- partial move failure and resume behavior
- purge behavior with retry/error states
- ZIP bomb / limits rejection cases

Also consider integration tests with local DynamoDB + S3 emulator for key workflows.

## 8) Operational visibility and SLOs

**Current state:** audit events are emitted, but there is limited explicit metrics coverage in this module.

**Recommendation:** add structured metrics/log fields for:
- request latency by operation (`list`, `upload`, `download`, `search`, `move`)
- bytes uploaded/downloaded
- search fallback rate (index hit vs scan fallback)
- purge throughput and error rate

This makes capacity planning and reliability tuning much easier.

## Priority plan (practical rollout)

1. **Security first (1 sprint):** presign-complete key/ticket validation + ZIP limits.
2. **Performance (1 sprint):** remove hot-path scan fallback and add index readiness checks.
3. **Reliability (1 sprint):** purge index + move resume tooling.
4. **Maintainability (ongoing):** split service into modules and extend tests.

## Suggested immediate next task

Implement a small, high-impact hardening patch:

- Add server-side upload ticketing for presigned uploads.
- Validate key prefix ownership in `register_presigned_upload`.
- Add configurable ZIP limits in settings + enforcement in `upload_zip`.

This gives meaningful security/reliability gains with limited API disruption.

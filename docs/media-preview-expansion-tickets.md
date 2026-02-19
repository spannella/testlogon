# Media Preview Expansion — Ticket Breakdown

This ticket set maps directly to `docs/media-preview-expansion-plan.md` and is sequenced to reduce delivery risk for video/audio preview support.

---

## Milestone 0 — Contracts, flags, and data model

### MP-001: Extend preview metadata contract for media artifacts
**Scope**
- Add the following fields to file list/info payloads for owned and shared views:
  - `preview_kind` (`image|document|video|audio|none`)
  - `preview_status` (`pending|ready|failed|unsupported`)
  - `poster_url` (nullable)
  - `hover_preview_url` (nullable)
  - `waveform_url` (nullable)
  - `preview_reason` (nullable enum)
- Preserve backward compatibility for existing clients.

**Acceptance criteria**
- Contract fields are present and documented for all relevant file APIs.
- Existing clients ignoring these fields continue to function.

**Dependencies**
- None.

---

### MP-002: Add media preview feature flags and rollout controls
**Scope**
- Introduce `filemgr_media_previews_v1` gate.
- Add per-artifact toggles if needed (`video_hover_clip_enabled`, `audio_waveform_enabled`).

**Acceptance criteria**
- Feature can be enabled per environment without code changes.
- Disabled flag path returns deterministic fallback metadata.

**Dependencies**
- MP-001.

---

### MP-003: Define derivative storage layout and versioning scheme
**Scope**
- Define object key format for `poster_image`, `hover_clip`, `waveform_image`.
- Key derivatives by source file version/hash to avoid stale artifacts.

**Acceptance criteria**
- Re-upload/new version invalidates old derivatives.
- Storage path spec documented in code/docs.

**Dependencies**
- MP-001.

---

## Milestone 1 — Media processing pipeline foundation

### MP-010: Build media inspection utility (`ffprobe` integration)
**Scope**
- Implement utility that extracts MIME/container/codec/duration/streams safely.
- Normalize inspection result for policy checks.

**Acceptance criteria**
- Utility handles valid files and malformed media gracefully.
- Inspection output is deterministic and test-covered.

**Dependencies**
- MP-003.

---

### MP-011: Implement eligibility policy + guardrails
**Scope**
- Enforce constraints for source size, duration, codec/container allowlist.
- Add configurable limits:
  - `FILEMGR_VIDEO_PREVIEW_MAX_MB`
  - `FILEMGR_VIDEO_PREVIEW_MAX_DURATION_SECONDS`
  - `FILEMGR_VIDEO_PREVIEW_CLIP_SECONDS`
  - `FILEMGR_VIDEO_PREVIEW_TARGET_HEIGHT`
  - `FILEMGR_AUDIO_WAVEFORM_MAX_MB`
  - `FILEMGR_PREVIEW_JOB_TIMEOUT_SECONDS`
  - `FILEMGR_PREVIEW_WORKER_CONCURRENCY`

**Acceptance criteria**
- Ineligible files receive `preview_status=unsupported` + explicit `preview_reason`.
- Limits are environment-configurable with safe defaults.

**Dependencies**
- MP-010.

---

### MP-012: Add async preview job orchestration
**Scope**
- Trigger derivative job workflow on upload/import for eligible media.
- Persist status transitions (`pending -> ready|failed|unsupported`).
- Ensure upload path is non-blocking.

**Acceptance criteria**
- Preview job lifecycle updates are reflected in API metadata.
- Failures do not break file upload or browse flows.

**Dependencies**
- MP-010, MP-011.

---

### MP-013: Retry, dead-letter, and idempotency for preview jobs
**Scope**
- Add bounded retries for transient transcoding failures.
- Dead-letter permanently failing jobs with diagnostic reason.
- Make derivative generation idempotent for duplicate enqueue events.

**Acceptance criteria**
- Duplicate events do not produce duplicate artifacts.
- Failed jobs expose actionable reason codes.

**Dependencies**
- MP-012.

---

## Milestone 2 — Video artifacts

### MP-020: Implement video poster extraction
**Scope**
- Generate still image (`webp`/`jpeg`) from representative frame.
- Add fallback behavior when representative frame selection fails.

**Acceptance criteria**
- Eligible video files produce `poster_url` + `preview_status=ready` (poster dimension).
- Poster generation failures set status/reason and do not crash pipeline.

**Dependencies**
- MP-012.

---

### MP-021: Implement short hover clip transcoding
**Scope**
- Generate short muted low-resolution clip (`mp4` and/or `webm`) for hover playback.
- Use fixed offset in v1; leave heuristic improvements for later.

**Acceptance criteria**
- Clip duration and target resolution honor config.
- `hover_preview_url` available for successful jobs.

**Dependencies**
- MP-012, MP-011.

---

### MP-022: Integrate CDN/signed URL delivery for video artifacts
**Scope**
- Serve poster/clip via CDN with immutable caching keyed by source version/hash.
- Preserve private-access semantics with signed URLs where required.

**Acceptance criteria**
- Cache headers and URL expirations match security policy.
- Unauthorized users cannot fetch private derivatives.

**Dependencies**
- MP-020, MP-021.

---

## Milestone 3 — Audio waveform artifacts

### MP-030: Implement waveform image generation
**Scope**
- Decode audio and generate waveform image with standardized dimensions/style.
- Normalize amplitude rendering for consistent display.

**Acceptance criteria**
- Eligible audio files produce `waveform_url` artifact.
- Unsupported/failed sources expose fallback metadata.

**Dependencies**
- MP-012, MP-011.

---

### MP-031: Integrate CDN/signed URL delivery for waveform artifacts
**Scope**
- Deliver waveform artifacts with same caching/auth model as video derivatives.

**Acceptance criteria**
- Waveform URLs resolve with expected cache semantics.
- Access control parity with source file permissions.

**Dependencies**
- MP-030.

---

## Milestone 4 — Frontend integration (file manager UX)

### MP-040: Add media branches to file tile/list preview renderer
**Scope**
- Add `video` and `audio` branches based on `preview_kind` and `preview_status`.
- Use deterministic fallback for `pending|failed|unsupported`.

**Acceptance criteria**
- Video shows poster when ready.
- Audio shows waveform when ready.
- Fallbacks are stable and localized.

**Dependencies**
- MP-001, MP-020, MP-030.

---

### MP-041: Implement hover/focus video playback behavior
**Scope**
- On hover/focus, swap poster to muted short clip playback.
- Respect `prefers-reduced-motion` by disabling autoplay.
- Ensure keyboard-accessible equivalent to hover behavior.

**Acceptance criteria**
- Desktop pointer and keyboard interactions work consistently.
- Reduced-motion users receive non-autoplay behavior.

**Dependencies**
- MP-040, MP-021.

---

### MP-042: Touch/mobile progressive enhancement
**Scope**
- Keep default poster/waveform render on touch devices.
- Add optional tap-to-preview behavior behind capability check.

**Acceptance criteria**
- Mobile interaction does not regress scroll/performance.
- No hover-only critical behavior remains.

**Dependencies**
- MP-040.

---

## Milestone 5 — Security, observability, and operations

### MP-050: Harden media processing security boundary
**Scope**
- Run ffmpeg/ffprobe in least-privilege worker runtime.
- Validate command invocation safety (no user-controlled shell interpolation).
- Enforce codec/container allowlist and malformed-media handling.

**Acceptance criteria**
- Security checklist completed and approved.
- Known malformed samples are rejected safely.

**Dependencies**
- MP-010, MP-011, MP-012.

---

### MP-051: Add preview pipeline metrics and tracing
**Scope**
- Emit:
  - `filemgr_preview_jobs_total{media_type,artifact,outcome,reason}`
  - `filemgr_preview_job_duration_seconds{artifact}`
  - `filemgr_preview_artifact_bytes{artifact}`
  - `filemgr_preview_hover_play_starts_total`
  - `filemgr_preview_hover_play_failures_total{reason}`
- Add structured logs for `preview_kind`, `preview_status`, `preview_reason`.

**Acceptance criteria**
- Metrics visible in telemetry backend with low-cardinality labels.
- Logs enable root-cause analysis of preview failures.

**Dependencies**
- MP-012, MP-040.

---

### MP-052: Build dashboard + alerting for media previews
**Scope**
- Add operational dashboard for success rate, queue depth, latency, and hover failures.
- Add alerts for sustained preview generation failure/backlog.

**Acceptance criteria**
- Dashboard artifacts committed and reviewed with ops.
- Alert thresholds documented in runbook.

**Dependencies**
- MP-051.

---

## Milestone 6 — Testing and release gates

### MP-060: Backend unit tests for inspection, eligibility, and status transitions
**Scope**
- Cover ffprobe normalization, eligibility limits, and status state machine.

**Acceptance criteria**
- Tests cover success and rejection paths with reason codes.

**Dependencies**
- MP-010, MP-011, MP-012.

---

### MP-061: Backend job/integration tests for derivatives
**Scope**
- Validate poster, hover clip, and waveform generation flows.
- Test retries, timeouts, dead-letter behavior.

**Acceptance criteria**
- CI verifies artifact generation and failure handling deterministically.

**Dependencies**
- MP-013, MP-020, MP-021, MP-030.

---

### MP-062: Frontend component tests for media preview rendering
**Scope**
- Test tile rendering for all `preview_status` values.
- Test hover/focus playback interaction and reduced-motion behavior.

**Acceptance criteria**
- Unit test matrix covers video/audio + fallback states.

**Dependencies**
- MP-040, MP-041, MP-042.

---

### MP-063: End-to-end tests for upload-to-preview flow
**Scope**
- Upload sample video/audio and verify poster/waveform/clip in list view.
- Validate permission boundaries on derivative URLs.

**Acceptance criteria**
- E2E suite confirms artifacts appear and unauthorized access is denied.

**Dependencies**
- MP-022, MP-031, MP-041.

---

### MP-064: Media preview release gate checklist
**Scope**
- Add release gate criteria:
  - feature flag strategy validated,
  - derivative generation success threshold met,
  - queue and latency SLOs met,
  - security review sign-off,
  - test suites green.

**Acceptance criteria**
- Release gate blocks rollout on unmet criteria.

**Dependencies**
- MP-050..MP-063.

---

## Suggested sprint sequencing

### Sprint 1
- MP-001, MP-002, MP-003, MP-010, MP-011

### Sprint 2
- MP-012, MP-013, MP-020, MP-021

### Sprint 3
- MP-022, MP-030, MP-031, MP-040

### Sprint 4
- MP-041, MP-042, MP-050, MP-051, MP-052

### Sprint 5
- MP-060, MP-061, MP-062, MP-063, MP-064

---

## Mapping back to plan doc
- Product experience: MP-020, MP-021, MP-030, MP-040..MP-042
- Architecture & pipeline: MP-001..MP-013
- Performance/cost guardrails: MP-011, MP-013
- Security/compliance: MP-050
- Observability: MP-051, MP-052
- Rollout/testing/DoD: MP-060..MP-064

# Video and Audio Preview Expansion Plan

## Goal
Extend folder/file previews to support rich media:
- **Videos:** generate still-image poster + short low-resolution hover playback clips.
- **Audio:** generate waveform-based preview images for list/grid display.

This should preserve existing security controls and keep list views fast at scale.

---

## Product Experience

### 1) Video preview experience
- Folder/list tiles display a **still poster image** for each video file.
- On hover (or focus for keyboard users), the tile plays a **short muted preview clip**.
- Preview clips should be:
  - low resolution (e.g., 240p/360p),
  - short duration (e.g., 3–8 seconds),
  - optimized for quick start and low bandwidth.
- If preview artifacts are not ready, UI shows a loading placeholder and then poster only fallback.

### 2) Audio preview experience
- Folder/list tiles display a generated **waveform image** (with generic audio icon overlay if desired).
- Optional next step: add short hover scrub animation over waveform (not required for v1).
- If waveform generation fails, fallback to existing audio icon.

### 3) Accessibility
- Hover behavior must have keyboard equivalent (focus/enter) and not be hover-only.
- Motion should respect reduced-motion preference by disabling autoplay preview clips.
- Provide alt text/ARIA labels for poster and waveform states.

---

## Proposed Architecture

## 1) Artifact model
For each media file, add derived preview artifacts:
- `poster_image` (video still frame, e.g., webp/jpeg)
- `hover_clip` (video preview clip, e.g., mp4/webm)
- `waveform_image` (audio waveform png/webp)

Store these as object-storage derivatives linked to source file version/hash so updates invalidate stale previews.

Suggested metadata fields in file info/list payloads:
- `preview_kind`: `image|document|video|audio|none`
- `preview_status`: `pending|ready|failed|unsupported`
- `poster_url` (nullable)
- `hover_preview_url` (nullable)
- `waveform_url` (nullable)
- `preview_reason` (nullable enum: `transcoding_pending`, `too_large`, `unsupported_codec`, `generation_failed`, ...)

## 2) Media processing pipeline
Use asynchronous background jobs triggered on upload/import:
1. Detect MIME/container/codec with `ffprobe` (or equivalent).
2. Decide eligibility via guardrails (size, duration, codec allowlist).
3. Enqueue derivative generation jobs.
4. Persist status transitions and publish completion events.

### Video derivatives (v1)
- Poster frame:
  - sample near first meaningful keyframe (avoid pure black first frame where possible).
- Hover clip:
  - pick short segment near start with scene-change heuristic (optional v2) or fixed offset (v1).
  - transcode to low-res, muted, low bitrate for instant playback.

### Audio derivatives (v1)
- Decode audio and render static waveform image with fixed dimensions for list/grid modes.
- Normalize amplitude visualization for consistent appearance.

## 3) Runtime delivery
- UI list endpoint returns artifact URLs and status.
- CDN cache derivatives aggressively (`Cache-Control: public, immutable`) keyed by source content hash/version.
- Signed URLs if storage is private.

---

## Performance & Cost Guardrails

### Processing limits
- Max source size and duration for derivative generation (configurable).
- Timeout budgets per job stage.
- Concurrency caps to prevent transcode queue saturation.

### Suggested config knobs
- `FILEMGR_VIDEO_PREVIEW_MAX_MB`
- `FILEMGR_VIDEO_PREVIEW_MAX_DURATION_SECONDS`
- `FILEMGR_VIDEO_PREVIEW_CLIP_SECONDS`
- `FILEMGR_VIDEO_PREVIEW_TARGET_HEIGHT`
- `FILEMGR_AUDIO_WAVEFORM_MAX_MB`
- `FILEMGR_PREVIEW_JOB_TIMEOUT_SECONDS`
- `FILEMGR_PREVIEW_WORKER_CONCURRENCY`

### Backpressure behavior
- If queue is overloaded, keep file browsable with fallback icons/posters and mark preview as pending.
- Never block upload completion on preview generation.

---

## Security & Compliance
- Continue existing authorization model for preview URLs.
- Run media tooling in sandboxed worker environment (least privilege, no shell interpolation from user input).
- Strict allowlist for codecs/containers; reject dangerous/malformed files safely.
- Virus/malware scan source file before derivative processing if pipeline supports it.
- Avoid embedding metadata that leaks sensitive source details in derivative outputs.

---

## Frontend Changes

### File manager tile/list component
- Add renderer branch for `preview_kind=video` and `preview_kind=audio`.
- Video tile behavior:
  - default render `poster_url`,
  - swap to autoplay muted loop/one-shot clip on hover/focus,
  - respect reduced motion setting.
- Audio tile behavior:
  - render `waveform_url` with fallback icon.

### Progressive enhancement strategy
- Desktop: hover playback enabled.
- Touch devices: poster/waveform only by default, optional tap-to-preview.

### Error/fallback UX
- `pending`: skeleton/placeholder.
- `failed`/`unsupported`: deterministic fallback icon and tooltip text.

---

## Observability

Add metrics:
- `filemgr_preview_jobs_total{media_type,artifact,outcome,reason}`
- `filemgr_preview_job_duration_seconds{artifact}`
- `filemgr_preview_artifact_bytes{artifact}`
- `filemgr_preview_hover_play_starts_total`
- `filemgr_preview_hover_play_failures_total{reason}`

Dashboards:
- Derivative generation success rate by media type.
- Queue depth + job latency percentiles.
- Hover playback success/failure and startup latency.

---

## Rollout Plan

## Phase 0 — Design & spike (0.5 sprint)
- Validate ffmpeg/ffprobe toolchain in worker runtime.
- Benchmark transcode costs on representative samples.
- Finalize metadata contract with frontend.

## Phase 1 — Backend foundation (1 sprint)
- Add artifact metadata fields and preview status lifecycle.
- Implement async jobs and storage layout for derivatives.
- Add feature flag: `filemgr_media_previews_v1`.

## Phase 2 — Video previews (1 sprint)
- Generate poster + hover clip artifacts.
- Integrate CDN delivery and signed URL flow.
- Implement frontend hover/focus playback behavior.

## Phase 3 — Audio waveform previews (0.5–1 sprint)
- Generate waveform artifacts.
- Add audio tile renderer and fallback states.

## Phase 4 — Hardening (ongoing)
- Improve frame selection heuristics.
- Add better cost controls, retries, dead-letter handling.
- Accessibility and motion preference polish.

---

## Testing Plan

### Backend
- Unit tests for eligibility rules and metadata state transitions.
- Job tests for success/failure/retry/dead-letter paths.
- Security tests for malformed media and unsupported codecs.

### Frontend
- Component tests for video/audio tile rendering across `preview_status` values.
- Interaction tests for hover/focus playback and reduced-motion behavior.
- Mobile/touch behavior validation.

### End-to-end
- Upload sample video/audio -> artifacts generated -> list view renders poster/waveform.
- Hover preview startup latency within target budget.
- Permission checks ensure unauthorized users cannot fetch derivatives.

---

## Risks and Mitigations
- **High compute/storage cost:** use aggressive limits, short clips, low resolutions, and lifecycle policies.
- **Queue backlog:** separate workers/queues for preview jobs, autoscaling, and backpressure.
- **Codec fragmentation:** start with constrained codec support and expand iteratively.
- **UX inconsistency on low-end devices:** disable autoplay where performance signals are poor.

---

## Definition of Done (v1)
- Video files show poster image in folder/list and short hover/focus playback when artifacts are ready.
- Audio files show waveform image preview.
- Preview generation is asynchronous, observable, and failure-tolerant.
- Existing preview behavior for non-media files remains unchanged.

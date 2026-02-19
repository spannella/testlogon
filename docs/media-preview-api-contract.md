# Media Preview Metadata Contract (MP-001)

This document defines the preview metadata fields now included in file metadata payloads for:
- `GET /v1/fs/list`
- `GET /v1/fs/info`
- `GET /v1/fs/shared-list`
- `GET /v1/fs/shared-info`

## Fields

Each file item now includes:
- `preview_kind`: `image | document | video | audio | none`
- `preview_status`: `pending | ready | failed | unsupported`
- `poster_url`: `string | null`
- `hover_preview_url`: `string | null`
- `waveform_url`: `string | null`
- `preview_reason`: `string | null`

Existing compatibility fields are preserved:
- `preview_supported`: `boolean`

## Derivation rules (current)

- `preview_kind`
  - `video` for `video/*` MIME types.
  - `audio` for `audio/*` MIME types.
  - `image` for image preview types.
  - `document` for text/pdf/office/table preview types.
  - `none` when preview classification is unsupported.

- `preview_status`
  - `ready` when a preview can be rendered immediately.
  - `pending` for video/audio awaiting generated derivatives.
  - `unsupported` when previews are disallowed/unsupported.

- Artifact URLs
  - `poster_url` and `hover_preview_url` are relevant to `video`.
  - `waveform_url` is relevant to `audio`.
  - Non-applicable fields are `null`.

## Backward compatibility

- Existing clients that ignore these fields continue to work unchanged.
- Existing `preview_supported` remains in responses to avoid breaking older consumers.

## Rollout controls (MP-002)

- `FILEMGR_MEDIA_PREVIEWS_V1`
  - `false`: video/audio metadata returns deterministic fallback with `preview_status=unsupported` and `preview_reason=not_enabled`.
  - `true`: video/audio metadata can surface `pending|ready` states based on artifact availability.
- `FILEMGR_VIDEO_HOVER_CLIP_ENABLED`
  - Controls emission of `hover_preview_url` for `preview_kind=video`.
- `FILEMGR_AUDIO_WAVEFORM_ENABLED`
  - Controls emission/readiness of `waveform_url` for `preview_kind=audio`.

## Derivative storage layout and versioning (MP-003)

Media derivatives are keyed by source object version material (`s3_key`, `etag`, `size`) so re-uploads/new versions invalidate prior derivative paths.

- Version token:
  - `media_preview_version = sha256("{s3_key}|{etag}|{size}")[:24]`
- Base prefix:
  - `{owner}/derived/media/{media_preview_version}`
- Derivative object keys:
  - `poster_image`: `{base_prefix}/poster_image.webp`
  - `hover_clip`: `{base_prefix}/hover_clip.mp4`
  - `waveform_image`: `{base_prefix}/waveform_image.png`

These values are persisted on file metadata as:
- `media_preview_version`
- `media_preview_prefix`
- `media_preview_keys` (object containing `poster_image`, `hover_clip`, `waveform_image`)

## Media inspection utility (`ffprobe`) (MP-010)

`inspect_media_object(bucket, s3_key, content_type_hint)` provides normalized inspection output for policy/eligibility checks.

Normalized output shape:
- `ok`: boolean
- `mime_type`: normalized MIME hint
- `container`: normalized container (from ffprobe `format_name` first token)
- `duration_seconds`: integer seconds or `null`
- `has_video`: boolean
- `has_audio`: boolean
- `primary_video_codec`: string or `null`
- `primary_audio_codec`: string or `null`
- `streams`: deterministic ordered array of normalized stream rows (`index`, `codec_type`, `codec_name`, dimensions/audio fields)
- `error`: `null` on success, otherwise one of `not_media|ffprobe_unavailable|probe_failed|probe_malformed`

The utility fails closed (safe fallback metadata) for malformed probe output and execution failures.

## Eligibility policy + guardrails (MP-011)

Media preview eligibility is enforced before video/audio previews are considered `pending|ready`.

Configured limits:
- `FILEMGR_VIDEO_PREVIEW_MAX_MB`
- `FILEMGR_VIDEO_PREVIEW_MAX_DURATION_SECONDS`
- `FILEMGR_VIDEO_PREVIEW_CLIP_SECONDS`
- `FILEMGR_VIDEO_PREVIEW_TARGET_HEIGHT`
- `FILEMGR_AUDIO_WAVEFORM_MAX_MB`
- `FILEMGR_PREVIEW_JOB_TIMEOUT_SECONDS`
- `FILEMGR_PREVIEW_WORKER_CONCURRENCY`

Current eligibility reasons for unsupported media preview:
- `too_large`
- `too_long`
- `unsupported_container`
- `unsupported_codec`
- `not_enabled`

## Async preview job orchestration (MP-012)

On upload/import, media files trigger best-effort async preview job orchestration:

- Eligible media:
  - Enqueue `media_preview` job record (`PREVIEWJOB#{job_id}`) with status `pending`.
  - File node status is set to `media_preview_status=pending`, `media_preview_reason=transcoding_pending`.
- Ineligible media:
  - File node status is set to `media_preview_status=unsupported` with explicit reason from eligibility policy.
- Queue/enqueue failures:
  - File node status is set to `media_preview_status=failed`, `media_preview_reason=job_enqueue_failed`.

`preview_capability_from_node(...)` reflects lifecycle transitions from node fields so API metadata can surface `pending|ready|failed|unsupported` without blocking upload/browse flows.

## Retry, dead-letter, and idempotency (MP-013)

- Enqueue idempotency:
  - Media preview jobs use a deterministic dedup token derived from node path + source version material.
  - Duplicate enqueue events with an existing active job (`pending|in_progress|retry_pending`) do not create duplicate jobs.
- Bounded retries:
  - `FILEMGR_PREVIEW_JOB_MAX_ATTEMPTS` controls retry budget.
  - Transient failures transition jobs to `retry_pending` and keep node preview status `pending` with reason `retry_scheduled`.
- Dead-letter handling:
  - Permanent failures or retry exhaustion transition jobs to `dead_letter` with `last_error_reason`.
  - Node preview status transitions to `failed` with diagnostic reason `dead_letter:<reason>`.

## Video poster extraction (MP-020)

- `run_media_preview_job(owner, job_id)` now processes `preview_kind=video` jobs to generate poster images.
- Poster extraction strategy:
  - Try representative frame at `+1s` first.
  - Fallback to `+0s` if representative frame selection fails.
  - Prefer `webp`; fallback to `jpeg` when needed.
- Success path:
  - Upload poster to derivative `poster_image` key,
  - set `poster_url`,
  - set `media_preview_status=ready` and clear reason.
- Failure path:
  - Uses MP-013 retry/dead-letter policy,
  - exposes actionable reasons (`poster_generation_failed`, `poster_upload_failed`, etc.) without crashing upload/browse flow.

## Hover clip transcoding (MP-021)

- `run_media_preview_job(owner, job_id)` also generates a short muted hover clip for `preview_kind=video`.
- Transcoding behavior (v1):
  - Fixed offset `+1s`.
  - Duration from `FILEMGR_VIDEO_PREVIEW_CLIP_SECONDS`.
  - Target height from `FILEMGR_VIDEO_PREVIEW_TARGET_HEIGHT`.
  - Output format: `mp4` (H.264, muted via `-an`).
- Success path:
  - Upload clip to derivative `hover_clip` key,
  - set `hover_preview_url`,
  - keep `media_preview_status=ready` when poster+clip are both present.
- Failure path:
  - routes through retry/dead-letter policy with actionable reasons (`hover_clip_generation_failed`, `hover_clip_or_poster_upload_failed`).

## CDN/signed URL delivery for video artifacts (MP-022)

- Artifact object writes include immutable cache policy:
  - `Cache-Control: public, immutable, max-age=31536000`
- URL delivery behavior:
  - Private mode (`FILEMGR_MEDIA_PREVIEW_PRIVATE=true`): API returns signed S3 URLs with `FILEMGR_MEDIA_PREVIEW_URL_TTL_SECONDS` expiry.
  - Public CDN mode (`FILEMGR_MEDIA_PREVIEW_PRIVATE=false` + `FILEMGR_MEDIA_PREVIEW_CDN_BASE_URL` set): API returns CDN URLs.
- URL paths are keyed by versioned derivative keys (`media_preview_version`) so cache immutability aligns with source version/hash invalidation.

## Waveform image generation (MP-030)

- `run_media_preview_job(owner, job_id)` processes `preview_kind=audio` jobs to generate waveform images.
- Waveform generation behavior:
  - decode/normalize audio (`aformat=channel_layouts=mono,compand`),
  - render standardized waveform image (`showwavespic=s=640x120`) with consistent color.
- Success path:
  - upload waveform artifact to derivative `waveform_image` key,
  - set `waveform_url`,
  - set `media_preview_status=ready`.
- Failure path:
  - uses retry/dead-letter policy with actionable reasons (`waveform_generation_failed`, `waveform_upload_failed`, `missing_waveform_derivative_key`).

## CDN/signed URL delivery for waveform artifacts (MP-031)

- Waveform artifact delivery uses the same model as video derivatives:
  - immutable object cache policy on writes,
  - signed URL delivery in private mode,
  - CDN URL delivery in public mode.
- Ready-state `waveform_url` is resolved from derivative key (`media_preview_keys.waveform_image`) using the same signed/CDN URL policy, ensuring auth parity with source-file access controls.


## Media processing security boundary (MP-050)

Security hardening for media processing is enforced in the worker path as follows:

- ffmpeg/ffprobe invocations run through a hardened helper (`_run_media_tool`) with:
  - `shell=False` (no shell interpolation),
  - argv list-only execution (`list[str]` validation),
  - null-byte argument rejection,
  - sanitized environment (`PATH=/usr/bin:/bin`, `HOME=/nonexistent`, `LANG/LC_ALL=C`),
  - `stdin=DEVNULL`, `close_fds=True`, and bounded timeout.
- Eligibility policy rejects malformed media deterministically using `preview_reason=malformed_media` when probe output is malformed/failed or required codec/container fields are unknown.
- Existing codec/container allowlists remain enforced for video/audio (`unsupported_container`, `unsupported_codec`).

### MP-050 Security checklist

- [x] Media command execution uses no shell interpolation.
- [x] Invocation arguments are validated as non-user-shell-expanded argv lists.
- [x] Worker runtime command environment is defanged/minimal.
- [x] Timeouts are enforced on media-tool subprocesses.
- [x] Malformed probe output is rejected safely with explicit reason code.
- [x] Codec/container allowlists are enforced before derivative generation.
- [x] Automated tests cover malformed-media rejection and hardened invocation defaults.
- [x] Security review approval recorded for MP-050 rollout gate.


## Preview pipeline metrics and tracing (MP-051)

The preview pipeline emits low-cardinality telemetry for backend observability and root-cause analysis.

Metrics:

- `filemgr_preview_jobs_total{media_type,artifact,outcome,reason}`
- `filemgr_preview_job_duration_seconds{artifact}`
- `filemgr_preview_artifact_bytes{artifact}`
- `filemgr_preview_hover_play_starts_total`
- `filemgr_preview_hover_play_failures_total{reason}`

Structured logs:

- `filemgr_preview_capability` includes `preview_kind`, `preview_status`, `preview_reason` for contract derivation paths.
- `filemgr_preview_job_failed` includes `preview_kind`, `preview_status`, `preview_reason`, `attempts`, `dead_letter`.
- `filemgr_preview_job_completed` includes `preview_kind`, `preview_status`, `preview_reason`.

Label policy:

- labels are constrained to bounded enums (`media_type`, `artifact`, `outcome`, `reason`) to avoid high-cardinality metric blowups.

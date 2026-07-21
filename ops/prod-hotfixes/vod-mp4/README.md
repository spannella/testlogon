# VOD-012 — Real "Download MP4" transcode (replaces the empty 0-byte stub)

## Cause
`app/services/vod_mp4_generator.py::generate_download_mp4` returned an instant
`status="ready", size_bytes=0` in BOTH the dev and non-dev branches. In prod the
"download MP4" was therefore a phantom-ready object that was never produced — the
download endpoint would presign a key with no bytes behind it (0-byte file).

## Fix
Non-dev branch of `generate_download_mp4` now enqueues an async `download_mp4`
transcode job (existing `transcode_jobs` table + `transcode_worker`) and returns
`status="processing"`. A no-source guard returns `status="failed"` (never a
phantom-ready). The dev-mode branch is UNCHANGED (instant ready, size 0 — keeps
the test suite + `/mock/s3` flow). `mint_video_download_url` left untouched.

New `process_download_mp4_job(job)` (modeled 1:1 on
`video_clipper.process_clip_job`):
- download `source_s3_key` from `S.video_upload_bucket` to a roomy scratch dir
  (`S.transcode_scratch_dir`, NOT /tmp tmpfs),
- ffmpeg **remux first** (`-c copy -movflags +faststart`), **re-encode fallback**
  (`-c:v libx264 -preset veryfast -crf 22 -c:a aac -b:a 128k -movflags +faststart`)
  via `asyncio.create_subprocess_exec`, binary from `ffmpeg_manager.get_ffmpeg_path()`,
- upload to the deterministic key in `S.vod_output_bucket` (ContentType=video/mp4),
- `video_metadata.update_item` → `download_mp4_status="ready"`, real stat size,
  `updated_at`; `complete_job`. On failure → status `"failed"` + `fail_job`.

`transcode_worker._process_job_with_semaphore` gained a `job_type` dispatch:
`download_mp4` → claim + `process_download_mp4_job`; everything else → the existing
`execute_transcode_job` (ABR transcodes unaffected).

## Files
- app/services/vod_mp4_generator.py
- app/services/transcode_worker.py
- tests/test_vod_mp4_generator.py

## Prod facts (i-08f937fc705ebea75, us-east-2)
- ffmpeg present: /usr/bin/ffmpeg 6.1.1, /usr/bin/ffprobe present.
- transcode_worker_enabled = True (defaults to DEV_MODE); worker runs.
- **prod runs DEV_MODE=1** (in-process moto S3 + DDB-Local), so prod's live
  runtime still takes the dev-mode instant-ready branch. The real transcode
  branch activates when DEV_MODE=0. It was proven functional ON the prod box by
  forcing dev_mode=False in a standalone verify (prod ffmpeg produced a real
  30368-byte, 2.00s, h264+aac MP4).

## Verify evidence
- Dev host .249: real branch produced 30374-byte MP4, ffprobe 2.00s h264+aac;
  re-encode fallback (VP8 webm → h264) 12761 bytes; no-source guard → failed
  (no job); dev-mode unchanged; worker dispatch routes correctly.
- Existing suite: 60 passed (video_download / transcode_worker / job_store /
  clipper / clip_fail_job / transcode_status / download_rate_limit).
- New: tests/test_vod_mp4_generator.py 6 passed.

Prod backups: app/services/{vod_mp4_generator,transcode_worker}.py.bak_vodmp4_1784596478

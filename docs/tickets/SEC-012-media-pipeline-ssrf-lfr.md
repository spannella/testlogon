# SEC-012: Media Pipeline SSRF / Local-File-Read (ffmpeg, watermark, subtitles)

**Ticket**: SEC-012 · **Status**: Open · **Priority**: High · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 2)

## Problem
- **ffmpeg input protocol not restricted** (`app/services/ffmpeg_abr_pipeline.py:75`,
  transcode/clip paths) — no `-protocol_whitelist`; if any input URI is influenced/
  mis-validated, ffmpeg can read `file://`, `http://169.254.169.254/...` (cloud
  metadata SSRF), or chained `concat:`/`subfile:` protocols.
- **`concat -safe 0`** (`app/services/video_concatenator.py:338`) allows `file://`
  entries in the concat list → local-file read.
- **Watermark download** (`app/services/ffmpeg_watermark_lifecycle.py:131`) fetches
  arbitrary `http(s)` asset URIs (only magic-byte checked) → SSRF to metadata.
- **Subtitle/VTT sanitization** regex-based (`vod_subtitle_manager.py:132`) — may miss
  `<c>`/data-attr HTML that some players render → XSS.

## Fix
- Add `-protocol_whitelist file,crypto,https` (drop http unless needed; never include
  data/concat/subfile from untrusted input) to all ffmpeg invocations; restrict the
  scratch dir; use `-safe 1` for concat and validate each entry is an owned scratch
  file. Validate all input URIs are `s3://owned-bucket/owned-prefix`.
- Route watermark/asset fetches through the SSRF guard (SEC-001) + domain allowlist +
  size/timeout caps.
- Replace VTT regex with a strict allowlist sanitizer (text + `<v>` only).

## Testing
pytest: ffmpeg job rejects `file://`/metadata/concat inputs; watermark download
rejects private/metadata URLs; malicious VTT is stripped.

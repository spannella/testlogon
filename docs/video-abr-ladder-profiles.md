# Video ABR Ladder Profiles and Naming (VWD-002)

This document defines canonical rendition profiles and naming conventions for both local open-source tooling and AWS production workflows.

## Canonical profiles

| Name  | Resolution | Video kbps | Audio kbps | FPS | GOP seconds |
|-------|------------|------------|------------|-----|-------------|
| 1080p | 1920x1080  | 6000       | 192        | 30  | 2           |
| 720p  | 1280x720   | 3500       | 128        | 30  | 2           |
| 540p  | 960x540    | 2200       | 128        | 30  | 2           |
| 360p  | 640x360    | 1200       | 96         | 30  | 2           |

## Naming conventions

- Rendition names are fixed to: `1080p`, `720p`, `540p`, `360p`.
- HLS variant manifest path:
  - `tenants/{tenant_id}/assets/{asset_id}/hls/{rendition}/index.m3u8`
- DASH representation ID:
  - `v_{rendition}` (example: `v_720p`)

## Source of truth

- Runtime constants and naming helpers live in `app/contracts/video_rendition_profiles.py`.
- Contract request validation uses these canonical rendition names via `app/contracts/video_pipeline_contract.py`.


## Generated artifacts

Generate synchronized local FFmpeg and AWS MediaLive profile outputs with:

```bash
python scripts/video/generate_abr_profiles.py
```

This writes:

- `config/video/ffmpeg_abr_profiles.json`
- `config/video/medialive_abr_profiles.json`

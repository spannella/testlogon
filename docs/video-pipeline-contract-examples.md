# Video Pipeline Contract v1 — Examples

Contract version: `2026-03-video-pipeline-v1`

## Local development request example

```json
{
  "contract_version": "2026-03-video-pipeline-v1",
  "asset": {
    "asset_id": "asset_local_demo_001",
    "tenant_id": "dev-tenant",
    "source_uri": "rtmp://ingest/live/demo",
    "input_codec": "h264",
    "input_fps": 30,
    "input_width": 1920,
    "input_height": 1080,
    "audio_layout": "stereo"
  },
  "renditions": [
    {"name": "1080p", "width": 1920, "height": 1080, "video_bitrate_kbps": 6000, "audio_bitrate_kbps": 192, "fps": 30},
    {"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3500, "audio_bitrate_kbps": 128, "fps": 30},
    {"name": "540p", "width": 960, "height": 540, "video_bitrate_kbps": 2200, "audio_bitrate_kbps": 128, "fps": 30},
    {"name": "360p", "width": 640, "height": 360, "video_bitrate_kbps": 1200, "audio_bitrate_kbps": 96, "fps": 30}
  ],
  "watermark": {
    "mode": "dynamic_text",
    "position": "top_right",
    "opacity": 0.7,
    "margin_x": 24,
    "margin_y": 24,
    "text_template": "tenant={{tenant_id}} session={{session_id}}",
    "asset_uri": null
  },
  "drm": {
    "profile": "none",
    "key_rotation_seconds": null,
    "per_content_key": true,
    "offline_allowed": false
  },
  "retention_days": 7
}
```

## Production request example

```json
{
  "contract_version": "2026-03-video-pipeline-v1",
  "asset": {
    "asset_id": "evt_2026_03_24_prod_123",
    "tenant_id": "tenant-prod-42",
    "source_uri": "srt://medialive-input.internal:9000?streamid=event123",
    "input_codec": "h264",
    "input_fps": 30,
    "input_width": 1920,
    "input_height": 1080,
    "audio_layout": "stereo"
  },
  "renditions": [
    {"name": "1080p", "width": 1920, "height": 1080, "video_bitrate_kbps": 6000, "audio_bitrate_kbps": 192, "fps": 30},
    {"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3500, "audio_bitrate_kbps": 128, "fps": 30},
    {"name": "540p", "width": 960, "height": 540, "video_bitrate_kbps": 2200, "audio_bitrate_kbps": 128, "fps": 30},
    {"name": "360p", "width": 640, "height": 360, "video_bitrate_kbps": 1200, "audio_bitrate_kbps": 96, "fps": 30}
  ],
  "watermark": {
    "mode": "static_image",
    "position": "bottom_right",
    "opacity": 0.8,
    "margin_x": 24,
    "margin_y": 24,
    "text_template": null,
    "asset_uri": "s3://branding-assets/tenant-prod-42/logo-white.png"
  },
  "drm": {
    "profile": "multi_drm",
    "key_rotation_seconds": 300,
    "per_content_key": true,
    "offline_allowed": false
  },
  "retention_days": 30
}
```

## Event example (job completed)

```json
{
  "contract_version": "2026-03-video-pipeline-v1",
  "event_type": "job.completed",
  "job_id": "job_123",
  "asset_id": "evt_2026_03_24_prod_123",
  "tenant_id": "tenant-prod-42",
  "status": "completed",
  "output_hls_manifest_uri": "s3://video-origin/tenants/tenant-prod-42/assets/evt_2026_03_24_prod_123/hls/master.m3u8",
  "output_dash_manifest_uri": "s3://video-origin/tenants/tenant-prod-42/assets/evt_2026_03_24_prod_123/dash/manifest.mpd",
  "error_code": null,
  "error_message": null
}
```

## Event example (job failed)

```json
{
  "contract_version": "2026-03-video-pipeline-v1",
  "event_type": "job.failed",
  "job_id": "job_124",
  "asset_id": "asset_local_demo_001",
  "tenant_id": "dev-tenant",
  "status": "failed",
  "output_hls_manifest_uri": null,
  "output_dash_manifest_uri": null,
  "error_code": "input_stream_timeout",
  "error_message": "No contribution packets received for 30s"
}
```

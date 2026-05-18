# Watermark Policy Specification (VWD-003)

This specification defines the watermark policy fields, template variable rules, and tenant-level defaults for the video pipeline contract.

## Policy fields

- `mode`: `none | static_image | dynamic_text`
- `position`: `top_left | top_right | bottom_left | bottom_right`
- `opacity`: float from `0.0` to `1.0`
- `margin_x`: integer >= 0
- `margin_y`: integer >= 0
- `text_template`: optional string (required when `mode=dynamic_text`)
- `asset_uri`: optional string (required when `mode=static_image`)

## Dynamic text template variables

Supported variables (must be wrapped in `{{...}}`):

- `tenant_id`
- `session_id`
- `timestamp`

Unsupported variables are rejected during validation.

## Tenant defaults

`TenantWatermarkSettings` stores tenant-level defaults:

- `tenant_id` (required)
- `default_policy` (a complete `WatermarkPolicy`)
- `branding_asset_uri` (optional)

## Validation behavior

- If `mode=dynamic_text`, `text_template` is required.
- If `mode=static_image`, `asset_uri` is required.
- Any template variable not in the supported set causes deterministic validation failure.

## Source of truth

- Runtime contract implementation: `app/contracts/watermark_policy.py`
- Video request contract usage: `app/contracts/video_pipeline_contract.py`


## Renderer mappings (FFmpeg + MediaLive)

The policy is rendered via service adapters in `app/services/watermark_profile_renderers.py`:

- `ffmpeg_watermark_filter(policy, tenant_settings=...)`
  - `dynamic_text` -> `drawtext` filter
  - `static_image` -> `movie + overlay` filter
- `medialive_watermark_settings(policy, tenant_settings=...)`
  - `dynamic_text` -> `MotionGraphicsImage` config
  - `static_image` -> `Image` overlay config

### Tenant fallback behavior

For static image mode, if `policy.asset_uri` is absent, the renderer will fall back to `TenantWatermarkSettings.branding_asset_uri` when available.

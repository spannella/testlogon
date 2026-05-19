from __future__ import annotations

import pytest

from app.contracts.watermark_policy import TenantWatermarkSettings, WatermarkPolicy
from app.services.watermark_profile_renderers import ffmpeg_watermark_filter, medialive_watermark_settings


def test_dynamic_text_renderers_interpolate_ffmpeg_and_medialive_settings() -> None:
    tenant = TenantWatermarkSettings(tenant_id="tenant-77")
    policy = WatermarkPolicy(
        mode="dynamic_text",
        position="top_right",
        opacity=0.7,
        margin_x=24,
        margin_y=24,
        text_template="tenant={{tenant_id}} session={{session_id}} at {{timestamp}}",
    )

    values = {"session_id": "sess-123", "timestamp": "2026-04-04T00:00:00+00:00"}
    ffmpeg = ffmpeg_watermark_filter(policy, tenant_settings=tenant, template_values=values)
    media = medialive_watermark_settings(policy, tenant_settings=tenant, template_values=values)

    assert ffmpeg is not None and "drawtext" in ffmpeg
    assert "tenant=tenant-77 session=sess-123 at 2026-04-04T00:00:00+00:00" in ffmpeg
    assert media is not None
    assert media["MotionGraphicsImage"]["Text"] == "tenant=tenant-77 session=sess-123 at 2026-04-04T00:00:00+00:00"


def test_dynamic_text_rejects_unsupported_variables_before_render() -> None:
    policy = WatermarkPolicy.model_construct(
        mode="dynamic_text",
        position="top_right",
        opacity=0.7,
        margin_x=24,
        margin_y=24,
        text_template="bad={{unknown_var}}",
        asset_uri=None,
    )

    with pytest.raises(ValueError) as exc:
        ffmpeg_watermark_filter(policy)
    assert "unsupported watermark template variable" in str(exc.value)


def test_static_logo_uses_tenant_fallback_asset_uri() -> None:
    policy = WatermarkPolicy(mode="static_image", position="bottom_right", opacity=0.8, asset_uri="s3://override/logo.png")
    tenant = TenantWatermarkSettings(tenant_id="t1", branding_asset_uri="s3://tenant/default.png")

    ffmpeg = ffmpeg_watermark_filter(policy, tenant_settings=tenant)
    media = medialive_watermark_settings(policy, tenant_settings=tenant)

    assert ffmpeg is not None and "s3://override/logo.png" in ffmpeg
    assert media is not None and media["Image"]["Uri"] == "s3://override/logo.png"


def test_static_logo_can_use_tenant_default_when_policy_asset_missing() -> None:
    tenant = TenantWatermarkSettings(tenant_id="t1", branding_asset_uri="s3://tenant/default.png")
    policy = WatermarkPolicy(mode="none")
    policy = policy.model_copy(update={"mode": "static_image", "asset_uri": "s3://tenant/default.png"})

    ffmpeg = ffmpeg_watermark_filter(policy, tenant_settings=tenant)
    media = medialive_watermark_settings(policy, tenant_settings=tenant)

    assert ffmpeg is not None and "s3://tenant/default.png" in ffmpeg
    assert media is not None and media["Image"]["Uri"] == "s3://tenant/default.png"


def test_none_mode_returns_no_rendering() -> None:
    policy = WatermarkPolicy(mode="none")
    assert ffmpeg_watermark_filter(policy) is None
    assert medialive_watermark_settings(policy) is None

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.contracts.watermark_policy import (
    TenantWatermarkSettings,
    WatermarkPolicy,
    interpolate_template_variables,
)

_POSITION_TO_FFMPEG = {
    "top_left": "x={mx}:y={my}",
    "top_right": "x=W-w-{mx}:y={my}",
    "bottom_left": "x={mx}:y=H-h-{my}",
    "bottom_right": "x=W-w-{mx}:y=H-h-{my}",
}

_POSITION_TO_MEDIALIVE = {
    "top_left": ("LEFT", "TOP"),
    "top_right": ("RIGHT", "TOP"),
    "bottom_left": ("LEFT", "BOTTOM"),
    "bottom_right": ("RIGHT", "BOTTOM"),
}


def _resolve_asset_uri(policy: WatermarkPolicy, tenant_settings: TenantWatermarkSettings | None) -> str | None:
    if policy.asset_uri:
        return policy.asset_uri
    if tenant_settings and tenant_settings.branding_asset_uri:
        return tenant_settings.branding_asset_uri
    return None


def _default_template_values(
    *,
    tenant_settings: TenantWatermarkSettings | None,
    template_values: dict[str, str] | None,
) -> dict[str, str]:
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    defaults = {
        "tenant_id": tenant_settings.tenant_id if tenant_settings else "",
        "session_id": "",
        "timestamp": now_iso,
    }
    if template_values:
        defaults.update({k: str(v) for k, v in template_values.items()})
    return defaults


def ffmpeg_watermark_filter(
    policy: WatermarkPolicy,
    *,
    tenant_settings: TenantWatermarkSettings | None = None,
    template_values: dict[str, str] | None = None,
) -> str | None:
    if policy.mode == "none":
        return None

    if policy.mode == "dynamic_text":
        alpha = max(0.0, min(1.0, policy.opacity))
        position = _POSITION_TO_FFMPEG[policy.position].format(mx=policy.margin_x, my=policy.margin_y)
        text = interpolate_template_variables(
            policy.text_template or "",
            _default_template_values(tenant_settings=tenant_settings, template_values=template_values),
        )
        text = text.replace("'", r"\'")
        return f"drawtext=text='{text}':{position}:fontcolor=white@{alpha}:fontsize=24"

    asset = _resolve_asset_uri(policy, tenant_settings)
    if not asset:
        return None
    position = _POSITION_TO_FFMPEG[policy.position].format(mx=policy.margin_x, my=policy.margin_y)
    alpha = max(0.0, min(1.0, policy.opacity))
    return f"movie={asset}[wm];[in][wm]overlay={position}:alpha={alpha}[out]"


def medialive_watermark_settings(
    policy: WatermarkPolicy,
    *,
    tenant_settings: TenantWatermarkSettings | None = None,
    template_values: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    if policy.mode == "none":
        return None

    horizontal, vertical = _POSITION_TO_MEDIALIVE[policy.position]
    base = {
        "ImageX": policy.margin_x,
        "ImageY": policy.margin_y,
        "Opacity": int(policy.opacity * 100),
        "HorizontalAlign": horizontal,
        "VerticalAlign": vertical,
    }

    if policy.mode == "static_image":
        asset = _resolve_asset_uri(policy, tenant_settings)
        if not asset:
            return None
        return {
            "Image": {
                **base,
                "Uri": asset,
            }
        }

    text = interpolate_template_variables(
        policy.text_template or "",
        _default_template_values(tenant_settings=tenant_settings, template_values=template_values),
    )
    return {
        "MotionGraphicsImage": {
            **base,
            "Text": text,
        }
    }

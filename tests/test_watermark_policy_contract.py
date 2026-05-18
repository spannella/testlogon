from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.contracts.watermark_policy import (
    ALLOWED_WATERMARK_TEMPLATE_VARIABLES,
    TenantWatermarkSettings,
    WatermarkPolicy,
    extract_template_variables,
    interpolate_template_variables,
)


def test_extract_template_variables() -> None:
    vars_found = extract_template_variables("tenant={{tenant_id}} ts={{timestamp}}")
    assert vars_found == ("tenant_id", "timestamp")


def test_dynamic_text_mode_requires_template() -> None:
    with pytest.raises(ValidationError) as exc:
        WatermarkPolicy(mode="dynamic_text", text_template=None)

    assert "text_template is required when mode=dynamic_text" in str(exc.value)


def test_static_image_mode_requires_asset_uri() -> None:
    with pytest.raises(ValidationError) as exc:
        WatermarkPolicy(mode="static_image", asset_uri=None)

    assert "asset_uri is required when mode=static_image" in str(exc.value)


def test_unsupported_template_variable_rejected() -> None:
    with pytest.raises(ValidationError) as exc:
        WatermarkPolicy(mode="dynamic_text", text_template="user={{user_id}}")

    assert "unsupported watermark template variable(s): user_id" in str(exc.value)


def test_tenant_watermark_settings_accepts_default_policy() -> None:
    settings = TenantWatermarkSettings(
        tenant_id="tenant-1",
        default_policy=WatermarkPolicy(mode="dynamic_text", text_template="tenant={{tenant_id}} session={{session_id}}"),
        branding_asset_uri="s3://branding/tenant-1/logo.png",
    )
    assert settings.tenant_id == "tenant-1"
    assert set(ALLOWED_WATERMARK_TEMPLATE_VARIABLES) == {"tenant_id", "session_id", "timestamp"}


def test_interpolate_template_variables_replaces_known_tokens() -> None:
    text = interpolate_template_variables("tenant={{tenant_id}} session={{session_id}}", {"tenant_id": "t1", "session_id": "s1"})
    assert text == "tenant=t1 session=s1"

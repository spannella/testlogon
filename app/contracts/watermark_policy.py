from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

ALLOWED_WATERMARK_TEMPLATE_VARIABLES: tuple[str, ...] = (
    "tenant_id",
    "session_id",
    "timestamp",
)

_TEMPLATE_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")


def extract_template_variables(template: str) -> tuple[str, ...]:
    return tuple(_TEMPLATE_VAR_RE.findall(template))


def validate_template_variables(template: str) -> tuple[str, ...]:
    found = extract_template_variables(template)
    unsupported = sorted({var for var in found if var not in ALLOWED_WATERMARK_TEMPLATE_VARIABLES})
    if unsupported:
        supported = ", ".join(ALLOWED_WATERMARK_TEMPLATE_VARIABLES)
        raise ValueError(
            f"unsupported watermark template variable(s): {', '.join(unsupported)}; supported: {supported}"
        )
    return found


def interpolate_template_variables(template: str, values: dict[str, str] | None = None) -> str:
    values = values or {}
    validate_template_variables(template)

    def _replace(match: re.Match[str]) -> str:
        key = match.group(1)
        return str(values.get(key, match.group(0)))

    return _TEMPLATE_VAR_RE.sub(_replace, template)


class WatermarkPolicy(BaseModel):
    mode: Literal["none", "static_image", "dynamic_text"] = "none"
    position: Literal["top_left", "top_right", "bottom_left", "bottom_right"] = "top_right"
    opacity: float = Field(default=0.7, ge=0.0, le=1.0)
    margin_x: int = Field(default=24, ge=0)
    margin_y: int = Field(default=24, ge=0)
    text_template: str | None = None
    asset_uri: str | None = None

    @field_validator("text_template")
    @classmethod
    def _validate_template_vars(cls, value: str | None) -> str | None:
        if value is None:
            return value
        validate_template_variables(value)
        return value

    @model_validator(mode="after")
    def _validate_mode_requirements(self) -> "WatermarkPolicy":
        if self.mode == "dynamic_text" and not self.text_template:
            raise ValueError("text_template is required when mode=dynamic_text")
        if self.mode == "static_image" and not self.asset_uri:
            raise ValueError("asset_uri is required when mode=static_image")
        return self


class TenantWatermarkSettings(BaseModel):
    tenant_id: str = Field(min_length=1)
    default_policy: WatermarkPolicy = Field(default_factory=WatermarkPolicy)
    branding_asset_uri: str | None = None

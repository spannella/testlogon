from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

DRM_ENTITLEMENT_CONTRACT_VERSION = "2026-03-drm-entitlement-v1"
SUPPORTED_DRM_ENTITLEMENT_CONTRACT_VERSIONS = {DRM_ENTITLEMENT_CONTRACT_VERSION}

DrmProfile = Literal["widevine", "fairplay", "playready", "multi_drm"]


class DrmEntitlementClaims(BaseModel):
    contract_version: Literal["2026-03-drm-entitlement-v1"] = DRM_ENTITLEMENT_CONTRACT_VERSION
    asset_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    device_id: str = Field(min_length=1)
    profile: DrmProfile
    issued_at_epoch: int = Field(ge=0)
    expires_at_epoch: int = Field(ge=0)
    key_id: str = Field(min_length=1)
    key_rotation_seconds: int = Field(ge=60)
    per_content_key: bool = True
    offline_allowed: bool = False


class DrmLicenseRequest(BaseModel):
    contract_version: Literal["2026-03-drm-entitlement-v1"] = DRM_ENTITLEMENT_CONTRACT_VERSION
    profile: DrmProfile
    asset_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    device_id: str = Field(min_length=1)
    challenge_b64: str = Field(min_length=1)


class DrmLicenseResponse(BaseModel):
    contract_version: Literal["2026-03-drm-entitlement-v1"] = DRM_ENTITLEMENT_CONTRACT_VERSION
    profile: DrmProfile
    key_id: str = Field(min_length=1)
    license_b64: str = Field(min_length=1)
    expires_at_epoch: int = Field(ge=0)
    renewal_url: str | None = None

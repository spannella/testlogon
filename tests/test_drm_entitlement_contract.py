from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.contracts.drm_entitlement_contract import (
    DRM_ENTITLEMENT_CONTRACT_VERSION,
    DrmEntitlementClaims,
    DrmLicenseRequest,
    DrmLicenseResponse,
)

SCHEMA_PATH = Path("docs/drm-license-contract-v1.json")


def test_drm_schema_version_is_stable() -> None:
    schema = json.loads(SCHEMA_PATH.read_text())
    assert schema["properties"]["contract_version"]["const"] == DRM_ENTITLEMENT_CONTRACT_VERSION


def test_entitlement_claims_validate() -> None:
    claims = DrmEntitlementClaims.model_validate(
        {
            "contract_version": DRM_ENTITLEMENT_CONTRACT_VERSION,
            "asset_id": "a1",
            "tenant_id": "t1",
            "session_id": "s1",
            "device_id": "d1",
            "profile": "widevine",
            "issued_at_epoch": 100,
            "expires_at_epoch": 200,
            "key_id": "key_1",
            "key_rotation_seconds": 300,
            "per_content_key": True,
            "offline_allowed": False,
        }
    )
    assert claims.profile == "widevine"


def test_license_request_and_response_validate() -> None:
    req = DrmLicenseRequest.model_validate(
        {
            "contract_version": DRM_ENTITLEMENT_CONTRACT_VERSION,
            "profile": "fairplay",
            "asset_id": "a1",
            "tenant_id": "t1",
            "session_id": "s1",
            "device_id": "d1",
            "challenge_b64": "abc",
        }
    )
    assert req.profile == "fairplay"

    resp = DrmLicenseResponse.model_validate(
        {
            "contract_version": DRM_ENTITLEMENT_CONTRACT_VERSION,
            "profile": "fairplay",
            "key_id": "key_1",
            "license_b64": "xyz",
            "expires_at_epoch": 1000,
            "renewal_url": None,
        }
    )
    assert resp.key_id == "key_1"


def test_invalid_profile_rejected() -> None:
    with pytest.raises(ValidationError):
        DrmLicenseRequest.model_validate(
            {
                "contract_version": DRM_ENTITLEMENT_CONTRACT_VERSION,
                "profile": "unknown",
                "asset_id": "a1",
                "tenant_id": "t1",
                "session_id": "s1",
                "device_id": "d1",
                "challenge_b64": "abc",
            }
        )

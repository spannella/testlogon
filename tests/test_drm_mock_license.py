from __future__ import annotations

import pytest

from app.services.drm_mock_license import issue_entitlement_token, issue_mock_license


def _license_req() -> dict:
    return {
        "contract_version": "2026-03-drm-entitlement-v1",
        "profile": "multi_drm",
        "asset_id": "asset_local_demo_001",
        "tenant_id": "dev-tenant",
        "session_id": "session-1",
        "device_id": "device-1",
        "challenge_b64": "abc",
    }


def test_issue_mock_license_success() -> None:
    ent = issue_entitlement_token(
        asset_id="asset_local_demo_001",
        tenant_id="dev-tenant",
        session_id="session-1",
        device_id="device-1",
        profile="multi_drm",
        key_id="k1",
        secret="secret",
        ttl_seconds=300,
    )

    res = issue_mock_license(payload=_license_req(), token=ent["token"], secret="secret")
    assert res["profile"] == "multi_drm"
    assert "clear_key" in res


def test_issue_mock_license_claim_mismatch_rejected() -> None:
    ent = issue_entitlement_token(
        asset_id="asset_local_demo_001",
        tenant_id="dev-tenant",
        session_id="session-1",
        device_id="device-1",
        profile="multi_drm",
        key_id="k1",
        secret="secret",
        ttl_seconds=300,
    )
    bad = _license_req()
    bad["asset_id"] = "other"

    with pytest.raises(ValueError) as exc:
        issue_mock_license(payload=bad, token=ent["token"], secret="secret")
    assert "claim mismatch" in str(exc.value)

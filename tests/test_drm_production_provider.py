from __future__ import annotations

from types import SimpleNamespace

from app.services import drm_license_service
from app.services.drm_mock_license import issue_entitlement_token
from app.services.drm_production_provider import (
    DrmKeyRotationController,
    DrmRotationConfig,
    ProductionDrmLicenseProvider,
)


class _FakeSecrets:
    def __init__(self, value: str = "api-key"):
        self.value = value

    def get_secret(self, name: str) -> str:
        assert name == "DRM_PROVIDER_API_KEY"
        return self.value


class _FakeTransport:
    def __init__(self):
        self.last_payload = None
        self.last_headers = None
        self.last_url = None

    def post_json(self, *, url: str, headers: dict[str, str], payload: dict, timeout_seconds: int) -> dict:
        self.last_url = url
        self.last_headers = headers
        self.last_payload = payload
        return {"license_b64": "cHJvZHVjdGlvbi1saWNlbnNl", "renewal_url": "https://license.example/renew"}


def _license_req(profile: str) -> dict:
    return {
        "contract_version": "2026-03-drm-entitlement-v1",
        "profile": profile,
        "asset_id": "asset-1",
        "tenant_id": "tenant-1",
        "session_id": "sess-1",
        "device_id": "device-1",
        "challenge_b64": "Y2hhbGxlbmdl",
    }


def _claims(profile: str) -> dict:
    return {
        "contract_version": "2026-03-drm-entitlement-v1",
        "asset_id": "asset-1",
        "tenant_id": "tenant-1",
        "session_id": "sess-1",
        "device_id": "device-1",
        "profile": profile,
        "issued_at_epoch": 1_700_000_000,
        "expires_at_epoch": 1_700_000_600,
        "key_id": "entitled-key",
        "key_rotation_seconds": 300,
        "per_content_key": True,
        "offline_allowed": False,
    }


def test_rotation_controller_changes_key_id_when_slot_changes() -> None:
    controller = DrmKeyRotationController(DrmRotationConfig(enabled=True, rotation_seconds=300, id_salt="salt"))
    key_1 = controller.key_id_for(tenant_id="t", asset_id="a", profile="widevine", now_epoch=1_700_000_000)
    key_2 = controller.key_id_for(tenant_id="t", asset_id="a", profile="widevine", now_epoch=1_700_000_400)
    assert key_1 != key_2


def test_rotation_controller_stable_when_disabled() -> None:
    controller = DrmKeyRotationController(DrmRotationConfig(enabled=False, rotation_seconds=300, id_salt="salt"))
    key_1 = controller.key_id_for(tenant_id="t", asset_id="a", profile="widevine", now_epoch=1_700_000_000)
    key_2 = controller.key_id_for(tenant_id="t", asset_id="a", profile="widevine", now_epoch=1_800_000_000)
    assert key_1 == key_2


def test_provider_builds_profile_specific_payloads_and_validates_response() -> None:
    transport = _FakeTransport()
    provider = ProductionDrmLicenseProvider(
        endpoint_url="https://license.vendor.example/issue",
        secret_name="DRM_PROVIDER_API_KEY",
        timeout_seconds=5,
        rotation=DrmKeyRotationController(DrmRotationConfig(enabled=True, rotation_seconds=300, id_salt="salt")),
        secret_provider=_FakeSecrets(),
        transport=transport,
    )

    for profile, expected_family_key in [
        ("widevine", "widevine"),
        ("fairplay", "fairplay"),
        ("playready", "playready"),
        ("multi_drm", "widevine"),
    ]:
        response = provider.issue_license(payload=_license_req(profile), entitlement_claims=_claims(profile), now_epoch=1_700_000_000)
        assert response["profile"] == profile
        assert response["license_b64"]
        assert expected_family_key in transport.last_payload


def test_license_orchestrator_can_use_production_mode() -> None:
    transport = _FakeTransport()
    provider = ProductionDrmLicenseProvider(
        endpoint_url="https://license.vendor.example/issue",
        secret_name="DRM_PROVIDER_API_KEY",
        timeout_seconds=5,
        rotation=DrmKeyRotationController(DrmRotationConfig(enabled=True, rotation_seconds=300, id_salt="salt")),
        secret_provider=_FakeSecrets(),
        transport=transport,
    )

    entitlement = issue_entitlement_token(
        asset_id="asset-1",
        tenant_id="tenant-1",
        session_id="sess-1",
        device_id="device-1",
        profile="widevine",
        key_id="k-entitled",
        secret="token-secret",
        ttl_seconds=300,
    )

    original = drm_license_service.S
    drm_license_service.S = SimpleNamespace(drm_license_provider_mode="production")
    try:
        response = drm_license_service.issue_drm_license(
            payload=_license_req("widevine"),
            token=entitlement["token"],
            secret="token-secret",
            provider=provider,
            now_epoch=1_700_000_100,
        )
    finally:
        drm_license_service.S = original

    assert response["profile"] == "widevine"
    assert response["renewal_url"] == "https://license.example/renew"

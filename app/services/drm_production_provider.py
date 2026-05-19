from __future__ import annotations

import hashlib
import json
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol

from app.contracts.drm_entitlement_contract import DrmEntitlementClaims, DrmLicenseRequest
from app.core.settings import S
from app.services.drm_entitlement_service import validate_license_request, validate_license_response


class SecretProvider(Protocol):
    def get_secret(self, name: str) -> str: ...


class HttpTransport(Protocol):
    def post_json(self, *, url: str, headers: dict[str, str], payload: dict[str, Any], timeout_seconds: int) -> dict[str, Any]: ...


class EnvSecretProvider:
    def get_secret(self, name: str) -> str:
        value = (name or "").strip()
        if not value:
            raise ValueError("secret name is required")
        if value == "DRM_PROVIDER_API_KEY":
            secret = (S.drm_provider_api_key or "").strip()
            if not secret:
                raise ValueError("drm provider api key is not configured")
            return secret
        raise ValueError(f"unsupported secret reference: {value}")


class UrllibHttpTransport:
    def post_json(self, *, url: str, headers: dict[str, str], payload: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url=url, data=body, method="POST")
        request.add_header("Content-Type", "application/json")
        for key, value in headers.items():
            request.add_header(key, value)
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            data = response.read().decode("utf-8")
            return json.loads(data) if data else {}


@dataclass(frozen=True)
class DrmRotationConfig:
    enabled: bool
    rotation_seconds: int
    id_salt: str


class DrmKeyRotationController:
    def __init__(self, config: DrmRotationConfig):
        self._config = config

    def key_id_for(self, *, tenant_id: str, asset_id: str, profile: str, now_epoch: int) -> str:
        if self._config.enabled:
            slot = max(0, int(now_epoch) // max(60, int(self._config.rotation_seconds)))
            basis = f"{tenant_id}|{asset_id}|{profile}|{slot}|{self._config.id_salt}"
        else:
            basis = f"{tenant_id}|{asset_id}|{profile}|stable|{self._config.id_salt}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]


class ProductionDrmLicenseProvider:
    def __init__(
        self,
        *,
        endpoint_url: str,
        secret_name: str,
        timeout_seconds: int,
        rotation: DrmKeyRotationController,
        secret_provider: SecretProvider | None = None,
        transport: HttpTransport | None = None,
    ):
        cleaned = endpoint_url.strip()
        if not cleaned:
            raise ValueError("drm provider endpoint_url is required")
        self._endpoint_url = cleaned
        self._secret_name = secret_name.strip()
        self._timeout_seconds = max(1, int(timeout_seconds))
        self._rotation = rotation
        self._secrets = secret_provider or EnvSecretProvider()
        self._transport = transport or UrllibHttpTransport()

    def issue_license(self, *, payload: dict[str, Any], entitlement_claims: dict[str, Any], now_epoch: int | None = None) -> dict[str, Any]:
        req = validate_license_request(payload)
        claims = DrmEntitlementClaims.model_validate(entitlement_claims)
        _validate_claim_match(req=req, claims=claims)

        now = int(time.time()) if now_epoch is None else int(now_epoch)
        key_id = self._rotation.key_id_for(
            tenant_id=claims.tenant_id,
            asset_id=claims.asset_id,
            profile=claims.profile,
            now_epoch=now,
        )
        provider_payload = _build_provider_payload(req=req, claims=claims, key_id=key_id)
        api_key = self._secrets.get_secret(self._secret_name)

        provider_response = self._transport.post_json(
            url=self._endpoint_url,
            headers={"Authorization": f"Bearer {api_key}"},
            payload=provider_payload,
            timeout_seconds=self._timeout_seconds,
        )

        response_payload = {
            "contract_version": claims.contract_version,
            "profile": req.profile,
            "key_id": key_id,
            "license_b64": str(provider_response.get("license_b64") or ""),
            "expires_at_epoch": min(claims.expires_at_epoch, now + max(60, int(claims.key_rotation_seconds))),
            "renewal_url": provider_response.get("renewal_url"),
        }
        validated = validate_license_response(response_payload)
        return validated.model_dump()


def _validate_claim_match(*, req: DrmLicenseRequest, claims: DrmEntitlementClaims) -> None:
    for field in ("asset_id", "tenant_id", "session_id", "device_id", "profile"):
        if str(getattr(req, field)) != str(getattr(claims, field)):
            raise ValueError(f"token claim mismatch: {field}")


def _build_provider_payload(*, req: DrmLicenseRequest, claims: DrmEntitlementClaims, key_id: str) -> dict[str, Any]:
    body: dict[str, Any] = {
        "tenant_id": claims.tenant_id,
        "asset_id": claims.asset_id,
        "session_id": claims.session_id,
        "device_id": claims.device_id,
        "profile": claims.profile,
        "key_id": key_id,
        "offline_allowed": bool(claims.offline_allowed),
    }

    if req.profile in {"widevine", "multi_drm"}:
        body["widevine"] = {"challenge_b64": req.challenge_b64}
    if req.profile in {"fairplay", "multi_drm"}:
        body["fairplay"] = {"spc_b64": req.challenge_b64}
    if req.profile in {"playready", "multi_drm"}:
        body["playready"] = {"challenge_b64": req.challenge_b64}

    return body


def default_production_drm_provider() -> ProductionDrmLicenseProvider:
    rotation = DrmKeyRotationController(
        DrmRotationConfig(
            enabled=bool(S.drm_key_rotation_enabled),
            rotation_seconds=max(60, int(S.drm_key_rotation_seconds)),
            id_salt=(S.drm_key_rotation_salt or "dev-drm-rotation-salt"),
        )
    )
    secret_name = (S.drm_provider_api_key_secret_name or "DRM_PROVIDER_API_KEY").strip()
    return ProductionDrmLicenseProvider(
        endpoint_url=S.drm_provider_license_endpoint,
        secret_name=secret_name,
        timeout_seconds=max(1, int(S.drm_provider_timeout_seconds)),
        rotation=rotation,
    )

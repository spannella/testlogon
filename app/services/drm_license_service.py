from __future__ import annotations

from typing import Any

from app.core.settings import S
from app.services.drm_mock_license import issue_mock_license
from app.services.drm_mock_tokens import verify_mock_token
from app.services.drm_production_provider import ProductionDrmLicenseProvider, default_production_drm_provider


def issue_drm_license(
    *,
    payload: dict[str, Any],
    token: str,
    secret: str,
    now_epoch: int | None = None,
    provider: ProductionDrmLicenseProvider | None = None,
) -> dict[str, Any]:
    mode = (S.drm_license_provider_mode or "mock").strip().lower()
    if mode == "mock":
        return issue_mock_license(payload=payload, token=token, secret=secret, now_epoch=now_epoch)

    if mode != "production":
        raise ValueError(f"unsupported drm license provider mode: {mode}")

    claims = verify_mock_token(token=token, secret=secret, now_epoch=now_epoch)
    prod_provider = provider or default_production_drm_provider()
    return prod_provider.issue_license(payload=payload, entitlement_claims=claims, now_epoch=now_epoch)

from __future__ import annotations

import time
from typing import Any

from pydantic import ValidationError

from app.contracts.drm_entitlement_contract import (
    DRM_ENTITLEMENT_CONTRACT_VERSION,
    DrmEntitlementClaims,
    DrmLicenseRequest,
    DrmLicenseResponse,
)


def build_entitlement_claims(payload: dict[str, Any]) -> DrmEntitlementClaims:
    now = int(time.time())
    enriched = {
        "contract_version": DRM_ENTITLEMENT_CONTRACT_VERSION,
        "issued_at_epoch": now,
        **payload,
    }
    if "expires_at_epoch" not in enriched and "ttl_seconds" in enriched:
        enriched["expires_at_epoch"] = now + int(enriched["ttl_seconds"])
    try:
        claims = DrmEntitlementClaims.model_validate(enriched)
    except ValidationError as exc:
        errors = sorted(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors(include_url=False))
        raise ValueError(f"invalid drm entitlement claims payload: {' | '.join(errors)}") from exc

    if claims.expires_at_epoch <= claims.issued_at_epoch:
        raise ValueError("invalid drm entitlement claims payload: expires_at_epoch must be greater than issued_at_epoch")
    return claims


def validate_license_request(payload: dict[str, Any]) -> DrmLicenseRequest:
    try:
        return DrmLicenseRequest.model_validate(payload)
    except ValidationError as exc:
        errors = sorted(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors(include_url=False))
        raise ValueError(f"invalid drm license request payload: {' | '.join(errors)}") from exc


def validate_license_response(payload: dict[str, Any]) -> DrmLicenseResponse:
    try:
        return DrmLicenseResponse.model_validate(payload)
    except ValidationError as exc:
        errors = sorted(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors(include_url=False))
        raise ValueError(f"invalid drm license response payload: {' | '.join(errors)}") from exc

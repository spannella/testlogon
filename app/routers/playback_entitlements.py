from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.core.settings import S
from app.services.playback_entitlements import (
    PlaybackEntitlementError,
    issue_playback_entitlement,
    revoke_playback_entitlement,
    validate_playback_entitlement,
)

router = APIRouter(prefix="/v1/playback", tags=["playback-entitlements"])


class IssuePlaybackEntitlementIn(BaseModel):
    tenant_id: str = Field(min_length=1)
    asset_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    device_id: str = Field(min_length=1)
    profile: str = Field(min_length=1)
    audience: str = Field(default="playback", min_length=1)
    ttl_seconds: int = Field(default=120, ge=1)


class RevokePlaybackEntitlementIn(BaseModel):
    jti: str | None = None
    session_id: str | None = None
    tenant_id: str | None = None
    expires_at_epoch: int = Field(..., ge=1)


def _require_any_revocation_selector(body: RevokePlaybackEntitlementIn) -> None:
    if not body.jti and not body.session_id:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_revocation_request", "message": "either jti or session_id is required"},
        )
    if body.session_id and not (body.tenant_id or "").strip():
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_revocation_request", "message": "tenant_id is required when revoking by session_id"},
        )


@router.post("/entitlements/issue")
def issue_entitlement(
    body: IssuePlaybackEntitlementIn,
    actor: AuthenticatedUser = Depends(get_authenticated_user),
):
    try:
        out = issue_playback_entitlement(
            tenant_id=body.tenant_id,
            asset_id=body.asset_id,
            session_id=body.session_id,
            device_id=body.device_id,
            profile=body.profile,
            audience=body.audience,
            ttl_seconds=body.ttl_seconds,
        )
    except PlaybackEntitlementError as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message}) from exc

    return {"entitlement": out, "issued_for": actor.sub}


@router.post("/entitlements/revoke")
def revoke_entitlement(
    body: RevokePlaybackEntitlementIn,
    actor: AuthenticatedUser = Depends(get_authenticated_user),
):
    _require_any_revocation_selector(body)
    try:
        revoke_playback_entitlement(
            jti=body.jti,
            session_id=body.session_id,
            tenant_id=body.tenant_id,
            expires_at_epoch=body.expires_at_epoch,
        )
    except PlaybackEntitlementError as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message}) from exc
    return {
        "ok": True,
        "revoked": {
            "jti": body.jti,
            "session_id": body.session_id,
            "tenant_id": body.tenant_id,
            "expires_at_epoch": body.expires_at_epoch,
        },
        "revoked_by": actor.sub,
    }


@router.get("/protected/ping")
def protected_playback_ping(req: Request):
    claims = getattr(req.state, "playback_claims", None)
    if claims is None:
        token = _extract_bearer_token(req)
        expected_aud = (S.playback_entitlement_expected_audience or "playback").strip() or "playback"
        try:
            claims = validate_playback_entitlement(token=token, expected_audience=expected_aud)
        except PlaybackEntitlementError as exc:
            raise HTTPException(status_code=401, detail={"code": exc.code, "message": exc.message}) from exc
    return {"ok": True, "claims": claims}


def _extract_bearer_token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail={"code": "missing_bearer", "message": "missing bearer token"})
    token = auth.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail={"code": "missing_bearer", "message": "missing bearer token"})
    return token

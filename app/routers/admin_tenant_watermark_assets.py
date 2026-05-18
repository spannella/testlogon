from __future__ import annotations

import importlib.util

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.services.alerts import audit_event
from app.services.tenant_watermark_assets import (
    assign_tenant_watermark_asset,
    list_tenant_watermark_assets,
    set_tenant_default_watermark_profile,
    upload_tenant_watermark_asset,
)

router = APIRouter(prefix="/v1/admin/tenants", tags=["admin-tenant-watermark-assets"])

_MULTIPART_AVAILABLE = importlib.util.find_spec("multipart") is not None


class SetDefaultWatermarkProfileIn(BaseModel):
    profile_id: str = Field(min_length=1)


@router.get("/{tenant_id}/watermark-assets")
def admin_list_tenant_watermark_assets(
    tenant_id: str,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    return list_tenant_watermark_assets(tenant_id=tenant_id)


if _MULTIPART_AVAILABLE:
    @router.post("/{tenant_id}/watermark-assets/upload")
    async def admin_upload_tenant_watermark_asset(
        req: Request,
        tenant_id: str,
        file: UploadFile = File(...),
        profile_id: str | None = Form(default=None),
        actor: AuthenticatedUser = Depends(require_admin_or_root),
    ):
        content = await file.read()
        asset = upload_tenant_watermark_asset(
            tenant_id=tenant_id,
            file_name=file.filename or "watermark.bin",
            content=content,
            content_type=file.content_type,
        )
        if profile_id:
            asset = assign_tenant_watermark_asset(
                tenant_id=tenant_id,
                profile_id=profile_id,
                asset_id=asset["asset_id"],
            )
        audit_event(
            "admin_tenant_watermark_asset_upload",
            actor.sub,
            req,
            outcome="success",
            tenant_id=tenant_id,
            asset_id=asset["asset_id"],
            profile_id=profile_id,
        )
        return {"asset": asset}
else:
    @router.post("/{tenant_id}/watermark-assets/upload")
    async def admin_upload_tenant_watermark_asset_unavailable(
        tenant_id: str,
        actor: AuthenticatedUser = Depends(require_admin_or_root),
    ):
        raise HTTPException(status_code=501, detail="python-multipart is required for uploads")


@router.post("/{tenant_id}/watermark-assets/{asset_id}/assign/{profile_id}")
def admin_assign_tenant_watermark_asset(
    req: Request,
    tenant_id: str,
    asset_id: str,
    profile_id: str,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    asset = assign_tenant_watermark_asset(tenant_id=tenant_id, profile_id=profile_id, asset_id=asset_id)
    audit_event(
        "admin_tenant_watermark_asset_assign",
        actor.sub,
        req,
        outcome="success",
        tenant_id=tenant_id,
        asset_id=asset_id,
        profile_id=profile_id,
    )
    return {"asset": asset}


@router.put("/{tenant_id}/watermark-default-profile")
def admin_set_tenant_watermark_default_profile(
    req: Request,
    tenant_id: str,
    body: SetDefaultWatermarkProfileIn,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    result = set_tenant_default_watermark_profile(tenant_id=tenant_id, profile_id=body.profile_id)
    audit_event(
        "admin_tenant_watermark_default_profile_set",
        actor.sub,
        req,
        outcome="success",
        tenant_id=tenant_id,
        profile_id=body.profile_id,
    )
    return result

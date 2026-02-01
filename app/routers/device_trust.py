from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.models import DeviceTrustListOut
from app.services.device_trust import list_devices, trust_device, revoke_device
from app.services.sessions import require_ui_session, require_fresh_mfa
from app.services.alerts import audit_event

router = APIRouter(prefix="/ui/devices", tags=["device-trust"])


@router.get("", response_model=DeviceTrustListOut)
async def ui_devices(ctx=Depends(require_ui_session)):
    return DeviceTrustListOut(devices=list_devices(ctx["user_sub"]))


@router.post("/{device_id}/trust")
async def ui_device_trust(req: Request, device_id: str, ctx=Depends(require_ui_session)):
    require_fresh_mfa(ctx)
    trust_device(ctx["user_sub"], device_id)
    audit_event("device_trust", ctx["user_sub"], req, outcome="success", device_id=device_id)
    return {"status": "ok"}


@router.post("/{device_id}/revoke")
async def ui_device_revoke(req: Request, device_id: str, ctx=Depends(require_ui_session)):
    require_fresh_mfa(ctx)
    revoke_device(ctx["user_sub"], device_id)
    audit_event("device_revoke", ctx["user_sub"], req, outcome="success", device_id=device_id)
    return {"status": "ok"}

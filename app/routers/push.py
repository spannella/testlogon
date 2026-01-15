from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.settings import S
from app.models import PushRegisterReq, PushRevokeReq
from app.services.alerts import audit_event
from app.services.push import list_push_devices, revoke_push_device, send_push_for_alert, upsert_push_device
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui", tags=["push"])


@router.get("/push/devices")
async def ui_list_push_devices(ctx=Depends(require_ui_session)):
    return {"devices": list_push_devices(ctx["user_sub"])}


@router.post("/push/register")
async def ui_register_push(req: Request, body: PushRegisterReq, ctx=Depends(require_ui_session)):
    if not S.push_enabled:
        raise HTTPException(400, "Push disabled")
    token = (body.token or "").strip()
    if len(token) < 20:
        raise HTTPException(400, "Bad token")
    platform = (body.platform or "").strip()[:32]
    it = upsert_push_device(ctx["user_sub"], token, platform)
    audit_event("push_device_register", ctx["user_sub"], req, outcome="success", platform=platform)
    return it


@router.post("/push/revoke")
async def ui_revoke_push(req: Request, body: PushRevokeReq, ctx=Depends(require_ui_session)):
    revoke_push_device(ctx["user_sub"], body.device_id)
    audit_event("push_device_revoke", ctx["user_sub"], req, outcome="success", device_id=body.device_id)
    return {"ok": True}


@router.post("/push/test")
async def ui_push_test(req: Request, ctx=Depends(require_ui_session)):
    send_push_for_alert(ctx["user_sub"], "security_event", "Test notification", "This is a test push.", "test")
    audit_event("push_test", ctx["user_sub"], req, outcome="success")
    return {"ok": True}

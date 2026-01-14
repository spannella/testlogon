from __future__ import annotations

from typing import Any, Dict

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException, Request

from app.models import (
    TotpDeviceBeginReq, TotpDeviceConfirmReq,
    SmsDeviceBeginReq, SmsDeviceConfirmReq, SmsDeviceRemoveBeginReq, SmsDeviceRemoveConfirmReq,
    EmailDeviceBeginReq, EmailDeviceConfirmReq, EmailDeviceRemoveBeginReq, EmailDeviceRemoveConfirmReq,
)
from app.services.alerts import audit_event
from app.services.mfa import (
    totp_begin_enroll, totp_confirm_enroll,
    sms_begin_enroll, sms_confirm_enroll,
    email_begin_enroll, email_confirm_enroll,
)
from app.services.sessions import require_ui_session
from app.core.tables import T

router = APIRouter(prefix="/ui/mfa", tags=["mfa-devices"])

@router.get("/totp/devices")
async def totp_devices(ctx=Depends(require_ui_session)):
    r = T.totp.query(KeyConditionExpression=Key("user_sub").eq(ctx["user_sub"]))
    devices = []
    for it in r.get("Items", []):
        devices.append({"device_id": it["device_id"], "label": it.get("label",""), "enabled": it.get("enabled", False), "created_at": it.get("created_at",0)})
    devices.sort(key=lambda x: x.get("created_at",0), reverse=True)
    return {"devices": devices}

@router.post("/totp/devices/begin")
async def totp_devices_begin(req: Request, body: TotpDeviceBeginReq, ctx=Depends(require_ui_session)):
    out = totp_begin_enroll(ctx["user_sub"], body.label)
    audit_event("totp_device_begin", ctx["user_sub"], req, outcome="success", device_id=out["device_id"])
    return out

@router.post("/totp/devices/confirm")
async def totp_devices_confirm(req: Request, body: TotpDeviceConfirmReq, ctx=Depends(require_ui_session)):
    totp_confirm_enroll(ctx["user_sub"], body.device_id, body.code)
    audit_event("totp_device_confirm", ctx["user_sub"], req, outcome="success", device_id=body.device_id)
    return {"status":"ok"}

@router.post("/totp/devices/{device_id}/remove")
async def totp_devices_remove(req: Request, device_id: str, ctx=Depends(require_ui_session)):
    try:
        T.totp.delete_item(Key={"user_sub": ctx["user_sub"], "device_id": device_id})
    except Exception:
        raise HTTPException(404, "Unknown device")
    audit_event("totp_device_remove", ctx["user_sub"], req, outcome="success", device_id=device_id)
    return {"status":"ok"}

@router.get("/sms/devices")
async def sms_devices(ctx=Depends(require_ui_session)):
    r = T.sms.query(KeyConditionExpression=Key("user_sub").eq(ctx["user_sub"]))
    devices=[]
    for it in r.get("Items", []):
        devices.append({"sms_device_id": it["sms_device_id"], "phone_e164": it.get("phone_e164",""), "label": it.get("label",""), "enabled": it.get("enabled", False), "created_at": it.get("created_at",0)})
    devices.sort(key=lambda x: x.get("created_at",0), reverse=True)
    return {"devices": devices}

@router.post("/sms/devices/begin")
async def sms_devices_begin(req: Request, body: SmsDeviceBeginReq, ctx=Depends(require_ui_session)):
    out = sms_begin_enroll(ctx["user_sub"], body.phone_e164, body.label)
    audit_event("sms_device_begin", ctx["user_sub"], req, outcome="success", sms_device_id=out["sms_device_id"])
    return out

@router.post("/sms/devices/confirm")
async def sms_devices_confirm(req: Request, body: SmsDeviceConfirmReq, ctx=Depends(require_ui_session)):
    sms_confirm_enroll(ctx["user_sub"], body.sms_device_id)
    audit_event("sms_device_confirm", ctx["user_sub"], req, outcome="success", sms_device_id=body.sms_device_id)
    return {"status":"ok"}

@router.post("/sms/devices/{sms_device_id}/remove/begin")
async def sms_devices_remove_begin(_: Request, sms_device_id: str, __=Depends(require_ui_session)):
    # TODO: require step-up before removal; kept for compatibility
    return {"status":"ok","sms_device_id": sms_device_id}

@router.post("/sms/devices/remove/confirm")
async def sms_devices_remove_confirm(req: Request, body: SmsDeviceRemoveConfirmReq, ctx=Depends(require_ui_session)):
    try:
        T.sms.delete_item(Key={"user_sub": ctx["user_sub"], "sms_device_id": body.sms_device_id})
    except Exception:
        raise HTTPException(404, "Unknown device")
    audit_event("sms_device_remove", ctx["user_sub"], req, outcome="success", sms_device_id=body.sms_device_id)
    return {"status":"ok"}

@router.get("/email/devices")
async def email_devices(ctx=Depends(require_ui_session)):
    r = T.email.query(KeyConditionExpression=Key("user_sub").eq(ctx["user_sub"]))
    devices=[]
    for it in r.get("Items", []):
        devices.append({"email_device_id": it["email_device_id"], "email": it.get("email",""), "label": it.get("label",""), "enabled": it.get("enabled", False), "created_at": it.get("created_at",0)})
    devices.sort(key=lambda x: x.get("created_at",0), reverse=True)
    return {"devices": devices}

@router.post("/email/devices/begin")
async def email_devices_begin(req: Request, body: EmailDeviceBeginReq, ctx=Depends(require_ui_session)):
    out = email_begin_enroll(ctx["user_sub"], body.email, body.label)
    audit_event("email_device_begin", ctx["user_sub"], req, outcome="success", email_device_id=out["email_device_id"])
    return out

@router.post("/email/devices/confirm")
async def email_devices_confirm(req: Request, body: EmailDeviceConfirmReq, ctx=Depends(require_ui_session)):
    email_confirm_enroll(ctx["user_sub"], body.email_device_id)
    audit_event("email_device_confirm", ctx["user_sub"], req, outcome="success", email_device_id=body.email_device_id)
    return {"status":"ok"}

@router.post("/email/devices/{email_device_id}/remove/begin")
async def email_devices_remove_begin(_: Request, email_device_id: str, __=Depends(require_ui_session)):
    # TODO: require step-up before removal; kept for compatibility
    return {"status":"ok","email_device_id": email_device_id}

@router.post("/email/devices/remove/confirm")
async def email_devices_remove_confirm(req: Request, body: EmailDeviceRemoveConfirmReq, ctx=Depends(require_ui_session)):
    try:
        T.email.delete_item(Key={"user_sub": ctx["user_sub"], "email_device_id": body.email_device_id})
    except Exception:
        raise HTTPException(404, "Unknown device")
    audit_event("email_device_remove", ctx["user_sub"], req, outcome="success", email_device_id=body.email_device_id)
    return {"status":"ok"}

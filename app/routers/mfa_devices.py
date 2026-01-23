from __future__ import annotations

from typing import Any, Callable, Dict, List

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException, Request

from app.models import (
    TotpDeviceBeginReq, TotpDeviceConfirmReq,
    TotpDeviceRemoveReq,
    SmsDeviceBeginReq, SmsDeviceConfirmReq, SmsDeviceRemoveConfirmReq,
    EmailDeviceBeginReq, EmailDeviceConfirmReq, EmailDeviceRemoveConfirmReq,
)
from app.core.crypto import sha256_str
from app.core.normalize import normalize_phone, normalize_email
from app.core.settings import S
from app.services.alerts import audit_event
from app.services.mfa import (
    totp_begin_enroll, totp_confirm_enroll,
    gen_numeric_code,
    list_enabled_emails,
    list_enabled_sms_numbers,
    send_email_code,
    totp_verify_any_enabled,
    twilio_start_sms,
    verify_code_any_sms,
    new_recovery_codes,
    store_recovery_codes,
)
from app.services.rate_limit import rate_limit_or_429
from app.services.sessions import create_action_challenge, load_challenge_or_401, require_ui_session, revoke_challenge
from app.core.tables import T
from app.core.time import now_ts

router = APIRouter(prefix="/ui/mfa", tags=["mfa-devices"])


def _sorted_devices(items: List[Dict[str, Any]], mapper: Callable[[Dict[str, Any]], Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    devices = [mapper(it) for it in items]
    devices.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return {"devices": devices}


@router.get("/totp/devices")
async def totp_devices(ctx=Depends(require_ui_session)):
    r = T.totp.query(KeyConditionExpression=Key("user_sub").eq(ctx["user_sub"]))
    return _sorted_devices(
        r.get("Items", []),
        lambda it: {
            "device_id": it["device_id"],
            "label": it.get("label", ""),
            "enabled": it.get("enabled", False),
            "created_at": it.get("created_at", 0),
            "last_used_at": it.get("last_used_at", 0),
        },
    )

@router.post("/totp/devices/begin")
async def totp_devices_begin(req: Request, body: TotpDeviceBeginReq, ctx=Depends(require_ui_session)):
    out = totp_begin_enroll(ctx["user_sub"], body.label)
    audit_event("totp_device_begin", ctx["user_sub"], req, outcome="success", device_id=out["device_id"])
    return out

@router.post("/totp/devices/confirm")
async def totp_devices_confirm(req: Request, body: TotpDeviceConfirmReq, ctx=Depends(require_ui_session)):
    totp_confirm_enroll(ctx["user_sub"], body.device_id, body.totp_code)
    audit_event("totp_device_confirm", ctx["user_sub"], req, outcome="success", device_id=body.device_id)
    return {"ok": True}

@router.post("/totp/devices/{device_id}/remove")
async def totp_devices_remove(req: Request, device_id: str, body: TotpDeviceRemoveReq, ctx=Depends(require_ui_session)):
    if not totp_verify_any_enabled(ctx["user_sub"], body.totp_code):
        raise HTTPException(401, "Bad TOTP")
    try:
        T.totp.delete_item(Key={"user_sub": ctx["user_sub"], "device_id": device_id})
    except Exception:
        raise HTTPException(404, "Unknown device")
    audit_event("totp_device_remove", ctx["user_sub"], req, outcome="success", device_id=device_id)
    return {"ok": True}

@router.get("/sms/devices")
async def sms_devices(ctx=Depends(require_ui_session)):
    r = T.sms.query(KeyConditionExpression=Key("user_sub").eq(ctx["user_sub"]))
    return _sorted_devices(
        r.get("Items", []),
        lambda it: {
            "sms_device_id": it["sms_device_id"],
            "phone_e164": it.get("phone_e164", ""),
            "label": it.get("label", ""),
            "enabled": it.get("enabled", False),
            "pending": it.get("pending", False),
            "created_at": it.get("created_at", 0),
            "last_used_at": it.get("last_used_at", 0),
        },
    )

@router.post("/sms/devices/begin")
async def sms_devices_begin(req: Request, body: SmsDeviceBeginReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    rate_limit_or_429(user_sub, "enroll_sms")
    phone = normalize_phone(body.phone_e164)
    r = T.sms.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    existing = r.get("Items", [])
    enabled_or_pending = [d for d in existing if d.get("enabled", False) or d.get("pending", False)]
    if len(enabled_or_pending) >= S.sms_device_limit:
        raise HTTPException(400, f"SMS device limit reached ({S.sms_device_limit})")
    sms_device_id = "sms_" + sha256_str(f"{user_sub}:{phone}:{now_ts()}")[:20]
    ts = now_ts()
    T.sms.put_item(Item={
        "user_sub": user_sub,
        "sms_device_id": sms_device_id,
        "phone_e164": phone,
        "label": (body.label or "")[:64],
        "enabled": False,
        "pending": True,
        "created_at": ts,
        "last_used_at": 0,
    })
    send_to = list(dict.fromkeys(list_enabled_sms_numbers(user_sub) + [phone]))
    for n in send_to:
        twilio_start_sms(n)
    challenge_id = create_action_challenge(
        req,
        user_sub=user_sub,
        purpose="sms_enroll",
        send_to=send_to,
        payload={"sms_device_id": sms_device_id},
    )
    audit_event("sms_device_begin", ctx["user_sub"], req, outcome="success", sms_device_id=sms_device_id)
    return {"challenge_id": challenge_id, "sent_to": send_to, "sms_device_id": sms_device_id}

@router.post("/sms/devices/confirm")
async def sms_devices_confirm(req: Request, body: SmsDeviceConfirmReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if chal.get("purpose") != "sms_enroll":
        raise HTTPException(400, "Wrong challenge purpose")
    send_to = chal.get("send_to", []) or []
    if not verify_code_any_sms(send_to, body.code.strip()):
        raise HTTPException(401, "Bad SMS code")
    sms_device_id = chal["sms_device_id"]
    T.sms.update_item(
        Key={"user_sub": user_sub, "sms_device_id": sms_device_id},
        UpdateExpression="SET enabled = :t, pending = :f",
        ExpressionAttributeValues={":t": True, ":f": False},
    )
    r = T.sms.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    enabled_count = sum(1 for d in r.get("Items", []) if d.get("enabled", False))
    recovery_codes: List[str] = []
    if enabled_count == 1:
        recovery_codes = new_recovery_codes(10)
        store_recovery_codes(user_sub, "sms", recovery_codes)
    revoke_challenge(user_sub, body.challenge_id)
    audit_event("sms_device_confirm", ctx["user_sub"], req, outcome="success", sms_device_id=sms_device_id)
    return {"ok": True, "sms_device_id": sms_device_id, "recovery_codes": recovery_codes}

@router.post("/sms/devices/{sms_device_id}/remove/begin")
async def sms_devices_remove_begin(req: Request, sms_device_id: str, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    rate_limit_or_429(user_sub, "remove_sms")
    it = T.sms.get_item(Key={"user_sub": user_sub, "sms_device_id": sms_device_id}).get("Item")
    if not it:
        raise HTTPException(404, "SMS device not found")
    nums = list_enabled_sms_numbers(user_sub)
    target = it.get("phone_e164")
    send_to = [n for n in nums if n != target]
    if not send_to:
        raise HTTPException(400, "No other enabled SMS numbers to confirm removal (use SMS recovery code)")
    for n in send_to:
        twilio_start_sms(n)
    challenge_id = create_action_challenge(
        req,
        user_sub=user_sub,
        purpose="sms_remove",
        send_to=send_to,
        payload={"sms_device_id": sms_device_id},
    )
    return {"challenge_id": challenge_id, "sent_to": send_to}

@router.post("/sms/devices/remove/confirm")
async def sms_devices_remove_confirm(req: Request, body: SmsDeviceRemoveConfirmReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if chal.get("purpose") != "sms_remove":
        raise HTTPException(400, "Wrong challenge purpose")
    send_to = chal.get("send_to", []) or []
    if not verify_code_any_sms(send_to, body.code.strip()):
        raise HTTPException(401, "Bad SMS code")
    sms_device_id = chal["sms_device_id"]
    T.sms.delete_item(Key={"user_sub": user_sub, "sms_device_id": sms_device_id})
    revoke_challenge(user_sub, body.challenge_id)
    audit_event("sms_device_remove", ctx["user_sub"], req, outcome="success", sms_device_id=sms_device_id)
    return {"ok": True}

@router.get("/email/devices")
async def email_devices(ctx=Depends(require_ui_session)):
    r = T.email.query(KeyConditionExpression=Key("user_sub").eq(ctx["user_sub"]))
    return _sorted_devices(
        r.get("Items", []),
        lambda it: {
            "email_device_id": it["email_device_id"],
            "email": it.get("email", ""),
            "label": it.get("label", ""),
            "enabled": it.get("enabled", False),
            "pending": it.get("pending", False),
            "created_at": it.get("created_at", 0),
            "last_used_at": it.get("last_used_at", 0),
        },
    )

@router.post("/email/devices/begin")
async def email_devices_begin(req: Request, body: EmailDeviceBeginReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    rate_limit_or_429(user_sub, "enroll_email")
    email = normalize_email(body.email)
    r = T.email.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    existing = r.get("Items", [])
    enabled_or_pending = [d for d in existing if d.get("enabled", False) or d.get("pending", False)]
    if len(enabled_or_pending) >= S.email_device_limit:
        raise HTTPException(400, f"Email device limit reached ({S.email_device_limit})")
    email_device_id = "em_" + sha256_str(f"{user_sub}:{email}:{now_ts()}")[:20]
    ts = now_ts()
    T.email.put_item(Item={
        "user_sub": user_sub,
        "email_device_id": email_device_id,
        "email": email,
        "label": (body.label or "")[:64],
        "enabled": False,
        "pending": True,
        "created_at": ts,
        "last_used_at": 0,
    })
    enabled_emails = [d["email"] for d in existing if d.get("enabled", False)]
    send_to = list(dict.fromkeys(enabled_emails + [email]))
    code = gen_numeric_code(6)
    code_hash = sha256_str(code)
    challenge_id = create_action_challenge(
        req,
        user_sub=user_sub,
        purpose="email_enroll",
        send_to=send_to,
        payload={"email_device_id": email_device_id, "email_code_hash": code_hash},
    )
    for e in send_to:
        send_email_code(e, "add-email", code)
    audit_event("email_device_begin", ctx["user_sub"], req, outcome="success", email_device_id=email_device_id)
    return {"challenge_id": challenge_id, "sent_to": send_to, "email_device_id": email_device_id}

@router.post("/email/devices/confirm")
async def email_devices_confirm(req: Request, body: EmailDeviceConfirmReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if chal.get("purpose") != "email_enroll":
        raise HTTPException(400, "Wrong challenge purpose")
    if sha256_str(body.code.strip()) != chal.get("email_code_hash"):
        raise HTTPException(401, "Bad email code")
    email_device_id = chal["email_device_id"]
    T.email.update_item(
        Key={"user_sub": user_sub, "email_device_id": email_device_id},
        UpdateExpression="SET enabled = :t, pending = :f",
        ExpressionAttributeValues={":t": True, ":f": False, ":p": True},
        ConditionExpression="pending = :p",
    )
    r = T.email.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    enabled_count = sum(1 for d in r.get("Items", []) if d.get("enabled", False))
    recovery_codes: List[str] = []
    if enabled_count == 1:
        recovery_codes = new_recovery_codes(10)
        store_recovery_codes(user_sub, "email", recovery_codes)
    revoke_challenge(user_sub, body.challenge_id)
    audit_event("email_device_confirm", ctx["user_sub"], req, outcome="success", email_device_id=email_device_id)
    return {"ok": True, "email_device_id": email_device_id, "recovery_codes": recovery_codes}

@router.post("/email/devices/{email_device_id}/remove/begin")
async def email_devices_remove_begin(req: Request, email_device_id: str, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    rate_limit_or_429(user_sub, "remove_email")
    it = T.email.get_item(Key={"user_sub": user_sub, "email_device_id": email_device_id}).get("Item")
    if not it:
        raise HTTPException(404, "Email device not found")
    enabled = list_enabled_emails(user_sub)
    target = it.get("email")
    send_to = [e for e in enabled if e != target]
    if not send_to:
        raise HTTPException(400, "No other enabled emails to confirm removal (use email recovery code)")
    code = gen_numeric_code(6)
    code_hash = sha256_str(code)
    challenge_id = create_action_challenge(
        req,
        user_sub=user_sub,
        purpose="email_remove",
        send_to=send_to,
        payload={"email_device_id": email_device_id, "email_code_hash": code_hash},
    )
    for e in send_to:
        send_email_code(e, "remove-email", code)
    return {"challenge_id": challenge_id, "sent_to": send_to}

@router.post("/email/devices/remove/confirm")
async def email_devices_remove_confirm(req: Request, body: EmailDeviceRemoveConfirmReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if chal.get("purpose") != "email_remove":
        raise HTTPException(400, "Wrong challenge purpose")
    if sha256_str(body.code.strip()) != chal.get("email_code_hash"):
        raise HTTPException(401, "Bad email code")
    email_device_id = chal["email_device_id"]
    T.email.delete_item(Key={"user_sub": user_sub, "email_device_id": email_device_id})
    revoke_challenge(user_sub, body.challenge_id)
    audit_event("email_device_remove", ctx["user_sub"], req, outcome="success", email_device_id=email_device_id)
    return {"ok": True}

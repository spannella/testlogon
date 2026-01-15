from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from app.core.crypto import sha256_str
from app.core.cursor import decode_cursor, encode_cursor
from app.core.normalize import normalize_email, normalize_phone
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    AlertEmailBeginReq,
    AlertEmailConfirmReq,
    AlertEmailPrefsReq,
    AlertEmailRemoveReq,
    AlertPushPrefsReq,
    AlertSmsBeginReq,
    AlertSmsConfirmReq,
    AlertSmsPrefsReq,
    AlertSmsRemoveReq,
    AlertToastPrefsReq,
    MarkReadReq,
)
from app.services.alerts import (
    ALERT_EVENT_TYPES,
    audit_event,
    get_alert_prefs,
    send_alert_email,
    send_alert_sms,
    set_alert_prefs,
    sse_subscribe,
    sse_unsubscribe,
)
from app.services.mfa import gen_numeric_code
from app.services.rate_limit import can_send_verification
from app.services.sessions import create_action_challenge, load_challenge_or_401, require_ui_session, revoke_challenge

router = APIRouter(prefix="/ui", tags=["alerts"])


@router.get("/alerts/types")
async def alert_types(_: Dict[str, str] = Depends(require_ui_session)):
    return {"types": ALERT_EVENT_TYPES, "event_types": ALERT_EVENT_TYPES}


@router.get("/alerts")
async def list_alerts(
    limit: int = 50,
    cursor: Optional[str] = None,
    unread_only: int = 0,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    eks = decode_cursor(cursor)
    r = T.alerts.query(
        KeyConditionExpression=Key("user_sub").eq(ctx["user_sub"]),
        ScanIndexForward=False,
        Limit=max(1, min(int(limit), 200)),
        ExclusiveStartKey=eks or None,
    )
    items = r.get("Items", [])
    next_cursor = encode_cursor(r.get("LastEvaluatedKey"))
    out = []
    for it in items:
        if unread_only and it.get("read", False):
            continue
        out.append({
            "alert_id": it.get("alert_id"),
            "ts": it.get("ts"),
            "event": it.get("event"),
            "outcome": it.get("outcome"),
            "title": it.get("title"),
            "details": it.get("details", {}),
            "read": it.get("read", False),
            "read_at": it.get("read_at", 0),
            "toast_delivered": it.get("toast_delivered", False),
        })
    return {"alerts": out, "next_cursor": next_cursor}


@router.post("/alerts/mark_read")
async def mark_read(body: MarkReadReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    ts = now_ts()
    updated = 0
    for aid in body.alert_ids[:200]:
        try:
            T.alerts.update_item(
                Key={"user_sub": ctx["user_sub"], "alert_id": aid},
                UpdateExpression="SET #r=:t, read_at=:ts",
                ExpressionAttributeNames={"#r": "read"},
                ExpressionAttributeValues={":t": True, ":ts": ts},
            )
            updated += 1
        except Exception:
            pass
    return {"ok": True, "updated": updated}


@router.get("/alerts/email_prefs")
async def get_email_prefs(ctx: Dict[str, str] = Depends(require_ui_session)):
    return get_alert_prefs(ctx["user_sub"])


@router.post("/alerts/email_prefs")
async def set_email_prefs(body: AlertEmailPrefsReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = set_alert_prefs(ctx["user_sub"], email_event_types=body.email_event_types)
    audit_event("alerts_email_prefs_set", ctx["user_sub"], None, outcome="success", enabled=len(prefs.get("email_event_types") or []))
    return prefs


@router.get("/alerts/sms_prefs")
async def get_sms_prefs(ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = get_alert_prefs(ctx["user_sub"])
    return {"sms_numbers": prefs["sms_numbers"], "event_types": prefs["sms_event_types"]}


@router.post("/alerts/sms_prefs")
async def set_sms_prefs(body: AlertSmsPrefsReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = set_alert_prefs(ctx["user_sub"], sms_event_types=body.sms_event_types)
    audit_event("alerts_sms_prefs_set", ctx["user_sub"], None, outcome="success", enabled=len(prefs.get("sms_event_types") or []))
    return prefs


@router.get("/alerts/toast_prefs")
async def get_toast_prefs(ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = get_alert_prefs(ctx["user_sub"])
    return {"event_types": prefs["toast_event_types"]}


@router.post("/alerts/toast_prefs")
async def set_toast_prefs(body: AlertToastPrefsReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = set_alert_prefs(ctx["user_sub"], toast_event_types=body.toast_event_types)
    audit_event("alerts_toast_prefs_set", ctx["user_sub"], None, outcome="success", enabled=len(prefs.get("toast_event_types") or []))
    return prefs


@router.post("/alerts/push_prefs")
async def set_push_prefs(body: AlertPushPrefsReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = set_alert_prefs(ctx["user_sub"], push_event_types=body.push_event_types)
    audit_event("alerts_push_prefs_set", ctx["user_sub"], None, outcome="success", enabled=len(prefs.get("push_event_types") or []))
    return prefs


@router.post("/alerts/mark_toast_delivered")
async def mark_toast_delivered(body: Dict[str, Any], ctx: Dict[str, str] = Depends(require_ui_session)):
    updated = 0
    for aid in (body.get("alert_ids") or [])[:200]:
        try:
            T.alerts.update_item(
                Key={"user_sub": ctx["user_sub"], "alert_id": aid},
                UpdateExpression="SET toast_delivered = :t, toast_delivered_at = :now",
                ExpressionAttributeValues={":t": True, ":now": now_ts()},
            )
            updated += 1
        except Exception:
            pass
    return {"ok": True, "updated": updated}


def _check_attempt_budget(chal: Dict[str, Any], *, prefix: str, max_attempts: int, window_seconds: int) -> None:
    attempts = int(chal.get(f"{prefix}_attempts", 0))
    sent_at = int(chal.get(f"{prefix}_sent_at", 0) or chal.get("created_at", 0))
    if attempts >= max_attempts and (now_ts() - sent_at) < window_seconds:
        raise HTTPException(429, "Too many attempts; wait and retry")


def _bump_attempt(user_sub: str, challenge_id: str, prefix: str, attempts: int) -> None:
    try:
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": challenge_id},
            UpdateExpression=f"SET {prefix}_attempts = :n",
            ExpressionAttributeValues={":n": attempts + 1},
        )
    except Exception:
        pass


@router.post("/alerts/sms/begin")
async def alert_sms_add_begin(req: Request, body: AlertSmsBeginReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    phone = normalize_phone(body.phone)
    code = gen_numeric_code(6)
    code_hash = sha256_str(code)
    challenge_id = create_action_challenge(
        req,
        user_sub=user_sub,
        purpose="alert_sms_add",
        send_to=[phone],
        payload={"sms_code_hash": code_hash, "phone": phone, "sms_code_attempts": 0, "sms_code_sent_at": now_ts()},
        ttl_seconds=600,
    )
    send_alert_sms([phone], f"Your confirmation code is: {code}")
    audit_event("alerts_sms_add_begin", user_sub, req, outcome="success", phone=phone)
    return {"challenge_id": challenge_id, "sent_to": phone}


@router.post("/alerts/sms/confirm")
async def alert_sms_add_confirm(req: Request, body: AlertSmsConfirmReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if chal.get("purpose") != "alert_sms_add":
        raise HTTPException(400, "Bad challenge")
    _check_attempt_budget(chal, prefix="sms_code", max_attempts=S.sms_code_max_attempts, window_seconds=S.sms_code_attempt_window_seconds)
    if sha256_str(body.code.strip()) != chal.get("sms_code_hash"):
        _bump_attempt(user_sub, body.challenge_id, "sms_code", int(chal.get("sms_code_attempts", 0)))
        audit_event("alerts_sms_add_confirm", user_sub, req, outcome="failure", reason="bad_code")
        raise HTTPException(401, "Bad SMS code")
    phone = chal.get("phone")
    prefs = get_alert_prefs(user_sub)
    nums = prefs.get("sms_numbers") or []
    if phone and phone not in nums:
        nums.append(phone)
    prefs2 = set_alert_prefs(user_sub, sms_numbers=nums)
    revoke_challenge(user_sub, body.challenge_id)
    audit_event("alerts_sms_add_confirm", user_sub, req, outcome="success", phone=phone)
    return prefs2


@router.post("/alerts/sms/remove")
async def alert_sms_remove(req: Request, body: AlertSmsRemoveReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    phone = normalize_phone(body.phone)
    prefs = get_alert_prefs(user_sub)
    nums = [n for n in (prefs.get("sms_numbers") or []) if n != phone]
    prefs2 = set_alert_prefs(user_sub, sms_numbers=nums)
    audit_event("alerts_sms_remove", user_sub, req, outcome="success", phone=phone)
    return prefs2


@router.post("/alerts/emails/begin")
async def alert_email_add_begin(req: Request, body: AlertEmailBeginReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    email = normalize_email(body.email)
    if not can_send_verification(user_sub, "email"):
        raise HTTPException(429, "Too many verification emails; try again later")
    code = gen_numeric_code(6)
    code_hash = sha256_str(code)
    challenge_id = create_action_challenge(
        req,
        user_sub=user_sub,
        purpose="alert_email_add",
        send_to=[email],
        payload={"email_code_hash": code_hash, "email": email, "email_code_attempts": 0, "email_code_sent_at": now_ts()},
        ttl_seconds=600,
    )
    send_alert_email([email], "Confirm alerts email", f"Your confirmation code is: {code}\n\nIf you didn't request this, ignore.")
    audit_event("alerts_email_add_begin", user_sub, req, outcome="success", email=email)
    return {"challenge_id": challenge_id, "sent_to": email}


@router.post("/alerts/emails/confirm")
async def alert_email_add_confirm(req: Request, body: AlertEmailConfirmReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if chal.get("purpose") != "alert_email_add":
        raise HTTPException(400, "Bad challenge")
    _check_attempt_budget(chal, prefix="email_code", max_attempts=S.email_code_max_attempts, window_seconds=S.email_code_attempt_window_seconds)
    if sha256_str(body.code.strip()) != chal.get("email_code_hash"):
        _bump_attempt(user_sub, body.challenge_id, "email_code", int(chal.get("email_code_attempts", 0)))
        audit_event("alerts_email_add_confirm", user_sub, req, outcome="failure", reason="bad_code")
        raise HTTPException(401, "Bad email code")
    email = chal.get("email")
    prefs = get_alert_prefs(user_sub)
    emails = prefs.get("emails") or []
    if email and email not in emails:
        emails.append(email)
    prefs2 = set_alert_prefs(user_sub, emails=emails)
    revoke_challenge(user_sub, body.challenge_id)
    audit_event("alerts_email_add_confirm", user_sub, req, outcome="success", email=email)
    return prefs2


@router.post("/alerts/emails/remove")
async def alert_email_remove(req: Request, body: AlertEmailRemoveReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    email = normalize_email(body.email)
    prefs = get_alert_prefs(user_sub)
    emails = [e for e in (prefs.get("emails") or []) if e != email]
    prefs2 = set_alert_prefs(user_sub, emails=emails)
    audit_event("alerts_email_remove", user_sub, req, outcome="success", email=email)
    return prefs2


@router.get("/alerts/stream")
async def alerts_stream(ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    q = sse_subscribe(user_sub)

    async def gen():
        try:
            yield "event: hello\ndata: {}\n\n"
            while True:
                item = await q.get()
                yield "event: alert\ndata: " + json.dumps(item, separators=(",", ":")) + "\n\n"
        finally:
            sse_unsubscribe(user_sub, q)

    return StreamingResponse(gen(), media_type="text/event-stream")

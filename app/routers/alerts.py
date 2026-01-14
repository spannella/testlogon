from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.models import MarkReadReq
from app.services.alerts import ALERT_EVENT_TYPES, get_alert_prefs, set_alert_prefs, sse_subscribe, sse_unsubscribe
from app.services.sessions import require_ui_session
from app.core.time import now_ts

router = APIRouter(prefix="/ui", tags=["alerts"])

@router.get("/alerts/types")
async def alert_types(_: Dict[str, str] = Depends(require_ui_session)):
    return {"event_types": ALERT_EVENT_TYPES}

@router.get("/alerts")
async def list_alerts(limit: int = 50, cursor: Optional[str] = None, ctx: Dict[str, str] = Depends(require_ui_session)):
    eks = decode_cursor(cursor)
    r = T.alerts.query(
        KeyConditionExpression=Key("user_sub").eq(ctx["user_sub"]),
        ScanIndexForward=False,
        Limit=max(1, min(int(limit), 200)),
        ExclusiveStartKey=eks or None,
    )
    items = r.get("Items", [])
    next_cursor = encode_cursor(r.get("LastEvaluatedKey"))
    # strip large details
    out = []
    for it in items:
        out.append({
            "alert_id": it.get("alert_id"),
            "ts": it.get("ts"),
            "event": it.get("event"),
            "outcome": it.get("outcome"),
            "title": it.get("title"),
            "details": it.get("details", {}),
            "read": it.get("read", False),
            "read_at": it.get("read_at", 0),
        })
    return {"alerts": out, "next_cursor": next_cursor}

@router.post("/alerts/mark_read")
async def mark_read(body: MarkReadReq, ctx: Dict[str, str] = Depends(require_ui_session)):
    ts = now_ts()
    for aid in body.alert_ids[:200]:
        try:
            T.alerts.update_item(
                Key={"user_sub": ctx["user_sub"], "alert_id": aid},
                UpdateExpression="SET #r=:t, read_at=:ts",
                ExpressionAttributeNames={"#r": "read"},
                ExpressionAttributeValues={":t": True, ":ts": ts},
            )
        except Exception:
            pass
    return {"status":"ok"}

@router.get("/alerts/email_prefs")
async def get_email_prefs(ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = get_alert_prefs(ctx["user_sub"])
    return {"emails": prefs["emails"], "event_types": prefs["email_event_types"]}

@router.post("/alerts/email_prefs")
async def set_email_prefs(body: Dict[str, Any], ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = set_alert_prefs(ctx["user_sub"], email_event_types=body.get("event_types", []))
    return {"status":"ok","event_types": prefs["email_event_types"]}

@router.get("/alerts/sms_prefs")
async def get_sms_prefs(ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = get_alert_prefs(ctx["user_sub"])
    return {"sms_numbers": prefs["sms_numbers"], "event_types": prefs["sms_event_types"]}

@router.post("/alerts/sms_prefs")
async def set_sms_prefs(body: Dict[str, Any], ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = set_alert_prefs(ctx["user_sub"], sms_event_types=body.get("event_types", []))
    return {"status":"ok","event_types": prefs["sms_event_types"]}

@router.get("/alerts/toast_prefs")
async def get_toast_prefs(ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = get_alert_prefs(ctx["user_sub"])
    return {"event_types": prefs["toast_event_types"]}

@router.post("/alerts/toast_prefs")
async def set_toast_prefs(body: Dict[str, Any], ctx: Dict[str, str] = Depends(require_ui_session)):
    prefs = set_alert_prefs(ctx["user_sub"], toast_event_types=body.get("event_types", []))
    return {"status":"ok","event_types": prefs["toast_event_types"]}

@router.post("/alerts/mark_toast_delivered")
async def mark_toast_delivered(_: Dict[str, Any], __: Dict[str, str] = Depends(require_ui_session)):
    # left as a hook; implement per-session delivery receipts if needed
    return {"status":"ok"}

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

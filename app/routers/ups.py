from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import Any, Dict

import requests
from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.sessions import require_ui_session
from app.services.ups import create_label, quote, verify_tracking_webhook_signature

router = APIRouter(tags=["ups", "mock"])


def _mock_enabled() -> bool:
    return S.dev_mode


def _ups_sig_secret() -> str:
    return (S.ups_webhook_secret or "local-ups-webhook-secret").strip()


@router.post("/api/ups/quote")
def ups_quote(body: Dict[str, Any], ctx=Depends(require_ui_session)) -> Dict[str, Any]:
    _ = ctx["user_sub"]
    return quote(body)


@router.post("/api/ups/label")
def ups_label(body: Dict[str, Any], ctx=Depends(require_ui_session)) -> Dict[str, Any]:
    _ = ctx["user_sub"]
    return create_label(body)


@router.post("/api/ups/tracking/webhook")
async def ups_tracking_webhook(req: Request) -> Dict[str, Any]:
    raw = await req.body()
    signature = req.headers.get("x-ups-signature", "")
    if not verify_tracking_webhook_signature(raw, signature):
        raise HTTPException(403, "Invalid UPS webhook signature")

    payload = await req.json() if raw else {}
    tracking_number = payload.get("tracking_number") or payload.get("trackingNumber") or "unknown"
    T.billing.put_item(
        Item={
            "user_sub": "UPS_TRACKING",
            "sk": f"{now_ts()}#{tracking_number}",
            "payload": payload,
            "created_at": now_ts(),
        }
    )
    return {"received": True}


def _decode_basic(auth_header: str) -> tuple[str, str]:
    if not auth_header.lower().startswith("basic "):
        return "", ""
    try:
        raw = base64.b64decode(auth_header.split(" ", 1)[1].strip()).decode("utf-8")
        return raw.split(":", 1) if ":" in raw else ("", "")
    except Exception:
        return "", ""


@router.post("/mock/ups/oauth/token")
def mock_ups_oauth(req: Request) -> Dict[str, Any]:
    if not _mock_enabled():
        raise HTTPException(404, "Not found")
    client_id, client_secret = _decode_basic(req.headers.get("authorization", ""))
    if S.ups_client_id and S.ups_client_secret and (client_id, client_secret) != (S.ups_client_id, S.ups_client_secret):
        raise HTTPException(401, "Invalid client credentials")
    if not client_id or not client_secret:
        raise HTTPException(401, "Missing client credentials")
    token = f"mock_ups_{int(time.time()*1000)}"
    return {"access_token": token, "token_type": "Bearer", "expires_in": 3600}


@router.post("/mock/ups/quote")
async def mock_ups_quote(req: Request) -> Dict[str, Any]:
    if not _mock_enabled():
        raise HTTPException(404, "Not found")
    body = await req.json()
    weight = float((body.get("package") or {}).get("weight", 1.0))
    amount = round(max(5.0, 3.5 + weight * 1.2), 2)
    return {
        "service": body.get("service", "ground"),
        "currency": "USD",
        "amount": amount,
        "eta_days": 3,
    }


@router.post("/mock/ups/label")
async def mock_ups_label(req: Request) -> Dict[str, Any]:
    if not _mock_enabled():
        raise HTTPException(404, "Not found")
    body = await req.json()
    tracking = f"1ZMOCK{int(time.time()*1000)}"
    return {
        "tracking_number": tracking,
        "label_url": f"https://mock-ups.local/labels/{tracking}.pdf",
        "service": body.get("service", "ground"),
        "status": "created",
    }


@router.post("/emit/ups-tracking-webhook")
def emit_ups_tracking_webhook(body: Dict[str, Any]) -> Dict[str, Any]:
    if not _mock_enabled():
        raise HTTPException(404, "Not found")
    payload = body.get("payload") or {"tracking_number": "1ZMOCK", "status": "DELIVERED"}
    if not isinstance(payload, dict):
        raise HTTPException(400, "payload must be object")
    target_url = str(body.get("target_url") or f"{S.public_base_url}/api/ups/tracking/webhook")
    raw = requests.models.complexjson.dumps(payload).encode("utf-8")
    sig = hmac.new(_ups_sig_secret().encode("utf-8"), raw, hashlib.sha256).hexdigest()
    resp = requests.post(
        target_url,
        headers={"content-type": "application/json", "x-ups-signature": sig},
        data=raw,
        timeout=10,
    )
    return {"ok": resp.status_code < 400, "status_code": resp.status_code, "response": resp.text[:1000]}

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
from app.models import AddressValidateReq, AddressValidateResp, ValidatedAddressOut
from app.services.ups import create_label, quote, validate_address, verify_tracking_webhook_signature

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


def _build_mock_validation_response(body: dict) -> AddressValidateResp:
    line1 = (body.get("line1") or "").strip()
    if not line1 or "INVALID" in line1.upper():
        return AddressValidateResp(valid=False, dpv_match_code="", candidates=[])
    candidate = ValidatedAddressOut(
        line1=line1.upper(),
        line2=(body.get("line2") or "").upper(),
        city=(body.get("city") or "").upper(),
        state=(body.get("state") or "").upper(),
        postal_code=body.get("postal_code") or "",
        country=(body.get("country") or "US").upper(),
    )
    return AddressValidateResp(valid=True, dpv_match_code="Y", candidates=[candidate])


@router.post("/api/ups/address-validate")
def ups_address_validate(body: AddressValidateReq, ctx=Depends(require_ui_session)) -> AddressValidateResp:
    _ = ctx["user_sub"]
    if S.dev_mode:
        return _build_mock_validation_response(body.model_dump())
    raw = validate_address(body.model_dump())
    xav = raw.get("XAVResponse", {})
    candidates_raw = xav.get("Candidate", [])
    if isinstance(candidates_raw, dict):
        candidates_raw = [candidates_raw]
    candidates = []
    for c in candidates_raw:
        af = c.get("AddressKeyFormat", {})
        lines = af.get("AddressLine", [])
        if isinstance(lines, str):
            lines = [lines]
        candidates.append(ValidatedAddressOut(
            line1=lines[0] if lines else "",
            line2=lines[1] if len(lines) > 1 else "",
            city=af.get("PoliticalDivision2", ""),
            state=af.get("PoliticalDivision1", ""),
            postal_code=af.get("PostcodePrimaryLow", ""),
            country=af.get("CountryCode", "US"),
        ))
    valid_indicator = xav.get("ValidAddressIndicator")
    amb_indicator = xav.get("AmbiguousAddressIndicator")
    dpv_code = "Y" if valid_indicator is not None else ("A" if amb_indicator is not None else "")
    return AddressValidateResp(
        valid=valid_indicator is not None,
        dpv_match_code=dpv_code,
        candidates=candidates,
    )


@router.post("/api/ups/tracking/webhook")
async def ups_tracking_webhook(req: Request) -> Dict[str, Any]:
    raw = await req.body()
    signature = req.headers.get("x-ups-signature", "")
    if not verify_tracking_webhook_signature(raw, signature):
        raise HTTPException(403, "Invalid UPS webhook signature")

    payload = await req.json() if raw else {}
    tracking_number = payload.get("tracking_number") or payload.get("trackingNumber") or "unknown"

    # 1. Audit log (existing behavior — preserved).
    T.billing.put_item(
        Item={
            "user_sub": "UPS_TRACKING",
            "sk": f"{now_ts()}#{tracking_number}",
            "payload": payload,
            "created_at": now_ts(),
        }
    )

    # 2. SHOP-004: resolve the tracking number to an order and update its
    #    shipping status (instead of only auditing). On delivery, fire the
    #    seller delivery alert. Best effort — webhook still returns 200.
    order_updated = False
    try:
        from app.services.carrier_tracking import apply_tracking_result, map_carrier_status
        from app.services.purchase_history import find_transaction_by_tracking

        order = find_transaction_by_tracking(tracking_number)
        if order:
            raw_status = (
                payload.get("status_description")
                or payload.get("statusDescription")
                or payload.get("status")
                or ""
            )
            new_status = map_carrier_status("ups", str(raw_status))
            result = {
                "status": new_status,
                "status_description": payload.get("status_description")
                or payload.get("statusDescription")
                or str(raw_status),
                "delivered_at": payload.get("delivered_at"),
                "events": payload.get("events"),
            }
            # apply_tracking_result updates the order shipping record and fires
            # the seller delivery alert on the transition to "delivered".
            if apply_tracking_result(order, result) is not None:
                order_updated = True
    except Exception:
        # Never fail the webhook on an order-update error; the audit row stands.
        pass

    return {"received": True, "order_updated": order_updated}


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


@router.post("/mock/ups/address-validate")
async def mock_ups_address_validate(req: Request) -> AddressValidateResp:
    if not _mock_enabled():
        raise HTTPException(404, "Not found")
    body = await req.json()
    return _build_mock_validation_response(body)


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

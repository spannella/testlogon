from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict

import requests
from fastapi import HTTPException

from app.core.settings import S


_TOKEN_CACHE: Dict[str, str] = {}


def _ups_auth_url() -> str:
    if S.ups_auth_url:
        return S.ups_auth_url
    if S.ups_base_url:
        return f"{S.ups_base_url}/oauth/token"
    raise HTTPException(500, "UPS base/auth URL not configured")


def _ups_api_base() -> str:
    if not S.ups_base_url:
        raise HTTPException(500, "UPS base URL not configured")
    return S.ups_base_url


def ups_access_token() -> str:
    cached = _TOKEN_CACHE.get("access_token")
    if cached:
        return cached

    if not S.ups_client_id or not S.ups_client_secret:
        raise HTTPException(500, "UPS client credentials not configured")

    r = requests.post(
        _ups_auth_url(),
        auth=(S.ups_client_id, S.ups_client_secret),
        data={"grant_type": "client_credentials"},
        timeout=15,
    )
    if r.status_code != 200:
        raise HTTPException(502, f"UPS auth failed: {r.status_code} {r.text}")
    token = r.json().get("access_token")
    if not token:
        raise HTTPException(502, "UPS auth response missing access_token")
    _TOKEN_CACHE["access_token"] = str(token)
    return str(token)


def _ups_post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    token = ups_access_token()
    r = requests.post(
        f"{_ups_api_base()}/{path.lstrip('/')}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload,
        timeout=20,
    )
    if r.status_code >= 400:
        raise HTTPException(502, f"UPS request failed: {r.status_code} {r.text}")
    return r.json()


def quote(shipment: Dict[str, Any]) -> Dict[str, Any]:
    return _ups_post("quote", shipment)


def create_label(shipment: Dict[str, Any]) -> Dict[str, Any]:
    return _ups_post("label", shipment)


def verify_tracking_webhook_signature(raw_body: bytes, signature_header: str) -> bool:
    secret = (S.ups_webhook_secret or "").strip()
    if not secret:
        return True
    if not signature_header:
        return False
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, signature_header.strip())

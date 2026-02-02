from __future__ import annotations

import secrets
from typing import Any, Dict, List

from fastapi import HTTPException, Request

from app.core.aws import ses
from app.core.crypto import sha256_str
from app.core.normalize import client_ip_from_request
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.mfa import list_enabled_emails
from app.services.ttl import with_ttl

def _ensure_enabled() -> None:
    if not S.magic_link_enabled:
        raise HTTPException(404, "Passwordless login disabled")

def _send_magic_link_email(to_email: str, link: str) -> None:
    if not ses:
        raise HTTPException(500, "SES not configured")
    subject = "Your magic sign-in link"
    body = f"Sign in with this link:\n{link}\n\nThis link expires soon. If you did not request it, ignore this email."
    ses.send_email(
        Source=S.ses_from_email,
        Destination={"ToAddresses": [to_email]},
        Message={"Subject": {"Data": subject[:120]}, "Body": {"Text": {"Data": body[:8000]}}},
    )

def create_magic_link(req: Request, user_sub: str) -> Dict[str, Any]:
    _ensure_enabled()
    emails = list_enabled_emails(user_sub)
    if not emails:
        raise HTTPException(400, "No email devices")
    raw_token = secrets.token_urlsafe(32)
    token_hash = sha256_str(raw_token)
    ts = now_ts()
    expires_at = ts + S.magic_link_ttl_seconds
    pk = f"ml#{token_hash}"
    item = {
        "user_sub": pk,
        "session_id": "magic",
        "target_user_sub": user_sub,
        "token_hash": token_hash,
        "created_at": ts,
        "expires_at": expires_at,
        "used": False,
        "ip": req.client.host if req.client else "",
        "user_agent": (req.headers.get("user-agent", "")[:512]),
    }
    T.sessions.put_item(Item=with_ttl(item, ttl_epoch=expires_at))
    link = f"{S.public_base_url}/ui/passwordless/verify?token={raw_token}"
    for email in emails[:S.email_device_limit]:
        _send_magic_link_email(email, link)
    return {"token": raw_token, "sent_to": emails[:S.email_device_limit]}

def load_magic_link(token: str) -> Dict[str, Any]:
    _ensure_enabled()
    token_hash = sha256_str(token.strip())
    pk = f"ml#{token_hash}"
    it = T.sessions.get_item(Key={"user_sub": pk, "session_id": "magic"}).get("Item")
    if not it:
        raise HTTPException(401, "Invalid or expired token")
    if it.get("used", False):
        raise HTTPException(401, "Token already used")
    if int(it.get("expires_at", 0) or 0) < now_ts():
        raise HTTPException(401, "Token expired")
    return it

def mark_magic_link_used(token: str) -> None:
    _ensure_enabled()
    token_hash = sha256_str(token.strip())
    pk = f"ml#{token_hash}"
    try:
        T.sessions.update_item(
            Key={"user_sub": pk, "session_id": "magic"},
            UpdateExpression="SET used=:t, used_at=:now",
            ConditionExpression="attribute_exists(session_id) AND used = :f",
            ExpressionAttributeValues={":t": True, ":f": False, ":now": now_ts()},
        )
    except Exception:
        raise HTTPException(401, "Invalid or expired token")

def magic_link_mismatch(record: Dict[str, Any], req: Request) -> Dict[str, bool]:
    expected_ip = record.get("ip", "") or ""
    expected_ua = record.get("user_agent", "") or ""
    current_ip = client_ip_from_request(req)
    current_ua = (req.headers.get("user-agent", "")[:512])
    return {
        "ip_mismatch": bool(expected_ip and current_ip and expected_ip != current_ip),
        "ua_mismatch": bool(expected_ua and current_ua and expected_ua != current_ua),
    }

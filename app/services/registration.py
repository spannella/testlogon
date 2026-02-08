from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Dict

from fastapi import HTTPException

from app.core.normalize import normalize_email
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.account_state import set_account_state
from app.services.profile import empty_profile, save_profile
from app.services.ttl import with_ttl
from app.services.mfa import gen_numeric_code, twilio_check_sms
from app.core.crypto import sha256_str

PASSWORD_HASH_ITERATIONS = 260_000
PASSWORD_HASH_ALGO = "pbkdf2_sha256"
REGISTRATION_CHALLENGE_ID = "register_verify"


def _hash_password(password: str) -> Dict[str, str]:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS)
    return {
        "algorithm": PASSWORD_HASH_ALGO,
        "iterations": str(PASSWORD_HASH_ITERATIONS),
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "hash_b64": base64.b64encode(digest).decode("ascii"),
    }


def _user_exists(user_sub: str) -> bool:
    existing = T.users.get_item(Key={"user_sub": user_sub}).get("Item")
    return bool(existing)


def create_user_record(
    *,
    email: str,
    full_name: str,
    password: str,
    verification_required: bool,
) -> Dict[str, str]:
    user_sub = normalize_email(email)
    if _user_exists(user_sub):
        raise HTTPException(409, "User already exists")

    password_hash = _hash_password(password)
    created_at = now_ts()
    item = {
        "user_sub": user_sub,
        "email": user_sub,
        "full_name": full_name.strip(),
        "password_hash": password_hash,
        "created_at": created_at,
    }
    try:
        T.users.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(user_sub)",
        )
    except Exception as exc:
        raise HTTPException(409, "User already exists") from exc

    profile = empty_profile()
    profile.update({
        "display_name": full_name.strip() or None,
        "displayed_email": user_sub,
    })
    save_profile(user_sub, profile, audit_entries=[{"event": "register_start", "at": created_at}])

    status = "pending_verification" if verification_required else "active"
    set_account_state(user_sub, status, reason="initial_registration", requested_by=user_sub)
    return {"user_sub": user_sub}


def create_registration_challenge(
    *,
    user_sub: str,
    channel: str,
    send_to: str,
) -> str:
    code = gen_numeric_code(6) if channel == "email" else ""
    ts = now_ts()
    expires = ts + S.session_challenge_ttl_seconds
    payload = {
        "user_sub": user_sub,
        "session_id": REGISTRATION_CHALLENGE_ID,
        "created_at": ts,
        "expires_at": expires,
        "revoked": False,
        "pending_auth": True,
        "purpose": "register_verify",
        "channel": channel,
        "send_to": send_to,
        "code_hash": sha256_str(code) if code else "",
        "code_attempts": 0,
    }
    T.sessions.put_item(Item=with_ttl(payload, ttl_epoch=expires))
    return code


def verify_registration_code(*, user_sub: str, code: str) -> Dict[str, str]:
    item = T.sessions.get_item(
        Key={"user_sub": user_sub, "session_id": REGISTRATION_CHALLENGE_ID},
    ).get("Item")
    if not item:
        raise HTTPException(400, "Registration verification not found")
    if int(item.get("expires_at") or 0) < now_ts():
        raise HTTPException(400, "Verification code expired")
    channel = item.get("channel") or "email"
    attempts = int(item.get("code_attempts") or 0)
    max_attempts = S.sms_code_max_attempts if channel == "sms" else S.email_code_max_attempts
    if attempts >= max_attempts:
        raise HTTPException(429, "Too many verification attempts")
    if channel == "sms":
        phone = item.get("send_to", "")
        if not twilio_check_sms(phone, code.strip()):
            _increment_registration_attempts(user_sub, attempts)
            raise HTTPException(401, "Invalid verification code")
    else:
        if sha256_str(code.strip()) != item.get("code_hash"):
            _increment_registration_attempts(user_sub, attempts)
            raise HTTPException(401, "Invalid verification code")
    try:
        T.sessions.delete_item(Key={"user_sub": user_sub, "session_id": REGISTRATION_CHALLENGE_ID})
    except Exception:
        pass
    return {"user_sub": user_sub}


def _increment_registration_attempts(user_sub: str, attempts: int) -> None:
    try:
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": REGISTRATION_CHALLENGE_ID},
            UpdateExpression="SET code_attempts = :c, last_failed_at = :t",
            ExpressionAttributeValues={":c": attempts + 1, ":t": now_ts()},
        )
    except Exception:
        pass


def mark_user_verified(user_sub: str) -> Dict[str, str]:
    normalized = normalize_email(user_sub)
    if not _user_exists(normalized):
        raise HTTPException(404, "User not found")
    set_account_state(normalized, "active", reason="email_verified", requested_by=normalized)
    return {"user_sub": normalized}

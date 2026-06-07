from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import uuid
from typing import Dict

from botocore.exceptions import ClientError
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
REGISTRATION_CHALLENGE_PREFIX = "register_verify#"
REGISTRATION_LATEST_POINTER_ID = "register_verify_latest"
logger = logging.getLogger(__name__)


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
    try:
        existing = T.users.get_item(Key={"user_sub": user_sub}).get("Item")
    except ClientError as exc:
        code = (exc.response or {}).get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            logger.warning("users table not found during registration lookup", extra={"user_sub": user_sub})
            return False
        raise
    return bool(existing)


def is_email_available(email: str) -> bool:
    normalized = normalize_email(email)
    return not _user_exists(normalized)


def check_email_status(email: str) -> Dict[str, bool]:
    """Return availability plus a pending-verification hint for an email address.

    Distinguishes the two "unavailable" states so the frontend can offer a
    recovery (resend) path for abandoned registrations instead of a dead-end
    error (GAP-0107):
      - unknown email          -> {"available": True,  "unverified": False}
      - active account         -> {"available": False, "unverified": False}
      - pending_verification   -> {"available": False, "unverified": True}

    The account_state lookup only runs when the user record exists, so the extra
    DynamoDB read is avoided for all "available" responses.
    """
    # Imported lazily to keep the module import graph identical to before and to
    # avoid any import-order coupling with app.services.account_state.
    from app.services.account_state import get_account_state

    normalized = normalize_email(email)
    if not _user_exists(normalized):
        return {"available": True, "unverified": False}
    state = get_account_state(normalized)
    if state.get("status") == "pending_verification":
        return {"available": False, "unverified": True}
    return {"available": False, "unverified": False}


def get_pending_user(email: str) -> bool:
    """Return True if the email exists and is in pending_verification state.

    Used by the /register/start resume path (GAP-0108) to decide whether to
    re-issue a verification challenge instead of raising the duplicate-email
    409. Returns False for active accounts so an active account owner can never
    trigger a fresh verification code via /start.
    """
    from app.services.account_state import get_account_state

    normalized = normalize_email(email)
    if not _user_exists(normalized):
        return False
    return get_account_state(normalized).get("status") == "pending_verification"


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
    pending_ttl = created_at + S.registration_pending_ttl_days * 86400
    item = {
        "user_sub": user_sub,
        "email": user_sub,
        "full_name": full_name.strip(),
        "password_hash": password_hash,
        "created_at": created_at,
    }
    # Attach a TTL to unverified records so abandoned registrations self-clean
    # and never permanently block re-use of the email address.
    if verification_required:
        item = with_ttl(item, ttl_epoch=pending_ttl)
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
    set_account_state(
        user_sub,
        status,
        reason="initial_registration",
        requested_by=user_sub,
        ttl_epoch=pending_ttl if verification_required else None,
    )
    return {"user_sub": user_sub}


def _challenge_session_id() -> str:
    return f"{REGISTRATION_CHALLENGE_PREFIX}{uuid.uuid4()}"


def _load_latest_challenge_id(user_sub: str) -> str:
    latest = T.sessions.get_item(
        Key={"user_sub": user_sub, "session_id": REGISTRATION_LATEST_POINTER_ID},
    ).get("Item") or {}
    challenge_id = latest.get("challenge_id") or ""
    return challenge_id if isinstance(challenge_id, str) else ""


def create_registration_challenge(
    *,
    user_sub: str,
    channel: str,
    send_to: str,
    mfa_setup: list[str] | None = None,
    sms_phone: str | None = None,
) -> str:
    code = gen_numeric_code(6) if channel == "email" else ""
    ts = now_ts()
    expires = ts + S.session_challenge_ttl_seconds
    challenge_id = _challenge_session_id()
    payload = {
        "user_sub": user_sub,
        "session_id": challenge_id,
        "created_at": ts,
        "expires_at": expires,
        "revoked": False,
        "pending_auth": True,
        "purpose": "register_verify",
        "channel": channel,
        "send_to": send_to,
        "code_hash": sha256_str(code) if code else "",
        "code_attempts": 0,
        "mfa_setup": mfa_setup or [],
        "sms_phone": sms_phone or "",
    }
    T.sessions.put_item(Item=with_ttl(payload, ttl_epoch=expires))
    pointer_payload = {
        "user_sub": user_sub,
        "session_id": REGISTRATION_LATEST_POINTER_ID,
        "challenge_id": challenge_id,
        "created_at": ts,
        "expires_at": expires,
        "purpose": "register_verify_pointer",
    }
    T.sessions.put_item(Item=with_ttl(pointer_payload, ttl_epoch=expires))
    return code


def verify_registration_code(*, user_sub: str, code: str) -> Dict[str, str]:
    challenge_id = _load_latest_challenge_id(user_sub)
    if not challenge_id:
        raise HTTPException(400, "Registration verification not found")
    item = T.sessions.get_item(
        Key={"user_sub": user_sub, "session_id": challenge_id},
    ).get("Item")
    if not item:
        raise HTTPException(400, "Registration verification not found")
    if int(item.get("expires_at") or 0) < now_ts():
        raise HTTPException(400, "Verification code expired")
    if item.get("purpose") != "register_verify":
        raise HTTPException(400, "Registration verification not found")
    channel = item.get("channel") or "email"
    attempts = int(item.get("code_attempts") or 0)
    max_attempts = S.sms_code_max_attempts if channel == "sms" else S.email_code_max_attempts
    if attempts >= max_attempts:
        raise HTTPException(429, "Too many verification attempts")
    if channel == "sms":
        phone = item.get("send_to", "")
        if not twilio_check_sms(phone, code.strip()):
            _increment_registration_attempts(user_sub, challenge_id, attempts)
            raise HTTPException(401, "Invalid verification code")
    else:
        if sha256_str(code.strip()) != item.get("code_hash"):
            _increment_registration_attempts(user_sub, challenge_id, attempts)
            raise HTTPException(401, "Invalid verification code")
    try:
        T.sessions.delete_item(Key={"user_sub": user_sub, "session_id": challenge_id})
        T.sessions.delete_item(Key={"user_sub": user_sub, "session_id": REGISTRATION_LATEST_POINTER_ID})
    except Exception:
        pass
    return {
        "user_sub": user_sub,
        "mfa_setup": list(item.get("mfa_setup") or []),
        "sms_phone": item.get("sms_phone") or "",
    }


def _increment_registration_attempts(user_sub: str, challenge_id: str, attempts: int) -> None:
    try:
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": challenge_id},
            UpdateExpression="SET code_attempts = :c, last_failed_at = :t",
            ExpressionAttributeValues={":c": attempts + 1, ":t": now_ts()},
        )
    except Exception:
        pass


def mark_user_verified(user_sub: str) -> Dict[str, str]:
    normalized = normalize_email(user_sub)
    if not _user_exists(normalized):
        raise HTTPException(404, "User not found")
    # Clear the pending-registration TTL so a verified account never expires.
    # set_account_state below rewrites the account_state item without a TTL
    # attribute; the users item needs an explicit REMOVE.
    try:
        T.users.update_item(
            Key={"user_sub": normalized},
            UpdateExpression=f"REMOVE {S.ddb_ttl_attr}",
        )
    except Exception:
        pass
    set_account_state(normalized, "active", reason="email_verified", requested_by=normalized)
    return {"user_sub": normalized}

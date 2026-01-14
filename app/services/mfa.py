from __future__ import annotations

import secrets
from typing import Any, Dict, List, Optional, Sequence

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.aws import ses, twilio
from app.core.crypto import kms_decrypt, kms_encrypt, sha256_str
from app.core.normalize import normalize_email, normalize_phone
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

try:
    import pyotp  # type: ignore
except Exception:  # pragma: no cover
    pyotp = None  # type: ignore

def _need_pyotp():
    if pyotp is None:
        raise HTTPException(500, "pyotp not installed (required for TOTP features)")

def gen_numeric_code(n_digits: int = 6) -> str:
    return str(secrets.randbelow(10**n_digits)).zfill(n_digits)

def send_email_code(to_email: str, purpose: str, code: str) -> None:
    if not ses:
        raise HTTPException(500, "SES not configured")
    subject = f"Your verification code ({purpose})"
    body = f"Your verification code is: {code}\n\nIf you did not request this, ignore this email."
    ses.send_email(
        Source=S.ses_from_email,
        Destination={"ToAddresses": [to_email]},
        Message={"Subject": {"Data": subject[:120]}, "Body": {"Text": {"Data": body[:8000]}}},
    )

def twilio_start_sms(to_e164: str) -> None:
    if not twilio:
        raise HTTPException(500, "Twilio not configured")
    twilio.verify.v2.services(S.twilio_verify_service_sid).verifications.create(to=to_e164, channel="sms")

def twilio_check_sms(to_e164: str, code: str) -> bool:
    if not twilio:
        raise HTTPException(500, "Twilio not configured")
    r = twilio.verify.v2.services(S.twilio_verify_service_sid).verification_checks.create(to=to_e164, code=code)
    return r.status == "approved"

def new_recovery_codes(n: int = 10) -> List[str]:
    out: List[str] = []
    for _ in range(n):
        raw = secrets.token_hex(6)
        out.append(f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}")
    return out

def store_recovery_codes(user_sub: str, factor: str, codes: Sequence[str]) -> None:
    ts = now_ts()
    for c in codes:
        T.recovery.put_item(Item={"user_sub": user_sub, "code_hash": f"{factor}#{sha256_str(c)}", "factor": factor, "used": False, "created_at": ts})

def consume_recovery_code(user_sub: str, factor: str, code: str) -> None:
    key = f"{factor}#{sha256_str(code.strip())}"
    try:
        T.recovery.update_item(
            Key={"user_sub": user_sub, "code_hash": key},
            UpdateExpression="SET used = :t, used_at = :u",
            ConditionExpression="attribute_exists(code_hash) AND used = :f",
            ExpressionAttributeValues={":t": True, ":f": False, ":u": now_ts()},
        )
    except Exception:
        raise HTTPException(401, "Invalid or already-used recovery code")

def list_enabled_sms_numbers(user_sub: str) -> List[str]:
    r = T.sms.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    return [d["phone_e164"] for d in r.get("Items", []) if d.get("enabled", False)]

def list_enabled_emails(user_sub: str) -> List[str]:
    r = T.email.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    return [d["email"] for d in r.get("Items", []) if d.get("enabled", False)]

def totp_verify_any_enabled(user_sub: str, code: str) -> Optional[str]:
    _need_pyotp()
    r = T.totp.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    devices = [d for d in r.get("Items", []) if d.get("enabled", False)]
    for d in devices:
        secret_b32 = kms_decrypt(d["secret_ct_b64"]).decode("utf-8")
        try:
            if pyotp.TOTP(secret_b32).verify(code.strip(), valid_window=1):
                return d["device_id"]
        except Exception:
            continue
    return None

def totp_begin_enroll(user_sub: str, label: Optional[str]) -> Dict[str, Any]:
    _need_pyotp()
    device_id = uuid4_hex()
    secret_b32 = pyotp.random_base32()
    secret_ct = kms_encrypt(secret_b32)
    ts = now_ts()
    T.totp.put_item(Item={"user_sub": user_sub, "device_id": device_id, "label": (label or "")[:64], "secret_ct_b64": secret_ct, "enabled": False, "created_at": ts})
    issuer = "YourApp"
    name = f"{user_sub[:8]}@{issuer}"
    otpauth_uri = pyotp.TOTP(secret_b32).provisioning_uri(name=name, issuer_name=issuer)
    codes = new_recovery_codes(10)
    store_recovery_codes(user_sub, "totp", codes)
    return {"device_id": device_id, "otpauth_uri": otpauth_uri, "recovery_codes": codes}

def totp_confirm_enroll(user_sub: str, device_id: str, totp_code: str) -> None:
    _need_pyotp()
    it = T.totp.get_item(Key={"user_sub": user_sub, "device_id": device_id}).get("Item")
    if not it:
        raise HTTPException(404, "Unknown device")
    secret_b32 = kms_decrypt(it["secret_ct_b64"]).decode("utf-8")
    if not pyotp.TOTP(secret_b32).verify(totp_code.strip(), valid_window=1):
        raise HTTPException(401, "Bad TOTP")
    T.totp.update_item(Key={"user_sub": user_sub, "device_id": device_id}, UpdateExpression="SET enabled = :t, confirmed_at = :now", ExpressionAttributeValues={":t": True, ":now": now_ts()})

def uuid4_hex() -> str:
    import uuid
    return uuid.uuid4().hex

def sms_begin_enroll(user_sub: str, phone_e164: str, label: Optional[str]) -> Dict[str, Any]:
    phone = normalize_phone(phone_e164)
    device_id = sha256_str(phone)[:16]
    ts = now_ts()
    T.sms.put_item(Item={"user_sub": user_sub, "sms_device_id": device_id, "phone_e164": phone, "label": (label or "")[:64], "enabled": False, "created_at": ts})
    return {"sms_device_id": device_id, "phone_e164": phone}

def sms_confirm_enroll(user_sub: str, sms_device_id: str) -> None:
    T.sms.update_item(Key={"user_sub": user_sub, "sms_device_id": sms_device_id}, UpdateExpression="SET enabled = :t, confirmed_at=:now", ExpressionAttributeValues={":t": True, ":now": now_ts()})

def email_begin_enroll(user_sub: str, email: str, label: Optional[str]) -> Dict[str, Any]:
    e = normalize_email(email)
    device_id = sha256_str(e)[:16]
    ts = now_ts()
    T.email.put_item(Item={"user_sub": user_sub, "email_device_id": device_id, "email": e, "label": (label or "")[:64], "enabled": False, "created_at": ts})
    return {"email_device_id": device_id, "email": e}

def email_confirm_enroll(user_sub: str, email_device_id: str) -> None:
    T.email.update_item(Key={"user_sub": user_sub, "email_device_id": email_device_id}, UpdateExpression="SET enabled = :t, confirmed_at=:now", ExpressionAttributeValues={":t": True, ":now": now_ts()})

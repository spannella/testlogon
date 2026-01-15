"""
Cleaned-up FastAPI server (single-file version)

Key improvements vs. the original:
- Centralized configuration (Settings)
- Centralized DynamoDB table access (Tables)
- Fixed session-start dependency issue (start should not require an existing UI session)
- Fixed missing auth dependency placeholder (ui_user_sub in original was undefined)
- De-duplicated challenge creation/verification patterns (SMS/Email enroll/remove)
- More consistent naming and error handling
- Safer session "touch" logic (single update + inactivity guard)

Notes:
- Replace `get_authenticated_user_sub()` with your real auth (e.g., Cognito JWT validation).
- DynamoDB key schemas must match the Key(...) usage here.
"""

from __future__ import annotations

import base64
import json
import re
import hashlib
import hmac
import os
import secrets
import ipaddress
import requests
import urllib.parse
import asyncio
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

import boto3
import pyotp
from boto3.dynamodb.conditions import Key
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
from twilio.rest import Client as TwilioClient

from auth_cognito import CognitoJWTVerifier


# ============================================================
#  Settings / wiring
# ============================================================

@dataclass(frozen=True)
class Settings:
    aws_region: str = os.environ.get("AWS_REGION", "us-east-1")

    cognito_user_pool_id: str = os.environ["COGNITO_USER_POOL_ID"]
    cognito_region: str = os.environ["COGNITO_REGION"]
    cognito_app_client_id: str = os.environ["COGNITO_APP_CLIENT_ID"]
    cognito_expected_token_use: str = os.environ.get("COGNITO_EXPECTED_TOKEN_USE", "access")

    mfa_send_min_interval_seconds: int = int(os.environ.get("MFA_SEND_MIN_INTERVAL_SECONDS", "30"))
    mfa_send_max_per_hour: int = int(os.environ.get("MFA_SEND_MAX_PER_HOUR", "20"))

    email_code_max_attempts: int = int(os.environ.get("EMAIL_CODE_MAX_ATTEMPTS", "5"))
    email_code_attempt_window_seconds: int = int(os.environ.get("EMAIL_CODE_ATTEMPT_WINDOW_SECONDS", "600"))
    sms_code_max_attempts: int = int(os.environ.get("SMS_CODE_MAX_ATTEMPTS", "8"))
    sms_code_attempt_window_seconds: int = int(os.environ.get("SMS_CODE_ATTEMPT_WINDOW_SECONDS", "600"))
    audit_log_enabled: bool = os.environ.get("AUDIT_LOG_ENABLED", "1") not in ("0","false","False")
    ui_session_ttl_seconds: int = int(os.environ.get("UI_SESSION_TTL_SECONDS", str(30*24*3600)))
    ddb_ttl_attr: str = os.environ.get("DDB_TTL_ATTR", "ttl_epoch")

    api_keys_table_name: str = os.environ.get("API_KEYS_TABLE_NAME", "api_keys")
    api_keys_user_index: str = os.environ.get("API_KEYS_USER_INDEX", "user_sub-index")
    api_key_pepper: str = os.environ.get("API_KEY_PEPPER", "")

    alerts_table_name: str = os.environ.get("ALERTS_TABLE_NAME", "alerts")
    alerts_enabled: bool = os.environ.get("ALERTS_ENABLED", "1") not in ("0","false","False")
    alerts_ttl_days: int = int(os.environ.get("ALERTS_TTL_DAYS", "90"))
    alert_prefs_table_name: str = os.environ.get("ALERT_PREFS_TABLE_NAME", "alert_prefs")
    alerts_from_email: str = os.environ.get("ALERTS_FROM_EMAIL", "")
    alerts_email_enabled: bool = os.environ.get("ALERTS_EMAIL_ENABLED", "0") not in ("0","false","False")
    alerts_email_max_per_window: int = int(os.environ.get("ALERTS_EMAIL_MAX_PER_WINDOW", "20"))
    alerts_email_window_seconds: int = int(os.environ.get("ALERTS_EMAIL_WINDOW_SECONDS", "3600"))
    alerts_sms_enabled: bool = os.environ.get("ALERTS_SMS_ENABLED", "0") not in ("0","false","False")
    alerts_sms_max_per_window: int = int(os.environ.get("ALERTS_SMS_MAX_PER_WINDOW", "10"))
    alerts_sms_window_seconds: int = int(os.environ.get("ALERTS_SMS_WINDOW_SECONDS", "3600"))
    verify_email_max_per_window: int = int(os.environ.get("VERIFY_EMAIL_MAX_PER_WINDOW", "5"))
    verify_email_window_seconds: int = int(os.environ.get("VERIFY_EMAIL_WINDOW_SECONDS", "3600"))
    verify_sms_max_per_window: int = int(os.environ.get("VERIFY_SMS_MAX_PER_WINDOW", "5"))
    verify_sms_window_seconds: int = int(os.environ.get("VERIFY_SMS_WINDOW_SECONDS", "3600"))
    ws_token_secret: str = os.environ.get("WS_TOKEN_SECRET", "")
    push_devices_table_name: str = os.environ.get("PUSH_DEVICES_TABLE_NAME", "push_devices")
    push_enabled: bool = os.environ.get("PUSH_ENABLED", "0") not in ("0","false","False")
    fcm_enabled: bool = os.environ.get("FCM_ENABLED", "0") not in ("0","false","False")
    fcm_project_id: str = os.environ.get("FCM_PROJECT_ID", "")
    fcm_client_email: str = os.environ.get("FCM_CLIENT_EMAIL", "")
    fcm_private_key: str = os.environ.get("FCM_PRIVATE_KEY", "")  # keep \n escaped

    ddb_sessions_table: str = os.environ["DDB_SESSIONS_TABLE"]
    ddb_totp_table: str = os.environ["DDB_TOTP_TABLE"]
    ddb_sms_table: str = os.environ["DDB_SMS_TABLE"]
    ddb_recovery_table: str = os.environ["DDB_RECOVERY_TABLE"]
    ddb_email_table: str = os.environ["DDB_EMAIL_TABLE"]

    kms_key_id: str = os.environ["KMS_KEY_ID"]

    session_challenge_ttl_seconds: int = int(os.environ.get("SESSION_CHALLENGE_TTL_SECONDS", "300"))
    ui_inactivity_seconds: int = int(os.environ.get("UI_INACTIVITY_SECONDS", "900"))
    sms_device_limit: int = int(os.environ.get("SMS_DEVICE_LIMIT", "3"))
    email_device_limit: int = int(os.environ.get("EMAIL_DEVICE_LIMIT", "5"))

    ses_from_email: str = os.environ["SES_FROM_EMAIL"]

    twilio_account_sid: str = os.environ["TWILIO_ACCOUNT_SID"]
    twilio_auth_token: str = os.environ["TWILIO_AUTH_TOKEN"]
    twilio_verify_service_sid: str = os.environ["TWILIO_VERIFY_SERVICE_SID"]


S = Settings()

ddb = boto3.resource("dynamodb")
kms = boto3.client("kms")
ses = boto3.client("ses", region_name=S.aws_region)
twilio = TwilioClient(S.twilio_account_sid, S.twilio_auth_token)

cognito_verifier = CognitoJWTVerifier(
    user_pool_id=S.cognito_user_pool_id,
    region=S.cognito_region,
    app_client_id=S.cognito_app_client_id,
)


@dataclass(frozen=True)
class Tables:
    sessions: Any
    totp: Any
    sms: Any
    recovery: Any
    email: Any


T = Tables(
    sessions=ddb.Table(S.ddb_sessions_table),
    totp=ddb.Table(S.ddb_totp_table),
    sms=ddb.Table(S.ddb_sms_table),
    recovery=ddb.Table(S.ddb_recovery_table),
    email=ddb.Table(S.ddb_email_table),
)


# ============================================================
#  Helpers
# ============================================================


def new_api_key_secret() -> str:
    # 32 bytes -> urlsafe base64 without padding
    raw = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def api_key_hash(secret: str) -> str:
    # pepper is optional but recommended (set API_KEY_PEPPER)
    return sha256_str(S.api_key_pepper + secret)



def normalize_cidr(s: str) -> str:
    s = (s or "").strip()
    if not s:
        raise ValueError("empty")
    # If single IP, convert to /32 or /128
    if "/" not in s:
        ip = ipaddress.ip_address(s)
        if ip.version == 4:
            return f"{ip}/32"
        return f"{ip}/128"
    net = ipaddress.ip_network(s, strict=False)
    return str(net)


def ip_in_any_cidr(ip_str: str, cidrs: List[str]) -> bool:
    if not cidrs:
        return False
    ip = ipaddress.ip_address(ip_str)
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            if ip in net:
                return True
        except Exception:
            continue
    return False


def enforce_api_key_ip_rules(req: Request, key_item: Dict[str, Any]) -> None:
    ip = client_ip_from_request(req)
    allow = key_item.get("allow_cidrs") or []
    deny = key_item.get("deny_cidrs") or []

    # If neither configured -> no restrictions
    if not allow and not deny:
        return

    # Allowlist if present: must match at least one CIDR
    if allow and not ip_in_any_cidr(ip, allow):
        raise HTTPException(403, "API key not allowed from this IP")

    # Denylist applied after allowlist
    if deny and ip_in_any_cidr(ip, deny):
        raise HTTPException(403, "API key denied from this IP")


def parse_api_key(key: str) -> Dict[str, str]:
    # format: ak_<key_id>.<secret>
    if not key or not key.startswith("ak_") or "." not in key:
        raise HTTPException(401, "Invalid API key format")
    kid, sec = key.split(".", 1)
    key_id = kid[len("ak_"):]
    if not key_id or not sec:
        raise HTTPException(401, "Invalid API key format")
    return {"key_id": key_id, "secret": sec}


def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def kms_encrypt(plaintext: str) -> str:
    r = kms.encrypt(KeyId=S.kms_key_id, Plaintext=plaintext.encode("utf-8"))
    return base64.b64encode(r["CiphertextBlob"]).decode("ascii")


def kms_decrypt(ct_b64: str) -> bytes:
    ct = base64.b64decode(ct_b64)
    r = kms.decrypt(CiphertextBlob=ct)
    return r["Plaintext"]


def now_ts() -> int:
    return int(time.time())


def cognito_expected_issuer(
def mint_ws_token(user_sub: str, ttl_seconds: int = 60) -> str:
    if not S.ws_token_secret:
        raise RuntimeError("WS_TOKEN_SECRET not set")
    now = int(time.time())
    payload = {"user_sub": user_sub, "exp": now + ttl_seconds, "iat": now}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(S.ws_token_secret.encode("utf-8"), raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=") + "." + base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")


) -> str:


def encode_cursor(last_evaluated_key: Optional[Dict[str, Any]]) -> Optional[str]:
    if not last_evaluated_key:
        return None
    raw = json.dumps(last_evaluated_key, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def decode_cursor(cursor: Optional[str]) -> Optional[Dict[str, Any]]:
    if not cursor:
        return None
    s = cursor.strip()
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    try:
        raw = base64.urlsafe_b64decode((s + pad).encode("utf-8"))
        obj = json.loads(raw.decode("utf-8"))
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None



ALERT_EVENT_TYPES: List[str] = [
    "login_success",
    "login_failure",
    "mfa_success",
    "mfa_failure",
    "challenge_created",
    "challenge_revoked",
    "challenge_failed",
    "api_key_created",
    "api_key_revoked",
    "api_key_ip_rules_updated",
    "session_revoked",
    "totp_device_added",
    "totp_device_removed",
    "rate_limited",
    "access_denied",
    "security_event",
]



def normalize_phone(s: str) -> str:
    s = (s or "").strip()
    if not s:
        raise ValueError("empty phone")
    # keep digits and leading +
    s2 = re.sub(r"[\s\-\(\)\.]", "", s)
    if s2.startswith("+"):
        digits = re.sub(r"\D", "", s2[1:])
        if not digits:
            raise ValueError("bad phone")
        return "+" + digits
    digits = re.sub(r"\D", "", s2)
    # default country +1 for 10-digit NANP numbers
    if len(digits) == 10:
        return "+1" + digits
    if len(digits) == 11 and digits.startswith("1"):
        return "+" + digits
    raise ValueError("bad phone format; use +E164 or 10-digit")

def sns_client():
    return boto3.client("sns")

def send_alert_sms(to_numbers: List[str], body_text: str) -> None:
    if not S.alerts_sms_enabled:
        return
    if not to_numbers:
        return
    try:
        sns = sns_client()
        for n in to_numbers[:5]:
            sns.publish(PhoneNumber=n, Message=body_text[:1400])
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}


# In-memory pubsub for SSE (single-process). For multi-process, swap with Redis/SQS/etc.
_SSE_SUBSCRIBERS: Dict[str, "set[asyncio.Queue]"] = {}

def sse_subscribe(user_sub: str) -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=200)
    s = _SSE_SUBSCRIBERS.get(user_sub)
    if s is None:
        s = set()
        _SSE_SUBSCRIBERS[user_sub] = s
    s.add(q)
    return q

def sse_unsubscribe(user_sub: str, q: asyncio.Queue) -> None:
    s = _SSE_SUBSCRIBERS.get(user_sub)
    if not s:
        return
    try:
        s.remove(q)
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}
    if not s:
        _SSE_SUBSCRIBERS.pop(user_sub, None)

def sse_publish_alert(user_sub: str, alert_obj: Dict[str, Any]) -> None:
    s = _SSE_SUBSCRIBERS.get(user_sub)
    if not s:
        return
    dead = []
    for q in list(s):
        try:
            q.put_nowait(alert_obj)
        except Exception:
            dead.append(q)
    for q in dead:
        sse_unsubscribe(user_sub, q)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def fcm_access_token() -> Optional[str]:
    if not S.fcm_enabled:
        return None
    if not (S.fcm_project_id and S.fcm_client_email and S.fcm_private_key):
        return None
    # Google service account JWT assertion flow
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    claim = {
        "iss": S.fcm_client_email,
        "scope": "https://www.googleapis.com/auth/firebase.messaging",
        "aud": "https://oauth2.googleapis.com/token",
        "iat": now,
        "exp": now + 3600,
    }
    # Private key env often has literal \n; fix it.
    pk = S.fcm_private_key.replace("\\n", "\n")
    try:
        import cryptography.hazmat.primitives.serialization as serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        key = serialization.load_pem_private_key(pk.encode("utf-8"), password=None)
        signing_input = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")) + "." + _b64url(json.dumps(claim, separators=(",", ":")).encode("utf-8"))
        sig = key.sign(signing_input.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
        jwt = signing_input + "." + _b64url(sig)
        r = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jwt,
            },
            timeout=5,
        )
        if r.status_code != 200:
            return None
        return r.json().get("access_token")
    except Exception:
        return None

def fcm_send(token: str, title: str, body: str, data: Optional[Dict[str, str]] = None) -> bool:
    at = fcm_access_token()
    if not at:
        return False
    url = f"https://fcm.googleapis.com/v1/projects/{S.fcm_project_id}/messages:send"
    msg = {
        "message": {
            "token": token,
            "notification": {"title": title[:60], "body": body[:180]},
            "data": data or {},
        }
    }
    try:
        r = requests.post(url, headers={"Authorization": f"Bearer {at}"}, json=msg, timeout=5)
        return r.status_code in (200, 202)
    except Exception:
        return False

def push_device_id(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]

def list_push_devices(user_sub: str) -> List[Dict[str, Any]]:
    try:
        r = T.push_devices.query(KeyConditionExpression=Key("user_sub").eq(user_sub), Limit=200)
        out = []
        for it in r.get("Items", []):
            out.append({
                "device_id": it.get("device_id"),
                "platform": it.get("platform"),
                "created_at": it.get("created_at"),
                "last_seen_at": it.get("last_seen_at"),
            })
        out.sort(key=lambda x: x.get("created_at", 0), reverse=True)
        return out
    except Exception:
        return []

def upsert_push_device(user_sub: str, token: str, platform: str) -> Dict[str, Any]:
    did = push_device_id(token)
    now = now_ts()
    ttl = now + 60 * 60 * 24 * 180  # 180d
    T.push_devices.put_item(Item=with_ttl({
        "user_sub": user_sub,
        "device_id": did,
        "token": token,
        "platform": platform,
        "created_at": now,
        "last_seen_at": now,
    }, ttl_epoch=ttl))
    return {"device_id": did, "platform": platform, "created_at": now, "last_seen_at": now}

def revoke_push_device(user_sub: str, device_id: str) -> None:
    try:
        T.push_devices.delete_item(Key={"user_sub": user_sub, "device_id": device_id})
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}

def send_push_for_alert(user_sub: str, alert_type: str, title: str, body: str, alert_id: str) -> None:
    if not S.push_enabled:
        return
    prefs = get_alert_prefs(user_sub)
    enabled = set(prefs.get("push_event_types") or [])
    if alert_type not in enabled:
        return
    # Rate limit per-user per-channel (reuse alert channel limiter)
    if not can_send_alert_channel(user_sub, "push"):
        return
    try:
        r = T.push_devices.query(KeyConditionExpression=Key("user_sub").eq(user_sub), Limit=200)
        items = r.get("Items", [])
        for it in items[:25]:
            tok = it.get("token")
            if not tok:
                continue
            ok = fcm_send(tok, title, body, data={"alert_id": alert_id, "alert_type": alert_type})
            if not ok:
                # If invalid token, best-effort revoke later; keep for now.
                pass
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}


def can_send_verification(user_sub: str, channel: str) -> bool:
    now = now_ts()
    if channel == "email":
        max_n = S.verify_email_max_per_window
        win = S.verify_email_window_seconds
        sid = "rl#verify_email"
    elif channel == "sms":
        max_n = S.verify_sms_max_per_window
        win = S.verify_sms_window_seconds
        sid = "rl#verify_sms"
    else:
        return True

    it = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": sid}).get("Item") or {}
    start = int(it.get("bucket_start", 0))
    count = int(it.get("bucket_count", 0))
    if start == 0 or (now - start) >= win:
        start = now
        count = 0
    if count >= max_n:
        return False
    try:
        T.sessions.put_item(
            Item=with_ttl(
                {"user_sub": user_sub, "session_id": sid, "bucket_start": start, "bucket_count": count + 1},
                ttl_epoch=now + win + 3600,
            )
        )
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}
    return True


def can_send_alert_channel(user_sub: str, channel: str) -> bool:
    now = now_ts()
    if channel == "email":
        max_n = S.alerts_email_max_per_window
        win = S.alerts_email_window_seconds
    elif channel == "sms":
        max_n = S.alerts_sms_max_per_window
        win = S.alerts_sms_window_seconds
    elif channel == "push":
        max_n = int(os.environ.get("ALERTS_PUSH_MAX_PER_WINDOW", "20"))
        win = int(os.environ.get("ALERTS_PUSH_WINDOW_SECONDS", "3600"))
    else:
        return True

    sid = f"rl#alert_{channel}"
    it = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": sid}).get("Item") or {}
    start = int(it.get("bucket_start", 0))
    count = int(it.get("bucket_count", 0))

    if start == 0 or (now - start) >= win:
        start = now
        count = 0

    if count >= max_n:
        return False

    # increment (best-effort)
    try:
        T.sessions.put_item(
            Item=with_ttl(
                {
                    "user_sub": user_sub,
                    "session_id": sid,
                    "bucket_start": start,
                    "bucket_count": count + 1,
                },
                ttl_epoch=now + win + 3600,
            )
        )
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}
    return True


def ses_client():
    return boto3.client("ses")


def send_alert_email(to_emails: List[str], subject: str, body_text: str) -> None:
    if not S.alerts_email_enabled:
        return
    if not S.alerts_from_email:
        return
    if not to_emails:
        return
    try:
        ses = ses_client()
        ses.send_email(
            Source=S.alerts_from_email,
            Destination={"ToAddresses": to_emails},
            Message={
                "Subject": {"Data": subject[:120]},
                "Body": {"Text": {"Data": body_text[:8000]}},
            },
        )
    except Exception:
        # best-effort
        pass


def get_alert_prefs(user_sub: str) -> Dict[str, Any]:
    it = T.alert_prefs.get_item(Key={"user_sub": user_sub}).get("Item")
    if not it:
        return {"emails": [], "sms_numbers": [], "email_event_types": [], "sms_event_types": [], "toast_event_types": [], "push_event_types": []}
    return {
        "emails": it.get("emails", []),
        "sms_numbers": it.get("sms_numbers", []),
        "email_event_types": it.get("email_event_types", []),
        "sms_event_types": it.get("sms_event_types", []),
        "toast_event_types": it.get("toast_event_types", []),
        "push_event_types": it.get("push_event_types", []),
    }


def set_alert_prefs(user_sub: str, emails: Optional[List[str]] = None, sms_numbers: Optional[List[str]] = None, email_event_types: Optional[List[str]] = None, sms_event_types: Optional[List[str]] = None, toast_event_types: Optional[List[str]] = None) -> Dict[str, Any]:
    cur = get_alert_prefs(user_sub)
    if emails is None:
        emails = cur["emails"]
    if sms_numbers is None:
        sms_numbers = cur.get("sms_numbers", [])
    if email_event_types is None:
        email_event_types = cur["email_event_types"]
    if sms_event_types is None:
        sms_event_types = cur.get("sms_event_types", [])
    if toast_event_types is None:
        toast_event_types = cur.get("toast_event_types", [])
    # normalize
    emails = [normalize_email(e) for e in emails if (e or "").strip()]
    sms_numbers = [normalize_phone(n) for n in (sms_numbers or []) if (n or "").strip()]
    # dedupe preserve order
    seen = set()
    out_emails = []
    for e in emails:
        if e not in seen:
            seen.add(e)
            out_emails.append(e)
    seen2 = set()
    out_sms = []
    for n in sms_numbers:
        if n not in seen2:
            seen2.add(n)
            out_sms.append(n)
    # only allow known types
    s = set(ALERT_EVENT_TYPES)
    out_types = [t for t in (email_event_types or []) if t in s]
    out_sms_types = [t for t in (sms_event_types or []) if t in s]
    out_toast_types = [t for t in (toast_event_types or []) if t in s]
    T.alert_prefs.put_item(Item={"user_sub": user_sub, "emails": out_emails, "sms_numbers": out_sms, "email_event_types": out_types, "sms_event_types": out_sms_types, "toast_event_types": out_toast_types,
            "push_event_types": out_push_types, "updated_at": now_ts()})
    return {"emails": out_emails, "sms_numbers": out_sms, "email_event_types": out_types, "sms_event_types": out_sms_types, "toast_event_types": out_toast_types}


def event_to_type(event: str, outcome: str, status_code: Optional[int] = None) -> str:
    e = event or ""
    o = (outcome or "").lower()
    if e in ("ui_session_finalize",):
        return "login_success" if o == "success" else "login_failure"
    if e.startswith("mfa_"):
        return "mfa_success" if o == "success" else "mfa_failure"
    if e.startswith("api_key_create"):
        return "api_key_created"
    if e.startswith("api_key_revoke"):
        return "api_key_revoked"
    if e.startswith("api_key_ip_rules"):
        return "api_key_ip_rules_updated"
    if e.startswith("ui_session_revoke"):
        return "session_revoked"
    if e.startswith("totp_device_confirm"):
        return "totp_device_added"
    if e.startswith("totp_device_remove"):
        return "totp_device_removed"
    if e.startswith("ui_rate_limited") or (status_code == 429):
        return "rate_limited"
    if status_code in (401, 403):
        return "access_denied"
    return "security_event"


def write_alert(user_sub: str, event: str, outcome: str, title: str, details: Dict[str, Any]) -> Dict[str, Any]:
    """Best-effort: persist an alert for the user."""
    if not S.alerts_enabled:
        return
    ts = now_ts()
    alert_id = f"{ts:010d}#{uuid.uuid4().hex}"
    ttl = ts + int(S.alerts_ttl_days) * 86400
    # Keep details small and safe (never include secrets)
    safe_details = {}
    for k, v in (details or {}).items():
        if v is None:
            continue
        if isinstance(v, (int, float, bool)):
            safe_details[k] = v
        else:
            safe_details[k] = str(v)[:512]
    item = {
        "user_sub": user_sub,
        "alert_id": alert_id,
        "ts": ts,
        "event": event,
        "outcome": outcome,
        "title": title[:120],
        "details": safe_details,
        "read": False,
        "read_at": 0,
    }
    try:
        T.alerts.put_item(Item=with_ttl(item, ttl_epoch=ttl))
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}


def with_ttl(item: Dict[str, Any], ttl_epoch: int) -> Dict[str, Any]:
    # DynamoDB TTL must be enabled on S.ddb_ttl_attr (default: ttl_epoch) for this to auto-expire.
    item[S.ddb_ttl_attr] = int(ttl_epoch)
    return item


def enforce_email_attempt_budget(user_sub: str, challenge_id: str) -> None:
    """Increment attempt counter for an email-code check, with a rolling window.

    Stored on the *challenge item* (in Sessions table today).
    Fields:
      - email_attempt_bucket_start (epoch seconds)
      - email_attempt_count (int)
    """
    now = now_ts()
    window = S.email_code_attempt_window_seconds
    max_attempts = S.email_code_max_attempts
    bucket_start = now - (now % window)

    key = {"user_sub": user_sub, "session_id": challenge_id}

    # If bucket differs (or doesn't exist), reset to 1 for this window.
    try:
        T.sessions.update_item(
            Key=key,
            UpdateExpression="SET email_attempt_bucket_start=:b, email_attempt_count=:one, updated_at=:now",
            ConditionExpression="attribute_not_exists(email_attempt_bucket_start) OR email_attempt_bucket_start <> :b",
            ExpressionAttributeValues={":b": bucket_start, ":one": 1, ":now": now},
        )
        return
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}

    # Same bucket: increment if still under limit.
    try:
        T.sessions.update_item(
            Key=key,
            UpdateExpression="ADD email_attempt_count :one SET updated_at=:now",
            ConditionExpression="email_attempt_bucket_start = :b AND email_attempt_count < :limit",
            ExpressionAttributeValues={":b": bucket_start, ":one": 1, ":limit": max_attempts, ":now": now},
        )
        return
    except Exception:
        raise HTTPException(429, "Too many email code attempts; try again later")



def enforce_sms_attempt_budget(user_sub: str, challenge_id: str) -> None:
    """Increment attempt counter for an SMS-code check, with a rolling window."""
    now = now_ts()
    window = S.sms_code_attempt_window_seconds
    max_attempts = S.sms_code_max_attempts
    bucket_start = now - (now % window)
    key = {"user_sub": user_sub, "session_id": challenge_id}

    # Reset for new bucket
    try:
        T.sessions.update_item(
            Key=key,
            UpdateExpression="SET sms_attempt_bucket_start=:b, sms_attempt_count=:one, updated_at=:now",
            ConditionExpression="attribute_not_exists(sms_attempt_bucket_start) OR sms_attempt_bucket_start <> :b",
            ExpressionAttributeValues={":b": bucket_start, ":one": 1, ":now": now},
        )
        return
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}

    # Same bucket: increment if under limit
    try:
        T.sessions.update_item(
            Key=key,
            UpdateExpression="ADD sms_attempt_count :one SET updated_at=:now",
            ConditionExpression="sms_attempt_bucket_start = :b AND sms_attempt_count < :limit",
            ExpressionAttributeValues={":b": bucket_start, ":one": 1, ":limit": max_attempts, ":now": now},
        )
        return
    except Exception:
        raise HTTPException(429, "Too many SMS code attempts; try again later")




def audit_event(event: str, user_sub: str, request: Optional[Request] = None, **fields: Any) -> None:
    """Best-effort structured audit logging (CloudWatch via stdout) + alerts history + optional email fanout.

    No secrets should be passed in fields (never log codes/tokens).
    """
    payload: Dict[str, Any] = {"event": event, "user_sub": user_sub, "ts": now_ts(), **fields}
    if request is not None:
        payload["ip"] = client_ip_from_request(request)
        ua = request.headers.get("user-agent", "")
        payload["user_agent"] = ua[:256]

    outcome = str(fields.get("outcome", "info"))
    status_code = fields.get("status_code")
    alert_type = event_to_type(event, outcome, status_code=status_code)

    # Alerts persistence (best-effort)
    try:
        title = event.replace("_", " ")
        pretty = {
            "ui_session_start": "UI session started",
            "ui_session_finalize": "Login",
            "mfa_email_verify": "Email verification",
            "mfa_sms_verify": "SMS verification",
            "mfa_totp_verify": "TOTP verification",
            "mfa_recovery": "Recovery code",
            "api_key_create": "API key created",
            "api_key_revoke": "API key revoked",
            "api_key_ip_rules_set": "API key IP rules updated",
            "ui_session_revoke": "Session revoked",
            "ui_session_revoke_others": "Other sessions revoked",
            "totp_device_confirm": "TOTP device added",
            "totp_device_remove": "TOTP device removed",
        }
        t = pretty.get(event, title)
        wr = write_alert(user_sub, event=event, outcome=outcome, title=t, details={**payload, "alert_type": alert_type})
        payload["alert_id"] = wr.get("alert_id") if isinstance(wr, dict) else payload.get("alert_id")
        # Push notification (FCM) if enabled for this alert_type
        try:
            send_push_for_alert(user_sub, alert_type, t, f"{event} ({outcome})", payload.get("alert_id",""))
        except Exception:
            pass
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}

    # Optional email fanout
    try:
        prefs = get_alert_prefs(user_sub)
        emails = prefs.get("emails") or []
        enabled = set(prefs.get("email_event_types") or [])
        if emails and (alert_type in enabled) and can_send_alert_channel(user_sub, "email"):
            subj = f"[Alert] {alert_type}: {event} ({outcome})"
            lines = [
                f"Type: {alert_type}",
                f"Event: {event}",
                f"Outcome: {outcome}",
                f"Time: {payload.get('ts')}",
            ]
            if request is not None:
                lines.append(f"IP: {payload.get('ip','')}")
                lines.append(f"User-Agent: {payload.get('user_agent','')}")
            reason = fields.get("reason")
            if reason:
                lines.append(f"Reason: {reason}")
            # Include a compact JSON detail at end
            lines.append("")
            lines.append(json.dumps(payload, indent=2)[:4000])
            send_alert_email(emails, subj, "
".join(lines))
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}

# Optional SMS fanout
try:
    prefs = get_alert_prefs(user_sub)
    nums = prefs.get("sms_numbers") or []
    enabled_sms = set(prefs.get("sms_event_types") or [])
    if nums and (alert_type in enabled_sms) and can_send_alert_channel(user_sub, "sms"):
        line = f"[{alert_type}] {event} {outcome}"
        if request is not None:
            line += f" ip={payload.get('ip','')}"
        reason = fields.get("reason")
        if reason:
            line += f" reason={str(reason)[:80]}"
        send_alert_sms(nums, line)
except Exception:
    pass


    # stdout audit log
    if not S.audit_log_enabled:
        return
    try:
        print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}


    No secrets should be passed in fields (never log codes/tokens).
    """
    payload: Dict[str, Any] = {"event": event, "user_sub": user_sub, "ts": now_ts(), **fields}
    if request is not None:
        payload["ip"] = client_ip_from_request(request)
        ua = request.headers.get("user-agent", "")
        payload["user_agent"] = ua[:256]

    # Alerts persistence (best-effort)
    try:
        title = event.replace("_", " ")
        outcome = str(fields.get("outcome", "info"))
        # For UI friendliness, translate a few key events
        pretty = {
            "ui_session_start": "UI session started",
            "ui_session_finalize": "Login successful",
            "mfa_email_verify": "Email verification",
            "mfa_sms_verify": "SMS verification",
            "mfa_totp_verify": "TOTP verification",
            "mfa_recovery": "Recovery code",
            "api_key_create": "API key created",
            "api_key_revoke": "API key revoked",
            "api_key_ip_rules_set": "API key IP rules updated",
            "ui_session_revoke": "Session revoked",
            "ui_session_revoke_others": "Other sessions revoked",
            "totp_device_confirm": "TOTP device added",
            "totp_device_remove": "TOTP device removed",
        }
        t = pretty.get(event, title)
        write_alert(user_sub, event=event, outcome=outcome, title=t, details=payload)
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}

# Optional SMS fanout
try:
    prefs = get_alert_prefs(user_sub)
    nums = prefs.get("sms_numbers") or []
    enabled_sms = set(prefs.get("sms_event_types") or [])
    if nums and (alert_type in enabled_sms) and can_send_alert_channel(user_sub, "sms"):
        line = f"[{alert_type}] {event} {outcome}"
        if request is not None:
            line += f" ip={payload.get('ip','')}"
        reason = fields.get("reason")
        if reason:
            line += f" reason={str(reason)[:80]}"
        send_alert_sms(nums, line)
except Exception:
    pass


    # stdout audit log
    if not S.audit_log_enabled:
        return
    try:
        print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}


    No secrets should be passed in fields (never log codes/tokens).
    """
    if not S.audit_log_enabled:
        return
    payload: Dict[str, Any] = {"event": event, "user_sub": user_sub, "ts": now_ts(), **fields}
    if request is not None:
        payload["ip"] = client_ip_from_request(request)
        ua = request.headers.get("user-agent", "")
        payload["user_agent"] = ua[:256]
    try:
        print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}

    # https://cognito-idp.<region>.amazonaws.com/<userPoolId>
    return f"https://cognito-idp.{S.cognito_region}.amazonaws.com/{S.cognito_user_pool_id}"


def rate_limit_or_429(user_sub: str, factor: str) -> None:
    """Simple per-user+factor rate limiting stored in Sessions table.

    Key: (user_sub, session_id=f"rl#{factor}")
    Enforces:
      - minimum interval between sends (MFA_SEND_MIN_INTERVAL_SECONDS)
      - max sends per hour bucket (MFA_SEND_MAX_PER_HOUR)
    """
    now = now_ts()
    earliest = now - S.mfa_send_min_interval_seconds
    bucket = now // 3600
    key = {"user_sub": user_sub, "session_id": f"rl#{factor}"}

    # Path A: new bucket -> reset counter to 1
    try:
        T.sessions.update_item(
            Key=key,
            UpdateExpression="SET bucket=:b, count=:one, last_sent_at=:now, updated_at=:now",
            ConditionExpression="attribute_not_exists(bucket) OR bucket <> :b",
            ExpressionAttributeValues={
                ":b": bucket,
                ":one": 1,
                ":now": now,
            },
        )
        return
    except Exception:
        # likely ConditionalCheckFailed -> same bucket
        pass

    # Path B: same bucket -> increment
    try:
        T.sessions.update_item(
            Key=key,
            UpdateExpression="ADD count :one SET last_sent_at=:now, updated_at=:now",
            ConditionExpression="bucket = :b AND count < :limit AND (attribute_not_exists(last_sent_at) OR last_sent_at <= :earliest)",
            ExpressionAttributeValues={
                ":b": bucket,
                ":one": 1,
                ":now": now,
                ":limit": S.mfa_send_max_per_hour,
                ":earliest": earliest,
            },
        )
        return
    except Exception:
        raise HTTPException(429, "Too many verification sends; try again shortly")


def client_ip_from_request(req: Request) -> str:
    xff = req.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return req.client.host if req.client else "0.0.0.0"


def normalize_e164(s: str) -> str:
    s = s.strip()
    if not s.startswith("+"):
        raise HTTPException(400, "Phone must be E.164 like +15551234567")
    if not s[1:].isdigit():
        raise HTTPException(400, "Phone must be E.164 digits")
    if len(s) < 9 or len(s) > 16:
        raise HTTPException(400, "Phone must be E.164 length")
    return s


def normalize_email(s: str) -> str:
    s = s.strip().lower()
    if "@" not in s or len(s) > 254:
        raise HTTPException(400, "Invalid email")
    return s



def is_real_ui_session_id(session_id: str) -> bool:
    # Real sessions are UUIDs (created by create_real_session).
    # Challenges use prefixes like 'chal_' or '<purpose>_' and rate limit uses 'rl#'.
    if session_id.startswith("chal_") or session_id.startswith("rl#"):
        return False
    if "_" in session_id:
        return False
    # quick UUID shape check: 36 chars with 4 dashes
    return len(session_id) == 36 and session_id.count("-") == 4


def gen_numeric_code(n_digits: int = 6) -> str:
    return str(secrets.randbelow(10**n_digits)).zfill(n_digits)


def send_email_code(to_email: str, purpose: str, code: str) -> None:
    subject = f"Your verification code ({purpose})"
    body = (
        f"Your verification code is: {code}\n\n"
        "If you did not request this, ignore this email."
    )
    ses.send_email(
        Source=S.ses_from_email,
        Destination={"ToAddresses": [to_email]},
        Message={"Subject": {"Data": subject}, "Body": {"Text": {"Data": body}}},
    )


def twilio_start_sms(to_e164: str) -> None:
    twilio.verify.v2.services(S.twilio_verify_service_sid).verifications.create(
        to=to_e164, channel="sms"
    )


def twilio_check_sms(to_e164: str, code: str) -> bool:
    r = twilio.verify.v2.services(S.twilio_verify_service_sid).verification_checks.create(
        to=to_e164, code=code
    )
    return r.status == "approved"


def new_recovery_codes(n: int = 10) -> List[str]:
    codes: List[str] = []
    for _ in range(n):
        raw = secrets.token_hex(6)  # 12 hex chars
        codes.append(f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}")
    return codes


def store_recovery_codes(user_sub: str, factor: str, codes: Sequence[str]) -> None:
    ts = now_ts()
    for c in codes:
        T.recovery.put_item(
            Item={
                "user_sub": user_sub,
                "code_hash": f"{factor}#{sha256_str(c)}",
                "factor": factor,
                "used": False,
                "created_at": ts,
            }
        )


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
    items = [d for d in r.get("Items", []) if d.get("enabled", False)]
    return [d["phone_e164"] for d in items]


def list_enabled_emails(user_sub: str) -> List[str]:
    r = T.email.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    items = [d for d in r.get("Items", []) if d.get("enabled", False)]
    return [d["email"] for d in items]


def totp_verify_any_enabled(user_sub: str, code: str) -> Optional[str]:
    """Returns device_id if verified, else None."""
    r = T.totp.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    devices = [d for d in r.get("Items", []) if d.get("enabled", False)]
    for d in devices:
        secret_b32 = kms_decrypt(d["secret_ct_b64"]).decode("utf-8")
        try:
            if pyotp.TOTP(secret_b32).verify(code.strip(), valid_window=1):
                return d["device_id"]
        except Exception:
            pass
    return None


# ============================================================
#  Auth (placeholder)
# ============================================================

async def get_authenticated_user_sub(_: Request) -> str:
    """
    Replace this with your real authentication.
    Examples:
      - Validate Cognito JWT from Authorization header
      - Validate signed session cookie
    """
    raise HTTPException(501, "Auth not wired: implement get_authenticated_user_sub()")


# ============================================================
#  UI session (post-login session cookie/header)
# ============================================================

async def require_ui_session(
    request: Request,
    user_sub: str = Depends(get_authenticated_user_sub),
    x_session_id: Optional[str] = Header(default=None, alias="X-SESSION-ID"),
) -> Dict[str, str]:
    if not x_session_id:
        raise HTTPException(401, "Missing X-SESSION-ID")

    it = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": x_session_id}).get("Item")
    if not it:
        raise HTTPException(401, "Unknown session")
    if it.get("revoked", False):
        raise HTTPException(401, "Session revoked")
    if it.get("pending_auth", False):
        raise HTTPException(401, "Session not finalized")

    ts = now_ts()
    last = int(it.get("last_seen_at", 0) or 0)
    if last and (ts - last) > S.ui_inactivity_seconds:
        # revoke expired session
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": x_session_id},
            UpdateExpression="SET revoked = :t",
            ExpressionAttributeValues={":t": True},
        )
        raise HTTPException(401, "Session expired (inactive)")

    # touch last_seen (best effort)
    T.sessions.update_item(
        Key={"user_sub": user_sub, "session_id": x_session_id},
        UpdateExpression="SET last_seen_at = :t",
        ExpressionAttributeValues={":t": ts},
    )
    return {"user_sub": user_sub, "session_id": x_session_id}


# ============================================================
#  Challenge session repository
# ============================================================


def create_real_session(req: Request, user_sub: str) -> str:
    session_id = str(uuid.uuid4())
    ts = now_ts()
    ttl = ts + S.ui_session_ttl_seconds
    T.sessions.put_item(
        Item=with_ttl(
            {
                "user_sub": user_sub,
                "session_id": session_id,
                "created_at": ts,
                "last_seen_at": ts,
                "ip": client_ip_from_request(req),
                "user_agent": (req.headers.get("user-agent", "")[:512]),
                "revoked": False,
                "pending_auth": False,
            },
            ttl_epoch=ttl,
        )
    )
    return session_id


def load_challenge_or_401(user_sub: str, challenge_id: str) -> Dict[str, Any]:
    it = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": challenge_id}).get("Item")
    if not it or it.get("revoked") or not it.get("pending_auth"):
        raise HTTPException(401, "Invalid challenge")
    ts = now_ts()
    if int(it.get("expires_at", ts + 1)) < ts:
        # expire it
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": challenge_id},
            UpdateExpression="SET revoked = :t",
            ExpressionAttributeValues={":t": True},
        )
        raise HTTPException(401, "Challenge expired")
    return it



def revoke_challenge(user_sub: str, challenge_id: str) -> None:
    # Mark revoked and make it eligible for TTL cleanup soon.
    try:
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": challenge_id},
            UpdateExpression="SET revoked = :t, #ttl = :ttl, revoked_at = :now",
            ExpressionAttributeNames={"#ttl": S.ddb_ttl_attr},
            ExpressionAttributeValues={":t": True, ":ttl": now_ts() + 3600, ":now": now_ts()},
        )
    except Exception:
        # best-effort
        pass



def mark_factor_passed(user_sub: str, challenge_id: str, factor: str) -> None:
    T.sessions.update_item(
        Key={"user_sub": user_sub, "session_id": challenge_id},
        UpdateExpression="SET passed.#f = :t",
        ExpressionAttributeNames={"#f": factor},
        ExpressionAttributeValues={":t": True},
    )


def challenge_done(chal: Dict[str, Any]) -> bool:
    required = chal.get("required_factors", []) or []
    passed = chal.get("passed", {}) or {}
    return all(bool(passed.get(f, False)) for f in required)


def compute_required_factors(user_sub: str) -> List[str]:
    required: List[str] = []

    r1 = T.totp.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    if any(d.get("enabled", False) for d in r1.get("Items", [])):
        required.append("totp")

    r2 = T.sms.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    if any(d.get("enabled", False) for d in r2.get("Items", [])):
        required.append("sms")

    r3 = T.email.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    if any(d.get("enabled", False) for d in r3.get("Items", [])):
        required.append("email")

    return required


def maybe_finalize(req: Request, user_sub: str, challenge_id: str) -> Optional[str]:
    chal = load_challenge_or_401(user_sub, challenge_id)
    if not challenge_done(chal):
        return None
    sid = create_real_session(req, user_sub)
    revoke_challenge(user_sub, challenge_id)
    return sid



def create_stepup_challenge(req: Request, user_sub: str, required_factors: List[str]) -> str:
    challenge_id = "chal_" + uuid.uuid4().hex
    ts = now_ts()
    expires = ts + S.session_challenge_ttl_seconds
    T.sessions.put_item(
        Item=with_ttl(
            {
                "user_sub": user_sub,
                "session_id": challenge_id,
                "created_at": ts,
                "last_seen_at": ts,
                "ip": client_ip_from_request(req),
                "user_agent": (req.headers.get("user-agent", "")[:512]),
                "revoked": False,
                "pending_auth": True,
                "required_factors": required_factors,
                "passed": {f: False for f in required_factors},
                "expires_at": expires,
            },
            ttl_epoch=expires,
        )
    )
    return challenge_id



def create_action_challenge(
    req: Request,
    user_sub: str,
    purpose: str,
    send_to: List[str],
    payload: Dict[str, Any],
    ttl_seconds: int = 300,
) -> str:
    challenge_id = f"{purpose}_" + uuid.uuid4().hex
    ts = now_ts()
    expires = ts + ttl_seconds
    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "session_id": challenge_id,
        "created_at": ts,
        "expires_at": expires,
        "revoked": False,
        "pending_auth": True,
        "purpose": purpose,
        "send_to": send_to,
        "ip": client_ip_from_request(req),
        "user_agent": (req.headers.get("user-agent", "")[:512]),
    }
    item.update(payload)
    T.sessions.put_item(Item=with_ttl(item, ttl_epoch=expires))
    return challenge_id


def verify_code_any_sms(send_to: Sequence[str], code: str) -> bool:
    for n in send_to:
        try:
            if twilio_check_sms(n, code):
                return True
        except Exception:
            pass
    return False


# ============================================================
#  Pydantic models
# ============================================================

class SessionStartResp(BaseModel):
    auth_required: bool
    challenge_id: Optional[str] = None
    required_factors: Optional[List[str]] = None
    session_id: Optional[str] = None


class FinalizeReq(BaseModel):
    challenge_id: str


class TotpVerifyReq(BaseModel):
    challenge_id: str
    totp_code: str


class SmsBeginReq(BaseModel):
    challenge_id: str


class SmsVerifyReq(BaseModel):
    challenge_id: str
    code: str


class EmailVerifyReq(BaseModel):
    challenge_id: str
    code: str


class RecoveryReq(BaseModel):
    challenge_id: str
    recovery_code: str


class TotpBeginReq(BaseModel):
    label: Optional[str] = None


class TotpBeginResp(BaseModel):
    device_id: str
    otpauth_uri: str
    recovery_codes: List[str]


class TotpConfirmReq(BaseModel):
    device_id: str
    totp_code: str


class TotpRemoveReq(BaseModel):
    totp_code: str


class SmsEnrollBeginReq(BaseModel):
    phone_e164: str
    label: Optional[str] = None


class SmsEnrollConfirmReq(BaseModel):
    challenge_id: str
    code: str


class SmsRemoveBeginResp(BaseModel):
    challenge_id: str
    sent_to: List[str]


class SmsRemoveConfirmReq(BaseModel):
    challenge_id: str
    code: str


class EmailEnrollBeginReq(BaseModel):
    email: str
    label: Optional[str] = None


class EmailEnrollConfirmReq(BaseModel):
    challenge_id: str
    code: str


class EmailRemoveConfirmReq(BaseModel):
    challenge_id: str
    code: str


# ============================================================
#  App + routes
# ============================================================

app = FastAPI()

from fastapi.responses import JSONResponse, StreamingResponse

@app.middleware("http")
async def attach_request_context(request: Request, call_next):
    # Set during auth dependencies when possible; keep defaults.
    request.state.user_sub = None
    request.state.auth_kind = None
    try:
        response = await call_next(request)
        return response
    except HTTPException as e:
        raise e


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Broad failure auditing for UI routes (best-effort)
    try:
        path = request.url.path
        if path.startswith("/ui/"):
            user_sub = getattr(request.state, "user_sub", None)
            if user_sub:
                audit_event(
                    "ui_http_error",
                    user_sub,
                    request,
                    outcome="failure",
                    status_code=exc.status_code,
                    reason=str(exc.detail)[:200],
                    path=path,
                    method=request.method,
                )
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})



# ------------------------------------------------------------
# A) Step-up login transaction (requires all enrolled factors)
# ------------------------------------------------------------

@app.post("/ui/session/start", response_model=SessionStartResp)
@app.post("/ui/session/start")
async def ui_session_start(req: Request, user_sub: str = Depends(get_authenticated_user_sub)):
    required = compute_required_factors(user_sub)
    if not required:
        sid = create_real_session(req, user_sub)
            audit_event("ui_session_start", user_sub, req, outcome="success")
return SessionStartResp(auth_required=False, session_id=sid)

    challenge_id = create_stepup_challenge(req, user_sub, required)
    return SessionStartResp(auth_required=True, challenge_id=challenge_id, required_factors=required)


@app.post("/ui/session/finalize")
async def ui_session_finalize(
    req: Request,
    body: FinalizeReq,
    user_sub: str = Depends(get_authenticated_user_sub),
):
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if not challenge_done(chal):
        missing = [
            f for f in (chal.get("required_factors", []) or [])
            if not (chal.get("passed", {}) or {}).get(f, False)
        ]
        raise HTTPException(400, f"Missing factors: {missing}")
    sid = maybe_finalize(req, user_sub, body.challenge_id)
        audit_event("ui_session_finalize", user_sub, req, outcome="success")
return {"session_id": sid}


# ------------------------------------------------------------
# B) Factor verification for login
# ------------------------------------------------------------

@app.post("/ui/mfa/totp/verify")
async def ui_totp_verify(req: Request, body: TotpVerifyReq, user=Depends(get_authenticated_user_sub)):
    user_sub = user
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if "totp" not in (chal.get("required_factors", []) or []):
        raise HTTPException(400, "TOTP not required for this login")

    dev_id = totp_verify_any_enabled(user_sub, body.totp_code)
    if not dev_id:
        raise HTTPException(401, "Bad TOTP")

    mark_factor_passed(user_sub, body.challenge_id, "totp")
    T.totp.update_item(
        Key={"user_sub": user_sub, "device_id": dev_id},
        UpdateExpression="SET last_used_at = :t",
        ExpressionAttributeValues={":t": now_ts()},
    )

    sid = maybe_finalize(req, user_sub, body.challenge_id)
    return {"ok": True, "session_id": sid}


@app.post("/ui/mfa/sms/begin")
async def ui_sms_begin(req: Request, body: SmsBeginReq, user=Depends(get_authenticated_user_sub)):
    user_sub = user
    rate_limit_or_429(user_sub, "login_sms")
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if "sms" not in (chal.get("required_factors", []) or []):
        raise HTTPException(400, "SMS not required for this login")

    nums = list_enabled_sms_numbers(user_sub)
    if not nums:
        raise HTTPException(400, "No SMS devices enrolled")

    for n in nums:
        twilio_start_sms(n)

    return {"ok": True, "sent_to": nums}


@app.post("/ui/mfa/sms/verify")
async def ui_sms_verify(req: Request, body: SmsVerifyReq, user=Depends(get_authenticated_user_sub)):
    user_sub = user
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if "sms" not in (chal.get("required_factors", []) or []):
        raise HTTPException(400, "SMS not required for this login")

    nums = list_enabled_sms_numbers(user_sub)
    if not nums:
        raise HTTPException(400, "No SMS devices enrolled")

    if not verify_code_any_sms(nums, body.code.strip()):
        raise HTTPException(401, "Bad SMS code")

    mark_factor_passed(user_sub, body.challenge_id, "sms")
    sid = maybe_finalize(req, user_sub, body.challenge_id)
    return {"ok": True, "session_id": sid}


@app.post("/ui/mfa/email/begin")
async def ui_email_begin(req: Request, body: SmsBeginReq, user=Depends(get_authenticated_user_sub)):
    user_sub = user
    rate_limit_or_429(user_sub, "login_email")
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if "email" not in (chal.get("required_factors", []) or []):
        raise HTTPException(400, "Email not required for this login")

    emails = list_enabled_emails(user_sub)
    if not emails:
        raise HTTPException(400, "No email devices enrolled")

    if not can_send_verification(user_sub, "sms"):
        audit_event("verify_sms_rate_limited", user_sub, req, outcome="failure", status_code=429, reason="verify_sms_rate_limited")
        raise HTTPException(429, "Too many verification SMS; try again later")
    code = gen_numeric_code(6)
    code_hash = sha256_str(code)

    # store hash + recipients on the challenge
    T.sessions.update_item(
        Key={"user_sub": user_sub, "session_id": body.challenge_id},
        UpdateExpression="SET email_code_hash = :h, email_sent_to = :to, email_sent_at = :t",
        ExpressionAttributeValues={":h": code_hash, ":to": emails, ":t": now_ts()},
    )

    for e in emails:
        send_email_code(e, "login", code)

    return {"ok": True, "sent_to": emails}


@app.post("/ui/mfa/email/verify")
async def ui_email_verify(req: Request, body: EmailVerifyReq, user=Depends(get_authenticated_user_sub)):
    user_sub = user
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if "email" not in (chal.get("required_factors", []) or []):
        raise HTTPException(400, "Email not required for this login")

    expected = chal.get("email_code_hash")
    if not expected:
        raise HTTPException(400, "Email code not sent (call /ui/mfa/email/begin)")

    provided = sha256_str(body.code.strip())
    if provided != expected:
        raise HTTPException(401, "Bad email code")

    # Conditional + idempotent factor pass
    mark_factor_passed(user_sub, body.challenge_id, "email")

    sid = maybe_finalize(req, user_sub, body.challenge_id)
    return {"ok": True, "session_id": sid}


# ------------------------------------------------------------
# C) Recovery (satisfies factor for this login)
# ------------------------------------------------------------


@app.post("/ui/recovery/totp")
async def ui_recovery_totp(req: Request, body: RecoveryReq, user=Depends(get_authenticated_user_sub)):
    return await ui_recovery_factor(req, "totp", body, user)

@app.post("/ui/recovery/sms")
async def ui_recovery_sms(req: Request, body: RecoveryReq, user=Depends(get_authenticated_user_sub)):
    return await ui_recovery_factor(req, "sms", body, user)

@app.post("/ui/recovery/email")
async def ui_recovery_email(req: Request, body: RecoveryReq, user=Depends(get_authenticated_user_sub)):
    return await ui_recovery_factor(req, "email", body, user)


@app.post("/ui/recovery/{factor}")
async def ui_recovery_factor(
    req: Request,
    factor: str,
    body: RecoveryReq,
    user=Depends(get_authenticated_user_sub),
):
    if factor not in {"totp", "sms", "email"}:
        raise HTTPException(404, "Unknown factor")

    user_sub = user
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if factor not in (chal.get("required_factors", []) or []):
        raise HTTPException(400, f"{factor} not required for this login")

    consume_recovery_code(user_sub, factor, body.recovery_code)
    mark_factor_passed(user_sub, body.challenge_id, factor)
    sid = maybe_finalize(req, user_sub, body.challenge_id)
    return {"ok": True, "session_id": sid}


# ------------------------------------------------------------
# D) Post-login endpoints
# ------------------------------------------------------------

@app.get("/ui/me")
async def ui_me(req: Request, ctx=Depends(require_ui_session)):
    return {"user_sub": ctx["user_sub"], "session_id": ctx["session_id"], "ip": client_ip_from_request(req)}


@app.get("/ui/sessions")
async def ui_list_sessions(ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    cur = ctx["session_id"]


@app.get("/ui/api_keys")
async def ui_list_api_keys(ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    # Requires a GSI on api_keys table: API_KEYS_USER_INDEX (default: user_sub-index) with partition key 'user_sub'
    r = T.api_keys.query(
        IndexName=S.api_keys_user_index,
        KeyConditionExpression=Key("user_sub").eq(user_sub),
    )
    items = r.get("Items", [])
    keys = []
    for it in items:
        keys.append(
            {
                "key_id": it.get("key_id"),
                "label": it.get("label", ""),
                "created_at": it.get("created_at"),
                "last_used_at": it.get("last_used_at", 0),
                "revoked": bool(it.get("revoked", False)),
                "revoked_at": it.get("revoked_at"),
                "prefix": it.get("prefix", ""),
                "allow_cidrs": it.get("allow_cidrs", []),
                "deny_cidrs": it.get("deny_cidrs", []),
            }
        )
    keys.sort(key=lambda x: int(x.get("created_at") or 0), reverse=True)
    return {"keys": keys}


@app.get("/ui/alerts")
async def ui_list_alerts(
    ctx=Depends(require_ui_session),
    limit: int = 50,
    cursor: Optional[str] = None,
    unread_only: int = 0,
):
    user_sub = ctx["user_sub"]
    lim = max(1, min(int(limit or 50), 200))
    eks = decode_cursor(cursor)



@app.get("/ui/alerts/stream")
async def ui_alerts_stream(req: Request, ctx=Depends(require_ui_session)):
    """Distributed SSE stream.

    This implementation is multi-instance safe because it reads from DynamoDB rather than
    relying on in-memory pubsub. It keeps a long-lived connection open and periodically
    queries for new alerts for this user.

    Reconnect support: EventSource may send Last-Event-ID header; we use it as a cursor.
    """
    user_sub = ctx["user_sub"]
    last_id = req.headers.get("last-event-id") or None

    async def gen():
        yield "event: hello\ndata: {}\n\n"
        nonlocal last_id
        while True:
            if await req.is_disconnected():
                break
            try:
                # Pull newest alerts; small limit keeps it cheap.
                r = T.alerts.query(
                    KeyConditionExpression=Key("user_sub").eq(user_sub),
                    Limit=25,
                    ScanIndexForward=False,
                )
                items = r.get("Items", [])

                # Items are newest->oldest. We want to emit only those newer than last_id.
                # alert_id sorts by ts prefix; this is sufficient for "newer than" checks.
                to_send = []
                for it in items:
                    aid = it.get("alert_id")
                    if not aid:
                        continue
                    # Stop when we hit last_id in the list (everything after is older)
                    if last_id and aid == last_id:
                        break
                    to_send.append(it)

                # Send oldest-first among the new ones so UI sees them in order.
                for it in reversed(to_send):
                    aid = it.get("alert_id")
                    payload = {
                        "alert_id": aid,
                        "ts": it.get("ts"),
                        "event": it.get("event"),
                        "outcome": it.get("outcome", "info"),
                        "title": it.get("title", ""),
                        "details": it.get("details", {}),
                        "read": bool(it.get("read", False)),
                        "read_at": it.get("read_at", 0),
                        "toast_delivered": bool(it.get("toast_delivered", False)),
                    }
                    data = json.dumps(payload, separators=(",", ":"))
                    # SSE id enables Last-Event-ID on reconnect
                    yield f"id: {aid}\nevent: alert\ndata: {data}\n\n"
                    last_id = aid
            except Exception:
                # ignore transient DDB issues
                pass

            # heartbeat + pacing
            yield "event: ping\ndata: {}\n\n"
            await asyncio.sleep(3)

    return StreamingResponse(gen(), media_type="text/event-stream")



@app.get("/ui/alerts/types")
async def ui_alert_types(ctx=Depends(require_ui_session)):
    return {"types": ALERT_EVENT_TYPES}


@app.get("/ui/ws_token")
async def ui_ws_token(ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    return {"token": mint_ws_token(user_sub, ttl_seconds=60)}



@app.get("/ui/alerts/email_prefs")
async def ui_get_email_prefs(ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    return get_alert_prefs(user_sub)


@app.get("/ui/push/devices")
async def ui_list_push_devices(ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    return {"devices": list_push_devices(user_sub)}


class PushRegisterReq(BaseModel):
    token: str
    platform: str  # "web_fcm", "android_fcm", "ios_fcm"


@app.post("/ui/push/register")
async def ui_register_push(req: Request, body: PushRegisterReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    if not S.push_enabled:
        raise HTTPException(400, "Push disabled")
    token = (body.token or "").strip()
    if len(token) < 20:
        raise HTTPException(400, "Bad token")
    platform = (body.platform or "").strip()[:32]
    it = upsert_push_device(user_sub, token, platform)
    audit_event("push_device_register", user_sub, req, outcome="success", platform=platform)
    return it


class PushRevokeReq(BaseModel):
    device_id: str


@app.post("/ui/push/revoke")
async def ui_revoke_push(req: Request, body: PushRevokeReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    revoke_push_device(user_sub, body.device_id)
    audit_event("push_device_revoke", user_sub, req, outcome="success", device_id=body.device_id)
    return {"ok": True}


class AlertPushPrefsReq(BaseModel):
    push_event_types: List[str]


@app.post("/ui/alerts/push_prefs")
async def ui_set_push_prefs(body: AlertPushPrefsReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    prefs = set_alert_prefs(user_sub, push_event_types=body.push_event_types)
    audit_event("alerts_push_prefs_set", user_sub, None, outcome="success", enabled=len(prefs.get("push_event_types") or []))
    return prefs


@app.post("/ui/push/test")
async def ui_push_test(req: Request, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    # sends a test notification to all registered devices if push prefs include "security_event"
    send_push_for_alert(user_sub, "security_event", "Test notification", "This is a test push.", "test")
    audit_event("push_test", user_sub, req, outcome="success")
    return {"ok": True}



class AlertEmailPrefsReq(BaseModel):
    email_event_types: List[str]


@app.post("/ui/alerts/email_prefs")
async def ui_set_email_prefs(body: AlertEmailPrefsReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    prefs = set_alert_prefs(user_sub, email_event_types=body.email_event_types)
    audit_event("alerts_email_prefs_set", user_sub, None, outcome="success", enabled=len(prefs.get("email_event_types") or []))
    return prefs


class AlertEmailBeginReq(BaseModel):
    email: str


class AlertSmsPrefsReq(BaseModel):
    sms_event_types: List[str]


@app.post("/ui/alerts/sms_prefs")
async def ui_set_sms_prefs(body: AlertSmsPrefsReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    prefs = set_alert_prefs(user_sub, sms_event_types=body.sms_event_types)
    audit_event("alerts_sms_prefs_set", user_sub, None, outcome="success", enabled=len(prefs.get("sms_event_types") or []))
    return prefs


class AlertSmsBeginReq(BaseModel):
    phone: str


class AlertToastPrefsReq(BaseModel):
    toast_event_types: List[str]


@app.post("/ui/alerts/toast_prefs")
async def ui_set_toast_prefs(body: AlertToastPrefsReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    prefs = set_alert_prefs(user_sub, toast_event_types=body.toast_event_types)
    audit_event("alerts_toast_prefs_set", user_sub, None, outcome="success", enabled=len(prefs.get("toast_event_types") or []))
    return prefs


class AlertsMarkToastDeliveredReq(BaseModel):
    alert_ids: List[str]


@app.post("/ui/alerts/mark_toast_delivered")
async def ui_mark_toast_delivered(body: AlertsMarkToastDeliveredReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    n = 0
    for aid in body.alert_ids[:200]:
        try:
            T.alerts.update_item(
                Key={"user_sub": user_sub, "alert_id": aid},
                UpdateExpression="SET toast_delivered = :t, toast_delivered_at = :now",
                ExpressionAttributeValues={":t": True, ":now": now_ts()},
            )
            n += 1
        except Exception:
            pass
    return {"ok": True, "updated": n}



class AlertSmsConfirmReq(BaseModel):
    challenge_id: str
    code: str


@app.post("/ui/alerts/sms/begin")
async def ui_alert_sms_add_begin(req: Request, body: AlertSmsBeginReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    try:
        phone = normalize_phone(body.phone)
    except Exception as e:
        raise HTTPException(400, f"Bad phone: {e}")
    code = gen_numeric_code(6)
    code_hash = sha256_str(code)
    chal = create_action_challenge(
        req,
        user_sub=user_sub,
        purpose="alert_sms_add",
        send_to=[phone],
        payload={"sms_code_hash": code_hash, "phone": phone},
        ttl_seconds=600,
    )
    # send via SNS
    send_alert_sms([phone], f"Your confirmation code is: {code}")
    audit_event("alerts_sms_add_begin", user_sub, req, outcome="success", phone=phone)
    return {"challenge_id": chal, "sent_to": phone}


@app.post("/ui/alerts/sms/confirm")
async def ui_alert_sms_add_confirm(req: Request, body: AlertSmsConfirmReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    chal = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": body.challenge_id}).get("Item")
    if not chal or chal.get("revoked", False) or chal.get("purpose") != "alert_sms_add":
        audit_event("alerts_sms_add_confirm", user_sub, req, outcome="failure", reason="bad_challenge")
        raise HTTPException(400, "Bad challenge")
    if now_ts() > int(chal.get("expires_at", 0)):
        audit_event("alerts_sms_add_confirm", user_sub, req, outcome="failure", reason="expired")
        raise HTTPException(400, "Challenge expired")
    enforce_sms_attempt_budget(user_sub, body.challenge_id)
    if sha256_str(body.code.strip()) != chal.get("sms_code_hash"):
        audit_event("alerts_sms_add_confirm", user_sub, req, outcome="failure", reason="bad_code")
        raise HTTPException(401, "Bad SMS code")
    phone = chal.get("phone")
    prefs = get_alert_prefs(user_sub)
    nums = prefs.get("sms_numbers") or []
    if phone not in nums:
        nums.append(phone)
    prefs2 = set_alert_prefs(user_sub, sms_numbers=nums)
    revoke_challenge(user_sub, body.challenge_id)
    audit_event("alerts_sms_add_confirm", user_sub, req, outcome="success", phone=phone)
    return prefs2


class AlertSmsRemoveReq(BaseModel):
    phone: str


@app.post("/ui/alerts/sms/remove")
async def ui_alert_sms_remove(req: Request, body: AlertSmsRemoveReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    try:
        phone = normalize_phone(body.phone)
    except Exception as e:
        raise HTTPException(400, f"Bad phone: {e}")
    prefs = get_alert_prefs(user_sub)
    nums = [n for n in (prefs.get("sms_numbers") or []) if n != phone]
    prefs2 = set_alert_prefs(user_sub, sms_numbers=nums)
    audit_event("alerts_sms_remove", user_sub, req, outcome="success", phone=phone)
    return prefs2



class AlertEmailConfirmReq(BaseModel):
    challenge_id: str
    code: str


@app.post("/ui/alerts/emails/begin")
async def ui_alert_email_add_begin(req: Request, body: AlertEmailBeginReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    email = normalize_email(body.email)
    if not can_send_verification(user_sub, "email"):
        audit_event("verify_email_rate_limited", user_sub, req, outcome="failure", status_code=429, reason="verify_email_rate_limited")
        raise HTTPException(429, "Too many verification emails; try again later")
    # send code via SES to that email
    code = gen_numeric_code(6)
    code_hash = sha256_str(code)
    chal = create_action_challenge(
        req,
        user_sub=user_sub,
        purpose="alert_email_add",
        send_to=[email],
        payload={"email_code_hash": code_hash, "email": email},
        ttl_seconds=600,
    )
    send_alert_email([email], "Confirm alerts email", f"Your confirmation code is: {code}\n\nIf you didn't request this, ignore.")
    audit_event("alerts_email_add_begin", user_sub, req, outcome="success", email=email)
    return {"challenge_id": chal, "sent_to": email}


@app.post("/ui/alerts/emails/confirm")
async def ui_alert_email_add_confirm(req: Request, body: AlertEmailConfirmReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    chal = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": body.challenge_id}).get("Item")
    if not chal or chal.get("revoked", False) or chal.get("purpose") != "alert_email_add":
        audit_event("alerts_email_add_confirm", user_sub, req, outcome="failure", reason="bad_challenge")
        raise HTTPException(400, "Bad challenge")
    if now_ts() > int(chal.get("expires_at", 0)):
        audit_event("alerts_email_add_confirm", user_sub, req, outcome="failure", reason="expired")
        raise HTTPException(400, "Challenge expired")
    # attempt budget reuse email attempt helper
    enforce_email_attempt_budget(user_sub, body.challenge_id)
    if sha256_str(body.code.strip()) != chal.get("email_code_hash"):
        audit_event("alerts_email_add_confirm", user_sub, req, outcome="failure", reason="bad_code")
        raise HTTPException(401, "Bad email code")
    email = chal.get("email")
    prefs = get_alert_prefs(user_sub)
    emails = prefs.get("emails") or []
    if email not in emails:
        emails.append(email)
    prefs2 = set_alert_prefs(user_sub, emails=emails)
    revoke_challenge(user_sub, body.challenge_id)
    audit_event("alerts_email_add_confirm", user_sub, req, outcome="success", email=email)
    return prefs2


class AlertEmailRemoveReq(BaseModel):
    email: str


@app.post("/ui/alerts/emails/remove")
async def ui_alert_email_remove(req: Request, body: AlertEmailRemoveReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    email = normalize_email(body.email)
    prefs = get_alert_prefs(user_sub)
    emails = [e for e in (prefs.get("emails") or []) if e != email]
    prefs2 = set_alert_prefs(user_sub, emails=emails)
    audit_event("alerts_email_remove", user_sub, req, outcome="success", email=email)
    return prefs2


    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("user_sub").eq(user_sub),
        "Limit": lim,
        "ScanIndexForward": False,
    }
    if eks:
        kwargs["ExclusiveStartKey"] = eks

    r = T.alerts.query(**kwargs)
    items = r.get("Items", [])

    # unread_only filtering is done client-side unless you add a GSI; keep simple for now
    if unread_only:
        items = [it for it in items if not it.get("read", False)]

    alerts = []
    for it in items:
        alerts.append(
            {
                "alert_id": it.get("alert_id"),
                "ts": it.get("ts"),
                "event": it.get("event"),
                "outcome": it.get("outcome", "info"),
                "title": it.get("title", ""),
                "details": it.get("details", {}),
                "read": bool(it.get("read", False)),
                "read_at": it.get("read_at", 0),
                "toast_delivered": bool(it.get("toast_delivered", False)),
            }
        )

    next_cursor = encode_cursor(r.get("LastEvaluatedKey"))
    return {"alerts": alerts, "next_cursor": next_cursor}


class AlertsMarkReadReq(BaseModel):
    alert_ids: List[str]


@app.post("/ui/alerts/mark_read")
async def ui_mark_alerts_read(body: AlertsMarkReadReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    now = now_ts()
    n = 0
    for aid in body.alert_ids[:200]:
        try:
            T.alerts.update_item(
                Key={"user_sub": user_sub, "alert_id": aid},
                UpdateExpression="SET #r=:t, read_at=:now",
                ExpressionAttributeNames={"#r": "read"},
                ExpressionAttributeValues={":t": True, ":now": now},
            )
            n += 1
        except Exception:
            pass
    return {"ok": True, "updated": n}



@app.post("/ui/api_keys")
async def ui_create_api_key(req: Request, body: ApiKeyCreateReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    key_id = uuid.uuid4().hex
    secret = new_api_key_secret()
    created = now_ts()
    item = {
        "key_id": key_id,
        "user_sub": user_sub,
        "label": body.label or "",
        "created_at": created,
        "last_used_at": 0,
        "revoked": False,
        "prefix": f"ak_{key_id[:8]}",
        "secret_hash": api_key_hash(secret),
        "allow_cidrs": [],
        "deny_cidrs": [],
    }
    T.api_keys.put_item(Item=item)
    audit_event("api_key_create", user_sub, req, outcome="success", key_id=key_id)
    return {"key_id": key_id, "api_key": f"ak_{key_id}.{secret}"}


@app.post("/ui/api_keys/revoke")
async def ui_revoke_api_key(body: ApiKeyRevokeReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    key_id = body.key_id
    try:
        T.api_keys.update_item(
            Key={"key_id": key_id},
            UpdateExpression="SET revoked=:t, revoked_at=:now",
            ExpressionAttributeValues={":t": True, ":now": now_ts(), ":u": user_sub},
            ConditionExpression="user_sub = :u",
        )
    except Exception:
        raise HTTPException(404, "API key not found")
    audit_event("api_key_revoke", user_sub, None, outcome="success", key_id=key_id)
    return {"ok": True}


    r = T.sessions.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    items = r.get("Items", [])


@app.post("/ui/api_keys/ip_rules")
async def ui_set_api_key_ip_rules(body: ApiKeyIpRulesReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    key_id = body.key_id

    # normalize + validate
    allow = []
    deny = []
    try:
        allow = [normalize_cidr(x) for x in body.allow_cidrs if (x or "").strip()]
        deny = [normalize_cidr(x) for x in body.deny_cidrs if (x or "").strip()]
    except Exception as e:
        raise HTTPException(400, f"Bad CIDR/IP: {e}")

    # Store lists (overwrite)
    try:
        T.api_keys.update_item(
            Key={"key_id": key_id},
            UpdateExpression="SET allow_cidrs=:a, deny_cidrs=:d, updated_at=:now",
            ExpressionAttributeValues={":a": allow, ":d": deny, ":now": now_ts(), ":u": user_sub},
            ConditionExpression="user_sub = :u",
        )
    except Exception:
        raise HTTPException(404, "API key not found")

    audit_event("api_key_ip_rules_set", user_sub, None, outcome="success", key_id=key_id, allow=len(allow), deny=len(deny))
    return {"ok": True, "allow_cidrs": allow, "deny_cidrs": deny}


    sessions = []
    for it in items:
        sid = it.get("session_id", "")
        if not sid or not is_real_ui_session_id(sid):
            continue
        if it.get("pending_auth", False):
            continue
        sessions.append(
            {
                "session_id": sid,
                "is_current": sid == cur,
                "created_at": it.get("created_at"),
                "last_seen_at": it.get("last_seen_at"),
                "ip": it.get("ip"),
                "user_agent": it.get("user_agent"),
                "revoked": bool(it.get("revoked", False)),
                "revoked_at": it.get("revoked_at"),
            }
        )

    # newest first
    sessions.sort(key=lambda x: int(x.get("created_at") or 0), reverse=True)
    return {"sessions": sessions}


@app.post("/ui/sessions/revoke")
async def ui_revoke_session(body: SessionRevokeReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    sid = body.session_id
    if not is_real_ui_session_id(sid):
        raise HTTPException(400, "Not a revocable session id")

    try:
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": sid},
            UpdateExpression="SET revoked = :t, revoked_at = :now, #ttl = :ttl",
            ExpressionAttributeNames={"#ttl": S.ddb_ttl_attr},
            ExpressionAttributeValues={":t": True, ":now": now_ts(), ":ttl": now_ts() + 3600, ":p": False},
            ConditionExpression="attribute_exists(session_id) AND pending_auth = :p"
        )
    except TypeError:
        # boto3 doesn't support ExpressionAttributeValuesAdditional; do proper call below
        pass


@app.post("/ui/sessions/revoke_others")
async def ui_revoke_other_sessions(ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    cur = ctx["session_id"]
    r = T.sessions.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    items = r.get("Items", [])
    now = now_ts()
    revoked = 0
    for it in items:
        sid = it.get("session_id", "")
        if not sid or sid == cur:
            continue
        if not is_real_ui_session_id(sid):
            continue
        if it.get("revoked", False):
            continue
        if it.get("pending_auth", False):
            continue
        try:
            T.sessions.update_item(
                Key={"user_sub": user_sub, "session_id": sid},
                UpdateExpression="SET revoked = :t, revoked_at = :now, #ttl = :ttl",
                ExpressionAttributeNames={"#ttl": S.ddb_ttl_attr},
                ExpressionAttributeValues={":t": True, ":now": now, ":ttl": now + 3600, ":p": False},
                ConditionExpression="pending_auth = :p",
            )
            revoked += 1
        except Exception:
            pass
    audit_event("ui_session_revoke_others", user_sub, None, outcome="success", revoked=revoked)
    return {"ok": True, "revoked": revoked}


    audit_event("ui_session_revoke", user_sub, None, outcome="success", session_id=sid)
    return {"ok": True}



# ------------------------------------------------------------
# E) TOTP device management
# ------------------------------------------------------------

@app.get("/ui/mfa/totp/devices")
async def ui_totp_devices(ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    r = T.totp.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    items = r.get("Items", [])
    for it in items:
        it.pop("secret_ct_b64", None)
    return {"devices": items}


@app.post("/ui/mfa/totp/devices/begin", response_model=TotpBeginResp)
async def ui_totp_begin(req: Request, body: TotpBeginReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    device_id = "totp_" + uuid.uuid4().hex
    secret_b32 = pyotp.random_base32()
    ts = now_ts()

    T.totp.put_item(
        Item={
            "user_sub": user_sub,
            "device_id": device_id,
            "label": body.label or "",
            "secret_ct_b64": kms_encrypt(secret_b32),
            "enabled": False,
            "created_at": ts,
            "last_used_at": 0,
        }
    )

    # If this is the first enabled TOTP device, generate recovery codes.
    r = T.totp.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    enabled_count = sum(1 for d in r.get("Items", []) if d.get("enabled", False))
    codes: List[str] = []
    if enabled_count == 0:
        codes = new_recovery_codes(10)
        store_recovery_codes(user_sub, "totp", codes)

    otpauth_uri = pyotp.totp.TOTP(secret_b32).provisioning_uri(name=user_sub, issuer_name="YourApp")
    return TotpBeginResp(device_id=device_id, otpauth_uri=otpauth_uri, recovery_codes=codes)


@app.post("/ui/mfa/totp/devices/confirm")
async def ui_totp_confirm(body: TotpConfirmReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    it = T.totp.get_item(Key={"user_sub": user_sub, "device_id": body.device_id}).get("Item")
    if not it:
        raise HTTPException(404, "Device not found")

    secret_b32 = kms_decrypt(it["secret_ct_b64"]).decode("utf-8")
    if not pyotp.TOTP(secret_b32).verify(body.totp_code.strip(), valid_window=1):
        raise HTTPException(401, "Bad TOTP")

    T.totp.update_item(
        Key={"user_sub": user_sub, "device_id": body.device_id},
        UpdateExpression="SET enabled = :t",
        ExpressionAttributeValues={":t": True},
    )
    return {"ok": True}


@app.post("/ui/mfa/totp/devices/{device_id}/remove")
async def ui_totp_remove(device_id: str, body: TotpRemoveReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    if not totp_verify_any_enabled(user_sub, body.totp_code):
        raise HTTPException(401, "Bad TOTP")
    T.totp.delete_item(Key={"user_sub": user_sub, "device_id": device_id})
    return {"ok": True}


# ------------------------------------------------------------
# F) SMS device management (enroll/remove)
# ------------------------------------------------------------

@app.get("/ui/mfa/sms/devices")
async def ui_sms_devices(ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    r = T.sms.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    return {"devices": r.get("Items", [])}


@app.post("/ui/mfa/sms/devices/begin")
async def ui_sms_enroll_begin(req: Request, body: SmsEnrollBeginReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    rate_limit_or_429(user_sub, "enroll_sms")
    phone = normalize_e164(body.phone_e164)

    r = T.sms.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    existing = r.get("Items", [])
    enabled_or_pending = [d for d in existing if d.get("enabled", False) or d.get("pending", False)]
    if len(enabled_or_pending) >= S.sms_device_limit:
        raise HTTPException(400, f"SMS device limit reached ({S.sms_device_limit})")

    sms_device_id = "sms_" + uuid.uuid4().hex
    ts = now_ts()
    T.sms.put_item(
        Item={
            "user_sub": user_sub,
            "sms_device_id": sms_device_id,
            "phone_e164": phone,
            "label": body.label or "",
            "enabled": False,
            "pending": True,
            "created_at": ts,
            "last_used_at": 0,
        }
    )

    send_to = list(dict.fromkeys(list_enabled_sms_numbers(user_sub) + [phone]))
    for n in send_to:
        twilio_start_sms(n)

    challenge_id = create_action_challenge(
        req,
        user_sub,
        purpose="sms_enroll",
        send_to=send_to,
        payload={"sms_device_id": sms_device_id},
    )
    return {"challenge_id": challenge_id, "sent_to": send_to, "sms_device_id": sms_device_id}


@app.post("/ui/mfa/sms/devices/confirm")
async def ui_sms_enroll_confirm(req: Request, body: SmsEnrollConfirmReq, ctx=Depends(require_ui_session)):
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
        ExpressionAttributeValues={":t": True, ":f": False, ":p": True},
        ConditionExpression="pending = :p",
    )

    r = T.sms.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    enabled_count = sum(1 for d in r.get("Items", []) if d.get("enabled", False))
    recovery_codes: List[str] = []
    if enabled_count == 1:
        recovery_codes = new_recovery_codes(10)
        store_recovery_codes(user_sub, "sms", recovery_codes)

    revoke_challenge(user_sub, body.challenge_id)
    return {"ok": True, "sms_device_id": sms_device_id, "recovery_codes": recovery_codes}


@app.post("/ui/mfa/sms/devices/{sms_device_id}/remove/begin", response_model=SmsRemoveBeginResp)
async def ui_sms_remove_begin(req: Request, sms_device_id: str, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]    rate_limit_or_429(user_sub, "remove_sms")


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
        user_sub,
        purpose="sms_remove",
        send_to=send_to,
        payload={"sms_device_id": sms_device_id},
    )
    return SmsRemoveBeginResp(challenge_id=challenge_id, sent_to=send_to)


@app.post("/ui/mfa/sms/devices/remove/confirm")
async def ui_sms_remove_confirm(req: Request, body: SmsRemoveConfirmReq, ctx=Depends(require_ui_session)):
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
    return {"ok": True}


# ------------------------------------------------------------
# G) Email device management (enroll/remove) + device listing
# ------------------------------------------------------------

@app.get("/ui/mfa/email/devices")
async def ui_email_devices(ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    r = T.email.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    return {"devices": r.get("Items", [])}


@app.post("/ui/mfa/email/devices/begin")
async def ui_email_enroll_begin(req: Request, body: EmailEnrollBeginReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    rate_limit_or_429(user_sub, "enroll_email")
    email = normalize_email(body.email)

    r = T.email.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    existing = r.get("Items", [])
    enabled_or_pending = [d for d in existing if d.get("enabled", False) or d.get("pending", False)]
    if len(enabled_or_pending) >= S.email_device_limit:
        raise HTTPException(400, f"Email device limit reached ({S.email_device_limit})")

    email_device_id = "em_" + uuid.uuid4().hex
    ts = now_ts()
    T.email.put_item(
        Item={
            "user_sub": user_sub,
            "email_device_id": email_device_id,
            "email": email,
            "label": body.label or "",
            "enabled": False,
            "pending": True,
            "created_at": ts,
            "last_used_at": 0,
        }
    )

    enabled_emails = [d["email"] for d in existing if d.get("enabled", False)]
    send_to = list(dict.fromkeys(enabled_emails + [email]))

    code = gen_numeric_code(6)
    code_hash = sha256_str(code)

    challenge_id = create_action_challenge(
        req,
        user_sub,
        purpose="email_enroll",
        send_to=send_to,
        payload={"email_device_id": email_device_id, "email_code_hash": code_hash},
    )

    for e in send_to:
        send_email_code(e, "add-email", code)

    return {"challenge_id": challenge_id, "sent_to": send_to, "email_device_id": email_device_id}


@app.post("/ui/mfa/email/devices/confirm")
async def ui_email_enroll_confirm(req: Request, body: EmailEnrollConfirmReq, ctx=Depends(require_ui_session)):
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
    return {"ok": True, "email_device_id": email_device_id, "recovery_codes": recovery_codes}


@app.post("/ui/mfa/email/devices/{email_device_id}/remove/begin")
async def ui_email_remove_begin(req: Request, email_device_id: str, ctx=Depends(require_ui_session)):
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
        user_sub,
        purpose="email_remove",
        send_to=send_to,
        payload={"email_device_id": email_device_id, "email_code_hash": code_hash},
    )

    for e in send_to:
        send_email_code(e, "remove-email", code)

    return {"challenge_id": challenge_id, "sent_to": send_to}


@app.post("/ui/mfa/email/devices/remove/confirm")
async def ui_email_remove_confirm(req: Request, body: EmailRemoveConfirmReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if chal.get("purpose") != "email_remove":
        raise HTTPException(400, "Wrong challenge purpose")

    if sha256_str(body.code.strip()) != chal.get("email_code_hash"):
        raise HTTPException(401, "Bad email code")

    email_device_id = chal["email_device_id"]
    T.email.delete_item(Key={"user_sub": user_sub, "email_device_id": email_device_id})
    revoke_challenge(user_sub, body.challenge_id)
    return {"ok": True}
class SessionRevokeAllOthersReq(BaseModel):
    # empty for now; reserved
    pass


class ApiKeyCreateReq(BaseModel):
    label: Optional[str] = None



class ApiKeyIpRulesReq(BaseModel):
    key_id: str
    allow_cidrs: List[str] = []
    deny_cidrs: List[str] = []

class ApiKeyRevokeReq(BaseModel):
    key_id: str


def require_api_key(x_api_key: Optional[str] = Header(default=None, alias="X-API-KEY")) -> str:
    if not x_api_key:
        raise HTTPException(401, "Missing X-API-KEY")
    parts = parse_api_key(x_api_key)
    key_id = parts["key_id"]
    secret = parts["secret"]
    it = T.api_keys.get_item(Key={"key_id": key_id}).get("Item")
    if not it or it.get("revoked", False):
        raise HTTPException(401, "Invalid API key")
    enforce_api_key_ip_rules(req, it)
    if api_key_hash(secret) != it.get("secret_hash"):
        raise HTTPException(401, "Invalid API key")
    req.state.user_sub = str(it.get("user_sub"))
    req.state.auth_kind = "api_key"
    # touch last_used_at (best-effort)
    try:
        T.api_keys.update_item(
            Key={"key_id": key_id},
            UpdateExpression="SET last_used_at = :now",
            ExpressionAttributeValues={":now": now_ts()},
        )
    except Exception:
        pass
    return {"alert_id": alert_id, "ts": ts}
    return str(it.get("user_sub"))





@app.get("/api/ping")
async def api_ping(user_sub=Depends(require_api_key)):
    return {"ok": True, "user_sub": user_sub}

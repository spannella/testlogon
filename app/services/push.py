from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import time
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.rate_limit import can_send_alert_channel
from app.services.ttl import with_ttl


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


_HAS_REQUESTS = importlib.util.find_spec("requests") is not None
_HAS_CRYPTO = importlib.util.find_spec("cryptography") is not None


def fcm_access_token() -> Optional[str]:
    if not S.fcm_enabled:
        return None
    if not (S.fcm_project_id and S.fcm_client_email and S.fcm_private_key):
        return None
    if not (_HAS_REQUESTS and _HAS_CRYPTO):
        return None

    try:
        import requests
        import cryptography.hazmat.primitives.serialization as serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        key_pem = S.fcm_private_key.replace("\\n", "\n").encode("utf-8")
        key = serialization.load_pem_private_key(key_pem, password=None)
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "iss": S.fcm_client_email,
            "scope": "https://www.googleapis.com/auth/firebase.messaging",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + 3600,
        }
        signing_input = f"{_b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))}.{_b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))}"
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
    if not _HAS_REQUESTS:
        return False
    import requests
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
    ttl = now + 60 * 60 * 24 * 180
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


def send_push_for_alert(user_sub: str, alert_type: str, title: str, body: str, alert_id: str) -> None:
    if not S.push_enabled:
        return
    from app.services.alerts import get_alert_prefs
    prefs = get_alert_prefs(user_sub)
    enabled = set(prefs.get("push_event_types") or [])
    if alert_type not in enabled:
        return
    if not can_send_alert_channel(user_sub, "push"):
        return
    try:
        r = T.push_devices.query(KeyConditionExpression=Key("user_sub").eq(user_sub), Limit=200)
        items = r.get("Items", [])
        for it in items[:25]:
            tok = it.get("token")
            if not tok:
                continue
            fcm_send(tok, title, body, data={"alert_id": alert_id, "alert_type": alert_type})
    except Exception:
        pass

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import logging
import time
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.rate_limit import can_send_alert_channel
from app.services.ttl import with_ttl

logger = logging.getLogger(__name__)


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
        header_json = json.dumps(header, separators=(",", ":")).encode("utf-8")
        payload_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signing_input = f"{_b64url(header_json)}.{_b64url(payload_json)}"
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


# ── Web Push delivery (PLATFORM-010) ────────────────────────────────────────


def web_push_send(
    subscription_json: str,
    title: str,
    body: str,
    url: str = "/",
    tag: str = "default",
    alert_id: str = "",
    alert_type: str = "",
) -> bool:
    """Send push via Web Push protocol (RFC 8030 + RFC 8291).

    Uses the pywebpush library for encryption and VAPID signing.

    In dev mode, logs the push payload instead of delivering (push
    services won't work with localhost).

    Returns True if push was accepted (or logged in dev mode), False otherwise.
    """
    if not (S.vapid_private_key and S.vapid_public_key):
        logger.debug("Web push skipped: VAPID keys not configured")
        return False

    # Parse subscription JSON
    try:
        subscription = json.loads(subscription_json)
        endpoint = subscription.get("endpoint", "")
        keys = subscription.get("keys", {})
        p256dh = keys.get("p256dh", "")
        auth = keys.get("auth", "")

        if not (endpoint and p256dh and auth):
            logger.warning("Web push: invalid subscription (missing fields)")
            return False
    except (json.JSONDecodeError, AttributeError, TypeError):
        logger.warning("Web push: invalid subscription JSON")
        return False

    # Build payload
    payload = json.dumps({
        "title": title[:60],
        "body": body[:180],
        "url": url,
        "tag": tag,
        "alert_id": alert_id,
        "alert_type": alert_type,
        "timestamp": now_ts(),
    })

    # In dev mode, log the payload instead of delivering
    # (push service endpoints won't work with localhost)
    if S.dev_mode:
        logger.info(
            "Web push (dev mode, not delivered): endpoint=%s, payload=%s",
            endpoint[:80],
            payload,
        )
        return True

    # Send using pywebpush
    try:
        from pywebpush import webpush, WebPushException  # noqa: F401

        vapid_claims = {
            "sub": S.vapid_subject or "mailto:admin@testlogon.local",
        }
        vapid_private_key = S.vapid_private_key.replace("\\n", "\n")

        response = webpush(
            subscription_info=subscription,
            data=payload,
            vapid_private_key=vapid_private_key,
            vapid_claims=vapid_claims,
            timeout=10,
        )
        status = response.status_code if hasattr(response, "status_code") else 201
        if status in (200, 201, 202):
            logger.info("Web push sent: endpoint=%s", endpoint[:80])
            return True
        else:
            logger.warning("Web push failed: status=%s, endpoint=%s", status, endpoint[:80])
            return False

    except Exception as exc:
        exc_str = str(exc)
        # 410 Gone = subscription expired
        if "410" in exc_str or "Gone" in exc_str:
            logger.info("Web push subscription expired (410): endpoint=%s", endpoint[:80])
            return False  # Caller should revoke device
        # 404 Not Found = subscription invalid
        if "404" in exc_str:
            logger.info("Web push subscription not found (404): endpoint=%s", endpoint[:80])
            return False
        logger.exception("Web push send error: endpoint=%s", endpoint[:80])
        return False


def _alert_url(alert_type: str, alert_id: str) -> str:
    """Map alert type to a specific app URL for notification click."""
    type_urls = {
        "new_message": "/messages",
        "messaging.new_message": "/messages",
        "post_tip": "/billing",
        "message_tip": "/messages",
        "billing.tip_received": "/billing",
        "payment_received": "/billing",
        "subscription_started": "/billing",
        "refund_processed": "/billing",
        "security_event": "/alerts",
        "login_failure": "/alerts",
        "mfa_failure": "/alerts",
        "access_denied": "/alerts",
        "device_new": "/alerts",
        "device_location_mismatch": "/alerts",
        "rate_limited": "/alerts",
    }
    return type_urls.get(alert_type, "/alerts")


def send_push_for_alert(user_sub: str, alert_type: str, title: str, body: str, alert_id: str) -> None:
    """Send push notification for an alert to all user's devices.

    Dispatches to web_push_send() for web devices and fcm_send() for
    native mobile devices. Stale web subscriptions (410 Gone) are
    auto-revoked.
    """
    if not S.push_enabled:
        return
    from app.services.alerts import get_alert_prefs
    prefs = get_alert_prefs(user_sub)
    enabled = set(prefs.get("push_event_types") or [])
    if alert_type not in enabled:
        return
    if not can_send_alert_channel(user_sub, "push"):
        return

    # Build type-specific URL for notification click target
    url = _alert_url(alert_type, alert_id)

    try:
        r = T.push_devices.query(KeyConditionExpression=Key("user_sub").eq(user_sub), Limit=200)
        items = r.get("Items", [])

        for it in items[:25]:
            tok = it.get("token", "")
            device_id = it.get("device_id", "")
            platform = it.get("platform", "")

            if not tok:
                continue

            if platform == "web" and S.web_push_enabled:
                success = web_push_send(
                    tok, title, body,
                    url=url,
                    tag=alert_type,
                    alert_id=alert_id,
                    alert_type=alert_type,
                )
                if not success and not S.dev_mode:
                    # Check if subscription is likely expired -- attempt revoke
                    try:
                        sub = json.loads(tok)
                        if "endpoint" in sub:
                            revoke_push_device(user_sub, device_id)
                            logger.info(
                                "Auto-revoked stale push device: user=%s, device=%s",
                                user_sub, device_id,
                            )
                    except (json.JSONDecodeError, TypeError):
                        # Placeholder token -- ignore
                        pass

            elif platform != "web" and S.fcm_enabled:
                fcm_send(
                    tok, title, body,
                    data={"alert_id": alert_id, "alert_type": alert_type},
                )

    except Exception:
        logger.exception("Push delivery error: user=%s, alert_type=%s", user_sub, alert_type)

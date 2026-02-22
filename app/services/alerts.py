from __future__ import annotations

import asyncio
import json
import uuid
import hashlib
import hmac
import logging
import requests
import time
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional, Set, Tuple

from boto3.dynamodb.conditions import Key

from app.core.aws import sns_client
from app.core.normalize import normalize_email, normalize_phone, client_ip_from_request
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.metrics import record_auth_event
from app.services.rate_limit import can_send_alert_channel
from app.services.profile import get_profile_identity
from app.services.push import send_push_for_alert
from app.services.ttl import with_ttl

# Events that are too high-frequency or low-importance to persist as user-visible alerts.
# They still flow through metrics and SIEM; they just never appear in the alert centre.
_NO_ALERT_EVENTS: frozenset = frozenset({
    # Presence / heartbeat — fires on every active client poll
    "messaging_presence_heartbeat_processed",
    # Routine in-app messaging activity (not security-relevant)
    "messaging_message_viewed",
    "messaging_conversation_read",
    "messaging_message_reaction",
    # Session lifecycle churn — fires on every page load / token refresh
    "ui_session_start",
    "ui_session_refresh",
    # Granular file-browser activity
    "filemgr_file_previewed",
    "filemgr_preview_hover_play_start",
    "filemgr_preview_hover_play_failure",
    "filemgr_client_remembered_password_used",
})

ALERT_EVENT_TYPES: List[str] = [
    "login_success","login_failure","mfa_success","mfa_failure","challenge_created","challenge_revoked",
    "challenge_failed","api_key_created","api_key_revoked","api_key_ip_rules_updated","session_revoked",
    "totp_device_added","totp_device_removed","rate_limited","access_denied","security_event",
    "device_new","device_location_mismatch","device_trust","device_revoke",
    "calendar_event_created","calendar_event_updated","calendar_event_deleted",
]

# In-memory pubsub for SSE (single-process). For multi-process, swap with Redis/SQS/etc.
_SSE_SUBSCRIBERS: Dict[str, Set[asyncio.Queue]] = {}
logger = logging.getLogger(__name__)

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
    if e == "calendar_event_create":
        return "calendar_event_created"
    if e == "calendar_event_update":
        return "calendar_event_updated"
    if e == "calendar_event_delete":
        return "calendar_event_deleted"
    if e.startswith("ui_rate_limited") or (status_code == 429):
        return "rate_limited"
    if status_code in (401, 403):
        return "access_denied"
    return "security_event"

def get_alert_prefs(user_sub: str) -> Dict[str, Any]:
    it = T.alert_prefs.get_item(Key={"user_sub": user_sub}).get("Item")
    if not it:
        return {
            "emails": [], "sms_numbers": [],
            "email_event_types": [], "sms_event_types": [],
            "toast_event_types": [], "push_event_types": [],
            "webhook_urls": [], "webhook_event_types": [],
        }
    return {
        "emails": it.get("emails", []),
        "sms_numbers": it.get("sms_numbers", []),
        "email_event_types": it.get("email_event_types", []),
        "sms_event_types": it.get("sms_event_types", []),
        "toast_event_types": it.get("toast_event_types", []),
        "push_event_types": it.get("push_event_types", []),
        "webhook_urls": it.get("webhook_urls", []),
        "webhook_event_types": it.get("webhook_event_types", []),
    }

def set_alert_prefs(
    user_sub: str,
    *,
    emails: Optional[List[str]] = None,
    sms_numbers: Optional[List[str]] = None,
    email_event_types: Optional[List[str]] = None,
    sms_event_types: Optional[List[str]] = None,
    toast_event_types: Optional[List[str]] = None,
    push_event_types: Optional[List[str]] = None,
    webhook_urls: Optional[List[str]] = None,
    webhook_event_types: Optional[List[str]] = None,
) -> Dict[str, Any]:
    cur = get_alert_prefs(user_sub)
    emails = cur["emails"] if emails is None else emails
    sms_numbers = cur["sms_numbers"] if sms_numbers is None else sms_numbers
    email_event_types = cur["email_event_types"] if email_event_types is None else email_event_types
    sms_event_types = cur["sms_event_types"] if sms_event_types is None else sms_event_types
    toast_event_types = cur["toast_event_types"] if toast_event_types is None else toast_event_types
    push_event_types = cur["push_event_types"] if push_event_types is None else push_event_types
    webhook_urls = cur["webhook_urls"] if webhook_urls is None else webhook_urls
    webhook_event_types = cur["webhook_event_types"] if webhook_event_types is None else webhook_event_types

    emails_n = []
    seen = set()
    for e in emails or []:
        if not (e or "").strip():
            continue
        ne = normalize_email(e)
        if ne not in seen:
            seen.add(ne)
            emails_n.append(ne)

    sms_n = []
    seen2 = set()
    for n in sms_numbers or []:
        if not (n or "").strip():
            continue
        nn = normalize_phone(n)
        if nn not in seen2:
            seen2.add(nn)
            sms_n.append(nn)

    allowed = set(ALERT_EVENT_TYPES)
    email_types = [t for t in (email_event_types or []) if t in allowed]
    sms_types = [t for t in (sms_event_types or []) if t in allowed]
    toast_types = [t for t in (toast_event_types or []) if t in allowed]
    push_types = [t for t in (push_event_types or []) if t in allowed]
    webhook_types = [t for t in (webhook_event_types or []) if t in allowed]
    webhook_urls_n = _normalize_webhook_urls(webhook_urls or [])

    T.alert_prefs.put_item(Item={
        "user_sub": user_sub,
        "emails": emails_n,
        "sms_numbers": sms_n,
        "email_event_types": email_types,
        "sms_event_types": sms_types,
        "toast_event_types": toast_types,
        "push_event_types": push_types,
        "webhook_urls": webhook_urls_n,
        "webhook_event_types": webhook_types,
        "updated_at": now_ts(),
    })
    return get_alert_prefs(user_sub)

def write_alert(user_sub: str, *, event: str, outcome: str, title: str, details: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not S.alerts_enabled:
        return None
    ts = now_ts()
    alert_id = f"{ts:010d}#{uuid.uuid4().hex}"
    ttl = ts + int(S.alerts_ttl_days) * 86400

    safe_details: Dict[str, Any] = {}
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

    # Also publish to SSE subscribers
    try:
        sse_publish_alert(user_sub, item)
    except Exception:
        pass

    return {"alert_id": alert_id, "ts": ts}

def _write_dev_log(path: str, entry: str) -> None:
    try:
        import os
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            f.write(entry)
    except Exception:
        pass


def send_alert_email(to_emails: List[str], subject: str, body_text: str) -> None:
    if not to_emails:
        return
    if S.dev_mode:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for addr in to_emails:
            entry = f"[{ts}] ALERT_EMAIL TO={addr}\n  Subject: {subject}\n  Body: {body_text}\n\n"
            _write_dev_log(S.dev_email_log, entry)
        return
    if not S.alerts_email_enabled or not S.alerts_from_email:
        return
    try:
        import boto3
        ses = boto3.client("ses")
        ses.send_email(
            Source=S.alerts_from_email,
            Destination={"ToAddresses": to_emails},
            Message={"Subject": {"Data": subject[:120]}, "Body": {"Text": {"Data": body_text[:8000]}}},
        )
    except Exception:
        pass

def send_alert_sms(to_numbers: List[str], body_text: str) -> None:
    if not to_numbers:
        return
    if S.dev_mode:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for n in to_numbers:
            entry = f"[{ts}] ALERT_SMS TO={n}\n  Body: {body_text}\n\n"
            _write_dev_log(S.dev_sms_log, entry)
        return
    if not S.alerts_sms_enabled:
        return
    try:
        sns = sns_client()
        for n in to_numbers[:5]:
            sns.publish(PhoneNumber=n, Message=body_text[:1400])
    except Exception:
        pass

def _webhook_event_types() -> Set[str]:
    if not S.alerts_webhook_event_types:
        return set()
    return {t.strip() for t in S.alerts_webhook_event_types.split(",") if t.strip()}

def _post_webhook_with_retry(
    url: str,
    *,
    data: bytes | None = None,
    json_payload: Dict[str, Any] | None = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[bool, str]:
    retries = 3
    backoff_seconds = 0.2
    for attempt in range(1, retries + 1):
        try:
            response = requests.post(
                url,
                data=data,
                json=json_payload,
                headers=headers,
                timeout=S.alerts_webhook_timeout_seconds,
            )
            if 200 <= response.status_code < 300:
                return True, ""
            raise RuntimeError(f"webhook status={response.status_code}")
        except Exception as exc:
            if attempt == retries:
                logger.warning(
                    "Alert webhook delivery failed after retries",
                    extra={"url": url, "attempts": retries},
                    exc_info=exc,
                )
                return False, str(exc)[:400]
            sleep_for = backoff_seconds * (2 ** (attempt - 1))
            time.sleep(sleep_for)

    return False, "retry_exhausted"


def send_alert_webhook(payload: Dict[str, Any], *, alert_type: str, alert_id: str = "") -> Dict[str, Any]:
    if not S.alerts_webhook_url:
        return {"enabled": False, "delivered": False, "reason": "disabled"}
    allowed = _webhook_event_types()
    if allowed and alert_type not in allowed:
        return {"enabled": True, "delivered": False, "reason": "event_type_filtered"}
    body = {
        "alert_type": alert_type,
        "event": payload.get("event"),
        "outcome": payload.get("outcome"),
        "user_sub": payload.get("user_sub"),
        "ts": payload.get("ts"),
        "alert_id": alert_id,
        "details": payload,
    }
    data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if S.alerts_webhook_secret:
        sig = hmac.new(S.alerts_webhook_secret.encode("utf-8"), data, hashlib.sha256).hexdigest()
        headers["X-Alert-Signature"] = f"sha256={sig}"
    delivered, error = _post_webhook_with_retry(S.alerts_webhook_url, data=data, headers=headers)
    return {
        "enabled": True,
        "delivered": delivered,
        "reason": "ok" if delivered else "delivery_failed",
        "target": "alerts_webhook",
        "url": S.alerts_webhook_url,
        "error": error,
    }


def _is_privileged_event(payload: Dict[str, Any]) -> bool:
    event = str(payload.get("event") or "")
    if event.startswith(("root_", "admin_")):
        return True
    actor_sub = str(payload.get("actor_sub") or "").strip()
    if actor_sub:
        return True
    role = str(payload.get("role") or payload.get("actual_role") or "").lower()
    return role in {"root", "admin"}


def send_siem_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not S.siem_webhook_enabled or not S.siem_webhook_url:
        return {"enabled": False, "delivered": False, "reason": "disabled"}
    if S.siem_root_admin_events_only and not _is_privileged_event(payload):
        return {"enabled": True, "delivered": False, "reason": "non_privileged_filtered"}
    body = {
        "stream": "security_audit",
        "ts": payload.get("ts"),
        "event": payload.get("event"),
        "user_sub": payload.get("user_sub"),
        "actor_sub": payload.get("actor_sub"),
        "effective_sub": payload.get("effective_sub"),
        "payload": payload,
    }
    data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if S.siem_webhook_secret:
        sig = hmac.new(S.siem_webhook_secret.encode("utf-8"), data, hashlib.sha256).hexdigest()
        headers["X-SIEM-Signature"] = f"sha256={sig}"
    delivered, error = _post_webhook_with_retry(S.siem_webhook_url, data=data, headers=headers)
    return {
        "enabled": True,
        "delivered": delivered,
        "reason": "ok" if delivered else "delivery_failed",
        "target": "siem_webhook",
        "url": S.siem_webhook_url,
        "error": error,
    }


def _normalize_webhook_urls(values: List[str]) -> List[str]:
    cleaned: List[str] = []
    seen = set()
    for raw in values:
        url = (raw or "").strip()
        if not url:
            continue
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            continue
        if url not in seen:
            seen.add(url)
            cleaned.append(url[:500])
    return cleaned

def send_alert_webhook_fanout(urls: List[str], payload: Dict[str, Any]) -> None:
    if not S.alerts_webhook_enabled:
        return
    if not urls:
        return
    for url in urls[:5]:
        _post_webhook_with_retry(url, json_payload=payload)

def audit_event(event: str, user_sub: str, request=None, **fields: Any) -> None:
    payload: Dict[str, Any] = {"event": event, "user_sub": user_sub, "ts": now_ts(), **fields}
    if bool(fields.get("cli", False)):
        payload.setdefault("event_source", "rootctl")
        payload.setdefault("event_channel", "cli")
        payload.setdefault("cli_event_name", f"rootctl.{event}")
        if event.startswith("root_"):
            payload.setdefault("root_cli_event_name", f"rootctl.root.{event}")
    if request is not None:
        payload["ip"] = client_ip_from_request(request)
        payload["user_agent"] = (request.headers.get("user-agent", "")[:256])
        state = getattr(request, "state", None)
        if state is not None:
            actor_sub = getattr(state, "actor_sub", "")
            effective_sub = getattr(state, "effective_sub", "")
            impersonation_id = getattr(state, "impersonation_id", "")
            if actor_sub:
                payload.setdefault("actor_sub", actor_sub)
            if effective_sub:
                payload.setdefault("effective_sub", effective_sub)
            if impersonation_id:
                payload.setdefault("impersonation_id", impersonation_id)
            if actor_sub or effective_sub:
                payload.setdefault("impersonation", True)
    try:
        identity = get_profile_identity(user_sub)
    except Exception:
        identity = {}
    if identity:
        if identity.get("display_name"):
            payload["profile_display_name"] = identity["display_name"]
        if identity.get("email"):
            payload["profile_email"] = identity["email"]
        if identity.get("phone"):
            payload["profile_phone"] = identity["phone"]
        if identity.get("profile_photo_url"):
            payload["profile_photo_url"] = identity["profile_photo_url"]

    outcome = str(fields.get("outcome", "info"))
    status_code = fields.get("status_code")
    alert_type = event_to_type(event, outcome, status_code=status_code)
    record_auth_event(alert_type)

    # Persist alert (best effort)
    try:
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
            "device_new": "New device detected",
            "device_location_mismatch": "Device location mismatch",
            "device_trust": "Device trusted",
            "device_revoke": "Device trust revoked",
        }
        title = pretty.get(event, event.replace("_", " "))
        alert_id = ""
        if event not in _NO_ALERT_EVENTS:
            wr = write_alert(user_sub, event=event, outcome=outcome, title=title, details={**payload, "alert_type": alert_type})
            alert_id = (wr or {}).get("alert_id", "")
            send_push_for_alert(user_sub, alert_type, title, f"{event} ({outcome})", alert_id)
        webhook_result = send_alert_webhook(payload, alert_type=alert_type, alert_id=alert_id)
        siem_result = send_siem_event(payload)

        delivery_failures: List[Dict[str, Any]] = []
        for result in (webhook_result, siem_result):
            if result.get("enabled") and not result.get("delivered") and result.get("reason") == "delivery_failed":
                delivery_failures.append(
                    {
                        "target": result.get("target"),
                        "url": result.get("url"),
                        "error": result.get("error"),
                    }
                )
        if delivery_failures:
            payload["delivery_failures"] = delivery_failures
            record_auth_event("alerts_delivery_failure")
            logger.warning(
                "Alert/SIEM delivery failure",
                extra={
                    "event": event,
                    "user_sub": user_sub,
                    "correlation_id": str(payload.get("correlation_id") or ""),
                    "failures": delivery_failures,
                },
            )
            try:
                write_alert(
                    user_sub,
                    event="alerts_delivery_failure",
                    outcome="error",
                    title="Alert delivery failure",
                    details={
                        "event": event,
                        "user_sub": user_sub,
                        "correlation_id": str(payload.get("correlation_id") or ""),
                        "delivery_failures": delivery_failures,
                    },
                )
            except Exception:
                pass
    except Exception:
        alert_id = ""

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
            if identity:
                display_name = identity.get("display_name")
                if display_name:
                    lines.append(f"User: {display_name}")
                email = identity.get("email")
                if email:
                    lines.append(f"Profile email: {email}")
            if request is not None:
                lines.append(f"IP: {payload.get('ip','')}")
                lines.append(f"User-Agent: {payload.get('user_agent','')}")
            if alert_id:
                lines.append(f"Alert-ID: {alert_id}")
            reason = fields.get("reason")
            if reason:
                lines.append(f"Reason: {str(reason)[:200]}")
            lines.append("")
            lines.append(json.dumps(payload, indent=2)[:4000])
            send_alert_email(emails, subj, "\n".join(lines))
    except Exception:
        pass

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

    # Optional webhook fanout
    try:
        prefs = get_alert_prefs(user_sub)
        urls = prefs.get("webhook_urls") or []
        enabled_webhooks = set(prefs.get("webhook_event_types") or [])
        if urls and (alert_type in enabled_webhooks) and can_send_alert_channel(user_sub, "webhook"):
            webhook_payload = {
                "alert_id": alert_id,
                "alert_type": alert_type,
                "event": event,
                "outcome": outcome,
                "title": title,
                "details": payload,
            }
            send_alert_webhook_fanout(urls, webhook_payload)
    except Exception:
        pass

    # stdout audit log
    if not S.audit_log_enabled:
        return
    try:
        print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    except Exception:
        pass

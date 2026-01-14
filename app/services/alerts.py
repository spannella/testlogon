from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any, Dict, List, Optional, Set

from boto3.dynamodb.conditions import Key

from app.core.aws import sns_client
from app.core.normalize import normalize_email, normalize_phone, client_ip_from_request
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.rate_limit import can_send_alert_channel
from app.services.ttl import with_ttl

ALERT_EVENT_TYPES: List[str] = [
    "login_success","login_failure","mfa_success","mfa_failure","challenge_created","challenge_revoked",
    "challenge_failed","api_key_created","api_key_revoked","api_key_ip_rules_updated","session_revoked",
    "totp_device_added","totp_device_removed","rate_limited","access_denied","security_event",
]

# In-memory pubsub for SSE (single-process). For multi-process, swap with Redis/SQS/etc.
_SSE_SUBSCRIBERS: Dict[str, Set[asyncio.Queue]] = {}

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
        }
    return {
        "emails": it.get("emails", []),
        "sms_numbers": it.get("sms_numbers", []),
        "email_event_types": it.get("email_event_types", []),
        "sms_event_types": it.get("sms_event_types", []),
        "toast_event_types": it.get("toast_event_types", []),
        "push_event_types": it.get("push_event_types", []),
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
) -> Dict[str, Any]:
    cur = get_alert_prefs(user_sub)
    emails = cur["emails"] if emails is None else emails
    sms_numbers = cur["sms_numbers"] if sms_numbers is None else sms_numbers
    email_event_types = cur["email_event_types"] if email_event_types is None else email_event_types
    sms_event_types = cur["sms_event_types"] if sms_event_types is None else sms_event_types
    toast_event_types = cur["toast_event_types"] if toast_event_types is None else toast_event_types
    push_event_types = cur["push_event_types"] if push_event_types is None else push_event_types

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

    T.alert_prefs.put_item(Item={
        "user_sub": user_sub,
        "emails": emails_n,
        "sms_numbers": sms_n,
        "email_event_types": email_types,
        "sms_event_types": sms_types,
        "toast_event_types": toast_types,
        "push_event_types": push_types,
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

def send_alert_email(to_emails: List[str], subject: str, body_text: str) -> None:
    if not S.alerts_email_enabled or not S.alerts_from_email:
        return
    if not to_emails:
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

def audit_event(event: str, user_sub: str, request=None, **fields: Any) -> None:
    payload: Dict[str, Any] = {"event": event, "user_sub": user_sub, "ts": now_ts(), **fields}
    if request is not None:
        payload["ip"] = client_ip_from_request(request)
        payload["user_agent"] = (request.headers.get("user-agent", "")[:256])

    outcome = str(fields.get("outcome", "info"))
    status_code = fields.get("status_code")
    alert_type = event_to_type(event, outcome, status_code=status_code)

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
        }
        title = pretty.get(event, event.replace("_", " "))
        wr = write_alert(user_sub, event=event, outcome=outcome, title=title, details={**payload, "alert_type": alert_type})
        alert_id = (wr or {}).get("alert_id", "")
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

    # stdout audit log
    if not S.audit_log_enabled:
        return
    try:
        print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    except Exception:
        pass

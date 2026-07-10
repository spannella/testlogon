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
from app.services.email_delivery import record_email_failure
from app.services.rate_limit import can_send_alert_channel
from app.services.profile import get_profile_identity
from app.services.push import send_push_for_alert
from app.services.ttl import with_ttl

# --------------------------------------------------------------------------- #
#  Alert categories & source entity helpers                                     #
# --------------------------------------------------------------------------- #

ALERT_CATEGORIES: Dict[str, set] = {
    "activity": {"new_follower", "post_liked", "post_reaction", "post_comment",
                 "comment_reply", "mention", "subscription_started", "post_shared",
                 "post_tip", "message_tip"},
    "security": {"login_success", "login_failure", "mfa_success", "mfa_failure",
                 "api_key_created", "api_key_revoked", "session_revoked",
                 "totp_device_added", "totp_device_removed", "device_new",
                 "rate_limited", "access_denied", "security_event"},
    "updates":  {"calendar_event_created", "calendar_event_updated",
                 "ticket_created", "ticket_assigned", "ticket_replied",
                 "ticket_status_changed", "ticket_reopened"},
    "commerce": {"cart.abandoned", "order_shipped"},
}

# Reverse lookup: event -> category
_EVENT_TO_CATEGORY: Dict[str, str] = {}
for _cat, _events in ALERT_CATEGORIES.items():
    for _ev in _events:
        _EVENT_TO_CATEGORY[_ev] = _cat


def get_alert_category(event: str) -> str:
    """Get the category for an alert event type."""
    return _EVENT_TO_CATEGORY.get(event, "security")


def _build_action_url(alert_type: str, details: Dict[str, Any]) -> Optional[str]:
    """Construct action_url from alert type and details."""
    post_id = details.get("post_id")
    conv_id = details.get("conversation_id")
    ticket_id = details.get("ticket_id")
    actor_id = details.get("actor_user_id")

    url_map: Dict[str, Optional[str]] = {
        "post_liked":       f"/feed?post={post_id}" if post_id else None,
        "post_reaction":    f"/feed?post={post_id}" if post_id else None,
        "post_comment":     f"/feed?post={post_id}" if post_id else None,
        "comment_reply":    f"/feed?post={post_id}" if post_id else None,
        "mention":          f"/feed?post={post_id}" if post_id else (f"/messages/{conv_id}" if conv_id else None),
        "new_follower":     f"/discover?user={actor_id}" if actor_id else None,
        "subscription_started": "/subscriptions",
        "post_shared":      f"/feed?post={post_id}" if post_id else None,
        "post_tip":         f"/feed?post={post_id}" if post_id else None,
        "message_tip":      f"/messages/{conv_id}" if conv_id else None,
        "login_success":    "/security/sessions",
        "login_failure":    "/security/sessions",
        "mfa_success":      "/security",
        "mfa_failure":      "/security",
        "api_key_created":  "/security/api-keys",
        "api_key_revoked":  "/security/api-keys",
        "session_revoked":  "/security/sessions",
        "ticket_created":   f"/tickets/{ticket_id}" if ticket_id else "/tickets",
        "ticket_assigned":  f"/tickets/{ticket_id}" if ticket_id else "/tickets",
        "ticket_replied":   f"/tickets/{ticket_id}" if ticket_id else "/tickets",
        "ticket_status_changed": f"/tickets/{ticket_id}" if ticket_id else "/tickets",
    }
    return url_map.get(alert_type)


def _determine_source(alert_type: str, details: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """Determine the source entity type and ID for grouping."""
    if alert_type in ("post_liked", "post_reaction", "post_comment", "comment_reply",
                      "post_shared", "post_tip"):
        return "post", details.get("post_id")
    if alert_type in ("message_tip",):
        return "message", details.get("message_id")
    if alert_type in ("new_follower",):
        return "follower", details.get("actor_user_id")
    if alert_type in ("ticket_assigned", "ticket_replied", "ticket_status_changed"):
        return "ticket", details.get("ticket_id")
    return None, None


def _validate_action_url(url: Optional[str]) -> Optional[str]:
    """Validate action_url is relative (prevent open redirect)."""
    if not url:
        return None
    if not url.startswith("/") or "://" in url:
        logger.warning("Invalid action_url rejected: %s", url)
        return None
    return url


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
    "ticket_created","ticket_assigned","ticket_replied","ticket_status_changed","ticket_reopened",
    # Social notifications (SOC-004)
    "new_follower","post_liked","post_reaction","post_comment",
    "comment_reply","mention","subscription_started","post_shared",
    "post_tip","message_tip",
    "cart.abandoned",
    # Achievements (ENGAGE-001)
    "achievement_unlocked",
    # Commerce / seller fulfillment (ECOM-SELLER G1: enables opt-in FCM push for shop_item_sold)
    "shop_item_sold",
    # Commerce / buyer order lifecycle (ECOM D3)
    "order_shipped",
]

# ECOM-SELLER P2 - TRANSACTIONAL push events that are ON-BY-DEFAULT (opt-OUT, not
# opt-in). A user receives these without manually enabling push prefs; they can
# still disable one via ``push_opt_out_event_types``. Keep to genuinely
# transactional order/payment events (never social/marketing noise).
DEFAULT_PUSH_EVENT_TYPES: List[str] = [
    "shop_item_sold",        # you sold an item -> ship it
    "subscription_started",  # a subscription/payment succeeded
    "post_tip",              # you received a tip
    "message_tip",           # you received a message tip
    "order_shipped",         # your order has shipped (buyer, D3)
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
    if e == "ticket_created":
        return "ticket_created"
    if e == "ticket_assigned":
        return "ticket_assigned"
    if e == "ticket_replied":
        return "ticket_replied"
    if e == "ticket_status_changed":
        return "ticket_status_changed"
    if e == "ticket_reopened":
        return "ticket_reopened"
    if e.startswith("ui_rate_limited") or (status_code == 429):
        return "rate_limited"
    if status_code in (401, 403):
        return "access_denied"
    return "security_event"

def _ticket_thread_url(ticket_id: str) -> str:
    base = (S.public_base_url or "").rstrip("/")
    if not base:
        return f"/tickets/{ticket_id}"
    return f"{base}/tickets/{ticket_id}"


def render_ticket_email_template(*, alert_type: str, payload: Dict[str, Any], outcome: str) -> Tuple[str, str] | None:
    if alert_type not in {"ticket_created", "ticket_assigned", "ticket_replied", "ticket_status_changed", "ticket_reopened"}:
        return None
    ticket_id = str(payload.get("ticket_id") or "").strip()
    if not ticket_id:
        return None
    ticket_subject = str(payload.get("ticket_subject") or "(no subject)").strip()
    actor = str(payload.get("actor_sub") or payload.get("user_sub") or "system").strip()
    status = str(payload.get("status") or "").strip()
    assignee = str(payload.get("assignee_admin_sub") or "").strip()
    url = _ticket_thread_url(ticket_id)

    subjects = {
        "ticket_created": f"[Ticket #{ticket_id}] Created: {ticket_subject}",
        "ticket_assigned": f"[Ticket #{ticket_id}] Assignment updated",
        "ticket_replied": f"[Ticket #{ticket_id}] New reply",
        "ticket_status_changed": f"[Ticket #{ticket_id}] Status updated",
        "ticket_reopened": f"[Ticket #{ticket_id}] Reopened",
    }
    subject = subjects.get(alert_type, f"[Ticket #{ticket_id}] Update")

    lines = [
        f"Ticket ID: {ticket_id}",
        f"Subject: {ticket_subject}",
        f"Actor: {actor}",
        f"Event: {alert_type}",
        f"Outcome: {outcome}",
    ]
    if status:
        lines.append(f"Status: {status}")
    if assignee:
        lines.append(f"Assignee: {assignee}")
    lines.append("")
    lines.append(f"Open ticket thread: {url}")
    return subject, "\n".join(lines)


def get_alert_prefs(user_sub: str) -> Dict[str, Any]:
    it = T.alert_prefs.get_item(Key={"user_sub": user_sub}).get("Item")
    if not it:
        return {
            "emails": [], "sms_numbers": [],
            "email_event_types": [], "sms_event_types": [],
            "toast_event_types": [], "push_event_types": [],
            "push_opt_out_event_types": [],
            "webhook_urls": [], "webhook_event_types": [],
        }
    return {
        "emails": it.get("emails", []),
        "sms_numbers": it.get("sms_numbers", []),
        "email_event_types": it.get("email_event_types", []),
        "sms_event_types": it.get("sms_event_types", []),
        "toast_event_types": it.get("toast_event_types", []),
        "push_event_types": it.get("push_event_types", []),
        "push_opt_out_event_types": it.get("push_opt_out_event_types", []),
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
    push_opt_out_event_types: Optional[List[str]] = None,
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
    push_opt_out_event_types = (
        cur.get("push_opt_out_event_types", [])
        if push_opt_out_event_types is None else push_opt_out_event_types
    )
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
    # P2: opt-out only carries the default-on transactional events (opting out of a
    # non-default event is a no-op - it is off already).
    default_on = set(DEFAULT_PUSH_EVENT_TYPES)
    push_opt_out = [t for t in (push_opt_out_event_types or []) if t in default_on]
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
        "push_opt_out_event_types": push_opt_out,
        "webhook_urls": webhook_urls_n,
        "webhook_event_types": webhook_types,
        "updated_at": now_ts(),
    })
    return get_alert_prefs(user_sub)

def write_alert(
    user_sub: str,
    *,
    event: str,
    outcome: str,
    title: str,
    details: Dict[str, Any],
    action_url: Optional[str] = None,
    source_type: Optional[str] = None,
    source_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
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

    # Determine priority for this alert
    from app.services.alert_priority import get_alert_priority
    alert_type = safe_details.get("alert_type") or event
    priority = get_alert_priority(str(alert_type))

    # Compute category from event type
    category = get_alert_category(event)

    # Auto-derive action_url if not provided
    if not action_url:
        action_url = _build_action_url(event, safe_details)

    # Auto-derive source entity if not provided
    if not source_type or not source_id:
        auto_source_type, auto_source_id = _determine_source(event, safe_details)
        if not source_type:
            source_type = auto_source_type
        if not source_id:
            source_id = auto_source_id

    # Validate action_url is relative (prevent open redirect)
    action_url = _validate_action_url(action_url)

    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "alert_id": alert_id,
        "ts": ts,
        "event": event,
        "outcome": outcome,
        "title": title[:120],
        "details": safe_details,
        "read": False,
        "read_at": 0,
        "priority": priority,
        "category": category,
    }
    if action_url:
        item["action_url"] = action_url
    if source_type:
        item["source_type"] = source_type
    if source_id:
        item["source_id"] = source_id

    try:
        T.alerts.put_item(Item=with_ttl(item, ttl_epoch=ttl))
    except Exception:
        pass

    # Increment atomic unread count sentinel
    unread_delta = 0
    if S.notification_unread_count_enabled:
        try:
            from app.services.notification_unread import increment_unread_count
            increment_unread_count(user_sub)
            unread_delta = 1
        except Exception:
            pass

    # Publish to SSE subscribers with priority and unread_delta
    try:
        sse_item = {**item, "toast_priority": priority, "unread_delta": unread_delta}
        sse_publish_alert(user_sub, sse_item)
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
    except Exception as exc:
        logger.exception("Failed to send alert email to %s", to_emails)
        try:
            from app.metrics import EMAIL_FAILED

            EMAIL_FAILED.inc()
        except Exception:
            logger.exception("Failed to increment EMAIL_FAILED metric")
        try:
            record_email_failure(to_emails, subject, str(exc))
        except Exception:
            logger.exception("Failed to record email failure for %s", to_emails)
        return None
    return None

def send_alert_sms(to_numbers: List[str], body_text: str) -> List[Dict[str, Any]]:
    """Send SMS via the production pipeline. Returns list of result dicts.

    Delegates each number to :func:`app.services.sms_delivery.send_sms`, the
    single production send path: dev-log in dev mode, real SNS publish (with
    MessageAttributes) when ``alerts_sms_enabled`` and SNS configured, always
    honouring suppression + per-number daily limits and recording a delivery
    row. Limited to the first 5 numbers per call.
    """
    if not to_numbers:
        return []
    from app.services.sms_delivery import send_sms_bulk

    return send_sms_bulk(to_numbers, body_text, limit=5)

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
            ticket_template = render_ticket_email_template(alert_type=alert_type, payload=payload, outcome=outcome)
            if ticket_template is not None:
                subj, body = ticket_template
                send_alert_email(emails, subj, body)
            else:
                # Try NOTIFY-001 HTML email templates
                html_template = None
                if S.notification_email_templates_enabled:
                    try:
                        from app.services.alert_email_templates import render_alert_email_template
                        html_template = render_alert_email_template(alert_type, payload)
                    except Exception:
                        pass
                if html_template is not None:
                    subj, body = html_template
                    send_alert_email(emails, subj, body)
                else:
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
        # GAP-0325: do NOT silently swallow email fanout failures (security
        # alert emails like new-device login / MFA changes could vanish with
        # no trace). Log and continue to the other channels (SMS/webhook) so
        # a single channel failure does not break multi-channel fanout.
        logger.exception("alert email fanout failed")

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

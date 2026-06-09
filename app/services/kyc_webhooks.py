"""KYC webhooks & notifications glue layer (KYC-011).

NET-NEW glue that REUSES the existing webhook + alert infrastructure:

* Webhook events for KYC state transitions are dispatched through the existing
  ``app.services.webhook_service.dispatch_webhook_event`` (which enqueues a
  signed, retried delivery to every user-registered webhook endpoint subscribed
  to the event type). The ``kyc.*`` event types are registered in the canonical
  webhook event-type registry (``KYC_WEBHOOK_EVENT_TYPES`` /
  ``WEBHOOK_EVENT_TYPES_V2``).
* In-app notifications are written via the existing
  ``app.services.alerts.write_alert``. Email uses the existing
  ``app.services.alerts.send_alert_email`` path.

No new DynamoDB tables: deliveries use the existing ``webhook_deliveries``
table; in-app notifications use the existing ``alerts`` table; preferences are
a small item on the existing ``profile`` table.

A single helper, :func:`emit_kyc_event`, is the entry point wired into KYC
status transitions (lazy-import-safe so importing a KYC service never hard-fails
if this module changes).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.core.time import now_ts
from app.services.webhook_service import (
    KYC_WEBHOOK_EVENT_TYPES,
    dispatch_webhook_event,
)

# Re-export the canonical KYC event-type allowlist for callers/tests.
KYC_EVENT_TYPES: Dict[str, str] = dict(KYC_WEBHOOK_EVENT_TYPES)

# Human-readable in-app alert titles per event.
_ALERT_TITLES: Dict[str, str] = {
    "kyc.case.created": "Verification case created",
    "kyc.case.submitted": "Verification submitted for review",
    "kyc.case.approved": "Identity verification approved",
    "kyc.case.rejected": "Identity verification not approved",
    "kyc.case.needs_info": "Additional information needed",
    "kyc.case.disputed": "Verification decision disputed",
    "kyc.case.resubmitted": "Verification resubmitted for review",
    "kyc.tier.changed": "Verification level changed",
    "kyc.tier.upgraded": "Verification level upgraded",
    "kyc.tier.downgraded": "Verification level changed",
    "kyc.document.verified": "Document verified",
    "kyc.document.rejected": "Document not accepted",
    "kyc.residency.verified": "Residency verified",
    "kyc.proof_of_funds.verified": "Proof of funds verified",
    "kyc.liveness.passed": "Verification call passed",
    "kyc.liveness.failed": "Verification call needs attention",
    "kyc.id_scan.result": "ID scan result available",
    "kyc.sanctions.match": "Screening review required",
    "kyc.sanctions.clear": "Screening cleared",
}

# Events for which we attempt an email notification (subject line).
_EMAIL_SUBJECTS: Dict[str, str] = {
    "kyc.case.submitted": "Your verification application has been submitted",
    "kyc.case.approved": "Your identity verification has been approved",
    "kyc.case.rejected": "Your identity verification requires attention",
    "kyc.case.needs_info": "Additional information needed for your verification",
    "kyc.case.disputed": "We have received your verification appeal",
    "kyc.case.resubmitted": "Your verification application has been resubmitted",
}

# Events relevant to admins/compliance (queue / risk).
_ADMIN_EVENTS = {
    "kyc.case.submitted",
    "kyc.case.disputed",
    "kyc.case.resubmitted",
    "kyc.sanctions.match",
    "kyc.liveness.failed",
}

_DEFAULT_PREFS: Dict[str, Any] = {
    "in_app_enabled": True,
    "email_enabled": True,
    "events": sorted(KYC_EVENT_TYPES.keys()),
}

_PREFS_SK = "KYC_WEBHOOKS_PREFS"


# ─── Event-type listing ──────────────────────────────────────────────────────

def list_kyc_event_types() -> List[Dict[str, str]]:
    """Return the canonical list of KYC webhook event types + descriptions."""
    return [
        {"event_type": k, "description": v}
        for k, v in sorted(KYC_EVENT_TYPES.items())
    ]


def is_kyc_event_type(event_type: str) -> bool:
    return event_type in KYC_EVENT_TYPES


# ─── Notification preferences (reuse profile table) ──────────────────────────

def get_kyc_webhooks_prefs(user_sub: str) -> Dict[str, Any]:
    """Get a user's KYC webhook/notification preferences (defaults if unset)."""
    try:
        from app.core.tables import T

        item = T.profile.get_item(
            Key={"user_sub": f"KYC_WEBHOOKS#{user_sub}"}
        ).get("Item")
    except Exception:
        item = None
    if not item:
        return dict(_DEFAULT_PREFS)
    events = item.get("events")
    if not isinstance(events, list):
        events = list(_DEFAULT_PREFS["events"])
    return {
        "in_app_enabled": bool(item.get("in_app_enabled", True)),
        "email_enabled": bool(item.get("email_enabled", True)),
        "events": [e for e in events if e in KYC_EVENT_TYPES],
    }


def update_kyc_webhooks_prefs(
    user_sub: str,
    *,
    in_app_enabled: Optional[bool] = None,
    email_enabled: Optional[bool] = None,
    events: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Update a user's KYC notification preferences (last-write-wins)."""
    from app.core.tables import T

    current = get_kyc_webhooks_prefs(user_sub)
    if in_app_enabled is not None:
        current["in_app_enabled"] = bool(in_app_enabled)
    if email_enabled is not None:
        current["email_enabled"] = bool(email_enabled)
    if events is not None:
        current["events"] = sorted({e for e in events if e in KYC_EVENT_TYPES})

    T.profile.put_item(
        Item={
            "user_sub": f"KYC_WEBHOOKS#{user_sub}",
            "kind": _PREFS_SK,
            "in_app_enabled": current["in_app_enabled"],
            "email_enabled": current["email_enabled"],
            "events": current["events"],
            "updated_at": now_ts(),
        }
    )
    return current


# ─── Notification history (reuse alerts table) ───────────────────────────────

def list_kyc_notifications(user_sub: str, *, limit: int = 50) -> List[Dict[str, Any]]:
    """Return the user's in-app KYC notifications (alerts with kyc.* events)."""
    try:
        from boto3.dynamodb.conditions import Attr, Key
        from app.core.tables import T

        resp = T.alerts.query(
            KeyConditionExpression=Key("user_sub").eq(user_sub),
            FilterExpression=Attr("event").begins_with("kyc."),
            ScanIndexForward=False,
            Limit=200,
        )
        items = resp.get("Items", [])
    except Exception:
        items = []

    out: List[Dict[str, Any]] = []
    for it in items:
        event = str(it.get("event", ""))
        # Exclude internal admin/compliance audit alerts from the user feed.
        if event.startswith("kyc.admin_notification."):
            continue
        out.append(
            {
                "alert_id": str(it.get("alert_id", "")),
                "event": event,
                "title": str(it.get("title", "")),
                "details": it.get("details", {}),
                "action_url": it.get("action_url"),
                "read": bool(it.get("read", False)),
                "created_at": int(it.get("ts", 0) or 0),
            }
        )
    out.sort(key=lambda x: x["created_at"], reverse=True)
    return out[:limit]


# ─── The single emit helper wired into KYC state transitions ─────────────────

def emit_kyc_event(
    *,
    event: str,
    user_sub: str,
    case_id: Optional[str] = None,
    request: Any = None,
    **payload: Any,
) -> Dict[str, Any]:
    """Emit a KYC event: in-app alert + webhook dispatch (+ email when relevant).

    Safe to call from any KYC state-transition point. Never raises — all
    channel failures are caught and reported in the returned result so a
    notification failure can't break a KYC state transition.
    """
    result: Dict[str, Any] = {
        "event": event,
        "user_sub": user_sub,
        "dispatched": False,
        "channels": {},
    }
    if not event or not is_kyc_event_type(event):
        result["reason"] = "unknown_event"
        return result
    if not user_sub:
        result["reason"] = "no_user"
        return result

    ts = now_ts()
    # Keep the alert/webhook payload FLAT — write_alert stringifies nested values.
    flat_payload: Dict[str, Any] = {"event": event, "timestamp": ts}
    if case_id:
        flat_payload["case_id"] = case_id
    for k, v in payload.items():
        if v is None:
            continue
        if isinstance(v, (list, tuple, set)):
            flat_payload[k] = ", ".join(str(x) for x in v)
        elif isinstance(v, dict):
            continue
        else:
            flat_payload[k] = v

    prefs = get_kyc_webhooks_prefs(user_sub)
    enabled_events = set(prefs.get("events") or [])

    # 1. In-app alert (always on, mirrors ticket's always-on in-app channel)
    try:
        from app.services.alerts import write_alert

        title = _ALERT_TITLES.get(event, f"KYC update: {event}")
        action_url = f"/kyc/status?case_id={case_id}" if case_id else "/kyc"
        wr = write_alert(
            user_sub,
            event=event,
            outcome="success",
            title=title,
            details={**flat_payload, "alert_type": event},
            action_url=action_url,
        )
        result["channels"]["in_app"] = bool(wr)
        if wr:
            result["alert_id"] = wr.get("alert_id")
    except Exception:
        result["channels"]["in_app"] = False

    # 2. Email (if user opted in for this event + has an email)
    if (
        prefs.get("email_enabled", True)
        and event in enabled_events
        and event in _EMAIL_SUBJECTS
    ):
        try:
            from app.services.alerts import send_alert_email
            from app.services.profile import get_profile

            email = (get_profile(user_sub) or {}).get("email")
            if email:
                send_alert_email(
                    [email],
                    _EMAIL_SUBJECTS[event],
                    _build_email_body(event, flat_payload),
                )
                result["channels"]["email"] = True
            else:
                result["channels"]["email"] = False
        except Exception:
            result["channels"]["email"] = False

    # 3. Webhook dispatch via the EXISTING dispatcher (signed + retried).
    #    Only events the user subscribed to in prefs are dispatched; the
    #    dispatcher additionally only enqueues for endpoints subscribed to the
    #    event type.
    if event in enabled_events:
        try:
            delivery_ids = dispatch_webhook_event(
                event_type=event,
                user_sub=user_sub,
                data=flat_payload,
            )
            result["channels"]["webhook"] = True
            result["webhook_delivery_ids"] = delivery_ids
        except Exception:
            result["channels"]["webhook"] = False

    # 4. Admin/compliance audit trail for queue-relevant events.
    if event in _ADMIN_EVENTS:
        try:
            from app.services.alerts import audit_event

            audit_event(
                f"kyc.admin_notification.{event}",
                user_sub,
                request,
                outcome="info",
                **{k: v for k, v in flat_payload.items() if k != "event"},
            )
            result["channels"]["admin"] = True
        except Exception:
            result["channels"]["admin"] = False

    result["dispatched"] = True
    return result


def _build_email_body(event: str, payload: Dict[str, Any]) -> str:
    case_id = payload.get("case_id", "N/A")
    if event == "kyc.case.submitted":
        return (
            f"Your identity verification application (Case {case_id}) has been "
            f"submitted and is now in our review queue. We will notify you when a "
            f"decision is made."
        )
    if event == "kyc.case.approved":
        return (
            f"Good news! Your identity verification (Case {case_id}) has been "
            f"approved. Your account verification level has been updated."
        )
    if event == "kyc.case.rejected":
        reasons = payload.get("reason_codes") or "See case details"
        return (
            f"Your identity verification (Case {case_id}) was not approved. "
            f"Reason(s): {reasons}. You may submit a new application with updated "
            f"documents."
        )
    if event == "kyc.case.needs_info":
        items = payload.get("requested_items") or "See case details"
        return (
            f"Additional information is needed for your verification "
            f"(Case {case_id}). Requested: {items}. Please log in and update your "
            f"application."
        )
    if event == "kyc.case.disputed":
        reason = payload.get("reason") or "See case details"
        return (
            f"We have received your appeal for verification Case {case_id}. "
            f"Reason: {reason}. Our compliance team will review your dispute and "
            f"notify you of the outcome."
        )
    if event == "kyc.case.resubmitted":
        return (
            f"Your verification application (Case {case_id}) has been resubmitted "
            f"with updated information and is back in our review queue. We will "
            f"notify you when a decision is made."
        )
    return f"KYC notification: {event}"
